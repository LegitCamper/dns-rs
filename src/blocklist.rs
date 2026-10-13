use std::hash::Hasher;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use rustc_hash::FxHasher;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::{BlocklistsConfig, WhitelistConfig};
use crate::dns::inline_name::MAX_NAME_LEN;
use crate::util::normalize_name;

/// Lock-free-to-read, hot-swappable set of blocked domains (normalized,
/// trailing-dot form). Checked on essentially every query that isn't a
/// cache hit or static host.
pub type BlockSet = Arc<ArcSwap<DomainIndex>>;

/// Hard ceiling on a single blocklist/whitelist URL's response body. The
/// largest real-world lists in use (e.g. hagezi's `pro.plus`) are a few tens
/// of MB; this leaves generous headroom while still bounding how much a
/// single fetch can allocate.
const MAX_LIST_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

/// Infrastructure hostnames that show up in hosts-format blocklist preambles
/// (pointing at 0.0.0.0/127.0.0.1) but must never actually be blocked.
const EXCLUDED_HOSTNAMES: &[&str] = &[
    "localhost.",
    "localhost.localdomain.",
    "local.",
    "broadcasthost.",
    "ip6-localhost.",
    "ip6-loopback.",
    "ip6-localnet.",
    "ip6-mcastprefix.",
    "ip6-allnodes.",
    "ip6-allrouters.",
    "ip6-allhosts.",
];

/// Marks an unused slot. No valid normalized name is zero-length, so a zero
/// length is an unambiguous "empty".
const EMPTY_SLOT: (u32, u32) = (0, 0);

/// Open-addressed set of normalized domain names stored in one contiguous
/// byte arena.
///
/// The obvious `FxHashSet<String>` costs a separate heap allocation plus a
/// 24-byte `String` header per domain, and two pointer dereferences per
/// lookup (table slot, then the string's heap buffer). At the ~1M domains
/// these blocklists actually reach that was ~100MB resident and two cache
/// misses on the hottest path in the server. Here the whole set is two
/// allocations total (`arena` + `slots`), ~28 bytes per domain, and a
/// lookup touches one slot and one arena span.
///
/// ponytail: linear probing with no deletion support — the set is only ever
/// built once and then swapped in wholesale, never mutated in place. If
/// incremental add/remove is ever needed, that needs tombstones.
pub struct DomainIndex {
    arena: Vec<u8>,
    slots: Vec<(u32, u32)>,
    mask: usize,
    len: usize,
}

fn hash_name(bytes: &[u8]) -> u64 {
    let mut hasher = FxHasher::default();
    hasher.write(bytes);
    hasher.finish()
}

impl DomainIndex {
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// `expected` is a hint for how many names will be inserted; sizing the
    /// table up front keeps a million-domain build from rehashing its way
    /// there.
    pub fn with_capacity(expected: usize) -> Self {
        let slots = expected.saturating_mul(2).next_power_of_two().max(16);
        Self {
            arena: Vec::new(),
            slots: vec![EMPTY_SLOT; slots],
            mask: slots - 1,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, name: &str) -> bool {
        self.contains_bytes(name.as_bytes())
    }

    pub fn contains_bytes(&self, bytes: &[u8]) -> bool {
        self.find(bytes).is_some()
    }

    fn name_at(&self, slot: (u32, u32)) -> &[u8] {
        let start = slot.0 as usize;
        &self.arena[start..start + slot.1 as usize]
    }

    fn find(&self, bytes: &[u8]) -> Option<usize> {
        if bytes.is_empty() {
            return None;
        }
        let mut i = hash_name(bytes) as usize & self.mask;
        loop {
            let slot = self.slots[i];
            if slot.1 == 0 {
                return None;
            }
            if self.name_at(slot) == bytes {
                return Some(i);
            }
            i = (i + 1) & self.mask;
        }
    }

    /// Inserts an already-normalized name. Duplicates are ignored.
    fn insert_normalized(&mut self, bytes: &[u8]) {
        if bytes.is_empty() || self.find(bytes).is_some() {
            return;
        }
        // Grow at 75% load; linear probing degrades badly past that.
        if (self.len + 1) * 4 >= self.slots.len() * 3 {
            self.grow();
        }
        let entry = (self.arena.len() as u32, bytes.len() as u32);
        self.arena.extend_from_slice(bytes);
        let mut i = hash_name(bytes) as usize & self.mask;
        while self.slots[i].1 != 0 {
            i = (i + 1) & self.mask;
        }
        self.slots[i] = entry;
        self.len += 1;
    }

    fn grow(&mut self) {
        let slots = self.slots.len() * 2;
        let old = std::mem::replace(&mut self.slots, vec![EMPTY_SLOT; slots]);
        self.mask = slots - 1;
        for slot in old {
            if slot.1 == 0 {
                continue;
            }
            // Only the 8-byte slots move; the arena bytes never do.
            let mut i = hash_name(self.name_at(slot)) as usize & self.mask;
            while self.slots[i].1 != 0 {
                i = (i + 1) & self.mask;
            }
            self.slots[i] = slot;
        }
    }

    /// Iterates the stored names in unspecified order.
    pub fn names(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.slots
            .iter()
            .copied()
            .filter(|slot| slot.1 != 0)
            .map(|slot| self.name_at(slot))
    }
}

/// Builds an index from names that still need normalizing.
impl<S: AsRef<str>> FromIterator<S> for DomainIndex {
    fn from_iter<I: IntoIterator<Item = S>>(names: I) -> Self {
        let names = names.into_iter();
        let mut index = Self::with_capacity(names.size_hint().0);
        let mut buf = [0u8; MAX_NAME_LEN];
        for name in names {
            if let Some(len) = normalize_into(name.as_ref(), &mut buf) {
                index.insert_normalized(&buf[..len]);
            }
        }
        index
    }
}

impl Default for DomainIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DomainIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_set()
            .entries(self.names().map(|n| String::from_utf8_lossy(n)))
            .finish()
    }
}

/// Normalizes `name` into `buf` (lowercased, exactly one trailing dot, no
/// leading dot), returning its length. The allocation-free counterpart to
/// `util::normalize_name`, used on the blocklist-parsing path where it would
/// otherwise run once per domain across millions of lines.
fn normalize_into(name: &str, buf: &mut [u8; MAX_NAME_LEN]) -> Option<usize> {
    let trimmed = name.trim().trim_end_matches('.').trim_start_matches('.');
    // Leave room for the trailing dot this appends.
    if trimmed.is_empty() || trimmed.len() + 1 > MAX_NAME_LEN {
        return None;
    }
    let len = trimmed.len();
    buf[..len].copy_from_slice(trimmed.as_bytes());
    buf[..len].make_ascii_lowercase();
    buf[len] = b'.';
    Some(len + 1)
}

/// One fetchable domain-list URL, refreshed independently on its own timer.
struct Source {
    url: String,
    refresh_interval: Duration,
    set: Mutex<Arc<DomainIndex>>,
}

/// One direction's worth of domains — either the blocklist or the
/// whitelist, both of which have the identical shape: a fixed set of
/// inline domains from config, plus zero or more URL sources each fetched
/// and refreshed on their own schedule.
struct DomainSet {
    sources: Vec<Arc<Source>>,
    inline: Vec<String>,
}

impl DomainSet {
    fn new(urls: &[String], domains: &[String], refresh_interval: Duration) -> Self {
        let sources = urls
            .iter()
            .map(|url| {
                Arc::new(Source {
                    url: url.clone(),
                    refresh_interval,
                    set: Mutex::new(Arc::new(DomainIndex::new())),
                })
            })
            .collect();
        Self {
            sources,
            inline: domains.iter().map(|d| normalize_name(d)).collect(),
        }
    }

    /// Point-in-time snapshot of every source's most recent fetch. Cloning
    /// `Arc`s, not contents, so this holds no lock while the (slow) merge runs.
    fn snapshot(&self) -> Vec<Arc<DomainIndex>> {
        self.sources
            .iter()
            .map(|src| Arc::clone(&src.set.lock().unwrap()))
            .collect()
    }
}

pub struct BlocklistManager {
    http: reqwest::Client,
    block: DomainSet,
    allow: DomainSet,
    merged: BlockSet,
}

impl BlocklistManager {
    pub fn new(config: &BlocklistsConfig, whitelist: &WhitelistConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("dns-rs/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build blocklist HTTP client");

        let block = DomainSet::new(&config.urls, &config.domains, Duration::from_secs(config.refresh_interval_secs));
        let allow = DomainSet::new(
            &whitelist.urls,
            &whitelist.domains,
            Duration::from_secs(whitelist.refresh_interval_secs),
        );

        Self {
            http,
            block,
            allow,
            merged: Arc::new(ArcSwap::from_pointee(DomainIndex::new())),
        }
    }

    pub fn merged_set(&self) -> BlockSet {
        self.merged.clone()
    }

    /// Fetches every blocklist and whitelist URL source concurrently,
    /// publishes the merged set, then spawns a background refresh loop per
    /// source — blocklist and whitelist sources alike, each on its own
    /// schedule — until `shutdown` fires. A source that fails to fetch
    /// keeps its previous contents rather than taking the server down.
    pub async fn start(self: &Arc<Self>, shutdown: CancellationToken) {
        let mut handles = Vec::with_capacity(self.block.sources.len() + self.allow.sources.len());
        for src in self.block.sources.iter().chain(self.allow.sources.iter()) {
            let this = Arc::clone(self);
            let src = Arc::clone(src);
            handles.push(tokio::spawn(async move { this.fetch_and_store(&src).await }));
        }
        for h in handles {
            let _ = h.await;
        }
        let whitelisted = self.republish_merged();
        info!(
            domains = self.merged.load().len(),
            blocklist_sources = self.block.sources.len(),
            whitelist_sources = self.allow.sources.len(),
            whitelisted,
            "initial blocklist/whitelist fetch complete"
        );

        self.spawn_refresh_loops(|m| &m.block, shutdown.clone());
        self.spawn_refresh_loops(|m| &m.allow, shutdown);
    }

    /// Spawns one refresh loop per source in the direction `accessor`
    /// selects (the blocklist or the whitelist). A plain fn pointer instead
    /// of a `&DomainSet` borrow, since each loop is a `'static` spawned
    /// task and re-derives the set it needs from `this: Arc<Self>` itself.
    fn spawn_refresh_loops(self: &Arc<Self>, accessor: fn(&BlocklistManager) -> &DomainSet, shutdown: CancellationToken) {
        for src in accessor(self).sources.clone() {
            let this = Arc::clone(self);
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(src.refresh_interval) => {}
                        _ = shutdown.cancelled() => return,
                    }
                    this.fetch_and_store(&src).await;
                    // Either direction refreshing can change the final
                    // published set, so this rebuilds from both regardless
                    // of which one just changed.
                    this.republish_merged();
                }
            });
        }
    }

    async fn fetch_and_store(&self, src: &Source) {
        match self.fetch_one(&src.url).await {
            Ok(set) => {
                let count = set.len();
                *src.set.lock().unwrap() = Arc::new(set);
                info!(url = %src.url, domains = count, "domain list source refreshed");
            }
            Err(err) => {
                warn!(url = %src.url, error = %err, "domain list refresh failed, keeping previous contents");
            }
        }
    }

    async fn fetch_one(&self, url: &str) -> Result<DomainIndex> {
        let mut resp = self.http.get(url).send().await?.error_for_status()?;

        // Streamed and capped rather than `resp.text()`, which buffers the
        // whole body regardless of size: a misconfigured, hijacked, or
        // just-unexpectedly-huge blocklist/whitelist source would otherwise
        // let a single fetch allocate without bound.
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > MAX_LIST_RESPONSE_BYTES {
                bail!("response from {url} exceeded the {MAX_LIST_RESPONSE_BYTES}-byte limit for a single domain list");
            }
        }
        let body = String::from_utf8(body).with_context(|| format!("response from {url} was not valid UTF-8"))?;
        Ok(parse_list_async(&body).await)
    }

    /// Rebuilds the published set as (inline blocklist domains ∪ every
    /// blocklist source) minus (inline whitelist domains ∪ every whitelist
    /// source), and swaps it in. Returns the size of the whitelist it
    /// subtracted.
    ///
    /// This builds the final set in one pass. The earlier version kept a
    /// per-direction `raw` union and then deep-cloned the blocklist one to
    /// subtract the whitelist from it, which meant two full copies of a
    /// ~1M-domain set live at once on every refresh — on a 512MB box that
    /// was the single largest memory spike in the process.
    fn republish_merged(&self) -> usize {
        let block_sources = self.block.snapshot();
        let allow_sources = self.allow.snapshot();

        let allow = DomainIndex::merged(&self.allow.inline, &allow_sources, None);
        let expected = self.block.inline.len() + block_sources.iter().map(|s| s.len()).sum::<usize>();
        let merged = DomainIndex::merged_with_capacity(expected, &self.block.inline, &block_sources, Some(&allow));

        let whitelisted = allow.len();
        self.merged.store(Arc::new(merged));
        whitelisted
    }
}

impl DomainIndex {
    /// Unions `inline` (already normalized) with every name in `sources`,
    /// skipping anything present in `exclude`.
    fn merged(inline: &[String], sources: &[Arc<DomainIndex>], exclude: Option<&DomainIndex>) -> Self {
        let expected = inline.len() + sources.iter().map(|s| s.len()).sum::<usize>();
        Self::merged_with_capacity(expected, inline, sources, exclude)
    }

    fn merged_with_capacity(
        expected: usize,
        inline: &[String],
        sources: &[Arc<DomainIndex>],
        exclude: Option<&DomainIndex>,
    ) -> Self {
        let mut out = Self::with_capacity(expected);
        let excluded = |bytes: &[u8]| exclude.is_some_and(|e| e.contains_bytes(bytes));
        for name in inline {
            if !excluded(name.as_bytes()) {
                out.insert_normalized(name.as_bytes());
            }
        }
        for source in sources {
            for name in source.names() {
                if !excluded(name) {
                    out.insert_normalized(name);
                }
            }
        }
        out
    }
}

/// Parses hosts-format, plain domain-per-line, and Adblock Plus network
/// rules (`||domain^`). Adblock Plus *cosmetic* rules (`domain##selector`,
/// `#@#`, `#?#`) hide a page element, not a domain, and are never treated as
/// one — an earlier parser treated `#` as a trailing comment marker and
/// truncated these down to a bare (and very much not blocked-worthy) domain,
/// NXDOMAIN'ing half the web. Only a line starting with `#` is a comment now.
///
/// Used identically for both `[blocklists]` and `[whitelist]` URLs - a
/// whitelist source is just a list of domains to allow, in the same
/// formats. It does not give Adblock exception rules (`@@||domain^`) any
/// special "this means allow" meaning; those are simply not extracted by
/// this parser regardless of which direction it's used for.
#[cfg(test)]
pub fn parse_list(body: &str) -> DomainIndex {
    // Roughly one domain per line; over-estimating the table is far cheaper
    // than rehashing a million-entry set several times on the way up.
    let mut index = DomainIndex::with_capacity(body.len() / 24);
    let mut buf = [0u8; MAX_NAME_LEN];
    for line in body.lines() {
        parse_line(line, &mut index, &mut buf);
    }
    index
}

/// How many lines to parse between cooperative yields. The runtime is
/// single-threaded, so a 1M-line list parsed straight through would block
/// every in-flight query for the whole parse; yielding periodically keeps
/// a refresh from showing up as a multi-second latency spike.
const PARSE_YIELD_INTERVAL: usize = 8192;

/// `parse_list`, but yields to the runtime periodically so a large list
/// doesn't stall query serving on a single-core machine.
pub async fn parse_list_async(body: &str) -> DomainIndex {
    let mut index = DomainIndex::with_capacity(body.len() / 24);
    let mut buf = [0u8; MAX_NAME_LEN];
    for (i, line) in body.lines().enumerate() {
        parse_line(line, &mut index, &mut buf);
        if i % PARSE_YIELD_INTERVAL == PARSE_YIELD_INTERVAL - 1 {
            tokio::task::yield_now().await;
        }
    }
    index
}

fn parse_line(raw_line: &str, index: &mut DomainIndex, buf: &mut [u8; MAX_NAME_LEN]) {
    let line = raw_line.trim();
    // `#` for hosts-format comments, `!` for Adblock Plus comments.
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return;
    }

    if let Some(domain) = adblock_network_rule_domain(line) {
        insert_if_valid(index, domain, buf);
        return;
    }

    let mut tokens = line.split_whitespace();
    let first = match tokens.next() {
        Some(t) => t,
        None => return,
    };

    // hosts-format: first token is an IP, remaining tokens are hostnames/aliases.
    // plain format: every token on the line is a standalone domain candidate.
    if first.parse::<IpAddr>().is_ok() {
        for domain in tokens {
            insert_if_valid(index, domain, buf);
        }
    } else {
        for domain in std::iter::once(first).chain(tokens) {
            insert_if_valid(index, domain, buf);
        }
    }
}

fn insert_if_valid(index: &mut DomainIndex, domain: &str, buf: &mut [u8; MAX_NAME_LEN]) {
    if !looks_like_domain(domain) {
        return;
    }
    let Some(len) = normalize_into(domain, buf) else {
        return;
    };
    let normalized = &buf[..len];
    if normalized == b"." || EXCLUDED_HOSTNAMES.iter().any(|h| h.as_bytes() == normalized) {
        return;
    }
    index.insert_normalized(normalized);
}

/// Extracts the domain from `||domain^` (optionally `||domain^$options`).
/// Skips rules with a wildcard/path in the domain, or a path after `^` (e.g.
/// `||domain^*/path`) — those match a specific path, not the whole domain.
/// Exception rules (`@@||domain^`) don't start with `||` so never match here.
fn adblock_network_rule_domain(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("||")?;
    let end = rest.find('^')?;
    let candidate = &rest[..end];
    if candidate.is_empty() || candidate.contains(['*', '/']) {
        return None;
    }
    let after = &rest[end + 1..];
    if !after.is_empty() && !after.starts_with('$') {
        return None;
    }
    Some(candidate)
}

/// Not a full RFC 1035 validator, just enough to reject filter-list syntax
/// and stray HTML. Requires an interior dot (after stripping leading/trailing
/// ones) so a CSS selector like `.ytd-browse` — one leading dot, no interior
/// one — doesn't pass through.
fn looks_like_domain(s: &str) -> bool {
    let trimmed = s.trim_matches('.');
    !trimmed.is_empty()
        && trimmed.contains('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocklists_config(urls: Vec<String>, domains: Vec<String>) -> BlocklistsConfig {
        BlocklistsConfig {
            urls,
            domains,
            refresh_interval_secs: 43_200,
        }
    }

    fn whitelist_config(urls: Vec<String>, domains: Vec<String>) -> WhitelistConfig {
        WhitelistConfig {
            urls,
            domains,
            refresh_interval_secs: 43_200,
        }
    }

    /// Simulates a source fetch landing entries directly (bypassing real
    /// HTTP), then re-derives the merged set the same way a background
    /// refresh would.
    fn land_fetch(manager: &BlocklistManager, set: &DomainSet, source_index: usize, domains: &[&str]) {
        *set.sources[source_index].set.lock().unwrap() = Arc::new(domains.iter().collect());
        manager.republish_merged();
    }

    #[test]
    fn inline_blocklist_domains_are_blocked_with_no_urls_configured() {
        let config = blocklists_config(vec![], vec!["ads.example.com".to_string()]);
        let whitelist = whitelist_config(vec![], vec![]);
        let manager = BlocklistManager::new(&config, &whitelist);
        manager.republish_merged();

        assert!(manager.merged_set().load().contains("ads.example.com."));
    }

    #[test]
    fn inline_whitelist_domains_remove_domains_from_the_merged_set_even_after_refresh() {
        let config = blocklists_config(vec!["https://example.invalid/list.txt".to_string()], vec![]);
        let whitelist = whitelist_config(vec![], vec!["s.youtube.com".to_string()]);
        let manager = BlocklistManager::new(&config, &whitelist);

        land_fetch(&manager, &manager.block, 0, &["ads.example.com.", "s.youtube.com."]);

        let merged = manager.merged_set();
        assert!(merged.load().contains("ads.example.com."));
        assert!(
            !merged.load().contains("s.youtube.com."),
            "whitelisted domain must never appear in the merged set, even though a source lists it"
        );
    }

    #[test]
    fn whitelist_urls_remove_domains_from_the_merged_set_just_like_inline_whitelist_domains() {
        let config = blocklists_config(vec!["https://example.invalid/block.txt".to_string()], vec![]);
        let whitelist = whitelist_config(vec!["https://example.invalid/allow.txt".to_string()], vec![]);
        let manager = BlocklistManager::new(&config, &whitelist);

        land_fetch(&manager, &manager.block, 0, &["ads.example.com.", "s.youtube.com."]);
        land_fetch(&manager, &manager.allow, 0, &["s.youtube.com."]);

        let merged = manager.merged_set();
        assert!(merged.load().contains("ads.example.com."));
        assert!(
            !merged.load().contains("s.youtube.com."),
            "a domain listed by a whitelist URL source must be removed from the merged set, same as an inline whitelist domain"
        );
    }

    #[test]
    fn a_whitelist_source_refreshing_on_its_own_can_un_block_a_domain() {
        // The domain starts out blocked (only the blocklist source has run).
        let config = blocklists_config(vec!["https://example.invalid/block.txt".to_string()], vec![]);
        let whitelist = whitelist_config(vec!["https://example.invalid/allow.txt".to_string()], vec![]);
        let manager = BlocklistManager::new(&config, &whitelist);
        land_fetch(&manager, &manager.block, 0, &["s.youtube.com."]);
        assert!(manager.merged_set().load().contains("s.youtube.com."), "should start out blocked");

        // The whitelist source refreshing on its own schedule (independent
        // of any blocklist refresh) must be enough to un-block it.
        land_fetch(&manager, &manager.allow, 0, &["s.youtube.com."]);
        assert!(
            !manager.merged_set().load().contains("s.youtube.com."),
            "a whitelist source refreshing on its own must be able to un-block a domain, without needing the blocklist to refresh too"
        );
    }

    #[test]
    fn domain_index_survives_growth_dedup_and_probing() {
        // Enough entries to force several table growths (starts at 16 slots,
        // grows at 75% load), which is where linear probing and rehashing
        // would go wrong.
        let names: Vec<String> = (0..5_000).map(|i| format!("host{i}.example.com")).collect();
        let index: DomainIndex = names.iter().collect();
        assert_eq!(index.len(), 5_000);
        for name in &names {
            assert!(index.contains(&normalize_name(name)), "{name} must be present after growth");
        }
        assert!(!index.contains("absent.example.com."), "a miss must terminate probing, not loop");

        // Duplicates (including case/trailing-dot variants that normalize to
        // the same name) must not grow the set.
        let deduped: DomainIndex = ["a.com", "A.com", "a.com.", ".a.com"].into_iter().collect();
        assert_eq!(deduped.len(), 1, "normalized duplicates must collapse to one entry");

        // Every stored name must come back out exactly once.
        let mut round_tripped: Vec<String> = index.names().map(|n| String::from_utf8(n.to_vec()).unwrap()).collect();
        round_tripped.sort();
        round_tripped.dedup();
        assert_eq!(round_tripped.len(), 5_000, "names() must yield each entry exactly once");

        assert!(DomainIndex::new().is_empty());
        assert!(!DomainIndex::new().contains("anything."), "an empty index must not match");
        assert!(!index.contains(""), "an empty lookup must never match");
    }

    #[test]
    fn republish_merged_subtracts_whitelist_without_a_second_full_copy() {
        // Also pins the behavior the single-pass merge has to preserve: a
        // name in both directions ends up excluded.
        let config = blocklists_config(vec!["https://example.invalid/block.txt".to_string()], vec!["inline-block.test".to_string()]);
        let whitelist = whitelist_config(vec![], vec!["inline-block.test".to_string()]);
        let manager = BlocklistManager::new(&config, &whitelist);
        land_fetch(&manager, &manager.block, 0, &["keep.test.", "drop.test."]);

        let merged = manager.merged_set();
        assert!(merged.load().contains("keep.test."));
        assert!(
            !merged.load().contains("inline-block.test."),
            "an inline whitelist entry must win over an inline blocklist entry"
        );
    }

    #[test]
    fn parses_hosts_format() {
        let body = "\
# comment line
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com other.example.com
0.0.0.0 localhost
";
        let set = parse_list(body);
        assert!(set.contains("ads.example.com."));
        assert!(set.contains("tracker.example.com."));
        assert!(set.contains("other.example.com."));
        assert!(!set.contains("localhost."));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn parses_plain_domain_list() {
        let body = "Ads.Example.com\n\nsome.tracker.net # inline comment\n";
        let set = parse_list(body);
        assert!(set.contains("ads.example.com."));
        assert!(set.contains("some.tracker.net."));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn ignores_adblock_plus_cosmetic_rules() {
        // Real lines from EasyList/Fanboy: "hide this element on this page",
        // not "block this domain". Must never end up blocking the domain.
        let body = "\
google.com##.GC3LC41DERB + div[style=\"position: relative; height: 170px;\"]
youtube.com###alert-banner > .ytd-browse > .yt-alert-with-actions-renderer
facebook.com#@##fb_header
chatgpt.com#?#.md\\:px-\\[60px\\]:has-text(By messaging ChatGPT)
";
        let set = parse_list(body);
        assert!(set.is_empty(), "cosmetic filter rules must never be treated as domains to block: {set:?}");
    }

    #[test]
    fn extracts_domains_from_adblock_plus_network_rules() {
        let body = "\
||doubleclick.net^
||ads.example.com^$third-party
@@||example.com^$document
||wildcard.*.example^
||path.example.com/ads/*^
||google.com^*/friendconnect.js
";
        let set = parse_list(body);
        assert!(set.contains("doubleclick.net."));
        assert!(set.contains("ads.example.com."));
        assert!(!set.contains("example.com."), "exception rules (@@) must never be treated as a block");
        assert!(
            !set.contains("google.com."),
            "a rule matching a specific path (^*/friendconnect.js) blocks that path, not the whole domain"
        );
        assert_eq!(set.len(), 2, "wildcard/path rules should be skipped rather than guessed at: {set:?}");
    }

    #[test]
    fn ignores_adblock_plus_comment_lines() {
        // Adblock Plus uses `!` for comments, not `#` — a naive parser can
        // easily mistake "! wordpress.org some explanatory text" for a plain
        // domain line.
        let body = "! wordpress.org https://wordpress.org/plugins/some-plugin/\n! linkedin.com\n";
        let set = parse_list(body);
        assert!(set.is_empty(), "`!` comment lines must never be treated as domains: {set:?}");
    }
}
