use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use rustc_hash::FxHashSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::{BlocklistsConfig, WhitelistConfig};
use crate::util::normalize_name;

/// Lock-free-to-read, hot-swappable set of blocked domains (normalized,
/// trailing-dot form). Checked on essentially every query that isn't a
/// cache hit or static host, so it uses a non-cryptographic hasher
/// (`rustc-hash`, same as the response cache) for speed. Trade-off: a
/// client that can choose which domain names it queries could in theory
/// engineer hash collisions to degrade this set's performance - a low-risk
/// concern for a personal/home resolver, but a real one if this is ever
/// exposed to less-trusted clients.
pub type BlockSet = Arc<ArcSwap<FxHashSet<String>>>;

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

/// One fetchable domain-list URL, refreshed independently on its own timer.
struct Source {
    url: String,
    refresh_interval: Duration,
    set: Mutex<Arc<FxHashSet<String>>>,
}

/// One direction's worth of domains - either the blocklist or the
/// whitelist, both of which have the identical shape: a fixed set of
/// inline domains from config, plus zero or more URL sources each fetched
/// and refreshed on their own schedule. `raw` is the union of all of them
/// for this direction alone; `BlocklistManager` combines both directions'
/// `raw` sets (block minus allow) into the actually-published `BlockSet`.
struct DomainSet {
    sources: Vec<Arc<Source>>,
    inline: FxHashSet<String>,
    raw: ArcSwap<FxHashSet<String>>,
}

impl DomainSet {
    fn new(urls: &[String], domains: &[String], refresh_interval: Duration) -> Self {
        let sources = urls
            .iter()
            .map(|url| {
                Arc::new(Source {
                    url: url.clone(),
                    refresh_interval,
                    set: Mutex::new(Arc::new(FxHashSet::default())),
                })
            })
            .collect();
        let inline = domains.iter().map(|d| normalize_name(d)).collect();
        Self {
            sources,
            inline,
            raw: ArcSwap::from_pointee(FxHashSet::default()),
        }
    }

    /// Recomputes `raw` as the inline domains union every source's most
    /// recent fetch. Called after any source in this direction refreshes.
    fn recompute_raw(&self) {
        let mut merged = self.inline.clone();
        for src in &self.sources {
            merged.extend(src.set.lock().unwrap().iter().cloned());
        }
        self.raw.store(Arc::new(merged));
    }

    fn len(&self) -> usize {
        self.raw.load().len()
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
            merged: Arc::new(ArcSwap::from_pointee(FxHashSet::default())),
        }
    }

    pub fn merged_set(&self) -> BlockSet {
        self.merged.clone()
    }

    /// Fetches every blocklist and whitelist URL source concurrently,
    /// publishes the merged set, then spawns a background refresh loop per
    /// source - blocklist and whitelist sources alike, each on its own
    /// schedule - until `shutdown` fires. A source that fails to fetch
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
        self.block.recompute_raw();
        self.allow.recompute_raw();
        self.republish_merged();
        info!(
            domains = self.merged.load().len(),
            blocklist_sources = self.block.sources.len(),
            whitelist_sources = self.allow.sources.len(),
            whitelisted = self.allow.len(),
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
                    // published set, so both are recomputed regardless of
                    // which one just changed.
                    this.block.recompute_raw();
                    this.allow.recompute_raw();
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

    async fn fetch_one(&self, url: &str) -> Result<FxHashSet<String>> {
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
        Ok(parse_list(&body))
    }

    fn republish_merged(&self) {
        let mut merged = (*self.block.raw.load_full()).clone();
        for domain in self.allow.raw.load().iter() {
            merged.remove(domain);
        }
        self.merged.store(Arc::new(merged));
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
pub fn parse_list(body: &str) -> FxHashSet<String> {
    let mut set = FxHashSet::default();
    for raw_line in body.lines() {
        let line = raw_line.trim();
        // `#` for hosts-format comments, `!` for Adblock Plus comments.
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        if let Some(domain) = adblock_network_rule_domain(line) {
            insert_if_valid(&mut set, domain);
            continue;
        }

        let mut tokens = line.split_whitespace();
        let first = match tokens.next() {
            Some(t) => t,
            None => continue,
        };

        // hosts-format: first token is an IP, remaining tokens are hostnames/aliases.
        // plain format: every token on the line is a standalone domain candidate.
        let domains: Box<dyn Iterator<Item = &str>> = if first.parse::<IpAddr>().is_ok() {
            Box::new(tokens)
        } else {
            Box::new(std::iter::once(first).chain(tokens))
        };

        for domain in domains {
            insert_if_valid(&mut set, domain);
        }
    }
    set
}

fn insert_if_valid(set: &mut FxHashSet<String>, domain: &str) {
    if !looks_like_domain(domain) {
        return;
    }
    let normalized = normalize_name(domain);
    if normalized == "." || EXCLUDED_HOSTNAMES.contains(&normalized.as_str()) {
        return;
    }
    set.insert(normalized);
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
        *set.sources[source_index].set.lock().unwrap() = Arc::new(domains.iter().map(|d| d.to_string()).collect());
        manager.block.recompute_raw();
        manager.allow.recompute_raw();
        manager.republish_merged();
    }

    #[test]
    fn inline_blocklist_domains_are_blocked_with_no_urls_configured() {
        let config = blocklists_config(vec![], vec!["ads.example.com".to_string()]);
        let whitelist = whitelist_config(vec![], vec![]);
        let manager = BlocklistManager::new(&config, &whitelist);
        manager.block.recompute_raw();
        manager.allow.recompute_raw();
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
