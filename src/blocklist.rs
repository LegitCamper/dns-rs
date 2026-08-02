use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
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

struct Source {
    url: String,
    refresh_interval: Duration,
    set: Mutex<Arc<FxHashSet<String>>>,
}

pub struct BlocklistManager {
    http: reqwest::Client,
    sources: Vec<Arc<Source>>,
    /// Subtracted from `merged` on every rebuild, so a refresh can't bring a
    /// whitelisted domain back.
    whitelist: FxHashSet<String>,
    merged: BlockSet,
}

impl BlocklistManager {
    pub fn new(config: &BlocklistsConfig, whitelist: &WhitelistConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("dns-rs/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build blocklist HTTP client");

        let refresh_interval = Duration::from_secs(config.refresh_interval_secs);
        let sources = config
            .urls
            .iter()
            .map(|url| {
                Arc::new(Source {
                    url: url.clone(),
                    refresh_interval,
                    set: Mutex::new(Arc::new(FxHashSet::default())),
                })
            })
            .collect();

        let whitelist = whitelist.domains.iter().map(|d| normalize_name(d)).collect();

        Self {
            http,
            sources,
            whitelist,
            merged: Arc::new(ArcSwap::from_pointee(FxHashSet::default())),
        }
    }

    pub fn merged_set(&self) -> BlockSet {
        self.merged.clone()
    }

    /// Fetches every source concurrently, publishes the merged set, then
    /// spawns a background refresh loop per source until `shutdown` fires.
    /// A source that fails to fetch keeps its previous contents rather than
    /// taking the server down.
    pub async fn start(self: &Arc<Self>, shutdown: CancellationToken) {
        let mut handles = Vec::with_capacity(self.sources.len());
        for src in &self.sources {
            let this = Arc::clone(self);
            let src = Arc::clone(src);
            handles.push(tokio::spawn(async move { this.fetch_and_store(&src).await }));
        }
        for h in handles {
            let _ = h.await;
        }
        self.republish_merged();
        info!(
            domains = self.merged.load().len(),
            sources = self.sources.len(),
            whitelisted = self.whitelist.len(),
            "initial blocklist fetch complete"
        );

        for src in &self.sources {
            let this = Arc::clone(self);
            let src = Arc::clone(src);
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(src.refresh_interval) => {}
                        _ = shutdown.cancelled() => return,
                    }
                    this.fetch_and_store(&src).await;
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
                info!(url = %src.url, domains = count, "blocklist source refreshed");
            }
            Err(err) => {
                warn!(url = %src.url, error = %err, "blocklist refresh failed, keeping previous contents");
            }
        }
    }

    async fn fetch_one(&self, url: &str) -> Result<FxHashSet<String>> {
        let resp = self.http.get(url).send().await?.error_for_status()?;
        let body = resp.text().await?;
        Ok(parse_list(&body))
    }

    fn republish_merged(&self) {
        let mut merged = FxHashSet::default();
        for src in &self.sources {
            let snapshot = src.set.lock().unwrap().clone();
            merged.extend(snapshot.iter().cloned());
        }
        for domain in &self.whitelist {
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

    #[test]
    fn whitelist_removes_domains_from_merged_set_even_after_refresh() {
        let config = BlocklistsConfig {
            urls: vec!["https://example.invalid/list.txt".to_string()],
            refresh_interval_secs: 43_200,
        };
        let whitelist = WhitelistConfig {
            domains: vec!["s.youtube.com".to_string()],
        };
        let manager = BlocklistManager::new(&config, &whitelist);

        // Simulate a source fetch landing entries directly, then re-derive
        // the merged set the same way a background refresh would.
        *manager.sources[0].set.lock().unwrap() =
            Arc::new(["ads.example.com.".to_string(), "s.youtube.com.".to_string()].into_iter().collect());
        manager.republish_merged();

        let merged = manager.merged_set();
        assert!(merged.load().contains("ads.example.com."));
        assert!(
            !merged.load().contains("s.youtube.com."),
            "whitelisted domain must never appear in the merged set, even though a source lists it"
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
