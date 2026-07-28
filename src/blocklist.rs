use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::BlocklistsConfig;
use crate::util::normalize_name;

/// Lock-free-to-read, hot-swappable set of blocked domains (normalized, trailing-dot form).
pub type BlockSet = Arc<ArcSwap<HashSet<String>>>;

/// Hostnames that commonly appear in the preamble of hosts-format blocklists
/// pointing at 0.0.0.0/127.0.0.1. These are infrastructure names, not ads/trackers,
/// and must never be blocked or the resolver breaks local name resolution.
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
    set: Mutex<Arc<HashSet<String>>>,
}

pub struct BlocklistManager {
    http: reqwest::Client,
    sources: Vec<Arc<Source>>,
    /// Normalized names that must never end up in `merged`, even if a source
    /// lists them — subtracted out every time `merged` is rebuilt, so a
    /// background refresh can never bring a whitelisted domain back.
    whitelist: HashSet<String>,
    merged: BlockSet,
}

impl BlocklistManager {
    pub fn new(config: &BlocklistsConfig) -> Self {
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
                    set: Mutex::new(Arc::new(HashSet::new())),
                })
            })
            .collect();

        let whitelist = config.whitelist.iter().map(|d| normalize_name(d)).collect();

        Self {
            http,
            sources,
            whitelist,
            merged: Arc::new(ArcSwap::from_pointee(HashSet::new())),
        }
    }

    pub fn merged_set(&self) -> BlockSet {
        self.merged.clone()
    }

    /// Fetches every source concurrently and blocks until the initial merged
    /// set is published, then spawns one background refresh loop per source.
    /// A source that fails to fetch (initially or on refresh) just keeps its
    /// previous contents (empty on first failure) rather than taking the
    /// server down — blocklist availability should fail open, not crash DNS.
    ///
    /// `shutdown` stops the background refresh loops once cancelled, so a
    /// config reload (which builds a brand-new `BlocklistManager`) doesn't
    /// leak the old one's tasks running forever alongside the new one's.
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

    async fn fetch_one(&self, url: &str) -> Result<HashSet<String>> {
        let resp = self.http.get(url).send().await?.error_for_status()?;
        let body = resp.text().await?;
        Ok(parse_list(&body))
    }

    fn republish_merged(&self) {
        let mut merged = HashSet::new();
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

/// Parses a blocklist body. Supports:
/// - hosts-format (`0.0.0.0 domain.tld [alias...]`)
/// - plain domain-per-line
/// - Adblock Plus network rules (`||domain^`, optionally with `$options`)
///
/// Adblock Plus *cosmetic* rules (`domain##selector`, `domain#@#selector`,
/// `domain#?#selector`, ...) are deliberately never treated as a domain to
/// block — they tell a browser extension to hide a page element, not block
/// the domain at the network level. An earlier version of this parser
/// treated `#` as starting a trailing comment, which silently truncated
/// exactly these lines down to the bare domain — so every site with an
/// EasyList/Fanboy cosmetic rule (i.e. most of the web, including things
/// like google.com and github.com) got NXDOMAIN'd. Only a whole line
/// starting with `#` is a comment now, and every extracted candidate is
/// validated to actually look like a domain before being inserted, which is
/// what makes a cosmetic-rule line a safe no-op instead of a corruption
/// vector.
pub fn parse_list(body: &str) -> HashSet<String> {
    let mut set = HashSet::new();
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

fn insert_if_valid(set: &mut HashSet<String>, domain: &str) {
    if !looks_like_domain(domain) {
        return;
    }
    let normalized = normalize_name(domain);
    if normalized == "." || EXCLUDED_HOSTNAMES.contains(&normalized.as_str()) {
        return;
    }
    set.insert(normalized);
}

/// Extracts the domain from an Adblock Plus network rule of the form
/// `||domain^`, optionally followed by nothing but a `$options` suffix.
/// Rules with wildcards or paths in the domain part (`*`, `/`) are skipped
/// rather than guessed at, and so is anything after the `^` that isn't a
/// `$options` suffix — `||domain^*/path` matches a specific path, not the
/// whole domain, so collapsing it down to "block domain" would over-block.
/// Exception rules (`@@||domain^`) don't start with `||` so they never
/// match here, which is what keeps them from being mistaken for a block.
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

/// A conservative sanity check, not a full RFC 1035 validator — just enough
/// to reject anything that couldn't plausibly be a DNS name (filter-list
/// syntax, stray HTML, etc.) rather than silently blocking it.
///
/// Requires an *interior* dot (i.e. still has one after stripping leading
/// and trailing dots, matching what `normalize_name` does) — a bare CSS
/// class selector like `.ytd-browse` contains a dot too, but it's only the
/// leading one, and normalizing strips that down to a single-label
/// "ytd-browse." that would otherwise pass right through.
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
            whitelist: vec!["s.youtube.com".to_string()],
        };
        let manager = BlocklistManager::new(&config);

        // Simulate a source fetch landing entries directly, then re-derive
        // the merged set the same way a background refresh would.
        *manager.sources[0].set.lock().unwrap() =
            Arc::new(HashSet::from(["ads.example.com.".to_string(), "s.youtube.com.".to_string()]));
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
