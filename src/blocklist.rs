use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
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

        Self {
            http,
            sources,
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
    pub async fn start(self: &Arc<Self>) {
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
            "initial blocklist fetch complete"
        );

        for src in &self.sources {
            let this = Arc::clone(self);
            let src = Arc::clone(src);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(src.refresh_interval).await;
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
        self.merged.store(Arc::new(merged));
    }
}

/// Parses a blocklist body supporting the two formats Pi-hole-style lists use:
/// hosts-format (`0.0.0.0 domain.tld [alias...]`) and plain domain-per-line.
/// `#` starts a comment (whole-line or inline); blank lines are skipped.
pub fn parse_list(body: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for raw_line in body.lines() {
        let line = match raw_line.split_once('#') {
            Some((before, _)) => before,
            None => raw_line,
        }
        .trim();
        if line.is_empty() {
            continue;
        }

        let mut tokens = line.split_whitespace();
        let first = match tokens.next() {
            Some(t) => t,
            None => continue,
        };

        // hosts-format: first token is an IP, remaining tokens are hostnames/aliases.
        // plain format: every token on the line is a standalone domain.
        let domains: Box<dyn Iterator<Item = &str>> = if first.parse::<IpAddr>().is_ok() {
            Box::new(tokens)
        } else {
            Box::new(std::iter::once(first).chain(tokens))
        };

        for domain in domains {
            let normalized = normalize_name(domain);
            if normalized == "." || EXCLUDED_HOSTNAMES.contains(&normalized.as_str()) {
                continue;
            }
            set.insert(normalized);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
