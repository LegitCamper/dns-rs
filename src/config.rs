use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(not(feature = "serverless"))]
use std::path::Path;
#[cfg(any(feature = "dot", feature = "doh-tls"))]
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::util::normalize_name;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub blocking: BlockingConfig,
    #[serde(default)]
    pub blocklists: BlocklistsConfig,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
    /// `"domain" = "ip"` pairs — see the example config for the format.
    #[serde(default)]
    pub static_hosts: HashMap<String, Ipv4Addr>,
    #[serde(default)]
    pub upstream: UpstreamsConfig,
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
    #[cfg(feature = "dot")]
    #[serde(default = "default_dot_port")]
    pub dot_port: u16,
    #[serde(default = "default_doh_port")]
    pub doh_port: u16,
    #[cfg(any(feature = "dot", feature = "doh-tls"))]
    pub tls_cert: PathBuf,
    #[cfg(any(feature = "dot", feature = "doh-tls"))]
    pub tls_key: PathBuf,
    #[serde(default = "default_ttl")]
    pub default_ttl: u32,
}

impl ServerConfig {
    #[cfg(feature = "dot")]
    pub fn dot_listen(&self) -> SocketAddr {
        SocketAddr::new(self.bind_address, self.dot_port)
    }

    pub fn doh_listen(&self) -> SocketAddr {
        SocketAddr::new(self.bind_address, self.doh_port)
    }
}

fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

#[cfg(feature = "dot")]
fn default_dot_port() -> u16 {
    853
}

fn default_doh_port() -> u16 {
    // Plaintext listener gets a high port: no cap_net_bind_service needed, and
    // it isn't meant to be the public 443 endpoint anyway.
    if cfg!(not(feature = "doh-tls")) {
        8053
    } else {
        443
    }
}

fn default_ttl() -> u32 {
    300
}

#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// Blocked domains get a "this domain doesn't exist" (NXDOMAIN) response.
    #[default]
    Nxdomain,
    /// Blocked domains resolve successfully, but to `sinkhole_ip` (classic
    /// Pi-hole-style "IP-based" blocking) instead of their real address.
    Sinkhole,
}

#[derive(Debug, Deserialize)]
pub struct BlockingConfig {
    #[serde(default)]
    pub mode: BlockMode,
    #[serde(default = "default_sinkhole_ip")]
    pub sinkhole_ip: Ipv4Addr,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            mode: BlockMode::default(),
            sinkhole_ip: default_sinkhole_ip(),
        }
    }
}

fn default_sinkhole_ip() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

/// Domains to block: `urls` are fetched (hosts-format, plain domain list, or
/// Adblock-style network rules — see `blocklist::parse_list`) and refreshed
/// every `refresh_interval_secs`; `domains` are literal names, always
/// applied in addition to whatever the URLs resolve to. Either or both may
/// be used.
#[derive(Debug, Deserialize)]
pub struct BlocklistsConfig {
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default = "default_list_refresh_secs")]
    pub refresh_interval_secs: u64,
}

impl Default for BlocklistsConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            domains: Vec::new(),
            refresh_interval_secs: default_list_refresh_secs(),
        }
    }
}

fn default_list_refresh_secs() -> u64 {
    43_200 // 12h
}

/// Domains that must never be blocked, even if a source in `[blocklists]`
/// lists them - checked as exact names, not by subdomain. Same shape as
/// `[blocklists]`: `urls` are fetched and refreshed on their own schedule,
/// `domains` are literal names always applied in addition.
#[derive(Debug, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default = "default_list_refresh_secs")]
    pub refresh_interval_secs: u64,
}

impl Default for WhitelistConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            domains: Vec::new(),
            refresh_interval_secs: default_list_refresh_secs(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct UpstreamsConfig {
    #[serde(default)]
    pub strategy: UpstreamStrategy,
    /// Plain URL-like strings; the protocol is inferred from the scheme
    /// (`https://` = DoH, `tls://` = DoT). See `UpstreamConfig::parse`.
    #[serde(default)]
    pub urls: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStrategy {
    /// Try each upstream in order, falling back on failure or timeout.
    #[default]
    Sequential,
    /// Start upstreams in order with a short delay between each, returning
    /// the first success. Usually as fast as racing every upstream while
    /// avoiding duplicate traffic when the preferred one responds promptly.
    Hedged,
    /// Query every upstream at once, use whichever answers first.
    Race,
}

#[derive(Debug, Clone)]
pub enum UpstreamConfig {
    Doh {
        url: String,
    },
    Dot {
        host: String,
        port: u16,
        tls_name: String,
    },
}

impl UpstreamConfig {
    /// `https://...` is DoH. `tls://host:port` is DoT; TLS name defaults to
    /// `host`, or override with `tls://host:port#tls_name` (e.g. connecting
    /// to a literal IP but validating against the provider's hostname).
    fn parse(entry: &str) -> Result<Self> {
        if entry.starts_with("https://") {
            return Ok(Self::Doh {
                url: entry.to_string(),
            });
        }
        if let Some(rest) = entry.strip_prefix("tls://") {
            let (host_port, tls_name) = match rest.split_once('#') {
                Some((hp, name)) => (hp, Some(name.to_string())),
                None => (rest, None),
            };
            let (host, port) = host_port.rsplit_once(':').with_context(|| {
                format!("upstream '{entry}' is missing a port, expected tls://host:port")
            })?;
            let port: u16 = port
                .parse()
                .with_context(|| format!("upstream '{entry}' has an invalid port"))?;
            let tls_name = tls_name.unwrap_or_else(|| host.to_string());
            return Ok(Self::Dot {
                host: host.to_string(),
                port,
                tls_name,
            });
        }
        bail!("upstream '{entry}' must start with https:// (DoH) or tls:// (DoT)");
    }
}

#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Total bytes reserved for cache storage, allocated once as a single
    /// pool that responses are suballocated from (see `dns::cache`).
    #[serde(default = "default_max_size_bytes")]
    pub max_size_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_size_bytes: default_max_size_bytes(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Ceiling on the cache byte budget: the arena is one eager allocation at
/// startup, so this is the point where a mistuned value is rejected instead of
/// OOM-killing the process.
const MAX_CACHE_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

fn default_max_size_bytes() -> u64 {
    #[cfg(feature = "serverless")]
    {
        const MIB: u64 = 1024 * 1024;
        memory_limit_bytes().map_or(64 * MIB, |limit| (limit / 4).clamp(MIB, 64 * MIB))
    }
    #[cfg(not(feature = "serverless"))]
    {
        64 * 1024 * 1024 // 64 MiB
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StaticHost {
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

/// Deserializes an environment value into a Serde enum using the enum's
/// declared variant names, keeping TOML and environment configuration in sync.
#[cfg(feature = "serverless")]
fn parse_env_enum<T>(name: &str, value: String) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    T::deserialize(serde::de::value::StringDeserializer::<
        serde::de::value::Error,
    >::new(value))
    .map_err(|err| anyhow::anyhow!("invalid {name}: {err}"))
}

/// Effective memory limit for this process's cgroup, resolved through the
/// process's own path in `/proc/self/cgroup` rather than the mount root, since
/// containerd/Kubernetes place the process in a nested cgroup. Assumes the
/// standard `/sys/fs/cgroup` (+ `/sys/fs/cgroup/memory` on v1) layout.
///
/// ponytail: reads only the leaf cgroup, so a limit set on an ancestor (a
/// systemd slice with delegation) shows up as `max` and falls back to the
/// default budget; upgrade path is walking the parent chain until a numeric
/// limit appears.
#[cfg(feature = "serverless")]
fn memory_limit_bytes() -> Option<u64> {
    fn parse_limit(raw: &str) -> Option<u64> {
        let raw = raw.trim();
        if raw == "max" {
            return None;
        }
        let bytes = raw.parse::<u64>().ok()?;
        // cgroup v1 spells "no limit" as PAGE_COUNTER_MAX * PAGE_SIZE, which is
        // just under 2^63 on every architecture; no real limit is near 4 EiB.
        (bytes < 1 << 62).then_some(bytes)
    }

    fn read_limit(path: &std::path::Path) -> Option<u64> {
        parse_limit(&std::fs::read_to_string(path).ok()?)
    }

    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let unified_path = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or("/");
    let v2 = std::path::Path::new("/sys/fs/cgroup")
        .join(unified_path.trim_start_matches('/'))
        .join("memory.max");
    if v2.is_file() {
        return read_limit(&v2);
    }

    let controller = cgroup
        .lines()
        .find_map(|line| {
            let (id, rest) = line.split_once(':')?;
            (id != "0"
                && rest
                    .split_once(':')
                    .is_some_and(|(controllers, _)| controllers.split(',').any(|c| c == "memory")))
            .then_some(rest.rsplit_once(':')?.1)
        })
        .unwrap_or("/");
    let v1 = std::path::Path::new("/sys/fs/cgroup/memory")
        .join(controller.trim_start_matches('/'))
        .join("memory.limit_in_bytes");
    read_limit(&v1)
}

impl Config {
    #[cfg(feature = "serverless")]
    pub fn from_env() -> Result<Config> {
        fn value(name: &str) -> Result<Option<String>> {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(std::env::VarError::NotUnicode(value)) => {
                    bail!("{name} must be valid Unicode: {}", value.to_string_lossy())
                }
            }
        }

        fn list(name: &str) -> Result<Option<Vec<String>>> {
            Ok(value(name)?.map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_owned)
                    .collect()
            }))
        }

        fn parse<T>(name: &str) -> Result<Option<T>>
        where
            T: std::str::FromStr,
            T::Err: std::fmt::Display,
        {
            match value(name)? {
                Some(raw) => raw
                    .parse()
                    .map(Some)
                    .map_err(|err| anyhow::anyhow!("invalid {name}: {err}")),
                None => Ok(None),
            }
        }

        let mut config = Config {
            server: ServerConfig {
                bind_address: default_bind_address(),
                doh_port: default_doh_port(),
                default_ttl: default_ttl(),
            },
            blocking: BlockingConfig::default(),
            blocklists: BlocklistsConfig::default(),
            whitelist: WhitelistConfig::default(),
            static_hosts: HashMap::new(),
            upstream: UpstreamsConfig {
                strategy: UpstreamStrategy::default(),
                urls: vec!["https://cloudflare-dns.com/dns-query".to_string()],
            },
            cache: CacheConfig::default(),
        };

        if let Some(bind_address) = parse("DNSRS_BIND_ADDRESS")? {
            config.server.bind_address = bind_address;
        }
        if let Some(port) = match parse("PORT")? {
            Some(port) => Some(port),
            None => parse("DNSRS_DOH_PORT")?,
        } {
            config.server.doh_port = port;
        }
        if let Some(ttl) = parse("DNSRS_DEFAULT_TTL")? {
            config.server.default_ttl = ttl;
        }
        if let Some(urls) = list("DNSRS_UPSTREAM_URLS")? {
            config.upstream.urls = urls;
        }
        if let Some(strategy) = value("DNSRS_UPSTREAM_STRATEGY")? {
            config.upstream.strategy = parse_env_enum("DNSRS_UPSTREAM_STRATEGY", strategy)?;
        }
        if let Some(urls) = list("DNSRS_BLOCKLIST_URLS")? {
            config.blocklists.urls = urls;
        }
        if let Some(domains) = list("DNSRS_BLOCKLIST_DOMAINS")? {
            config.blocklists.domains = domains;
        }
        if let Some(seconds) = parse("DNSRS_BLOCKLIST_REFRESH_SECS")? {
            config.blocklists.refresh_interval_secs = seconds;
        }
        if let Some(urls) = list("DNSRS_WHITELIST_URLS")? {
            config.whitelist.urls = urls;
        }
        if let Some(domains) = list("DNSRS_WHITELIST_DOMAINS")? {
            config.whitelist.domains = domains;
        }
        if let Some(seconds) = parse("DNSRS_WHITELIST_REFRESH_SECS")? {
            config.whitelist.refresh_interval_secs = seconds;
        }
        if let Some(mode) = value("DNSRS_BLOCK_MODE")? {
            config.blocking.mode = parse_env_enum("DNSRS_BLOCK_MODE", mode)?;
        }
        if let Some(ip) = parse("DNSRS_SINKHOLE_IP")? {
            config.blocking.sinkhole_ip = ip;
        }
        if let Some(entries) = list("DNSRS_STATIC_HOSTS")? {
            for entry in entries {
                let (name, ip) = entry.split_once('=').with_context(|| {
                    format!("invalid DNSRS_STATIC_HOSTS entry '{entry}': expected name=ip")
                })?;
                config.static_hosts.insert(
                    name.trim().to_string(),
                    ip.trim().parse().with_context(|| {
                        format!("invalid IP in DNSRS_STATIC_HOSTS entry '{entry}'")
                    })?,
                );
            }
        }
        if let Some(enabled) = parse("DNSRS_CACHE_ENABLED")? {
            config.cache.enabled = enabled;
        }
        if let Some(bytes) = parse("DNSRS_CACHE_MAX_SIZE_BYTES")? {
            // Below this the arena can't hold a usable number of responses, and
            // `ResponseCache::new` would silently run cacheless.
            const MIN_CACHE_BYTES: u64 = 1024 * 1024;
            if config.cache.enabled && bytes < MIN_CACHE_BYTES {
                bail!(
                    "DNSRS_CACHE_MAX_SIZE_BYTES must be at least {MIN_CACHE_BYTES} (1 MiB) while the cache is enabled; set DNSRS_CACHE_ENABLED=false to disable it"
                );
            }
            config.cache.max_size_bytes = bytes;
        }

        config.validate()?;
        Ok(config)
    }

    #[cfg(not(feature = "serverless"))]
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        let config: Config = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file at {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.upstream.urls.is_empty() {
            bail!("config must define at least one entry in [upstream] urls");
        }
        self.parsed_upstreams()?;
        #[cfg(any(feature = "dot", feature = "doh-tls"))]
        if !self.server.tls_cert.is_file() {
            bail!(
                "server.tls_cert does not point to a file: {}",
                self.server.tls_cert.display()
            );
        }
        #[cfg(any(feature = "dot", feature = "doh-tls"))]
        if !self.server.tls_key.is_file() {
            bail!(
                "server.tls_key does not point to a file: {}",
                self.server.tls_key.display()
            );
        }
        #[cfg(feature = "dot")]
        if self.server.dot_port == self.server.doh_port {
            bail!("server.dot_port and server.doh_port must be different");
        }
        // The arena is allocated eagerly at startup (`vec![0u8; n]`), so an
        // absurd budget would OOM-kill the process rather than fail cleanly.
        // Also catches a `usize` truncation on 32-bit targets.
        if self.cache.enabled && self.cache.max_size_bytes > MAX_CACHE_BYTES {
            bail!(
                "cache.max_size_bytes must be at most {MAX_CACHE_BYTES} ({} MiB)",
                MAX_CACHE_BYTES / 1024 / 1024
            );
        }
        if !self.blocklists.urls.is_empty() && self.blocklists.refresh_interval_secs == 0 {
            bail!("blocklists.refresh_interval_secs must not be 0");
        }
        if !self.whitelist.urls.is_empty() && self.whitelist.refresh_interval_secs == 0 {
            bail!("whitelist.refresh_interval_secs must not be 0");
        }
        Ok(())
    }

    pub fn parsed_upstreams(&self) -> Result<Vec<UpstreamConfig>> {
        self.upstream
            .urls
            .iter()
            .map(|s| UpstreamConfig::parse(s))
            .collect()
    }

    pub fn static_hosts_map(&self) -> rustc_hash::FxHashMap<String, StaticHost> {
        self.static_hosts
            .iter()
            .map(|(domain, ip)| {
                (
                    normalize_name(domain),
                    StaticHost {
                        ip: *ip,
                        ttl: self.server.default_ttl,
                    },
                )
            })
            .collect()
    }
}

/// `from_env` is the only config path in the serverless build, so it has to
/// produce a working resolver with no variables set at all. One test function
/// because env mutation is process-global (and `unsafe` in edition 2024): the
/// variables are set and cleared sequentially rather than raced across tests.
#[cfg(all(test, feature = "serverless"))]
mod tests {
    use super::*;

    #[test]
    fn from_env_defaults_then_overrides() {
        let base = Config::from_env().expect("no env vars must still yield a valid config");
        assert_eq!(base.server.doh_port, 8053);
        assert_eq!(base.server.bind_address.to_string(), "0.0.0.0");
        assert_eq!(
            base.upstream.urls,
            vec!["https://cloudflare-dns.com/dns-query".to_string()]
        );
        assert_eq!(base.upstream.strategy, UpstreamStrategy::Sequential);
        assert_eq!(base.blocking.mode, BlockMode::Nxdomain);
        assert!(base.cache.enabled);
        assert!(base.cache.max_size_bytes > 0);

        // SAFETY: this process runs no other test that touches DNSRS_*/PORT.
        unsafe {
            std::env::set_var("PORT", "9000");
            std::env::set_var("DNSRS_DOH_PORT", "9001");
            std::env::set_var(
                "DNSRS_UPSTREAM_URLS",
                "tls://1.1.1.1:853, https://dns.google/dns-query",
            );
            std::env::set_var("DNSRS_UPSTREAM_STRATEGY", "race");
            std::env::set_var("DNSRS_BLOCK_MODE", "sinkhole");
            std::env::set_var("DNSRS_SINKHOLE_IP", "10.0.0.2");
            std::env::set_var("DNSRS_STATIC_HOSTS", " router.local = 192.168.1.10 ");
            std::env::set_var("DNSRS_BLOCKLIST_DOMAINS", "ads.example.com,tracker.example");
            std::env::set_var("DNSRS_CACHE_MAX_SIZE_BYTES", "4194304");
        }

        let overridden = Config::from_env().expect("overrides must validate");
        assert_eq!(
            overridden.server.doh_port, 9000,
            "PORT must win over DNSRS_DOH_PORT"
        );
        assert_eq!(overridden.upstream.urls.len(), 2);
        assert_eq!(overridden.upstream.strategy, UpstreamStrategy::Race);
        assert_eq!(overridden.blocking.mode, BlockMode::Sinkhole);
        assert_eq!(overridden.blocking.sinkhole_ip.to_string(), "10.0.0.2");
        assert_eq!(overridden.static_hosts.len(), 1);
        assert_eq!(
            overridden
                .static_hosts_map()
                .get("router.local.")
                .expect("trimmed entry must be stored under the normalized name")
                .ip
                .to_string(),
            "192.168.1.10"
        );
        assert_eq!(
            overridden.blocklists.domains,
            vec!["ads.example.com", "tracker.example"]
        );
        assert_eq!(overridden.cache.max_size_bytes, 4 * 1024 * 1024);

        // Bad values have to be rejected here, not silently defaulted.
        unsafe {
            std::env::set_var("DNSRS_UPSTREAM_STRATEGY", "first-one-wins");
        }
        assert!(
            Config::from_env().is_err(),
            "an unknown strategy must fail startup"
        );
        unsafe {
            std::env::set_var("DNSRS_UPSTREAM_STRATEGY", "sequential");
            std::env::set_var("DNSRS_CACHE_MAX_SIZE_BYTES", "9999999999999");
        }
        assert!(
            Config::from_env().is_err(),
            "an arena bigger than the ceiling must be rejected, not allocated"
        );
        unsafe {
            std::env::remove_var("DNSRS_CACHE_MAX_SIZE_BYTES");
            std::env::set_var("DNSRS_UPSTREAM_URLS", "");
        }
        assert!(
            Config::from_env().is_err(),
            "empty upstreams must not start a resolver that answers nothing"
        );

        // A sub-MiB budget would otherwise run the resolver cachelessly in silence.
        unsafe {
            std::env::remove_var("DNSRS_UPSTREAM_URLS");
            std::env::set_var("DNSRS_CACHE_MAX_SIZE_BYTES", "1000");
        }
        assert!(
            Config::from_env().is_err(),
            "a cache budget too small to hold anything must be rejected, not ignored"
        );
        unsafe {
            std::env::set_var("DNSRS_CACHE_ENABLED", "false");
        }
        assert!(
            Config::from_env().is_ok(),
            "the same budget is fine once the cache is explicitly off"
        );
    }
}
