use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
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
    #[serde(default = "default_dot_port")]
    pub dot_port: u16,
    #[serde(default = "default_doh_port")]
    pub doh_port: u16,
    /// May be omitted if `DNS_RS_TLS_CERT_B64`/`DNS_RS_TLS_KEY_B64` are set
    /// instead — see `tls::resolve_tls_material`.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    #[serde(default = "default_ttl")]
    pub default_ttl: u32,
}

impl ServerConfig {
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

fn default_dot_port() -> u16 {
    853
}

fn default_doh_port() -> u16 {
    443
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
            return Ok(Self::Doh { url: entry.to_string() });
        }
        if let Some(rest) = entry.strip_prefix("tls://") {
            let (host_port, tls_name) = match rest.split_once('#') {
                Some((hp, name)) => (hp, Some(name.to_string())),
                None => (rest, None),
            };
            let (host, port) = host_port
                .rsplit_once(':')
                .with_context(|| format!("upstream '{entry}' is missing a port, expected tls://host:port"))?;
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
    /// pool that responses are suballocated from (see `dns::cache`). If
    /// unset, `memlimit::resolve_cache_max_bytes` picks a default — a
    /// share of the container's cgroup memory limit if one is detected,
    /// otherwise a fixed fallback.
    #[serde(default)]
    pub max_size_bytes: Option<u64>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_size_bytes: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy)]
pub struct StaticHost {
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

impl Config {
    /// Parses and validates a TOML config document, regardless of where its
    /// raw text came from (a local file or an env var — see `main::ConfigSource`).
    pub fn parse(raw: &str) -> Result<Config> {
        let config: Config = toml::from_str(raw).context("failed to parse config")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.upstream.urls.is_empty() {
            bail!("config must define at least one entry in [upstream] urls");
        }
        self.parsed_upstreams()?;
        check_tls_source(
            &self.server.tls_cert,
            &self.server.tls_key,
            std::env::var(crate::tls::TLS_CERT_ENV).is_ok(),
            std::env::var(crate::tls::TLS_KEY_ENV).is_ok(),
        )?;
        if self.server.dot_port == self.server.doh_port {
            bail!("server.dot_port and server.doh_port must be different");
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
        self.upstream.urls.iter().map(|s| UpstreamConfig::parse(s)).collect()
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

/// Decides where TLS material comes from, given the two `Option<PathBuf>`
/// config fields and whether the corresponding env var
/// (`tls::TLS_CERT_ENV`/`TLS_KEY_ENV`) is set. Takes plain bools for the env
/// checks (rather than reading `std::env` itself) so this is unit-testable
/// without mutating real process state.
fn check_tls_source(cert: &Option<PathBuf>, key: &Option<PathBuf>, cert_env: bool, key_env: bool) -> Result<()> {
    match (cert_env, key_env) {
        (true, true) => Ok(()),
        (true, false) | (false, true) => {
            bail!(
                "both {} and {} must be set together, or neither",
                crate::tls::TLS_CERT_ENV,
                crate::tls::TLS_KEY_ENV
            )
        }
        (false, false) => {
            let cert = cert.as_ref().with_context(|| {
                format!(
                    "server.tls_cert must be set, or set {}/{} instead",
                    crate::tls::TLS_CERT_ENV,
                    crate::tls::TLS_KEY_ENV
                )
            })?;
            if !cert.is_file() {
                bail!("server.tls_cert does not point to a file: {}", cert.display());
            }
            let key = key.as_ref().with_context(|| {
                format!(
                    "server.tls_key must be set, or set {}/{} instead",
                    crate::tls::TLS_CERT_ENV,
                    crate::tls::TLS_KEY_ENV
                )
            })?;
            if !key.is_file() {
                bail!("server.tls_key does not point to a file: {}", key.display());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_toml() -> String {
        format!(
            "[server]\ntls_cert = {:?}\ntls_key = {:?}\n\n[upstream]\nurls = [\"https://cloudflare-dns.com/dns-query\"]\n",
            env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml",
            env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.lock",
        )
    }

    #[test]
    fn parse_accepts_minimal_valid_config() {
        Config::parse(&base_toml()).expect("minimal config should parse and validate");
    }

    #[test]
    fn parse_rejects_missing_upstream_urls() {
        let toml = base_toml().replace("urls = [\"https://cloudflare-dns.com/dns-query\"]", "urls = []");
        let err = Config::parse(&toml).unwrap_err();
        assert!(err.to_string().contains("upstream"), "unexpected error: {err}");
    }

    #[test]
    fn parse_rejects_equal_dot_and_doh_ports() {
        let toml = base_toml().replace("[server]\n", "[server]\ndot_port = 1000\ndoh_port = 1000\n");
        let err = Config::parse(&toml).unwrap_err();
        assert!(err.to_string().contains("dot_port"), "unexpected error: {err}");
    }

    #[test]
    fn parse_rejects_nonexistent_cert_path_with_no_env_vars() {
        let toml = base_toml().replace(
            &(env!("CARGO_MANIFEST_DIR").to_string() + "/Cargo.toml"),
            "/does/not/exist.pem",
        );
        let err = Config::parse(&toml).unwrap_err();
        assert!(err.to_string().contains("tls_cert"), "unexpected error: {err}");
    }

    #[test]
    fn check_tls_source_both_env_set_ignores_file_paths() {
        check_tls_source(&None, &None, true, true).expect("both env vars set should be fine with no file paths");
    }

    #[test]
    fn check_tls_source_exactly_one_env_set_is_an_error() {
        assert!(check_tls_source(&None, &None, true, false).is_err());
        assert!(check_tls_source(&None, &None, false, true).is_err());
    }

    #[test]
    fn check_tls_source_no_env_requires_both_paths_present_and_real_files() {
        assert!(check_tls_source(&None, &None, false, false).is_err());
        let real = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(check_tls_source(&Some(real.clone()), &Some(real.clone()), false, false).is_ok());
        let missing = PathBuf::from("/does/not/exist.pem");
        assert!(check_tls_source(&Some(missing), &Some(real), false, false).is_err());
    }
}
