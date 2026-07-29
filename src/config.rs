use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

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
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
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

#[derive(Debug, Deserialize)]
pub struct BlocklistsConfig {
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default = "default_blocklist_refresh_secs")]
    pub refresh_interval_secs: u64,
}

impl Default for BlocklistsConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            refresh_interval_secs: default_blocklist_refresh_secs(),
        }
    }
}

fn default_blocklist_refresh_secs() -> u64 {
    43_200 // 12h
}

/// Unlike `[blocklists]`, this isn't a list of URLs to fetch — just literal
/// domain names that must never be blocked, even if a source in
/// `[blocklists]` lists them. Checked as exact names, not by subdomain.
#[derive(Debug, Default, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub domains: Vec<String>,
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

fn default_max_size_bytes() -> u64 {
    64 * 1024 * 1024 // 64 MiB
}

#[derive(Debug, Clone, Copy)]
pub struct StaticHost {
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

impl Config {
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
        if !self.server.tls_cert.is_file() {
            bail!(
                "server.tls_cert does not point to a file: {}",
                self.server.tls_cert.display()
            );
        }
        if !self.server.tls_key.is_file() {
            bail!(
                "server.tls_key does not point to a file: {}",
                self.server.tls_key.display()
            );
        }
        if self.server.dot_port == self.server.doh_port {
            bail!("server.dot_port and server.doh_port must be different");
        }
        if !self.blocklists.urls.is_empty() && self.blocklists.refresh_interval_secs == 0 {
            bail!("blocklists.refresh_interval_secs must not be 0");
        }
        Ok(())
    }

    pub fn parsed_upstreams(&self) -> Result<Vec<UpstreamConfig>> {
        self.upstream.urls.iter().map(|s| UpstreamConfig::parse(s)).collect()
    }

    pub fn static_hosts_map(&self) -> HashMap<String, StaticHost> {
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
