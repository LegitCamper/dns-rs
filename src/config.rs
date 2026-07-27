use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    pub blocklists: Vec<BlocklistSource>,
    #[serde(default)]
    pub static_hosts: Vec<StaticHostConfig>,
    pub upstream: Vec<UpstreamConfig>,
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub dot_listen: SocketAddr,
    pub doh_listen: SocketAddr,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    #[serde(default = "default_ttl")]
    pub default_ttl: u32,
}

fn default_ttl() -> u32 {
    300
}

#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    #[default]
    Nxdomain,
    Sinkhole,
}

#[derive(Debug, Deserialize)]
pub struct BlockingConfig {
    #[serde(default)]
    pub mode: BlockMode,
    #[serde(default = "default_sinkhole_v4")]
    pub sinkhole_ipv4: Ipv4Addr,
    #[serde(default = "default_sinkhole_v6")]
    pub sinkhole_ipv6: Ipv6Addr,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            mode: BlockMode::default(),
            sinkhole_ipv4: default_sinkhole_v4(),
            sinkhole_ipv6: default_sinkhole_v6(),
        }
    }
}

fn default_sinkhole_v4() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

fn default_sinkhole_v6() -> Ipv6Addr {
    Ipv6Addr::UNSPECIFIED
}

#[derive(Debug, Deserialize, Clone)]
pub struct BlocklistSource {
    pub url: String,
    pub refresh_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StaticHostConfig {
    pub domain: String,
    pub addresses: Vec<IpAddr>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "protocol", rename_all = "snake_case")]
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

#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_entries: default_max_entries(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_entries() -> usize {
    10_000
}

#[derive(Debug, Clone)]
pub struct StaticHost {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
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
        if self.upstream.is_empty() {
            bail!("config must define at least one [[upstream]] resolver");
        }
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
        if self.server.dot_listen == self.server.doh_listen {
            bail!("server.dot_listen and server.doh_listen must be different addresses");
        }
        for b in &self.blocklists {
            if b.refresh_interval_secs == 0 {
                bail!("blocklists entry {} has refresh_interval_secs = 0", b.url);
            }
        }
        for h in &self.static_hosts {
            if h.addresses.is_empty() {
                bail!("static_hosts entry {} has no addresses", h.domain);
            }
        }
        Ok(())
    }

    pub fn static_hosts_map(&self) -> HashMap<String, StaticHost> {
        let mut map = HashMap::with_capacity(self.static_hosts.len());
        for entry in &self.static_hosts {
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for addr in &entry.addresses {
                match addr {
                    IpAddr::V4(v4) => ipv4.push(*v4),
                    IpAddr::V6(v6) => ipv6.push(*v6),
                }
            }
            map.insert(
                normalize_name(&entry.domain),
                StaticHost {
                    ipv4,
                    ipv6,
                    ttl: entry.ttl.unwrap_or(self.server.default_ttl),
                },
            );
        }
        map
    }
}
