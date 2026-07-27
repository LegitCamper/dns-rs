use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;

use crate::blocklist::{BlockSet, BlocklistManager};
use crate::config::{BlockMode, Config, StaticHost};
use crate::dns::cache::ResponseCache;
use crate::dns::upstream::UpstreamPool;

/// Shared, read-mostly state handed to every DoT/DoH connection handler.
pub struct AppState {
    pub static_hosts: HashMap<String, StaticHost>,
    pub blocklist: BlockSet,
    pub cache: ResponseCache,
    pub upstreams: UpstreamPool,
    pub block_mode: BlockMode,
    pub sinkhole_ipv4: Ipv4Addr,
    pub sinkhole_ipv6: Ipv6Addr,
    pub sinkhole_ttl: u32,
}

impl AppState {
    /// Builds shared state from config and kicks off the blocklist manager's
    /// initial fetch + background refresh loops.
    pub async fn build(config: &Config) -> Result<Self> {
        let blocklist_manager = std::sync::Arc::new(BlocklistManager::new(&config.blocklists));
        blocklist_manager.start().await;

        Ok(Self {
            static_hosts: config.static_hosts_map(),
            blocklist: blocklist_manager.merged_set(),
            cache: ResponseCache::new(config.cache.enabled, config.cache.max_entries),
            upstreams: UpstreamPool::new(&config.upstream)?,
            block_mode: config.blocking.mode,
            sinkhole_ipv4: config.blocking.sinkhole_ipv4,
            sinkhole_ipv6: config.blocking.sinkhole_ipv6,
            sinkhole_ttl: config.server.default_ttl,
        })
    }
}
