use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::blocklist::{BlockSet, BlocklistManager};
use crate::config::{BlockMode, Config, StaticHost};
use crate::dns::cache::ResponseCache;
use crate::dns::inflight::InFlightRegistry;
use crate::dns::upstream::{self, MultiUpstream, SingleUpstream, Upstream};

/// Shared, read-mostly state handed to every DoT/DoH connection handler.
/// Generic over the upstream implementation so tests can substitute a fake
/// upstream with no real network/TLS involved; production always uses the
/// default, `SingleUpstream`.
pub struct AppState<U: Upstream = SingleUpstream> {
    pub static_hosts: HashMap<String, StaticHost>,
    pub blocklist: BlockSet,
    pub cache: ResponseCache,
    pub in_flight: InFlightRegistry,
    pub upstreams: MultiUpstream<U>,
    pub block_mode: BlockMode,
    pub sinkhole_ip: Ipv4Addr,
    pub sinkhole_ttl: u32,
}

impl AppState<SingleUpstream> {
    /// Builds shared state from config and kicks off the blocklist manager's
    /// initial fetch + background refresh loops. `shutdown` stops those
    /// background loops when cancelled — the caller cancels it when this
    /// state is being replaced by a config reload.
    pub async fn build(config: &Config, shutdown: CancellationToken) -> Result<Self> {
        let blocklist_manager = std::sync::Arc::new(BlocklistManager::new(&config.blocklists));
        blocklist_manager.start(shutdown).await;

        let upstream_configs = config.parsed_upstreams()?;

        Ok(Self {
            static_hosts: config.static_hosts_map(),
            blocklist: blocklist_manager.merged_set(),
            cache: ResponseCache::new(config.cache.enabled, config.cache.max_entries),
            in_flight: InFlightRegistry::new(),
            upstreams: upstream::build(&upstream_configs, config.upstream.strategy)?,
            block_mode: config.blocking.mode,
            sinkhole_ip: config.blocking.sinkhole_ip,
            sinkhole_ttl: config.server.default_ttl,
        })
    }
}
