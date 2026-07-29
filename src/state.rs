use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

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
    pub cache: Arc<ResponseCache>,
    pub in_flight: InFlightRegistry,
    pub upstreams: MultiUpstream<U>,
    pub block_mode: BlockMode,
    pub sinkhole_ip: Ipv4Addr,
    pub sinkhole_ttl: u32,
}

impl AppState<SingleUpstream> {
    /// Builds shared state from config and kicks off the blocklist manager's
    /// initial fetch + background refresh loops, plus the cache's background
    /// TTL sweeper. `shutdown` stops those background loops when cancelled —
    /// the caller cancels it when this state is being replaced by a config
    /// reload.
    pub async fn build(config: &Config, shutdown: CancellationToken) -> Result<Self> {
        let blocklist_manager = Arc::new(BlocklistManager::new(&config.blocklists, &config.whitelist));
        blocklist_manager.start(shutdown.clone()).await;

        let cache = Arc::new(ResponseCache::new(config.cache.enabled, config.cache.max_size_bytes));
        cache.start_ttl_sweeper(shutdown);

        let upstream_configs = config.parsed_upstreams()?;

        Ok(Self {
            static_hosts: config.static_hosts_map(),
            blocklist: blocklist_manager.merged_set(),
            cache,
            in_flight: InFlightRegistry::new(),
            upstreams: upstream::build(&upstream_configs, config.upstream.strategy)?,
            block_mode: config.blocking.mode,
            sinkhole_ip: config.blocking.sinkhole_ip,
            sinkhole_ttl: config.server.default_ttl,
        })
    }
}
