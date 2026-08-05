use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use rustc_hash::FxHashMap;
use tokio_util::sync::CancellationToken;

use crate::blocklist::{BlockSet, BlocklistManager};
use crate::config::{BlockMode, Config, StaticHost};
use crate::dns::cache::ResponseCache;
use crate::dns::inflight::InFlightRegistry;
use crate::dns::upstream::{self, MultiUpstream, SingleUpstream, Upstream};

/// Shared, read-mostly state handed to every DoT/DoH connection handler.
/// Generic over `Upstream` so tests can substitute a fake with no real
/// network/TLS involved; production uses the default, `SingleUpstream`.
pub struct AppState<U: Upstream = SingleUpstream> {
    /// Checked on every query, so this uses the same fast non-cryptographic
    /// hasher as `BlockSet` and the response cache (see the tradeoff note
    /// on `blocklist::BlockSet`).
    pub static_hosts: FxHashMap<String, StaticHost>,
    pub blocklist: BlockSet,
    pub cache: Arc<ResponseCache>,
    pub in_flight: InFlightRegistry,
    pub upstreams: MultiUpstream<U>,
    pub block_mode: BlockMode,
    pub sinkhole_ip: Ipv4Addr,
    pub sinkhole_ttl: u32,
}

impl AppState<SingleUpstream> {
    /// Builds shared state and starts the blocklist refresh loop and cache
    /// TTL sweeper. `shutdown` stops both when this state is replaced by a
    /// config reload.
    pub async fn build(config: &Config, shutdown: CancellationToken) -> Result<Self> {
        let blocklist_manager = Arc::new(BlocklistManager::new(&config.blocklists, &config.whitelist));
        blocklist_manager.start(shutdown.clone()).await;

        let cache_max_bytes = crate::memlimit::resolve_cache_max_bytes(config.cache.max_size_bytes);
        let cache = Arc::new(ResponseCache::new(config.cache.enabled, cache_max_bytes));
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
