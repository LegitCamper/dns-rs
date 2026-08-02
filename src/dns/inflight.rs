use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use hickory_proto::rr::{DNSClass, RecordType};
use tokio::sync::OnceCell;

use super::inline_name::InlineName;

type FlightKey = (RecordType, DNSClass, InlineName);

/// Coalesces concurrent identical cache-miss queries into a single upstream
/// fetch. Whichever caller registers first runs `fetch`; the rest just await
/// the same `OnceCell`, which guarantees it runs at most once.
#[derive(Default)]
pub struct InFlightRegistry {
    entries: Mutex<HashMap<FlightKey, Arc<OnceCell<Vec<u8>>>>>,
}

impl InFlightRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn dedup<F, Fut>(&self, name: &str, record_type: RecordType, dns_class: DNSClass, fetch: F) -> Vec<u8>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Vec<u8>>,
    {
        // A name too long to key on can't be deduped; just fetch directly
        // rather than silently skipping coalescing for it.
        let Some(inline_name) = InlineName::new(name) else {
            return fetch().await;
        };
        let key = (record_type, dns_class, inline_name);

        let cell = self.cell_for(key);
        let wire = cell.get_or_init(fetch).await.clone();
        // The fetch is done, so there's nothing left to coalesce. A brand-new
        // query racing in right at this moment might still see the entry and
        // reuse this same result rather than the freshly-populated cache —
        // harmless, since it's the identical answer either way.
        self.remove(&key);
        wire
    }

    fn cell_for(&self, key: FlightKey) -> Arc<OnceCell<Vec<u8>>> {
        self.entries.lock().unwrap().entry(key).or_insert_with(|| Arc::new(OnceCell::new())).clone()
    }

    fn remove(&self, key: &FlightKey) {
        self.entries.lock().unwrap().remove(key);
    }
}
