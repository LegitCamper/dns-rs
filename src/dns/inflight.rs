use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use hickory_proto::rr::{DNSClass, RecordType};
use tokio::sync::OnceCell;

/// Coalesces concurrent identical cache-miss queries into a single upstream
/// fetch, so a burst of clients asking for the same currently-uncached name
/// (e.g. right after it expires) doesn't turn into a burst of duplicate
/// upstream queries. Whichever caller registers first ("the leader") runs
/// `fetch`; everyone else concurrently asking for the same (name, qtype,
/// qclass) just awaits the same result via `OnceCell`, which guarantees the
/// initializer runs at most once regardless of how many callers race in.
#[derive(Default)]
pub struct InFlightRegistry {
    entries: Mutex<HashMap<(RecordType, DNSClass), HashMap<String, Arc<OnceCell<Vec<u8>>>>>>,
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
        let cell = self.cell_for(name, record_type, dns_class);
        let wire = cell.get_or_init(fetch).await.clone();
        // The fetch is done, so there's nothing left to coalesce. A brand-new
        // query racing in right at this moment might still see the entry and
        // reuse this same result rather than the freshly-populated cache —
        // harmless, since it's the identical answer either way.
        self.remove(name, record_type, dns_class);
        wire
    }

    fn cell_for(&self, name: &str, record_type: RecordType, dns_class: DNSClass) -> Arc<OnceCell<Vec<u8>>> {
        let mut entries = self.entries.lock().unwrap();
        let bucket = entries.entry((record_type, dns_class)).or_default();
        if let Some(existing) = bucket.get(name) {
            return existing.clone();
        }
        bucket
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone()
    }

    fn remove(&self, name: &str, record_type: RecordType, dns_class: DNSClass) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(bucket) = entries.get_mut(&(record_type, dns_class)) {
            bucket.remove(name);
        }
    }
}
