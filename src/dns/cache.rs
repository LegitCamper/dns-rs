use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::rr::{DNSClass, RecordType};
use lru::LruCache;
use tracing::debug;

struct CacheEntry {
    wire: Vec<u8>,
    expires_at: Instant,
}

type CacheKey = (RecordType, DNSClass, String);

/// TTL-aware in-memory cache of upstream responses' encoded wire bytes,
/// keyed by (qtype, qclass, qname). Never caches blocklist/static-host
/// answers — only genuine upstream responses, since those are the only ones
/// worth saving a round trip for.
///
/// Storing the already-encoded bytes (rather than a parsed `Message`) means a
/// cache hit only needs a byte-vec clone plus a 2-byte ID patch, skipping a
/// full DNS re-encode.
///
/// Eviction is LRU, not "reject new entries once full": once `max_entries`
/// live entries are held, inserting a new name evicts whichever entry (of
/// any qtype/qclass) was least recently *read*, not just least recently
/// inserted. `get` counts as a touch, so a name that keeps getting queried
/// stays resident while cold ones age out — a name that falls out and comes
/// back is indistinguishable from a first-ever query, since nothing besides
/// eviction order is tracked. That's an acceptable trade for a resolver-scale
/// cache; if the working set legitimately thrashes against `max_entries`, the
/// fix is a bigger cache, not a fancier eviction policy.
pub struct ResponseCache {
    enabled: bool,
    entries: Mutex<LruCache<CacheKey, CacheEntry>>,
}

impl ResponseCache {
    pub fn new(enabled: bool, max_entries: usize) -> Self {
        // LruCache requires a nonzero capacity; a configured 0 is treated the
        // same as `enabled = false` since nothing could ever be stored anyway.
        let capacity = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            enabled: enabled && max_entries > 0,
            entries: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Returns cached wire bytes if present and not yet expired. The caller
    /// is responsible for patching the message ID to match the current request.
    pub fn get(&self, name: &str, record_type: RecordType, dns_class: DNSClass) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }
        let key = (record_type, dns_class, name.to_string());
        let mut entries = self.entries.lock().unwrap();
        match entries.get(&key) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.wire.clone()),
            Some(_) => {
                entries.pop(&key);
                None
            }
            None => None,
        }
    }

    /// Stores an upstream response's encoded wire bytes under the given TTL
    /// (the caller derives this from the response's answer records and should
    /// skip calling `insert` at all for a zero/absent TTL, since that means
    /// "don't cache"). If the cache is already at capacity, this evicts the
    /// least-recently-used entry to make room.
    pub fn insert(&self, name: String, record_type: RecordType, dns_class: DNSClass, ttl: u32, wire: Vec<u8>) {
        if !self.enabled {
            return;
        }
        let key = (record_type, dns_class, name);
        let entry = CacheEntry {
            wire,
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
        };

        let mut entries = self.entries.lock().unwrap();
        let is_new_key = !entries.contains(&key);
        if let Some((evicted_key, _)) = entries.push(key, entry)
            && is_new_key
        {
            let (evicted_type, _, evicted_name) = &evicted_key;
            debug!(name = %evicted_name, record_type = ?evicted_type, "evicted least-recently-used cache entry to make room");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: RecordType = RecordType::A;
    const IN: DNSClass = DNSClass::IN;

    #[test]
    fn evicts_least_recently_used_entry_when_full() {
        let cache = ResponseCache::new(true, 2);
        cache.insert("a.".to_string(), A, IN, 60, vec![1]);
        cache.insert("b.".to_string(), A, IN, 60, vec![2]);

        // Touching "a" makes "b" the least-recently-used entry.
        assert!(cache.get("a.", A, IN).is_some());

        cache.insert("c.".to_string(), A, IN, 60, vec![3]);

        assert!(cache.get("a.", A, IN).is_some(), "recently-touched entry should survive eviction");
        assert!(cache.get("c.", A, IN).is_some(), "newly-inserted entry should be present");
        assert!(cache.get("b.", A, IN).is_none(), "least-recently-used entry should have been evicted");
    }

    #[test]
    fn zero_max_entries_disables_caching_instead_of_panicking() {
        let cache = ResponseCache::new(true, 0);
        cache.insert("a.".to_string(), A, IN, 60, vec![1]);
        assert!(cache.get("a.", A, IN).is_none());
    }
}
