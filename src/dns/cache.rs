use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::rr::{DNSClass, RecordType};

struct CacheEntry {
    wire: Vec<u8>,
    expires_at: Instant,
}

/// TTL-aware in-memory cache of upstream responses' encoded wire bytes,
/// keyed by (qtype, qclass, qname). Never caches blocklist/static-host
/// answers — only genuine upstream responses, since those are the only ones
/// worth saving a round trip for.
///
/// Storing the already-encoded bytes (rather than a parsed `Message`) means a
/// cache hit only needs a byte-vec clone plus a 2-byte ID patch, skipping a
/// full DNS re-encode. Nesting by (qtype, qclass) first lets a lookup borrow
/// `name: &str` straight into the inner `HashMap<String, _>` with no
/// allocation, since `String` already implements `Borrow<str>`.
pub struct ResponseCache {
    enabled: bool,
    max_entries: usize,
    entries: Mutex<HashMap<(RecordType, DNSClass), HashMap<String, CacheEntry>>>,
}

impl ResponseCache {
    pub fn new(enabled: bool, max_entries: usize) -> Self {
        Self {
            enabled,
            max_entries,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns cached wire bytes if present and not yet expired. The caller
    /// is responsible for patching the message ID to match the current request.
    pub fn get(&self, name: &str, record_type: RecordType, dns_class: DNSClass) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }
        let mut entries = self.entries.lock().unwrap();
        let bucket = entries.get_mut(&(record_type, dns_class))?;
        match bucket.get(name) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.wire.clone()),
            Some(_) => {
                bucket.remove(name);
                None
            }
            None => None,
        }
    }

    /// Stores an upstream response's encoded wire bytes under the given TTL
    /// (the caller derives this from the response's answer records and should
    /// skip calling `insert` at all for a zero/absent TTL, since that means
    /// "don't cache").
    pub fn insert(&self, name: String, record_type: RecordType, dns_class: DNSClass, ttl: u32, wire: Vec<u8>) {
        if !self.enabled {
            return;
        }
        let mut entries = self.entries.lock().unwrap();

        let already_present = entries
            .get(&(record_type, dns_class))
            .is_some_and(|bucket| bucket.contains_key(&name));

        if !already_present {
            let total: usize = entries.values().map(HashMap::len).sum();
            if total >= self.max_entries {
                let now = Instant::now();
                for bucket in entries.values_mut() {
                    bucket.retain(|_, entry| entry.expires_at > now);
                }
                let total: usize = entries.values().map(HashMap::len).sum();
                if total >= self.max_entries {
                    return;
                }
            }
        }

        entries.entry((record_type, dns_class)).or_default().insert(
            name,
            CacheEntry {
                wire,
                expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
            },
        );
    }
}
