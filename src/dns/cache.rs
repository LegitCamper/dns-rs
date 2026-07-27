use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, RecordType};

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
    record_type: RecordType,
    dns_class: DNSClass,
}

struct CacheEntry {
    message: Message,
    expires_at: Instant,
}

/// TTL-aware in-memory cache of upstream responses, keyed by (qname, qtype, qclass).
/// Never caches blocklist/static-host answers — only genuine upstream responses,
/// since those are the only ones worth saving a round trip for.
pub struct ResponseCache {
    enabled: bool,
    max_entries: usize,
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl ResponseCache {
    pub fn new(enabled: bool, max_entries: usize) -> Self {
        Self {
            enabled,
            max_entries,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a cached response if present and not yet expired. The caller
    /// is responsible for rewriting the message ID to match the current request.
    pub fn get(&self, name: &str, record_type: RecordType, dns_class: DNSClass) -> Option<Message> {
        if !self.enabled {
            return None;
        }
        let key = CacheKey {
            name: name.to_string(),
            record_type,
            dns_class,
        };
        let mut entries = self.entries.lock().unwrap();
        match entries.get(&key) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.message.clone()),
            Some(_) => {
                entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Stores an upstream response, using the minimum TTL across its answer
    /// records. Responses with no answers or a zero TTL are not cached.
    pub fn insert(&self, name: &str, record_type: RecordType, dns_class: DNSClass, message: Message) {
        if !self.enabled {
            return;
        }
        let Some(ttl) = message.answers.iter().map(|r| r.ttl).min() else {
            return;
        };
        if ttl == 0 {
            return;
        }

        let key = CacheKey {
            name: name.to_string(),
            record_type,
            dns_class,
        };
        let mut entries = self.entries.lock().unwrap();

        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            let now = Instant::now();
            entries.retain(|_, v| v.expires_at > now);
            if entries.len() >= self.max_entries {
                return;
            }
        }

        entries.insert(
            key,
            CacheEntry {
                message,
                expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
            },
        );
    }
}
