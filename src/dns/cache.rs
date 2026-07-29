use std::alloc::Layout;
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::rr::{DNSClass, RecordType};
use linked_list_allocator::Heap;
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// How often the background sweeper (`ResponseCache::start_ttl_sweeper`)
/// scans for and evicts expired entries. A tradeoff between how much dead
/// weight can accumulate between sweeps and how often a full scan briefly
/// holds the cache lock; DNS TTLs are rarely under this, so most expired
/// entries are caught well before anything on the request path would have
/// needed to reclaim their space anyway.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum wire-format domain name length (RFC 1035 §3.1) — the hard upper
/// bound used to size each key's inline name storage. A name is stored
/// inline (fixed-size array, no heap `String`) so a lookup never needs to
/// allocate just to build a key to compare against.
const MAX_NAME_LEN: usize = 255;

/// Below this, there isn't even enough room for the allocator's own
/// bookkeeping (`linked_list_allocator` panics if given a region smaller
/// than a few words) — treated the same as `enabled = false`, since nothing
/// meaningful could ever be cached in it anyway.
const MIN_POOL_BYTES: u64 = 64;

#[derive(Clone, Copy)]
struct InlineName {
    len: u8,
    bytes: [u8; MAX_NAME_LEN],
}

impl InlineName {
    fn new(name: &str) -> Option<Self> {
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        let mut bytes = [0u8; MAX_NAME_LEN];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self { len: name.len() as u8, bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Domain names reaching this cache are always normalized ASCII
    /// (lowercased wire names), so this is purely for `debug!` logging —
    /// never trusted for anything that affects correctness.
    fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).unwrap_or("<invalid-utf8>")
    }
}

impl PartialEq for InlineName {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for InlineName {}

impl std::hash::Hash for InlineName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

type CacheKey = (RecordType, DNSClass, InlineName);

/// Bookkeeping for one cached response. The bytes themselves live in
/// `CacheState::pool` at `[offset, offset + len)` — storing the offset
/// rather than a pointer keeps this (and so the whole cache) trivially
/// `Send`/`Sync`, since a `usize` carries no aliasing/lifetime baggage the
/// way a raw pointer into the pool would.
struct EntryMeta {
    offset: usize,
    len: usize,
    expires_at: Instant,
    prev: Option<CacheKey>,
    next: Option<CacheKey>,
}

/// TTL-aware in-memory cache of upstream responses' encoded wire bytes,
/// keyed by (qtype, qclass, qname). Never caches blocklist/static-host
/// answers — only genuine upstream responses, since those are the only ones
/// worth saving a round trip for.
///
/// Storage is one preallocated arena (`CacheState::pool`, exactly
/// `max_size_bytes`, allocated once at construction and never resized) that
/// individual responses are dynamically suballocated from via
/// `linked_list_allocator`, a small first-fit allocator with free-block
/// coalescing — each response uses exactly as many bytes as it needs, not a
/// fixed slot sized for the worst case. Fragmentation is the allocator's
/// problem to manage (coalescing adjacent free blocks on every dealloc), not
/// something this cache reasons about directly.
///
/// Capacity is therefore "as many responses as currently fit," which varies
/// with their actual sizes. When an allocation doesn't fit, `insert` evicts
/// to make room: first any *expired* entry (freeing dead weight before
/// evicting anything still theoretically useful), then the least-recently
/// *read* entry, one at a time, retrying the allocation after each, until it
/// fits or the cache is completely empty (meaning the response is simply too
/// big for the configured pool — it's skipped, not cached).
///
/// The one heap allocation this cache still performs is `get`'s return
/// value: callers need an owned `Vec<u8>` to patch the message ID into and
/// hand to the socket, so a cache hit costs one copy out of the pool. That's
/// unavoidable without holding the cache lock across the socket write, which
/// would hurt concurrency for a dubious win.
///
/// Expired entries are also reclaimed proactively: `start_ttl_sweeper` spawns
/// a background task that periodically evicts anything past its TTL, so a
/// request that needs to `insert` a new response usually doesn't have to
/// scan for and evict dead entries itself first — that work already
/// happened off the request path. It's a complement to, not a replacement
/// for, the eviction `insert` still does on demand for space taken by
/// still-live entries, which can only ever be discovered reactively.
pub struct ResponseCache {
    enabled: bool,
    state: Mutex<CacheState>,
}

struct CacheState {
    /// The entire cache's storage: one allocation made once in
    /// `ResponseCache::new`, never resized afterward. `heap` suballocates
    /// out of this same memory.
    pool: Box<[u8]>,
    heap: Heap,
    entries: HashMap<CacheKey, EntryMeta>,
    lru_head: Option<CacheKey>,
    lru_tail: Option<CacheKey>,
}

impl ResponseCache {
    pub fn new(enabled: bool, max_size_bytes: u64) -> Self {
        let enabled = enabled && max_size_bytes >= MIN_POOL_BYTES;
        let size = if enabled { max_size_bytes as usize } else { 0 };

        let mut pool = vec![0u8; size].into_boxed_slice();
        let heap = if size > 0 {
            // SAFETY: `pool` is exactly `size` bytes, owned solely by this
            // `CacheState`, and never resized or moved out from under
            // `heap` for as long as both live — a `Box<[u8]>`'s backing
            // allocation is fixed-size and never reallocated.
            unsafe { Heap::new(pool.as_mut_ptr(), pool.len()) }
        } else {
            Heap::empty()
        };

        Self {
            enabled,
            state: Mutex::new(CacheState {
                pool,
                heap,
                entries: HashMap::new(),
                lru_head: None,
                lru_tail: None,
            }),
        }
    }

    /// Spawns a background task that evicts expired entries every
    /// `SWEEP_INTERVAL`, until `shutdown` is cancelled (the caller cancels it
    /// when this cache is being replaced by a config reload). A no-op when
    /// the cache is disabled.
    pub fn start_ttl_sweeper(self: &Arc<Self>, shutdown: CancellationToken) {
        self.start_ttl_sweeper_with_interval(shutdown, SWEEP_INTERVAL);
    }

    fn start_ttl_sweeper_with_interval(self: &Arc<Self>, shutdown: CancellationToken, interval: Duration) {
        if !self.enabled {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = shutdown.cancelled() => return,
                }
                this.evict_expired();
            }
        });
    }

    /// Evicts every currently-expired entry in one pass. Called periodically
    /// by `start_ttl_sweeper`; also safe to call directly (e.g. from tests).
    pub fn evict_expired(&self) {
        if !self.enabled {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let expired: Vec<CacheKey> = state.entries.iter().filter(|(_, meta)| meta.expires_at <= now).map(|(key, _)| *key).collect();
        let count = expired.len();
        for key in expired {
            state.evict(key);
        }
        if count > 0 {
            debug!(count, "swept expired cache entries");
        }
    }

    /// Returns cached wire bytes if present and not yet expired. The caller
    /// is responsible for patching the message ID to match the current request.
    pub fn get(&self, name: &str, record_type: RecordType, dns_class: DNSClass) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }
        let key = (record_type, dns_class, InlineName::new(name)?);
        let mut state = self.state.lock().unwrap();

        let is_expired = match state.entries.get(&key) {
            Some(meta) => meta.expires_at <= Instant::now(),
            None => return None,
        };
        if is_expired {
            state.evict(key);
            return None;
        }

        state.touch(key);
        let meta = state.entries.get(&key).unwrap();
        let (offset, len) = (meta.offset, meta.len);
        Some(state.pool[offset..offset + len].to_vec())
    }

    /// Stores an upstream response's encoded wire bytes under the given TTL
    /// (the caller derives this from the response's answer records, or an
    /// RFC 2308 negative-cache TTL, and should skip calling `insert` at all
    /// for a zero/absent TTL, since that means "don't cache"). If the pool
    /// doesn't have room, evicts expired entries and then least-recently-used
    /// ones until it does, or gives up and doesn't cache if the response
    /// can't fit even in an empty pool.
    pub fn insert(&self, name: String, record_type: RecordType, dns_class: DNSClass, ttl: u32, wire: Vec<u8>) {
        if !self.enabled {
            return;
        }
        let Some(inline_name) = InlineName::new(&name) else {
            debug!(%name, "name too long for the cache, not caching");
            return;
        };
        let Ok(layout) = Layout::from_size_align(wire.len(), 1) else {
            return;
        };
        let key = (record_type, dns_class, inline_name);
        let expires_at = Instant::now() + Duration::from_secs(u64::from(ttl));

        let mut state = self.state.lock().unwrap();

        // Already cached under this key: free its old allocation first, both
        // to let the allocator reuse the space and so it's never picked as
        // an eviction victim for its own replacement.
        if state.entries.contains_key(&key) {
            state.evict(key);
        }

        let ptr = loop {
            match state.heap.allocate_first_fit(layout) {
                Ok(ptr) => break ptr,
                Err(()) => {
                    if !state.evict_one_for_space() {
                        debug!(
                            %name, ?record_type, size = wire.len(),
                            "response doesn't fit in the cache even when empty, not caching"
                        );
                        return;
                    }
                }
            }
        };

        let offset = ptr.as_ptr() as usize - state.pool.as_ptr() as usize;
        // SAFETY: `ptr` was just returned by the allocator for exactly
        // `wire.len()` bytes, and nothing else can alias cache-owned memory.
        unsafe {
            std::ptr::copy_nonoverlapping(wire.as_ptr(), ptr.as_ptr(), wire.len());
        }
        state.entries.insert(key, EntryMeta { offset, len: wire.len(), expires_at, prev: None, next: None });
        state.attach_front(key);
    }
}

impl CacheState {
    /// Deallocates the pool memory backing `meta`. Must be called exactly
    /// once per allocation, with the same offset/length `insert` recorded.
    fn free(&mut self, meta: &EntryMeta) {
        // SAFETY: `offset`/`len` came verbatim from a previous
        // `heap.allocate_first_fit` call, and `evict` (this method's only
        // caller) never runs twice for the same entry.
        unsafe {
            let ptr = NonNull::new_unchecked(self.pool.as_mut_ptr().add(meta.offset));
            self.heap.deallocate(ptr, Layout::from_size_align(meta.len, 1).unwrap());
        }
    }

    /// Unlinks `key` from the LRU list without removing it from `entries`.
    fn unlink(&mut self, key: CacheKey) {
        let (prev, next) = {
            let meta = self.entries.get(&key).unwrap();
            (meta.prev, meta.next)
        };
        match prev {
            Some(p) => self.entries.get_mut(&p).unwrap().next = next,
            None => self.lru_head = next,
        }
        match next {
            Some(n) => self.entries.get_mut(&n).unwrap().prev = prev,
            None => self.lru_tail = prev,
        }
    }

    fn attach_front(&mut self, key: CacheKey) {
        let old_head = self.lru_head;
        {
            let entry = self.entries.get_mut(&key).unwrap();
            entry.prev = None;
            entry.next = old_head;
        }
        if let Some(old_head) = old_head {
            self.entries.get_mut(&old_head).unwrap().prev = Some(key);
        }
        self.lru_head = Some(key);
        if self.lru_tail.is_none() {
            self.lru_tail = Some(key);
        }
    }

    fn touch(&mut self, key: CacheKey) {
        if self.lru_head == Some(key) {
            return;
        }
        self.unlink(key);
        self.attach_front(key);
    }

    /// Removes `key` entirely: unlinks it from the LRU list, drops its
    /// bookkeeping, and frees its pool memory back to the allocator.
    fn evict(&mut self, key: CacheKey) {
        self.unlink(key);
        if let Some(meta) = self.entries.remove(&key) {
            self.free(&meta);
        }
    }

    /// Evicts one entry to make room for a pending allocation: an expired
    /// entry if one exists (found by scanning — cheap relative to how rarely
    /// this runs, only when the allocator is already out of space), else the
    /// least-recently-used live entry. Returns false if there's nothing left
    /// to evict (the cache is empty).
    fn evict_one_for_space(&mut self) -> bool {
        let now = Instant::now();
        let victim = self.entries.iter().find(|(_, m)| m.expires_at <= now).map(|(k, _)| *k).or(self.lru_tail);
        let Some(victim) = victim else {
            return false;
        };
        debug!(name = %victim.2.as_str(), record_type = ?victim.0, "evicted a cache entry to make room");
        self.evict(victim);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: RecordType = RecordType::A;
    const IN: DNSClass = DNSClass::IN;

    #[test]
    fn evicts_least_recently_used_entry_when_full() {
        // Room for two 24-byte entries plus their allocator overhead, but
        // not three.
        let cache = ResponseCache::new(true, 64);
        cache.insert("a.".to_string(), A, IN, 60, vec![1; 24]);
        cache.insert("b.".to_string(), A, IN, 60, vec![2; 24]);

        // Touching "a" makes "b" the least-recently-used entry.
        assert!(cache.get("a.", A, IN).is_some());

        cache.insert("c.".to_string(), A, IN, 60, vec![3; 24]);

        assert!(cache.get("a.", A, IN).is_some(), "recently-touched entry should survive eviction");
        assert!(cache.get("c.", A, IN).is_some(), "newly-inserted entry should be present");
        assert!(cache.get("b.", A, IN).is_none(), "least-recently-used entry should have been evicted");
    }

    #[test]
    fn zero_max_size_bytes_disables_caching_instead_of_panicking() {
        let cache = ResponseCache::new(true, 0);
        cache.insert("a.".to_string(), A, IN, 60, vec![1]);
        assert!(cache.get("a.", A, IN).is_none());
    }

    #[test]
    fn tiny_max_size_bytes_disables_caching_instead_of_panicking() {
        // Too small even for the allocator's own bookkeeping.
        let cache = ResponseCache::new(true, 4);
        cache.insert("a.".to_string(), A, IN, 60, vec![1]);
        assert!(cache.get("a.", A, IN).is_none());
    }

    #[test]
    fn entry_larger_than_the_whole_pool_is_not_cached() {
        let cache = ResponseCache::new(true, 256);
        cache.insert("a.".to_string(), A, IN, 60, vec![0; 10_000]);
        assert!(cache.get("a.", A, IN).is_none());
    }

    #[test]
    fn name_longer_than_255_bytes_is_not_cached() {
        let cache = ResponseCache::new(true, 4096);
        let long_name = "a".repeat(256);
        cache.insert(long_name.clone(), A, IN, 60, vec![1]);
        assert!(cache.get(&long_name, A, IN).is_none());
    }

    #[test]
    fn reinserting_an_existing_key_reuses_its_space_without_evicting_others() {
        let cache = ResponseCache::new(true, 256);
        cache.insert("a.".to_string(), A, IN, 60, vec![1; 8]);
        cache.insert("b.".to_string(), A, IN, 60, vec![2; 8]);

        cache.insert("a.".to_string(), A, IN, 60, vec![9, 9]);

        assert_eq!(cache.get("a.", A, IN), Some(vec![9, 9]));
        assert!(cache.get("b.", A, IN).is_some(), "updating an existing key must not evict an unrelated entry");
    }

    #[test]
    fn differently_sized_entries_each_use_only_the_space_they_need() {
        // A pool sized for one maximal entry plus several tiny ones - only
        // possible because entries aren't padded out to a fixed slot size.
        let cache = ResponseCache::new(true, 4096);
        cache.insert("big.".to_string(), A, IN, 60, vec![0; 2000]);
        for i in 0..10 {
            cache.insert(format!("small{i}."), A, IN, 60, vec![i as u8; 4]);
        }

        assert!(cache.get("big.", A, IN).is_some(), "large entry should still be cached alongside many small ones");
        for i in 0..10 {
            assert!(cache.get(&format!("small{i}."), A, IN).is_some(), "small entry {i} should still be cached");
        }
    }

    #[test]
    fn pool_is_preallocated_up_front_regardless_of_how_many_entries_are_live() {
        let cache = ResponseCache::new(true, 4096);
        let state = cache.state.lock().unwrap();
        assert_eq!(state.pool.len(), 4096, "the whole pool must be allocated at construction, not grown per insert");
    }

    #[test]
    fn evict_expired_reclaims_only_expired_entries_and_frees_their_space() {
        let cache = ResponseCache::new(true, 4096);
        cache.insert("expired.".to_string(), A, IN, 0, vec![1; 8]);
        cache.insert("live.".to_string(), A, IN, 3600, vec![2; 8]);
        std::thread::sleep(Duration::from_millis(5));

        cache.evict_expired();

        {
            let state = cache.state.lock().unwrap();
            assert!(!state.entries.contains_key(&(A, IN, InlineName::new("expired.").unwrap())));
            assert!(state.entries.contains_key(&(A, IN, InlineName::new("live.").unwrap())));
        }
        assert!(cache.get("live.", A, IN).is_some(), "unexpired entry must survive a sweep");

        // The reclaimed space should be usable again, not left stranded.
        cache.insert("reuse.".to_string(), A, IN, 60, vec![3; 8]);
        assert!(cache.get("reuse.", A, IN).is_some());
    }

    #[tokio::test]
    async fn start_ttl_sweeper_evicts_expired_entries_in_the_background() {
        let cache = Arc::new(ResponseCache::new(true, 4096));
        cache.insert("expired.".to_string(), A, IN, 0, vec![1; 8]);
        cache.insert("live.".to_string(), A, IN, 3600, vec![2; 8]);
        tokio::time::sleep(Duration::from_millis(5)).await;

        let shutdown = CancellationToken::new();
        // A short interval so the test doesn't wait out a real 30s sweep.
        cache.start_ttl_sweeper_with_interval(shutdown.clone(), Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.cancel();

        {
            let state = cache.state.lock().unwrap();
            assert!(
                !state.entries.contains_key(&(A, IN, InlineName::new("expired.").unwrap())),
                "background sweeper should have evicted the expired entry without any get()/insert() call"
            );
        }
        assert!(cache.get("live.", A, IN).is_some(), "unexpired entry must survive the sweep");
    }
}
