use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::rr::{DNSClass, RecordType};
use linked_list_allocator::Heap;
use rustc_hash::FxHashMap;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::inline_name::InlineName;

/// How often the background sweeper evicts expired entries.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Below this, `linked_list_allocator` can't even fit its own bookkeeping.
const MIN_POOL_BYTES: u64 = 64;

type CacheKey = (RecordType, DNSClass, InlineName);

/// One cached response's bookkeeping. Bytes live in `CacheState::pool` at
/// `[offset, offset + len)` — an offset instead of a pointer keeps this
/// (and the whole cache) auto-`Send`/`Sync`.
struct EntryMeta {
    offset: usize,
    len: usize,
    expires_at: Instant,
    prev: Option<CacheKey>,
    next: Option<CacheKey>,
}

/// TTL-aware cache of upstream responses' wire bytes, keyed by (qtype,
/// qclass, qname). Storage is one preallocated arena (`max_size_bytes`,
/// allocated once and never resized); responses are suballocated from it via
/// `linked_list_allocator`, so each one uses only the bytes it needs. When
/// full, `insert` evicts the least-recently-used entry until the new
/// response fits (or gives up if it never will). `start_ttl_sweeper`
/// reclaims expired entries in the background independently of that.
pub struct ResponseCache {
    enabled: bool,
    state: Mutex<CacheState>,
}

struct CacheState {
    pool: Box<[u8]>,
    heap: Heap,
    // Checked/updated on every request, so this uses the same fast
    // non-cryptographic hasher as `BlockSet` (see the tradeoff note there).
    entries: FxHashMap<CacheKey, EntryMeta>,
    lru_head: Option<CacheKey>,
    lru_tail: Option<CacheKey>,
}

impl ResponseCache {
    pub fn new(enabled: bool, max_size_bytes: u64) -> Self {
        let enabled = enabled && max_size_bytes >= MIN_POOL_BYTES;
        let size = if enabled { max_size_bytes as usize } else { 0 };

        let mut pool = vec![0u8; size].into_boxed_slice();
        let heap = if size > 0 {
            // SAFETY: `pool` is exactly `size` bytes and never moves or resizes.
            unsafe { Heap::new(pool.as_mut_ptr(), pool.len()) }
        } else {
            Heap::empty()
        };

        Self {
            enabled,
            state: Mutex::new(CacheState {
                pool,
                heap,
                entries: FxHashMap::default(),
                lru_head: None,
                lru_tail: None,
            }),
        }
    }

    /// Spawns a background sweep loop until `shutdown` fires. No-op if disabled.
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

    /// Evicts every currently-expired entry.
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

    /// Stores wire bytes under the given TTL. A zero TTL means "don't cache" -
    /// callers should just skip calling this instead.
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

        // Replace in place rather than evict-then-insert.
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
    /// Frees the pool memory backing `meta`. Callers must not use it twice.
    fn free(&mut self, meta: &EntryMeta) {
        // SAFETY: offset/len came from a matching `allocate_first_fit` call.
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

    fn evict(&mut self, key: CacheKey) {
        self.unlink(key);
        if let Some(meta) = self.entries.remove(&key) {
            self.free(&meta);
        }
    }

    /// Evicts the least-recently-used entry to make room. Returns false if
    /// the cache is empty.
    ///
    /// This used to scan every entry first looking for an already-expired
    /// one to reclaim instead of evicting a still-live LRU entry - a nicer
    /// eviction choice, but an O(n) scan on every insert into a full cache,
    /// which is precisely the hot path under sustained churn. The
    /// background TTL sweeper (`evict_expired`, every `SWEEP_INTERVAL`)
    /// already reclaims expired entries independently, so this doesn't
    /// leave expired garbage stuck forever - it just isn't preferred over
    /// the O(1) LRU-tail choice on the insert path anymore.
    fn evict_one_for_space(&mut self) -> bool {
        let Some(victim) = self.lru_tail else {
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

    /// High-churn stress test: many worker tasks hammering a small, always-
    /// full pool with randomly-sized inserts, gets, and TTL expiry, all
    /// racing the LRU eviction path and each other. This is the scenario
    /// that would surface `linked_list_allocator` corruption or a broken LRU
    /// invariant under sustained production load (many unique names cycling
    /// through a bounded cache) that the smaller deterministic tests above
    /// can't exercise.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn high_churn_concurrent_insert_get_evict_does_not_corrupt_the_pool() {
        const POOL_BYTES: u64 = 64 * 1024;
        const WORKERS: usize = 8;
        const OPS_PER_WORKER: usize = 5_000;

        let cache = Arc::new(ResponseCache::new(true, POOL_BYTES));
        let mut handles = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                for i in 0..OPS_PER_WORKER {
                    // A bounded pool of names so gets/reinserts of the same
                    // key (not just fresh misses) get exercised too.
                    let name = format!("churn-{}.example.", rand::random::<u16>() % 200);
                    let size = 8 + (rand::random::<u16>() % 512) as usize;
                    let ttl = 1 + rand::random::<u32>() % 5; // short TTLs so expiry races eviction
                    cache.insert(name.clone(), A, IN, ttl, vec![(i % 256) as u8; size]);
                    let _ = cache.get(&name, A, IN);
                    if i % 137 == 0 {
                        cache.evict_expired();
                    }
                }
            }));
        }
        for h in handles {
            h.await.expect("worker task panicked");
        }

        cache.evict_expired();
        let state = cache.state.lock().unwrap();
        assert_eq!(state.pool.len(), POOL_BYTES as usize, "the preallocated pool must never grow or move");

        // Walk the LRU list and confirm it's still a simple acyclic chain
        // that reaches exactly the entries HashMap holds - the invariant
        // that would break first if concurrent eviction corrupted a link.
        let mut seen = std::collections::HashSet::new();
        let mut cursor = state.lru_head;
        while let Some(key) = cursor {
            assert!(seen.insert(key), "LRU list must not contain a cycle");
            cursor = state.entries.get(&key).expect("LRU list must only reference live entries").next;
        }
        assert_eq!(seen.len(), state.entries.len(), "LRU list must reach every live entry exactly once");

        if state.entries.is_empty() {
            assert!(state.lru_head.is_none() && state.lru_tail.is_none());
        } else {
            let head = state.lru_head.expect("non-empty cache must have a head");
            let tail = state.lru_tail.expect("non-empty cache must have a tail");
            assert!(state.entries.get(&head).unwrap().prev.is_none(), "head must have no prev");
            assert!(state.entries.get(&tail).unwrap().next.is_none(), "tail must have no next");
        }
    }
}
