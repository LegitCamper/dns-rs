use std::alloc::Layout;
use std::hash::{Hash, Hasher};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::rr::{DNSClass, RecordType};
use linked_list_allocator::Heap;
use rustc_hash::FxHasher;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::inline_name::MAX_NAME_LEN;

/// How often the background sweeper evicts entries past their stale window.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Keep expired answers available briefly while one caller refreshes them in
/// the background. Clients receive TTL=0 on these answers, so they may use
/// the result for this query but won't retain it.
///
/// ponytail: fixed 30s window; expose it in config if different workloads
/// need longer outage tolerance versus faster freshness.
const SERVE_STALE_WINDOW: Duration = Duration::from_secs(30);

/// Below this, `linked_list_allocator` can't even fit its own bookkeeping.
const MIN_POOL_BYTES: u64 = 64;

const EMPTY: u32 = u32::MAX;
const TOMBSTONE: u32 = u32::MAX - 1;
const NONE: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct KeySlot {
    hash: u64,
    entry: u32,
}

impl KeySlot {
    const EMPTY: Self = Self {
        hash: 0,
        entry: EMPTY,
    };
}

/// One cached response's bookkeeping. Both qname and wire bytes live in
/// `CacheState::pool` at `[offset, offset + name_len + wire_len)`. Storing
/// the name there lets the hash table carry only a 64-bit hash + slab index,
/// instead of copying a fixed 255-byte `InlineName` into the hash table and
/// twice more into the old LRU links.
struct EntryMeta {
    offset: usize,
    name_len: u16,
    wire_len: u32,
    record_type: RecordType,
    dns_class: DNSClass,
    flags: u8,
    expires_at: Instant,
    stale_until: Instant,
    original_ttl: Duration,
    refresh_claimed: bool,
    prev: u32,
    next: u32,
    table_slot: u32,
}

/// TTL-aware cache of upstream responses' wire bytes. One preallocated arena
/// holds both names and responses. A compact open-addressed index points into
/// a slab of metadata; LRU links are u32 slab indexes.
pub struct ResponseCache {
    enabled: bool,
    state: Mutex<CacheState>,
}

struct CacheState {
    pool: Box<[u8]>,
    heap: Heap,
    table: Vec<KeySlot>,
    table_len: usize,
    tombstones: usize,
    entries: Vec<Option<EntryMeta>>,
    free_entries: Vec<u32>,
    lru_head: u32,
    lru_tail: u32,
}

fn key_hash(name: &[u8], record_type: RecordType, dns_class: DNSClass, flags: u8) -> u64 {
    let mut hasher = FxHasher::default();
    record_type.hash(&mut hasher);
    dns_class.hash(&mut hasher);
    flags.hash(&mut hasher);
    name.hash(&mut hasher);
    hasher.finish()
}

enum Locate {
    Found(u32),
    Vacant(usize),
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
                table: vec![KeySlot::EMPTY; 64],
                table_len: 0,
                tombstones: 0,
                entries: Vec::new(),
                free_entries: Vec::new(),
                lru_head: NONE,
                lru_tail: NONE,
            }),
        }
    }

    pub fn start_ttl_sweeper(self: &Arc<Self>, shutdown: CancellationToken) {
        self.start_ttl_sweeper_with_interval(shutdown, SWEEP_INTERVAL);
    }

    fn start_ttl_sweeper_with_interval(
        self: &Arc<Self>,
        shutdown: CancellationToken,
        interval: Duration,
    ) {
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

    /// Evicts entries whose TTL plus serve-stale window has elapsed.
    pub fn evict_expired(&self) {
        if !self.enabled {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let expired: Vec<u32> = state
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry
                    .as_ref()
                    .filter(|meta| meta.stale_until <= now)
                    .map(|_| index as u32)
            })
            .collect();
        let count = expired.len();
        for entry in expired {
            state.evict(entry);
        }
        if count > 0 {
            debug!(count, "swept expired cache entries");
        }
    }

    #[cfg(test)]
    pub fn get(
        &self,
        name: &str,
        record_type: RecordType,
        dns_class: DNSClass,
    ) -> Option<(Vec<u8>, bool)> {
        self.get_with_flags(name.as_bytes(), record_type, dns_class, 0)
    }

    /// Returns cached wire bytes if present and not past the serve-stale
    /// window, plus whether this caller claimed the one refresh opportunity.
    pub fn get_with_flags(
        &self,
        name: &[u8],
        record_type: RecordType,
        dns_class: DNSClass,
        flags: u8,
    ) -> Option<(Vec<u8>, bool)> {
        if !self.enabled || name.len() > MAX_NAME_LEN {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        let hash = key_hash(name, record_type, dns_class, flags);
        let entry = match state.locate(hash, name, record_type, dns_class, flags) {
            Locate::Found(entry) => entry,
            Locate::Vacant(_) => return None,
        };
        let now = Instant::now();
        if state.entry(entry).stale_until <= now {
            state.evict(entry);
            return None;
        }

        state.touch(entry);
        let meta = state.entry_mut(entry);
        let stale = meta.expires_at <= now;
        let should_refresh = !meta.refresh_claimed
            && (stale || meta.expires_at.duration_since(now) <= meta.original_ttl / 10);
        if should_refresh {
            meta.refresh_claimed = true;
        }
        let elapsed = meta
            .original_ttl
            .saturating_sub(meta.expires_at.saturating_duration_since(now));
        let wire_start = meta.offset + usize::from(meta.name_len);
        let wire_end = wire_start + meta.wire_len as usize;
        let mut wire = state.pool[wire_start..wire_end].to_vec();
        super::wire::age_ttls(
            &mut wire,
            elapsed.as_secs().min(u64::from(u32::MAX)) as u32,
            stale,
        );
        Some((wire, should_refresh))
    }

    #[cfg(test)]
    pub fn release_refresh_claim(&self, name: &str, record_type: RecordType, dns_class: DNSClass) {
        self.release_refresh_claim_with_flags(name.as_bytes(), record_type, dns_class, 0);
    }

    pub fn release_refresh_claim_with_flags(
        &self,
        name: &[u8],
        record_type: RecordType,
        dns_class: DNSClass,
        flags: u8,
    ) {
        let mut state = self.state.lock().unwrap();
        let hash = key_hash(name, record_type, dns_class, flags);
        if let Locate::Found(entry) = state.locate(hash, name, record_type, dns_class, flags) {
            state.entry_mut(entry).refresh_claimed = false;
        }
    }

    #[cfg(test)]
    pub(crate) fn set_remaining_ttl_for_test(
        &self,
        name: &str,
        record_type: RecordType,
        dns_class: DNSClass,
        remaining: Duration,
    ) {
        let mut state = self.state.lock().unwrap();
        let hash = key_hash(name.as_bytes(), record_type, dns_class, 0);
        let Locate::Found(entry) = state.locate(hash, name.as_bytes(), record_type, dns_class, 0)
        else {
            panic!("missing test entry")
        };
        let meta = state.entry_mut(entry);
        meta.expires_at = Instant::now() + remaining;
        meta.stale_until = meta.expires_at + SERVE_STALE_WINDOW;
    }

    #[cfg(test)]
    fn expire_fully_for_test(&self, name: &str, record_type: RecordType, dns_class: DNSClass) {
        let mut state = self.state.lock().unwrap();
        let hash = key_hash(name.as_bytes(), record_type, dns_class, 0);
        let Locate::Found(entry) = state.locate(hash, name.as_bytes(), record_type, dns_class, 0)
        else {
            panic!("missing test entry")
        };
        let meta = state.entry_mut(entry);
        meta.expires_at = Instant::now();
        meta.stale_until = Instant::now();
    }

    #[cfg(test)]
    pub fn insert(
        &self,
        name: String,
        record_type: RecordType,
        dns_class: DNSClass,
        ttl: u32,
        wire: Vec<u8>,
    ) {
        self.insert_with_flags(name.as_bytes(), record_type, dns_class, 0, ttl, wire);
    }

    pub fn insert_with_flags(
        &self,
        name: &[u8],
        record_type: RecordType,
        dns_class: DNSClass,
        flags: u8,
        ttl: u32,
        wire: Vec<u8>,
    ) {
        if !self.enabled || name.len() > MAX_NAME_LEN {
            return;
        }
        let total_len = name.len().saturating_add(wire.len());
        let Ok(layout) = Layout::from_size_align(total_len, 1) else {
            return;
        };
        let hash = key_hash(name, record_type, dns_class, flags);
        let original_ttl = Duration::from_secs(u64::from(ttl));
        let expires_at = Instant::now() + original_ttl;
        let stale_until = expires_at + SERVE_STALE_WINDOW;

        let mut state = self.state.lock().unwrap();
        if let Locate::Found(entry) = state.locate(hash, name, record_type, dns_class, flags) {
            state.evict(entry);
        }
        state.ensure_table_capacity();

        let ptr = loop {
            match state.heap.allocate_first_fit(layout) {
                Ok(ptr) => break ptr,
                Err(()) => {
                    if !state.evict_one_for_space() {
                        debug!(name = %String::from_utf8_lossy(name), ?record_type, size = wire.len(), "response doesn't fit in the cache even when empty, not caching");
                        return;
                    }
                }
            }
        };
        let offset = ptr.as_ptr() as usize - state.pool.as_ptr() as usize;
        // SAFETY: `ptr` was returned for exactly `total_len` bytes, with the
        // name followed by the response; the arena never moves.
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), ptr.as_ptr(), name.len());
            std::ptr::copy_nonoverlapping(wire.as_ptr(), ptr.as_ptr().add(name.len()), wire.len());
        }

        let entry = state.alloc_entry(EntryMeta {
            offset,
            name_len: name.len() as u16,
            wire_len: wire.len() as u32,
            record_type,
            dns_class,
            flags,
            expires_at,
            stale_until,
            original_ttl,
            refresh_claimed: false,
            prev: NONE,
            next: NONE,
            table_slot: 0,
        });
        let Locate::Vacant(table_slot) = state.locate(hash, name, record_type, dns_class, flags)
        else {
            unreachable!("existing entry was evicted before insert")
        };
        if state.table[table_slot].entry == TOMBSTONE {
            state.tombstones -= 1;
        }
        state.table[table_slot] = KeySlot { hash, entry };
        state.table_len += 1;
        state.entry_mut(entry).table_slot = table_slot as u32;
        state.attach_front(entry);
    }
}

impl CacheState {
    fn entry(&self, index: u32) -> &EntryMeta {
        self.entries[index as usize]
            .as_ref()
            .expect("live cache index")
    }

    fn entry_mut(&mut self, index: u32) -> &mut EntryMeta {
        self.entries[index as usize]
            .as_mut()
            .expect("live cache index")
    }

    fn name(&self, index: u32) -> &[u8] {
        let meta = self.entry(index);
        &self.pool[meta.offset..meta.offset + usize::from(meta.name_len)]
    }

    fn key_matches(
        &self,
        index: u32,
        name: &[u8],
        record_type: RecordType,
        dns_class: DNSClass,
        flags: u8,
    ) -> bool {
        let meta = self.entry(index);
        meta.record_type == record_type
            && meta.dns_class == dns_class
            && meta.flags == flags
            && self.name(index) == name
    }

    fn locate(
        &self,
        hash: u64,
        name: &[u8],
        record_type: RecordType,
        dns_class: DNSClass,
        flags: u8,
    ) -> Locate {
        let mask = self.table.len() - 1;
        let mut slot = hash as usize & mask;
        let mut first_tombstone = None;
        loop {
            let candidate = self.table[slot];
            match candidate.entry {
                EMPTY => return Locate::Vacant(first_tombstone.unwrap_or(slot)),
                TOMBSTONE => {
                    first_tombstone.get_or_insert(slot);
                }
                entry
                    if candidate.hash == hash
                        && self.key_matches(entry, name, record_type, dns_class, flags) =>
                {
                    return Locate::Found(entry);
                }
                _ => {}
            };
            slot = (slot + 1) & mask;
        }
    }

    fn ensure_table_capacity(&mut self) {
        if (self.table_len + self.tombstones + 1) * 4 < self.table.len() * 3 {
            return;
        }
        let new_len = if self.tombstones > self.table_len / 2 {
            self.table.len()
        } else {
            self.table.len() * 2
        };
        self.rehash(new_len);
    }

    fn rehash(&mut self, new_len: usize) {
        self.table = vec![KeySlot::EMPTY; new_len];
        self.table_len = 0;
        self.tombstones = 0;
        for index in 0..self.entries.len() as u32 {
            if self.entries[index as usize].is_none() {
                continue;
            }
            let meta = self.entry(index);
            let hash = key_hash(
                self.name(index),
                meta.record_type,
                meta.dns_class,
                meta.flags,
            );
            let Locate::Vacant(slot) = self.locate(
                hash,
                self.name(index),
                meta.record_type,
                meta.dns_class,
                meta.flags,
            ) else {
                unreachable!("slab contains duplicate cache keys")
            };
            self.table[slot] = KeySlot { hash, entry: index };
            self.table_len += 1;
            self.entry_mut(index).table_slot = slot as u32;
        }
    }

    fn alloc_entry(&mut self, meta: EntryMeta) -> u32 {
        if let Some(index) = self.free_entries.pop() {
            self.entries[index as usize] = Some(meta);
            index
        } else {
            let index = self.entries.len() as u32;
            self.entries.push(Some(meta));
            index
        }
    }

    fn unlink(&mut self, entry: u32) {
        let (prev, next) = {
            let meta = self.entry(entry);
            (meta.prev, meta.next)
        };
        if prev == NONE {
            self.lru_head = next
        } else {
            self.entry_mut(prev).next = next
        };
        if next == NONE {
            self.lru_tail = prev
        } else {
            self.entry_mut(next).prev = prev
        };
    }

    fn attach_front(&mut self, entry: u32) {
        let old_head = self.lru_head;
        let meta = self.entry_mut(entry);
        meta.prev = NONE;
        meta.next = old_head;
        if old_head != NONE {
            self.entry_mut(old_head).prev = entry;
        }
        self.lru_head = entry;
        if self.lru_tail == NONE {
            self.lru_tail = entry;
        }
    }

    fn touch(&mut self, entry: u32) {
        if self.lru_head == entry {
            return;
        }
        self.unlink(entry);
        self.attach_front(entry);
    }

    fn evict(&mut self, entry: u32) {
        self.unlink(entry);
        let meta = self.entries[entry as usize]
            .take()
            .expect("evicting live cache entry");
        let slot = meta.table_slot as usize;
        self.table[slot].entry = TOMBSTONE;
        self.table_len -= 1;
        self.tombstones += 1;
        let total_len = usize::from(meta.name_len) + meta.wire_len as usize;
        // SAFETY: offset/length came from one matching allocation.
        unsafe {
            let ptr = NonNull::new_unchecked(self.pool.as_mut_ptr().add(meta.offset));
            self.heap
                .deallocate(ptr, Layout::from_size_align(total_len, 1).unwrap());
        }
        self.free_entries.push(entry);
    }

    fn evict_one_for_space(&mut self) -> bool {
        let victim = self.lru_tail;
        if victim == NONE {
            return false;
        }
        debug!(name = %String::from_utf8_lossy(self.name(victim)), record_type = ?self.entry(victim).record_type, "evicted a cache entry to make room");
        self.evict(victim);
        true
    }

    #[cfg(test)]
    fn contains(&self, name: &str, record_type: RecordType, dns_class: DNSClass) -> bool {
        matches!(
            self.locate(
                key_hash(name.as_bytes(), record_type, dns_class, 0),
                name.as_bytes(),
                record_type,
                dns_class,
                0
            ),
            Locate::Found(_)
        )
    }

    #[cfg(test)]
    fn live_len(&self) -> usize {
        self.table_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: RecordType = RecordType::A;
    const IN: DNSClass = DNSClass::IN;

    #[test]
    fn cache_metadata_stays_compact() {
        assert!(
            std::mem::size_of::<KeySlot>() <= 16,
            "hash slot must remain two machine words"
        );
        assert!(
            std::mem::size_of::<EntryMeta>() <= 128,
            "LRU metadata must not regress to embedding 255-byte domain keys"
        );
    }

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

        assert!(
            cache.get("a.", A, IN).is_some(),
            "recently-touched entry should survive eviction"
        );
        assert!(
            cache.get("c.", A, IN).is_some(),
            "newly-inserted entry should be present"
        );
        assert!(
            cache.get("b.", A, IN).is_none(),
            "least-recently-used entry should have been evicted"
        );
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

        assert_eq!(cache.get("a.", A, IN), Some((vec![9, 9], false)));
        assert!(
            cache.get("b.", A, IN).is_some(),
            "updating an existing key must not evict an unrelated entry"
        );
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

        assert!(
            cache.get("big.", A, IN).is_some(),
            "large entry should still be cached alongside many small ones"
        );
        for i in 0..10 {
            assert!(
                cache.get(&format!("small{i}."), A, IN).is_some(),
                "small entry {i} should still be cached"
            );
        }
    }

    #[test]
    fn pool_is_preallocated_up_front_regardless_of_how_many_entries_are_live() {
        let cache = ResponseCache::new(true, 4096);
        let state = cache.state.lock().unwrap();
        assert_eq!(
            state.pool.len(),
            4096,
            "the whole pool must be allocated at construction, not grown per insert"
        );
    }

    #[test]
    fn evict_expired_reclaims_only_expired_entries_and_frees_their_space() {
        let cache = ResponseCache::new(true, 4096);
        cache.insert("expired.".to_string(), A, IN, 0, vec![1; 8]);
        cache.insert("live.".to_string(), A, IN, 3600, vec![2; 8]);
        cache.expire_fully_for_test("expired.", A, IN);

        cache.evict_expired();

        {
            let state = cache.state.lock().unwrap();
            assert!(!state.contains("expired.", A, IN));
            assert!(state.contains("live.", A, IN));
        }
        assert!(
            cache.get("live.", A, IN).is_some(),
            "unexpired entry must survive a sweep"
        );

        // The reclaimed space should be usable again, not left stranded.
        cache.insert("reuse.".to_string(), A, IN, 60, vec![3; 8]);
        assert!(cache.get("reuse.", A, IN).is_some());
    }

    #[test]
    fn entry_in_the_last_ten_percent_of_its_original_ttl_is_flagged_for_refresh() {
        let cache = ResponseCache::new(true, 4096);
        cache.insert("near-expiry.example.".to_string(), A, IN, 100, vec![1]);
        cache.set_remaining_ttl_for_test("near-expiry.example.", A, IN, Duration::from_secs(9));

        let (_, should_refresh) = cache
            .get("near-expiry.example.", A, IN)
            .expect("entry should still be alive");

        assert!(
            should_refresh,
            "an entry in the final ten percent of its original TTL should be refreshed"
        );
    }

    #[test]
    fn entry_with_more_than_ten_percent_of_its_original_ttl_is_not_flagged_for_refresh() {
        let cache = ResponseCache::new(true, 4096);
        cache.insert("fresh.example.".to_string(), A, IN, 100, vec![1]);
        cache.set_remaining_ttl_for_test("fresh.example.", A, IN, Duration::from_secs(11));

        let (_, should_refresh) = cache
            .get("fresh.example.", A, IN)
            .expect("entry should still be alive");

        assert!(
            !should_refresh,
            "an entry outside the final ten percent of its original TTL should not be refreshed"
        );
    }

    #[test]
    fn near_expiry_entry_refresh_is_claimed_exactly_once_across_many_concurrent_gets() {
        let cache = Arc::new(ResponseCache::new(true, 4096));
        cache.insert("popular.example.".to_string(), A, IN, 100, vec![1]);
        cache.set_remaining_ttl_for_test("popular.example.", A, IN, Duration::from_secs(9));

        let claims = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..100)
                .map(|_| {
                    let cache = Arc::clone(&cache);
                    scope.spawn(move || cache.get("popular.example.", A, IN).unwrap().1)
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|claimed| *claimed)
                .count()
        });

        assert_eq!(
            claims, 1,
            "the refresh claim must be set atomically under the cache mutex"
        );
    }

    #[test]
    fn failed_refresh_claim_can_be_released_and_claimed_again() {
        let cache = ResponseCache::new(true, 4096);
        cache.insert("retry.example.".to_string(), A, IN, 100, vec![1]);
        cache.set_remaining_ttl_for_test("retry.example.", A, IN, Duration::from_secs(9));
        assert!(
            cache.get("retry.example.", A, IN).unwrap().1,
            "first refresh attempt should claim the entry"
        );

        cache.release_refresh_claim("retry.example.", A, IN);

        assert!(
            cache.get("retry.example.", A, IN).unwrap().1,
            "a failed refresh must release its claim so a later hit can retry before expiry"
        );
    }

    #[test]
    fn expired_entry_is_served_stale_with_zero_ttl_and_claims_refresh() {
        use hickory_proto::op::{Message, OpCode, Query};
        use hickory_proto::rr::rdata::A as AData;
        use hickory_proto::rr::{Name, RData, Record};
        use std::net::Ipv4Addr;

        let cache = ResponseCache::new(true, 4096);
        let name = Name::from_ascii("stale.example.").unwrap();
        let mut response = Message::response(1, OpCode::Query);
        response.add_query(Query::query(name.clone(), A));
        response.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(AData::from(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        cache.insert(
            "stale.example.".to_string(),
            A,
            IN,
            60,
            response.to_vec().unwrap(),
        );
        cache.set_remaining_ttl_for_test("stale.example.", A, IN, Duration::ZERO);

        let (wire, should_refresh) = cache
            .get("stale.example.", A, IN)
            .expect("stale window keeps entry available");
        let response = Message::from_vec(&wire).unwrap();
        assert_eq!(
            response.answers[0].ttl, 0,
            "stale answers must never be retained by the client"
        );
        assert!(
            should_refresh,
            "first stale reader must own the background refresh"
        );
        assert!(
            !cache.get("stale.example.", A, IN).unwrap().1,
            "only one reader may own refresh"
        );
    }

    #[test]
    fn replacing_an_entry_clears_its_previous_refresh_claim() {
        let cache = ResponseCache::new(true, 4096);
        cache.insert("replaced.example.".to_string(), A, IN, 100, vec![1]);
        cache.set_remaining_ttl_for_test("replaced.example.", A, IN, Duration::from_secs(9));
        assert!(
            cache.get("replaced.example.", A, IN).unwrap().1,
            "first generation should be claimed"
        );

        cache.insert("replaced.example.".to_string(), A, IN, 100, vec![2]);
        cache.set_remaining_ttl_for_test("replaced.example.", A, IN, Duration::from_secs(9));

        assert!(
            cache.get("replaced.example.", A, IN).unwrap().1,
            "a fresh insert must make its own refresh claim available"
        );
    }

    #[tokio::test]
    async fn start_ttl_sweeper_evicts_expired_entries_in_the_background() {
        let cache = Arc::new(ResponseCache::new(true, 4096));
        cache.insert("expired.".to_string(), A, IN, 0, vec![1; 8]);
        cache.insert("live.".to_string(), A, IN, 3600, vec![2; 8]);
        cache.expire_fully_for_test("expired.", A, IN);

        let shutdown = CancellationToken::new();
        // A short interval so the test doesn't wait out a real 30s sweep.
        cache.start_ttl_sweeper_with_interval(shutdown.clone(), Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.cancel();

        {
            let state = cache.state.lock().unwrap();
            assert!(
                !state.contains("expired.", A, IN),
                "background sweeper should have evicted the expired entry without any get()/insert() call"
            );
        }
        assert!(
            cache.get("live.", A, IN).is_some(),
            "unexpired entry must survive the sweep"
        );
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
        assert_eq!(
            state.pool.len(),
            POOL_BYTES as usize,
            "the preallocated pool must never grow or move"
        );

        // Walk the LRU list and confirm it's still a simple acyclic chain
        // that reaches exactly the entries HashMap holds - the invariant
        // that would break first if concurrent eviction corrupted a link.
        let mut seen = std::collections::HashSet::new();
        let mut cursor = state.lru_head;
        while cursor != NONE {
            assert!(seen.insert(cursor), "LRU list must not contain a cycle");
            cursor = state.entry(cursor).next;
        }
        assert_eq!(
            seen.len(),
            state.live_len(),
            "LRU list must reach every live entry exactly once"
        );

        if state.live_len() == 0 {
            assert!(state.lru_head == NONE && state.lru_tail == NONE);
        } else {
            assert_eq!(
                state.entry(state.lru_head).prev,
                NONE,
                "head must have no prev"
            );
            assert_eq!(
                state.entry(state.lru_tail).next,
                NONE,
                "tail must have no next"
            );
        }
    }
}
