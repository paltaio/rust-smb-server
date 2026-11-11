//! What the backend remembers of the store: what it found at a key, and the
//! entries of directories.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use super::keys::{DirListing, FileStamp, Row};
use super::object::ObjectHead;

/// Most keys the cache remembers a lookup of.
const MAX_KEYS: usize = 10_000;

/// Most directory rows the cache holds over all the listings it keeps. A
/// listing with more rows is kept alone.
const MAX_ROWS: usize = 100_000;

/// A set of entries that drops the least recently used ones when their
/// weights add up to more than `cap`. The entry inserted last always stays.
#[derive(Debug)]
struct Lru<V> {
    cap: usize,
    weight: usize,
    next_tick: u64,
    entries: HashMap<String, Entry<V>>,
    /// The keys by the tick of their last use.
    order: BTreeMap<u64, String>,
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    weight: usize,
    tick: u64,
}

impl<V> Lru<V> {
    fn new(cap: usize) -> Self {
        Lru {
            cap,
            weight: 0,
            next_tick: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    /// The value of `key`, which counts as used.
    fn get(&mut self, key: &str) -> Option<&V> {
        let entry = self.entries.get_mut(key)?;
        self.order.remove(&entry.tick);
        entry.tick = self.next_tick;
        self.next_tick += 1;
        self.order.insert(entry.tick, key.to_owned());
        Some(&entry.value)
    }

    /// Stores `value` under `key`, then drops the least recently used entries
    /// until the weights fit the cap. A value heavier than the cap stays,
    /// alone, until the next insert.
    fn insert(&mut self, key: &str, value: V, weight: usize) {
        self.remove(key);
        let tick = self.next_tick;
        self.next_tick += 1;
        self.order.insert(tick, key.to_owned());
        self.entries.insert(
            key.to_owned(),
            Entry {
                value,
                weight,
                tick,
            },
        );
        self.weight += weight;
        while self.weight > self.cap && self.order.len() > 1 {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.weight -= entry.weight;
            }
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.order.remove(&entry.tick);
            self.weight -= entry.weight;
        }
    }

    #[cfg(test)]
    fn peek(&self, key: &str) -> Option<&V> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// What the store had at a key.
#[derive(Debug, Clone)]
pub(super) enum Known {
    /// An object, as its last HEAD described it.
    File(Arc<ObjectHead>),
    /// A directory, with the description of its marker object if it has one.
    Dir(Option<Arc<ObjectHead>>),
    /// Neither.
    Missing,
}

/// A value and when it was learned.
#[derive(Debug)]
struct Slot<T> {
    at: Instant,
    value: T,
}

/// What the backend learned of the store, each item trusted for `ttl`: what
/// is at a key, and the entries of a directory by its key.
#[derive(Debug)]
pub(super) struct MetaCache {
    ttl: Duration,
    keys: Lru<Slot<Known>>,
    listings: Lru<Slot<Arc<DirListing>>>,
}

impl MetaCache {
    pub(super) fn new(ttl: Duration) -> Self {
        Self::with_limits(ttl, MAX_KEYS, MAX_ROWS)
    }

    fn with_limits(ttl: Duration, keys: usize, rows: usize) -> Self {
        MetaCache {
            ttl,
            keys: Lru::new(keys),
            listings: Lru::new(rows),
        }
    }

    /// Bounds the listings to `rows` rows and drops the ones held.
    #[cfg(test)]
    pub(super) fn limit_rows(&mut self, rows: usize) {
        self.listings = Lru::new(rows);
    }

    /// What the last lookup of `key` found, if that was less than `ttl` ago.
    pub(super) fn known(&mut self, key: &str, now: Instant) -> Option<Known> {
        let ttl = self.ttl;
        let slot = self.keys.get(key)?;
        fresh(ttl, slot.at, now).then(|| slot.value.clone())
    }

    /// The last HEAD of `key`, at any age, if it describes the object that a
    /// listing row stamps: the same size, ETag and modification second.
    pub(super) fn head_for_row(&mut self, key: &str, stamp: &FileStamp) -> Option<Arc<ObjectHead>> {
        let Known::File(head) = &self.keys.get(key)?.value else {
            return None;
        };
        let same = head.etag == stamp.etag
            && head.size == stamp.size
            && seconds(head.last_modified) == seconds(stamp.last_modified);
        same.then(|| Arc::clone(head))
    }

    pub(super) fn put_known(&mut self, key: &str, known: Known, now: Instant) {
        self.keys.insert(
            key,
            Slot {
                at: now,
                value: known,
            },
            1,
        );
    }

    /// Drops what is known of the object at `key` and the listing of the
    /// directory `dir` it is in.
    pub(super) fn forget_file(&mut self, key: &str, dir: &str) {
        self.keys.remove(key);
        self.listings.remove(dir);
    }

    /// The listing of the directory with key `dir`, if it was read less than
    /// `ttl` ago.
    pub(super) fn listing(&mut self, dir: &str, now: Instant) -> Option<Arc<DirListing>> {
        let ttl = self.ttl;
        let slot = self.listings.get(dir)?;
        fresh(ttl, slot.at, now).then(|| Arc::clone(&slot.value))
    }

    /// Adds `row` to the cached listing of the directory `dir`, if there is
    /// one. The listing keeps its age.
    pub(super) fn add_row(&mut self, dir: &str, row: Row) {
        let Some(slot) = self.listings.get(dir) else {
            return;
        };
        let (at, listing) = (slot.at, Arc::new(slot.value.with_row(row)));
        self.put_listing(dir, listing, at);
    }

    pub(super) fn put_listing(&mut self, dir: &str, listing: Arc<DirListing>, now: Instant) {
        let weight = listing.rows.len().max(1);
        self.listings.insert(
            dir,
            Slot {
                at: now,
                value: listing,
            },
            weight,
        );
    }
}

/// Whether something learned at `at` is still trusted at `now`.
fn fresh(ttl: Duration, at: Instant, now: Instant) -> bool {
    now.checked_duration_since(at).is_some_and(|age| age < ttl)
}

/// Whole seconds since the epoch; the headers of an object carry no more.
fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::keys::{Row, RowKind};
    use crate::s3::object::Metadata;

    fn head(etag: &str, size: u64, secs: u64) -> Arc<ObjectHead> {
        Arc::new(ObjectHead {
            size,
            etag: etag.to_owned(),
            last_modified: UNIX_EPOCH + Duration::from_secs(secs),
            metadata: Metadata::default(),
        })
    }

    fn stamp(etag: &str, size: u64, millis: u64) -> FileStamp {
        FileStamp {
            size,
            etag: etag.to_owned(),
            last_modified: UNIX_EPOCH + Duration::from_millis(millis),
        }
    }

    fn listing(rows: usize) -> Arc<DirListing> {
        Arc::new(DirListing {
            rows: (0..rows)
                .map(|n| Row {
                    name: n.to_string(),
                    kind: RowKind::Dir,
                })
                .collect(),
        })
    }

    fn is_file(known: Option<Known>) -> bool {
        matches!(known, Some(Known::File(_)))
    }

    #[test]
    fn a_row_added_to_a_cached_listing_keeps_the_age_of_the_listing() {
        let ttl = Duration::from_secs(10);
        let mut cache = MetaCache::new(ttl);
        let start = Instant::now();
        cache.put_listing("d", listing(2), start);
        let row = Row {
            name: "new".to_owned(),
            kind: RowKind::Dir,
        };
        cache.add_row("d", row.clone());
        cache.add_row("absent", row);
        assert_eq!(cache.listing("d", start).unwrap().rows.len(), 3);
        assert!(cache.listing("absent", start).is_none());
        assert!(cache.listing("d", start + ttl).is_none());
    }

    #[test]
    fn the_least_recently_used_entry_goes_first() {
        let mut lru = Lru::new(3);
        for key in ["a", "b", "c"] {
            lru.insert(key, key.to_uppercase(), 1);
        }
        assert!(lru.get("a").is_some());
        lru.insert("d", "D".into(), 1);
        assert!(lru.peek("b").is_none(), "b was the least recently used");
        for key in ["a", "c", "d"] {
            assert!(lru.peek(key).is_some(), "{key}");
        }
        assert_eq!(lru.len(), 3);
    }

    #[test]
    fn peeking_does_not_count_as_use() {
        let mut lru = Lru::new(2);
        lru.insert("a", 1, 1);
        lru.insert("b", 2, 1);
        assert_eq!(lru.peek("a"), Some(&1));
        lru.insert("c", 3, 1);
        assert!(lru.peek("a").is_none());
        assert!(lru.peek("b").is_some());
    }

    #[test]
    fn the_weights_stay_within_the_cap() {
        let mut lru = Lru::new(10);
        for n in 0..100 {
            lru.insert(&n.to_string(), n, 1 + n % 4);
            assert!(lru.weight <= 10, "{}", lru.weight);
            let counted: usize = lru.entries.values().map(|e| e.weight).sum();
            assert_eq!(counted, lru.weight);
            assert_eq!(lru.order.len(), lru.entries.len());
        }
        assert!(lru.peek("99").is_some(), "the newest entry stays");
    }

    #[test]
    fn a_heavy_entry_pushes_out_several_light_ones() {
        let mut lru = Lru::new(10);
        for n in 0..10 {
            lru.insert(&n.to_string(), n, 1);
        }
        lru.insert("big", 100, 7);
        assert_eq!(lru.weight, 10);
        assert!(lru.peek("big").is_some());
        for n in 0..7 {
            assert!(lru.peek(&n.to_string()).is_none(), "{n}");
        }
        for n in 7..10 {
            assert!(lru.peek(&n.to_string()).is_some(), "{n}");
        }
    }

    #[test]
    fn an_entry_over_the_cap_stays_alone_until_the_next_insert() {
        let mut lru = Lru::new(5);
        lru.insert("a", 1, 2);
        lru.insert("b", 2, 2);
        lru.insert("huge", 3, 6);
        assert_eq!(lru.peek("huge"), Some(&3));
        assert!(lru.peek("a").is_none() && lru.peek("b").is_none());
        assert_eq!(lru.weight, 6);
        lru.insert("c", 4, 1);
        assert!(lru.peek("huge").is_none());
        assert_eq!(lru.peek("c"), Some(&4));
        assert_eq!(lru.weight, 1);
        lru.insert("c", 5, 7);
        assert_eq!(lru.peek("c"), Some(&5));
        assert_eq!((lru.weight, lru.len()), (7, 1));
    }

    #[test]
    fn inserting_a_key_again_replaces_its_value_and_weight() {
        let mut lru = Lru::new(10);
        lru.insert("a", 1, 4);
        lru.insert("a", 2, 1);
        assert_eq!(lru.peek("a"), Some(&2));
        assert_eq!(lru.weight, 1);
        assert_eq!(lru.len(), 1);
        lru.remove("a");
        lru.remove("a");
        assert_eq!((lru.weight, lru.len()), (0, 0));
        assert!(lru.order.is_empty());
    }

    #[test]
    fn the_cache_remembers_at_most_the_most_recent_keys() {
        let now = Instant::now();
        let mut cache = MetaCache::with_limits(Duration::from_secs(60), 3, 100);
        for n in 0..5 {
            cache.put_known(&format!("k{n}"), Known::File(head("\"e\"", 1, 1)), now);
        }
        assert!(cache.known("k0", now).is_none());
        assert!(cache.known("k1", now).is_none());
        for n in 2..5 {
            assert!(is_file(cache.known(&format!("k{n}"), now)), "k{n}");
        }
    }

    #[test]
    fn the_cache_holds_at_most_the_most_recent_rows() {
        let now = Instant::now();
        let mut cache = MetaCache::with_limits(Duration::from_secs(60), 10, 10);
        cache.put_listing("a/", listing(6), now);
        cache.put_listing("b/", listing(4), now);
        assert!(cache.listing("a/", now).is_some());
        assert!(cache.listing("b/", now).is_some());
        cache.put_listing("c/", listing(0), now);
        assert!(
            cache.listing("a/", now).is_none(),
            "a was the least recently used"
        );
        assert!(cache.listing("b/", now).is_some());
        assert!(cache.listing("c/", now).is_some());
        cache.put_listing("big/", listing(11), now);
        assert!(
            cache.listing("big/", now).is_some(),
            "a listing over the cap is kept"
        );
        assert!(cache.listing("b/", now).is_none());
        assert!(cache.listing("c/", now).is_none());
        cache.put_listing("d/", listing(1), now);
        assert!(cache.listing("big/", now).is_none());
        assert!(cache.listing("d/", now).is_some());
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let start = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30));
        cache.put_known("k", Known::File(head("\"e\"", 1, 1)), start);
        cache.put_known("gone", Known::Missing, start);
        cache.put_known("d", Known::Dir(None), start);
        cache.put_listing("d/", listing(2), start);
        let before = start + Duration::from_secs(29);
        assert!(is_file(cache.known("k", before)));
        assert!(matches!(cache.known("gone", before), Some(Known::Missing)));
        assert!(matches!(cache.known("d", before), Some(Known::Dir(None))));
        assert!(cache.listing("d/", before).is_some());
        let after = start + Duration::from_secs(30);
        assert!(cache.known("k", after).is_none());
        assert!(cache.known("gone", after).is_none());
        assert!(cache.known("d", after).is_none());
        assert!(cache.listing("d/", after).is_none());
        assert!(cache.known("unknown", start).is_none());
    }

    #[test]
    fn a_zero_ttl_trusts_nothing() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::ZERO);
        cache.put_known("k", Known::File(head("\"e\"", 1, 1)), now);
        cache.put_listing("d/", listing(1), now);
        assert!(cache.known("k", now).is_none());
        assert!(cache.listing("d/", now).is_none());
    }

    #[test]
    fn a_cached_head_stays_valid_for_the_row_it_matches_at_any_age() {
        let start = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30));
        cache.put_known("k", Known::File(head("\"e\"", 5, 1_000)), start);
        let late = start + Duration::from_secs(3_600);
        assert!(cache.known("k", late).is_none());
        // The listing has milliseconds, the HEAD whole seconds.
        assert!(
            cache
                .head_for_row("k", &stamp("\"e\"", 5, 1_000_999))
                .is_some()
        );
    }

    #[test]
    fn a_row_that_differs_does_not_match_the_cached_head() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30));
        cache.put_known("k", Known::File(head("\"e\"", 5, 1_000)), now);
        for (what, row) in [
            ("etag", stamp("\"other\"", 5, 1_000_000)),
            ("size", stamp("\"e\"", 6, 1_000_000)),
            ("second", stamp("\"e\"", 5, 1_001_000)),
            ("earlier second", stamp("\"e\"", 5, 999_999)),
            ("no etag", stamp("", 5, 1_000_000)),
        ] {
            assert!(cache.head_for_row("k", &row).is_none(), "{what}");
        }
        assert!(
            cache
                .head_for_row("unknown", &stamp("\"e\"", 5, 1_000_000))
                .is_none()
        );
    }

    #[test]
    fn an_object_without_an_etag_matches_by_size_and_time() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30));
        cache.put_known("k", Known::File(head("", 5, 1_000)), now);
        assert!(cache.head_for_row("k", &stamp("", 5, 1_000_000)).is_some());
        assert!(cache.head_for_row("k", &stamp("", 6, 1_000_000)).is_none());
        assert!(cache.head_for_row("k", &stamp("", 5, 1_001_000)).is_none());
    }

    #[test]
    fn a_cached_miss_or_directory_does_not_match_a_row() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30));
        cache.put_known("gone", Known::Missing, now);
        cache.put_known("dir", Known::Dir(Some(head("\"e\"", 5, 1_000))), now);
        for key in ["gone", "dir"] {
            assert!(
                cache
                    .head_for_row(key, &stamp("\"e\"", 5, 1_000_000))
                    .is_none(),
                "{key}"
            );
        }
    }

    #[test]
    fn a_forgotten_file_takes_its_directory_listing_with_it() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30));
        cache.put_known("d/f", Known::File(head("\"e\"", 1, 1)), now);
        cache.put_known("d/g", Known::File(head("\"e\"", 1, 1)), now);
        cache.put_listing("d", listing(2), now);
        cache.put_listing("other", listing(1), now);
        cache.forget_file("d/f", "d");
        assert!(cache.known("d/f", now).is_none());
        assert!(cache.listing("d", now).is_none());
        assert!(cache.known("d/g", now).is_some());
        assert!(cache.listing("other", now).is_some());
    }

    #[test]
    fn a_key_learned_again_replaces_what_was_known() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30));
        cache.put_known("k", Known::Missing, now);
        cache.put_known("k", Known::File(head("\"e\"", 1, 1)), now);
        assert!(is_file(cache.known("k", now)));
    }
}
