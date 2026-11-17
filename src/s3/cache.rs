//! What the backend remembers of the store: what it found at a key, and the
//! entries of directories.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use super::keys::{DirListing, FileStamp, Row, RowEdit, Slot, last_name, slot};
use super::object::ObjectHead;

/// Most keys the cache remembers a lookup of.
const MAX_KEYS: usize = 10_000;

/// Most directory rows the cache holds over all the listings it keeps. A
/// listing with more rows is kept alone.
const MAX_ROWS: usize = 100_000;

/// A set of entries that drops the least recently used ones when their
/// weights add up to more than `cap`. The entry inserted last always stays.
///
/// With `fold`, keys that differ in case only are spellings of one name. Each
/// has an entry of its own, and a change to the name takes them all.
#[derive(Debug)]
struct Lru<V> {
    cap: usize,
    fold: bool,
    weight: usize,
    next_tick: u64,
    entries: HashMap<String, Entry<V>>,
    /// The keys by the tick of their last use.
    order: BTreeMap<u64, String>,
    /// With `fold`, the keys that have an entry, by name.
    spellings: HashMap<Slot, Vec<String>>,
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    weight: usize,
    tick: u64,
}

impl<V> Lru<V> {
    fn new(cap: usize, fold: bool) -> Self {
        Lru {
            cap,
            fold,
            weight: 0,
            next_tick: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            spellings: HashMap::new(),
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
        if self.fold {
            self.spellings
                .entry(slot(key, true))
                .or_default()
                .push(key.to_owned());
        }
        self.weight += weight;
        while self.weight > self.cap && self.order.len() > 1 {
            let Some(oldest) = self.order.first_key_value().map(|(_, key)| key.clone()) else {
                break;
            };
            self.remove(&oldest);
        }
    }

    fn remove(&mut self, key: &str) {
        if !self.take(key) || !self.fold {
            return;
        }
        let name = slot(key, true);
        if let Some(held) = self.spellings.get_mut(&name) {
            held.retain(|spelling| spelling != key);
            if held.is_empty() {
                self.spellings.remove(&name);
            }
        }
    }

    /// Takes the entry of `key` out of the entries and the order, and returns
    /// whether there was one. The spellings still list the key.
    fn take(&mut self, key: &str) -> bool {
        let Some(entry) = self.entries.remove(key) else {
            return false;
        };
        self.order.remove(&entry.tick);
        self.weight -= entry.weight;
        true
    }

    /// Drops the entries of the spellings of `key` other than `key`.
    fn remove_others(&mut self, key: &str) {
        if !self.fold {
            return;
        }
        let name = slot(key, true);
        let Some(held) = self.spellings.remove(&name) else {
            return;
        };
        let (same, others): (Vec<String>, Vec<String>) =
            held.into_iter().partition(|spelling| spelling == key);
        for spelling in &others {
            self.take(spelling);
        }
        if !same.is_empty() {
            self.spellings.insert(name, same);
        }
    }

    /// Drops the entries of all the spellings of `key`.
    fn remove_spellings(&mut self, key: &str) {
        if !self.fold {
            self.remove(key);
            return;
        }
        for spelling in self.spellings.remove(&slot(key, true)).unwrap_or_default() {
            self.take(&spelling);
        }
    }

    /// Drops the entries of all the spellings of `key` that `keep` does not
    /// keep.
    fn remove_spellings_unless(&mut self, key: &str, keep: impl Fn(&V) -> bool) {
        let spellings = if self.fold {
            self.spellings
                .get(&slot(key, true))
                .cloned()
                .unwrap_or_default()
        } else {
            vec![key.to_owned()]
        };
        for spelling in spellings {
            if self
                .entries
                .get(&spelling)
                .is_some_and(|entry| !keep(&entry.value))
            {
                self.remove(&spelling);
            }
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
struct Learned<T> {
    at: Instant,
    value: T,
}

/// Most changes to rows kept for one read of a listing. A read that meets more
/// is not cached.
const MAX_READ_CHANGES: usize = 1000;

/// What the backend did to a row of a directory.
#[derive(Clone, Copy)]
enum Change<'a> {
    /// A row put in place of the row of its name.
    Put(&'a Row),
    /// The directory row with this name taken out, or the file row if the
    /// flag is not set.
    Take(&'a str, bool),
}

/// A read of the listing of a directory, from the cache or the store.
#[derive(Debug)]
struct Read {
    dir: String,
    /// `dir` as names are compared.
    name: Slot,
    /// The backend changed the rows of the directory since the read began.
    changed: bool,
    /// The changes to the rows of `dir` since the read began, oldest first,
    /// each with the name it changes.
    changes: Vec<(String, RowEdit)>,
    /// Whether `changes` is the whole of what the backend did to the rows
    /// since the read began. It is not for a read of a cached listing, nor
    /// after the rows were dropped, after a change to another spelling of
    /// `dir`, after more changes than are kept, or once the read is done.
    keep: bool,
}

impl Read {
    /// Notes a change to the rows of the directory `dir`, or that they were
    /// dropped when `change` is `None`.
    fn note(&mut self, dir: &str, change: Option<Change<'_>>) {
        self.changed = true;
        let room = self.keep && self.dir == dir && self.changes.len() < MAX_READ_CHANGES;
        match change {
            Some(Change::Put(row)) if room => {
                self.changes
                    .push((row.name.clone(), RowEdit::Put(row.clone())));
            }
            Some(Change::Take(name, dir)) if room => {
                self.changes.push((name.to_owned(), RowEdit::Take { dir }));
            }
            _ => self.stop_keeping(),
        }
    }

    fn stop_keeping(&mut self) {
        self.keep = false;
        self.changes = Vec::new();
    }
}

/// What the backend learned of the store, each item trusted for `ttl`: what
/// is at a key, and the entries of a directory by its key. With `fold`, a
/// change to a key or a directory reaches what is held under every spelling of
/// it, as the store may hold them as one.
#[derive(Debug)]
pub(super) struct MetaCache {
    ttl: Duration,
    fold: bool,
    keys: Lru<Learned<Known>>,
    listings: Lru<Learned<Arc<DirListing>>>,
    reads: HashMap<u64, Read>,
    next_read: u64,
}

impl MetaCache {
    pub(super) fn new(ttl: Duration, fold: bool) -> Self {
        Self::with_limits(ttl, fold, MAX_KEYS, MAX_ROWS)
    }

    fn with_limits(ttl: Duration, fold: bool, keys: usize, rows: usize) -> Self {
        MetaCache {
            ttl,
            fold,
            keys: Lru::new(keys, fold),
            listings: Lru::new(rows, fold),
            reads: HashMap::new(),
            next_read: 0,
        }
    }

    /// Bounds the listings to `rows` rows and drops the ones held.
    #[cfg(test)]
    pub(super) fn limit_rows(&mut self, rows: usize) {
        self.listings = Lru::new(rows, self.fold);
    }

    /// What the last lookup of `key` found, if that was less than `ttl` ago.
    pub(super) fn known(&mut self, key: &str, now: Instant) -> Option<Known> {
        let ttl = self.ttl;
        let learned = self.keys.get(key)?;
        fresh(ttl, learned.at, now).then(|| learned.value.clone())
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
            Learned {
                at: now,
                value: known,
            },
            1,
        );
    }

    /// Drops what is known of the object at `key` and the listing of the
    /// directory `dir` it is in. The reads of that listing that are under way
    /// are not kept.
    pub(super) fn forget_file(&mut self, key: &str, dir: &str) {
        self.keys.remove_spellings(key);
        self.rows_changed(dir, None);
        self.listings.remove_spellings(dir);
    }

    /// The listing of the directory with key `dir`, if it was read less than
    /// `ttl` ago.
    pub(super) fn listing(&mut self, dir: &str, now: Instant) -> Option<Arc<DirListing>> {
        let ttl = self.ttl;
        let learned = self.listings.get(dir)?;
        fresh(ttl, learned.at, now).then(|| Arc::clone(&learned.value))
    }

    /// Adds `row` to the cached listing of the directory `dir`, if there is
    /// one. The listing keeps its age. With `fold`, the listings of the other
    /// spellings of `dir` go, and so does a listing that has a row of another
    /// spelling of the name: the store may hold the two as one object. The
    /// reads of that listing that are under way take in the row.
    pub(super) fn add_row(&mut self, dir: &str, row: Row) {
        self.rows_changed(dir, Some(Change::Put(&row)));
        self.listings.remove_others(dir);
        let Some(learned) = self.listings.get(dir) else {
            return;
        };
        let (at, listing) = (learned.at, Arc::clone(&learned.value));
        if self.fold && listing.has_other_spelling(&row.name) {
            self.listings.remove(dir);
            return;
        }
        self.put_listing(dir, Arc::new(listing.with_row(row)), at);
    }

    /// Drops what is known of the object at `key`, which the backend
    /// deleted, and its row in the cached listing of the directory `dir`. With
    /// `fold`, the listings of the other spellings of `dir` go, and so does a
    /// listing whose row for the object is spelled in another case than `key`.
    /// The reads of that listing that are under way take in the change.
    pub(super) fn deleted_file(&mut self, key: &str, dir: &str) {
        self.deleted_row(key, dir, false);
    }

    /// [`deleted_file`](Self::deleted_file) for the marker object of the
    /// directory `key`, whose key has no trailing `/` here. Only the directory
    /// row goes: a file of the same name keeps its row.
    pub(super) fn deleted_dir(&mut self, key: &str, dir: &str) {
        self.deleted_row(key, dir, true);
    }

    fn deleted_row(&mut self, key: &str, dir: &str, is_dir: bool) {
        let name = last_name(key);
        self.keys.remove_spellings_unless(key, |learned| {
            if is_dir {
                matches!(learned.value, Known::File(_))
            } else {
                matches!(learned.value, Known::Dir(_))
            }
        });
        self.rows_changed(dir, Some(Change::Take(name, is_dir)));
        self.listings.remove_others(dir);
        let Some(learned) = self.listings.get(dir) else {
            return;
        };
        let (at, listing) = (learned.at, Arc::clone(&learned.value));
        if self.fold && listing.has_other_spelling_only(name, is_dir) {
            self.listings.remove(dir);
            return;
        }
        self.put_listing(dir, Arc::new(listing.without_row(name, is_dir)), at);
    }

    /// Tells the reads of the listing of `dir` that are under way that the
    /// backend made `change` to its rows, or dropped them when there is none.
    fn rows_changed(&mut self, dir: &str, change: Option<Change<'_>>) {
        if self.reads.is_empty() {
            return;
        }
        let name = slot(dir, self.fold);
        for read in self.reads.values_mut().filter(|read| read.name == name) {
            read.note(dir, change);
        }
    }

    /// Starts a read of the listing of `dir`, and returns its id with the
    /// cached listing, if there is a fresh one. Until
    /// [`end_read`](Self::end_read), the changes the backend makes to the rows
    /// of `dir` are noted, and kept when the listing is to be read from the
    /// store.
    pub(super) fn begin_read(&mut self, dir: &str, now: Instant) -> (u64, Option<Arc<DirListing>>) {
        let cached = self.listing(dir, now);
        let id = self.next_read;
        self.next_read += 1;
        self.reads.insert(
            id,
            Read {
                dir: dir.to_owned(),
                name: slot(dir, self.fold),
                changed: false,
                changes: Vec::new(),
                keep: cached.is_none(),
            },
        );
        (id, cached)
    }

    /// Ends the read `id`.
    pub(super) fn end_read(&mut self, id: u64) {
        self.reads.remove(&id);
    }

    /// Whether the backend changed the rows of the directory of the read `id`
    /// since it began.
    pub(super) fn read_changed(&self, id: u64) -> bool {
        self.reads.get(&id).is_some_and(|read| read.changed)
    }

    /// How many reads are under way.
    #[cfg(test)]
    pub(super) fn reads(&self) -> usize {
        self.reads.len()
    }

    /// Keeps `listing`, which the read `id` got from the store, as the cached
    /// listing of its directory, with the changes the backend made to the
    /// rows since the read began. The store may have answered before a
    /// change: the changes are made to the listing in the order they were
    /// made, and one that the listing already shows leaves it as it is.
    /// Returns the listing as kept. When the changes cannot be made, because
    /// the rows were dropped, more were made than are kept, or names that
    /// differ in case only are in play, nothing is kept and the listing is
    /// returned as it was read.
    pub(super) fn keep_read(
        &mut self,
        id: u64,
        listing: DirListing,
        now: Instant,
    ) -> Arc<DirListing> {
        let fold = self.fold;
        let Some(read) = self.reads.get_mut(&id).filter(|read| read.keep) else {
            return Arc::new(listing);
        };
        let changes = std::mem::take(&mut read.changes);
        read.stop_keeping();
        let dir = read.dir.clone();
        match replay(listing, changes, fold) {
            Ok(listing) => {
                let listing = Arc::new(listing);
                self.put_listing(&dir, Arc::clone(&listing), now);
                listing
            }
            Err(listing) => Arc::new(listing),
        }
    }

    pub(super) fn put_listing(&mut self, dir: &str, listing: Arc<DirListing>, now: Instant) {
        let weight = listing.rows.len().max(1);
        self.listings.insert(
            dir,
            Learned {
                at: now,
                value: listing,
            },
            weight,
        );
    }
}

/// `listing` with `changes` made to it, oldest first. When names fold and a
/// changed name has another spelling in the listing or among the changes, the
/// store may hold both as one object: the listing is returned as it was.
fn replay(
    listing: DirListing,
    changes: Vec<(String, RowEdit)>,
    fold: bool,
) -> Result<DirListing, DirListing> {
    if changes.is_empty() {
        return Ok(listing);
    }
    let mut edits: HashMap<String, Vec<RowEdit>> = HashMap::new();
    for (name, edit) in changes {
        edits.entry(name).or_default().push(edit);
    }
    if fold && folds_apart(&listing, &edits) {
        return Err(listing);
    }
    Ok(listing.edited(edits))
}

/// Whether a changed name has another spelling among the rows of `listing` or
/// the changed names.
fn folds_apart(listing: &DirListing, changed: &HashMap<String, Vec<RowEdit>>) -> bool {
    let mut folded: HashMap<String, &str> = HashMap::with_capacity(changed.len());
    for name in changed.keys() {
        if folded.insert(name.to_lowercase(), name).is_some() {
            return true;
        }
    }
    // The rows are checked with the cache lock held: one buffer holds each
    // ASCII name in lowercase in turn.
    let mut lower = String::new();
    listing.rows.iter().any(|row| {
        let owned;
        let key = if row.name.is_ascii() {
            lower.clear();
            lower.push_str(&row.name);
            lower.make_ascii_lowercase();
            lower.as_str()
        } else {
            owned = row.name.to_lowercase();
            owned.as_str()
        };
        folded.get(key).is_some_and(|name| *name != row.name)
    })
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

    fn file_row(name: &str) -> Row {
        Row {
            name: name.to_owned(),
            kind: RowKind::File(stamp("\"e\"", 1, 1_000)),
        }
    }

    fn named(names: &[&str]) -> Arc<DirListing> {
        Arc::new(DirListing {
            rows: names.iter().map(|name| file_row(name)).collect(),
        })
    }

    fn row_names(cache: &mut MetaCache, dir: &str, now: Instant) -> Option<Vec<String>> {
        let listing = cache.listing(dir, now)?;
        Some(listing.rows.iter().map(|row| row.name.clone()).collect())
    }

    fn is_file(known: Option<Known>) -> bool {
        matches!(known, Some(Known::File(_)))
    }

    #[test]
    fn a_row_added_to_a_cached_listing_keeps_the_age_of_the_listing() {
        let ttl = Duration::from_secs(10);
        let mut cache = MetaCache::new(ttl, false);
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
        let mut lru = Lru::new(3, false);
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
    fn the_weights_stay_within_the_cap() {
        let mut lru = Lru::new(10, false);
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
        let mut lru = Lru::new(10, false);
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
        let mut lru = Lru::new(5, false);
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
        let mut lru = Lru::new(10, false);
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
        let mut cache = MetaCache::with_limits(Duration::from_secs(60), false, 3, 100);
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
        let mut cache = MetaCache::with_limits(Duration::from_secs(60), false, 10, 10);
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
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
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
    fn a_cached_head_stays_valid_for_the_row_it_matches_at_any_age() {
        let start = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
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
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
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
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        cache.put_known("k", Known::File(head("", 5, 1_000)), now);
        assert!(cache.head_for_row("k", &stamp("", 5, 1_000_000)).is_some());
        assert!(cache.head_for_row("k", &stamp("", 6, 1_000_000)).is_none());
        assert!(cache.head_for_row("k", &stamp("", 5, 1_001_000)).is_none());
    }

    #[test]
    fn a_cached_miss_or_directory_does_not_match_a_row() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
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
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
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
    fn a_forgotten_file_leaves_what_is_cached_under_every_spelling_of_its_name() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), true);
        for dir in ["Dir", "dir", "DIR"] {
            cache.put_known(&format!("{dir}/f"), Known::File(head("\"e\"", 1, 1)), now);
            cache.put_listing(dir, named(&["f"]), now);
        }
        cache.put_known("dir/g", Known::File(head("\"e\"", 1, 1)), now);
        cache.put_listing("other", named(&["f"]), now);
        cache.forget_file("Dir/f", "Dir");
        for dir in ["Dir", "dir", "DIR"] {
            assert!(cache.known(&format!("{dir}/f"), now).is_none(), "{dir}");
            assert!(cache.listing(dir, now).is_none(), "{dir}");
        }
        assert!(cache.known("dir/g", now).is_some());
        assert!(cache.listing("other", now).is_some());
    }

    #[test]
    fn a_deleted_file_leaves_what_is_cached_under_every_spelling_of_its_name() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), true);
        for dir in ["Dir", "dir", "DIR"] {
            cache.put_known(&format!("{dir}/f"), Known::File(head("\"e\"", 1, 1)), now);
            cache.put_listing(dir, named(&["f", "g"]), now);
        }
        cache.deleted_file("DIR/f", "DIR");
        assert!(cache.known("Dir/f", now).is_none());
        assert!(cache.known("dir/f", now).is_none());
        assert!(cache.known("DIR/f", now).is_none());
        assert!(cache.listing("Dir", now).is_none());
        assert!(cache.listing("dir", now).is_none());
        assert_eq!(
            row_names(&mut cache, "DIR", now),
            Some(vec!["g".to_owned()])
        );
    }

    fn dir_row(name: &str) -> Row {
        Row {
            name: name.to_owned(),
            kind: RowKind::Dir,
        }
    }

    fn rows_of(rows: Vec<Row>) -> Arc<DirListing> {
        Arc::new(DirListing { rows })
    }

    #[test]
    fn a_deleted_marker_leaves_what_is_cached_of_a_file_of_its_name() {
        let now = Instant::now();
        for fold in [false, true] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            cache.put_known("d", Known::File(head("\"e\"", 1, 1)), now);
            cache.put_listing("", rows_of(vec![file_row("d"), file_row("x")]), now);
            cache.deleted_dir("d", "");
            assert!(is_file(cache.known("d", now)), "fold {fold}");
            assert_eq!(
                row_names(&mut cache, "", now),
                Some(vec!["d".to_owned(), "x".to_owned()]),
                "fold {fold}"
            );
            cache.deleted_file("d", "");
            assert!(cache.known("d", now).is_none(), "fold {fold}");
            assert_eq!(
                row_names(&mut cache, "", now),
                Some(vec!["x".to_owned()]),
                "fold {fold}"
            );
        }
    }

    #[test]
    fn a_deleted_file_leaves_what_is_cached_of_a_directory_of_its_name() {
        let now = Instant::now();
        for fold in [false, true] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            cache.put_known("d", Known::Dir(None), now);
            cache.put_listing("", rows_of(vec![dir_row("d"), file_row("x")]), now);
            cache.deleted_file("d", "");
            assert!(
                matches!(cache.known("d", now), Some(Known::Dir(None))),
                "fold {fold}"
            );
            assert_eq!(
                row_names(&mut cache, "", now),
                Some(vec!["d".to_owned(), "x".to_owned()]),
                "fold {fold}"
            );
            cache.deleted_dir("d", "");
            assert!(cache.known("d", now).is_none(), "fold {fold}");
            assert_eq!(
                row_names(&mut cache, "", now),
                Some(vec!["x".to_owned()]),
                "fold {fold}"
            );
        }
    }

    #[test]
    fn a_marker_deleted_in_another_case_drops_the_listing_when_names_fold() {
        let now = Instant::now();
        for (fold, kept) in [(true, false), (false, true)] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            cache.put_listing("", rows_of(vec![dir_row("Dir"), file_row("dir")]), now);
            cache.deleted_dir("dir", "");
            assert_eq!(cache.listing("", now).is_some(), kept, "fold {fold}");
            cache.put_listing("", rows_of(vec![file_row("Dir")]), now);
            cache.deleted_dir("dir", "");
            assert!(
                cache.listing("", now).is_some(),
                "fold {fold}: no directory row"
            );
        }
    }

    /// The names, and whether each is a directory, of a listing of the root
    /// the store gave as `d` and `x`, a directory and a file, after `change`
    /// was made to the rows while it was read.
    fn read_with(fold: bool, change: impl FnOnce(&mut MetaCache)) -> Vec<(String, bool)> {
        let mut cache = MetaCache::new(Duration::from_secs(30), fold);
        let read = begin(&mut cache, "");
        change(&mut cache);
        let listing = DirListing {
            rows: vec![dir_row("d"), file_row("x")],
        };
        let kept = cache.keep_read(read, listing, Instant::now());
        kept.rows
            .iter()
            .map(|row| (row.name.clone(), row.is_dir()))
            .collect()
    }

    #[test]
    fn a_listing_read_while_a_file_was_put_and_a_marker_of_its_name_deleted_has_the_file() {
        let both = [("d".to_owned(), false), ("x".to_owned(), false)];
        for fold in [false, true] {
            let put_then_marker = read_with(fold, |cache| {
                cache.add_row("", file_row("d"));
                cache.deleted_dir("d", "");
            });
            assert_eq!(put_then_marker, both, "fold {fold}");
            let marker_then_put = read_with(fold, |cache| {
                cache.deleted_dir("d", "");
                cache.add_row("", file_row("d"));
            });
            assert_eq!(marker_then_put, both, "fold {fold}");
            let put_then_file = read_with(fold, |cache| {
                cache.add_row("", file_row("d"));
                cache.deleted_file("d", "");
            });
            assert_eq!(put_then_file, &both[1..], "fold {fold}");
        }
    }

    #[test]
    fn spellings_of_a_name_stay_apart_unless_names_fold() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        cache.put_known("Dir/f", Known::File(head("\"e\"", 1, 1)), now);
        cache.put_listing("Dir", named(&["f", "F"]), now);
        cache.deleted_file("dir/f", "dir");
        cache.add_row("dir", file_row("new"));
        assert!(is_file(cache.known("Dir/f", now)));
        assert_eq!(row_names(&mut cache, "Dir", now).unwrap().len(), 2);
        cache.put_listing("dir", named(&["f", "F"]), now);
        cache.deleted_file("dir/f", "dir");
        assert_eq!(
            row_names(&mut cache, "dir", now),
            Some(vec!["F".to_owned()])
        );
    }

    #[test]
    fn a_listing_with_the_row_of_a_deleted_file_in_another_case_goes() {
        let now = Instant::now();
        for (fold, kept) in [(true, false), (false, true)] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            cache.put_listing("d", named(&["File.txt", "other"]), now);
            cache.deleted_file("d/file.txt", "d");
            assert_eq!(cache.listing("d", now).is_some(), kept, "fold {fold}");
        }
    }

    #[test]
    fn a_row_added_to_one_spelling_of_a_directory_drops_the_listings_of_the_others() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), true);
        cache.put_listing("Dir", named(&["a"]), now);
        cache.put_listing("dir", named(&["a"]), now);
        cache.add_row("dir", file_row("b"));
        assert!(cache.listing("Dir", now).is_none());
        assert_eq!(
            row_names(&mut cache, "dir", now),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn a_row_for_another_spelling_of_a_listed_name_drops_the_listing_when_names_fold() {
        let now = Instant::now();
        for fold in [true, false] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            cache.put_listing("d", named(&["File.txt", "other"]), now);
            cache.add_row("d", file_row("file.txt"));
            let rows = row_names(&mut cache, "d", now);
            if fold {
                assert_eq!(rows, None);
            } else {
                assert_eq!(
                    rows,
                    Some(vec![
                        "File.txt".to_owned(),
                        "file.txt".to_owned(),
                        "other".to_owned()
                    ])
                );
            }
        }
    }

    #[test]
    fn a_row_for_a_listed_name_replaces_it_when_names_fold() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), true);
        cache.put_listing("d", named(&["a", "b"]), now);
        cache.add_row("d", file_row("a"));
        assert_eq!(
            row_names(&mut cache, "d", now),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
    }

    fn names_of(listing: &DirListing) -> Vec<&str> {
        listing.rows.iter().map(|row| row.name.as_str()).collect()
    }

    fn read_of(names: &[&str]) -> DirListing {
        DirListing {
            rows: names.iter().map(|name| file_row(name)).collect(),
        }
    }

    fn sized_row(name: &str, size: u64) -> Row {
        Row {
            name: name.to_owned(),
            kind: RowKind::File(stamp("\"e\"", size, 1_000)),
        }
    }

    fn begin(cache: &mut MetaCache, dir: &str) -> u64 {
        cache.begin_read(dir, Instant::now()).0
    }

    #[test]
    fn a_listing_read_while_the_rows_of_its_directory_stood_is_kept() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.add_row("other", file_row("x"));
        cache.deleted_file("other/y", "other");
        assert!(!cache.read_changed(read));
        let listing = cache.keep_read(read, read_of(&["a", "b"]), now);
        assert_eq!(listing.rows.len(), 2);
        assert_eq!(
            row_names(&mut cache, "d", now),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn a_listing_read_while_the_directory_changed_has_the_changes() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.add_row("d", file_row("new"));
        cache.deleted_file("d/old", "d");
        cache.add_row("other", file_row("x"));
        assert!(cache.read_changed(read));
        let listing = cache.keep_read(read, read_of(&["keep", "old"]), now);
        assert_eq!(names_of(&listing), ["keep", "new"]);
        assert_eq!(
            row_names(&mut cache, "d", now),
            Some(vec!["keep".to_owned(), "new".to_owned()])
        );
        assert!(cache.listing("other", now).is_none());
        assert!(cache.read_changed(read));
    }

    #[test]
    fn a_row_put_during_a_read_replaces_the_row_the_read_has() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.add_row("d", sized_row("a", 9));
        let held = DirListing {
            rows: vec![sized_row("a", 1), sized_row("b", 1)],
        };
        let listing = cache.keep_read(read, held, now);
        assert_eq!(listing.rows, [sized_row("a", 9), sized_row("b", 1)]);
        assert_eq!(cache.listing("d", now).unwrap().rows, listing.rows);
    }

    #[test]
    fn a_change_the_read_already_shows_leaves_it_as_it_is() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.add_row("d", file_row("a"));
        cache.deleted_file("d/z", "d");
        let listing = cache.keep_read(read, read_of(&["a", "b"]), now);
        assert_eq!(*listing, read_of(&["a", "b"]));
        assert_eq!(*cache.listing("d", now).unwrap(), read_of(&["a", "b"]));
    }

    #[test]
    fn rows_put_during_a_read_take_their_place_in_the_order_of_the_keys() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.add_row("d", file_row("c"));
        cache.add_row(
            "d",
            Row {
                name: "b".to_owned(),
                kind: RowKind::Dir,
            },
        );
        cache.add_row("d", file_row("a"));
        let listing = cache.keep_read(read, read_of(&["b.txt", "d"]), now);
        assert_eq!(names_of(&listing), ["a", "b.txt", "b", "c", "d"]);
    }

    #[test]
    fn changes_to_one_name_made_during_a_read_apply_in_order() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.add_row("d", file_row("a"));
        cache.deleted_file("d/a", "d");
        cache.deleted_file("d/b", "d");
        cache.add_row("d", file_row("b"));
        cache.add_row("d", file_row("c"));
        cache.deleted_file("d/c", "d");
        cache.add_row("d", sized_row("c", 5));
        let listing = cache.keep_read(read, read_of(&["b", "c"]), now);
        assert_eq!(listing.rows, [file_row("b"), sized_row("c", 5)]);
    }

    #[test]
    fn a_listing_read_while_its_rows_were_dropped_is_not_kept() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.forget_file("d/f", "d");
        assert!(cache.read_changed(read));
        let listing = cache.keep_read(read, read_of(&["f", "g"]), now);
        assert_eq!(names_of(&listing), ["f", "g"]);
        assert!(cache.listing("d", now).is_none());
        assert!(cache.read_changed(read));
    }

    #[test]
    fn a_listing_read_while_its_rows_were_dropped_is_not_kept_whatever_else_changed() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let before = begin(&mut cache, "d");
        cache.add_row("d", file_row("n"));
        cache.forget_file("d/f", "d");
        let after = begin(&mut cache, "d");
        cache.forget_file("d/f", "d");
        cache.add_row("d", file_row("m"));
        for read in [before, after] {
            let listing = cache.keep_read(read, read_of(&["a"]), now);
            assert_eq!(names_of(&listing), ["a"]);
            assert!(cache.listing("d", now).is_none());
        }
    }

    #[test]
    fn a_listing_read_while_another_spelling_of_the_directory_changed_is_not_kept() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), true);
        let read = begin(&mut cache, "Dir");
        cache.add_row("dir", file_row("new"));
        let listing = cache.keep_read(read, read_of(&["a"]), now);
        assert_eq!(names_of(&listing), ["a"]);
        assert!(cache.listing("Dir", now).is_none());
    }

    #[test]
    fn a_read_that_ended_keeps_no_changes() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.end_read(read);
        cache.add_row("d", file_row("new"));
        assert_eq!(cache.reads(), 0);
        let listing = cache.keep_read(read, read_of(&["a"]), now);
        assert_eq!(names_of(&listing), ["a"]);
        assert!(cache.listing("d", now).is_none());
    }

    #[test]
    fn reads_of_one_directory_that_overlap_each_get_the_changes_made_since_they_began() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let first = begin(&mut cache, "d");
        cache.add_row("d", file_row("c1"));
        let second = begin(&mut cache, "d");
        cache.add_row("d", file_row("c2"));
        let listed = cache.keep_read(first, read_of(&["x"]), now);
        assert_eq!(names_of(&listed), ["c1", "c2", "x"]);
        cache.end_read(first);
        assert_eq!(cache.reads(), 1);

        cache.add_row("d", file_row("c3"));
        cache.deleted_file("d/x", "d");
        let listed = cache.keep_read(second, read_of(&["x", "c1"]), now);
        assert_eq!(names_of(&listed), ["c1", "c2", "c3"]);
        assert_eq!(
            row_names(&mut cache, "d", now),
            Some(vec!["c1".to_owned(), "c2".to_owned(), "c3".to_owned()])
        );
        cache.end_read(second);
        assert_eq!(cache.reads(), 0);
    }

    #[test]
    fn a_listing_read_while_more_changes_were_made_than_are_kept_is_not_kept() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        for n in 0..=MAX_READ_CHANGES {
            cache.add_row("d", file_row(&format!("n{n}")));
        }
        let listing = cache.keep_read(read, read_of(&["a"]), now);
        assert_eq!(names_of(&listing), ["a"]);
        assert!(cache.listing("d", now).is_none());
        assert!(cache.read_changed(read));

        let read = begin(&mut cache, "d");
        for n in 0..MAX_READ_CHANGES {
            cache.add_row("d", file_row(&format!("n{n}")));
        }
        let listing = cache.keep_read(read, read_of(&["a"]), now);
        assert_eq!(listing.rows.len(), MAX_READ_CHANGES + 1);
        assert!(cache.listing("d", now).is_some());
    }

    #[test]
    fn a_read_of_a_cached_listing_notes_the_changes_made_to_it_and_keeps_none() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        cache.put_listing("d", named(&["a"]), now);
        let (read, cached) = cache.begin_read("d", now);
        assert_eq!(names_of(&cached.unwrap()), ["a"]);
        assert!(!cache.read_changed(read));
        cache.add_row("d", file_row("b"));
        cache.deleted_file("d/a", "d");
        assert!(cache.read_changed(read));
        assert!(cache.reads[&read].changes.is_empty());
    }

    #[test]
    fn a_read_that_took_in_its_changes_only_notes_the_ones_after() {
        let now = Instant::now();
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let read = begin(&mut cache, "d");
        cache.add_row("d", file_row("a"));
        cache.keep_read(read, read_of(&[]), now);
        cache.add_row("d", file_row("b"));
        assert!(cache.read_changed(read));
        assert!(cache.reads[&read].changes.is_empty());
        let again = cache.keep_read(read, read_of(&["z"]), now);
        assert_eq!(names_of(&again), ["z"]);
        assert_eq!(
            row_names(&mut cache, "d", now),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn a_change_is_noted_by_the_reads_that_began_before_it() {
        let mut cache = MetaCache::new(Duration::from_secs(30), false);
        let first = begin(&mut cache, "d");
        cache.add_row("d", file_row("c"));
        let second = begin(&mut cache, "d");
        let apart = begin(&mut cache, "e");
        assert!(cache.read_changed(first));
        assert!(!cache.read_changed(second));
        assert!(!cache.read_changed(apart));
        assert_eq!(cache.reads(), 3);
    }

    #[test]
    fn a_change_to_another_spelling_of_the_directory_is_a_change_when_names_fold() {
        for fold in [true, false] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            let read = begin(&mut cache, "Dir");
            cache.add_row("dir", file_row("new"));
            assert_eq!(cache.read_changed(read), fold, "fold {fold}");
        }
    }

    #[test]
    fn the_changes_made_to_a_read_give_what_they_give_a_cached_listing() {
        let now = Instant::now();
        let base = ["a", "b", "c", "d", "e"];
        for fold in [false, true] {
            let mut read_cache = MetaCache::new(Duration::from_secs(30), fold);
            let mut held_cache = MetaCache::new(Duration::from_secs(30), fold);
            held_cache.put_listing("d", named(&base), now);
            let read = begin(&mut read_cache, "d");
            for cache in [&mut read_cache, &mut held_cache] {
                cache.add_row("d", file_row("f"));
                cache.deleted_file("d/b", "d");
                cache.add_row("d", file_row("a"));
                cache.add_row("d", file_row("b"));
                cache.deleted_file("d/f", "d");
                cache.deleted_file("d/e", "d");
                cache.add_row("d", file_row("g"));
            }
            let listed = read_cache.keep_read(read, read_of(&base), now);
            let held = held_cache.listing("d", now).unwrap();
            assert_eq!(listed.rows, held.rows, "fold {fold}");
            assert_eq!(names_of(&listed), ["a", "b", "c", "d", "g"]);
        }
    }

    #[test]
    fn a_listing_read_while_a_row_of_another_case_was_put_is_kept_only_when_names_differ() {
        let now = Instant::now();
        for fold in [true, false] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            let read = begin(&mut cache, "d");
            cache.add_row("d", file_row("file.txt"));
            let listing = cache.keep_read(read, read_of(&["File.txt"]), now);
            assert_eq!(cache.listing("d", now).is_some(), !fold, "fold {fold}");
            assert_eq!(listing.rows.len(), if fold { 1 } else { 2 }, "fold {fold}");
        }
    }

    #[test]
    fn a_listing_read_while_a_row_of_another_case_was_deleted_is_kept_only_when_names_differ() {
        let now = Instant::now();
        for fold in [true, false] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            let read = begin(&mut cache, "d");
            cache.deleted_file("d/file.txt", "d");
            let listing = cache.keep_read(read, read_of(&["File.txt"]), now);
            assert_eq!(names_of(&listing), ["File.txt"], "fold {fold}");
            assert_eq!(cache.listing("d", now).is_some(), !fold, "fold {fold}");
        }
    }

    #[test]
    fn a_listing_read_while_a_name_moved_to_another_case_is_kept_only_when_names_differ() {
        let now = Instant::now();
        for fold in [true, false] {
            let mut cache = MetaCache::new(Duration::from_secs(30), fold);
            let read = begin(&mut cache, "d");
            cache.deleted_file("d/File.txt", "d");
            cache.add_row("d", file_row("file.txt"));
            let listing = cache.keep_read(read, read_of(&["File.txt"]), now);
            assert_eq!(cache.listing("d", now).is_some(), !fold, "fold {fold}");
            let want: &[&str] = if fold { &["File.txt"] } else { &["file.txt"] };
            assert_eq!(names_of(&listing), want, "fold {fold}");
        }
    }

    fn changed_names(names: &[&str]) -> HashMap<String, Vec<RowEdit>> {
        names
            .iter()
            .map(|name| ((*name).to_owned(), vec![RowEdit::Put(file_row(name))]))
            .collect()
    }

    #[test]
    fn a_changed_name_folds_apart_from_a_row_or_a_change_of_another_case() {
        let rows = read_of(&["Alpha.txt", "caf\u{e9}.txt", "other"]);
        let apart = |names: &[&str]| folds_apart(&rows, &changed_names(names));
        assert!(apart(&["ALPHA.TXT"]));
        assert!(apart(&["alpha.txt"]));
        assert!(apart(&["CAF\u{c9}.TXT"]));
        assert!(apart(&["new", "NEW"]));
        assert!(apart(&["\u{c9}", "\u{e9}"]));
        assert!(!apart(&["Alpha.txt"]));
        assert!(!apart(&["caf\u{e9}.txt", "new"]));
        assert!(!apart(&["alpha.txt.bak", "Other2"]));
        assert!(!apart(&[]));
    }

    #[test]
    fn the_spellings_held_follow_the_entries() {
        let mut lru = Lru::new(3, true);
        for key in ["A", "a", "b", "B", "c"] {
            lru.insert(key, key.to_owned(), 1);
            let held: usize = lru.spellings.values().map(Vec::len).sum();
            assert_eq!(held, lru.len(), "{key}");
        }
        assert!(lru.peek("A").is_none() && lru.peek("a").is_none());
        lru.remove_others("B");
        assert!(lru.peek("b").is_none() && lru.peek("B").is_some());
        lru.remove_spellings("b");
        assert!(lru.peek("b").is_none() && lru.peek("B").is_none());
        assert_eq!(lru.len(), 1);
        assert_eq!(lru.spellings.len(), 1);
        lru.remove("c");
        assert!(lru.spellings.is_empty());
    }
}
