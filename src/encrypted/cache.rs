//! The decoded names of directories, and of long entries.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use super::locks::{DirLock, lock};
use super::lru::Lru;
use super::node::is_at_or_below;

/// Weight limit of the directory name cache, in names counted across
/// directories, an empty directory counting as one. A directory with more
/// names than this is kept alone.
pub(super) const MAX_CACHED_NAMES: usize = 100_000;

/// Most long entries the long-name cache holds.
pub(super) const MAX_LONG_NAMES: usize = 10_000;

/// A name of a directory, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    /// The name as the client spells it.
    pub(super) plain: String,
    /// The name of the entry in the inner backend.
    pub(super) stored: String,
    pub(super) directory: bool,
}

/// The names of one directory as the inner backend listed them.
#[derive(Clone)]
pub(super) struct Snapshot {
    built: Instant,
    len: usize,
    /// The entries whose names fold to the same lowercase form, by that
    /// form, each group in the order of the stored names.
    groups: HashMap<String, Vec<Entry>>,
}

impl Snapshot {
    /// The snapshot of `entries`, which the listing began to read at `built`.
    pub(super) fn new(entries: Vec<Entry>, built: Instant) -> Self {
        let len = entries.len();
        let mut groups: HashMap<String, Vec<Entry>> = HashMap::new();
        for entry in entries {
            groups
                .entry(entry.plain.to_lowercase())
                .or_default()
                .push(entry);
        }
        for group in groups.values_mut() {
            group.sort_by(|a, b| a.stored.cmp(&b.stored));
        }
        Self { built, len, groups }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    /// What the snapshot weighs in the cache: its names, and at least one.
    fn weight(&self) -> usize {
        self.len.max(1)
    }

    /// Adds `entry`, replacing the one with the same stored name.
    fn put(&mut self, entry: Entry) {
        let group = self.groups.entry(entry.plain.to_lowercase()).or_default();
        match group.binary_search_by(|held| held.stored.cmp(&entry.stored)) {
            Ok(at) => group[at] = entry,
            Err(at) => {
                group.insert(at, entry);
                self.len += 1;
            }
        }
    }

    /// Drops the entry with the same name and stored name as `entry`.
    fn remove(&mut self, entry: &Entry) {
        let folded = entry.plain.to_lowercase();
        let Some(group) = self.groups.get_mut(&folded) else {
            return;
        };
        if let Ok(at) = group.binary_search_by(|held| held.stored.cmp(&entry.stored)) {
            group.remove(at);
            self.len -= 1;
            if group.is_empty() {
                self.groups.remove(&folded);
            }
        }
    }

    /// The entry that `name` stands for: the one stored as `canonical`, else
    /// the one spelled `name`, else of those that differ only in case the one
    /// with the smallest stored name.
    pub(super) fn entry(&self, name: &str, canonical: &str) -> Option<Entry> {
        self.pick(name, canonical, false)
    }

    /// `entry`, among the directories only.
    pub(super) fn directory(&self, name: &str, canonical: &str) -> Option<Entry> {
        self.pick(name, canonical, true)
    }

    fn pick(&self, name: &str, canonical: &str, directories: bool) -> Option<Entry> {
        let group = self.groups.get(&name.to_lowercase())?;
        let mut spelled = None;
        let mut first = None;
        for entry in group.iter().filter(|entry| entry.directory || !directories) {
            if entry.stored == canonical {
                return Some(entry.clone());
            }
            if spelled.is_none() && entry.plain == name {
                spelled = Some(entry);
            }
            first = first.or(Some(entry));
        }
        spelled.or(first).cloned()
    }
}

/// The snapshots of the directories, by stored path, for as long as they
/// are trusted.
pub(super) struct NameCache {
    ttl: Duration,
    directories: Mutex<Lru<Arc<Snapshot>>>,
}

impl NameCache {
    /// A cache that keeps a snapshot for `ttl`, up to `limit` names in all.
    /// One directory over the limit is kept alone.
    pub(super) fn new(ttl: Duration, limit: usize) -> Self {
        Self {
            ttl,
            directories: Mutex::new(Lru::new(limit)),
        }
    }

    /// The snapshot of the directory `key` if it is younger than the
    /// time-to-live. An older one is dropped.
    pub(super) fn fresh(&self, key: &str) -> Option<Arc<Snapshot>> {
        let mut directories = lock(&self.directories);
        let snapshot = directories.get(key)?;
        if snapshot.built.elapsed() < self.ttl {
            return Some(snapshot);
        }
        directories.remove(key);
        None
    }

    /// Keeps `snapshot` as the names of the directory `key` when `wanted`
    /// says so and the snapshot held there was not built later. `wanted` runs
    /// while the cache is locked, so nothing can slip in between its answer
    /// and the install. With no time-to-live nothing is kept. A directory is
    /// weighed by its names, and at least one.
    pub(super) fn install_if(
        &self,
        key: String,
        snapshot: Arc<Snapshot>,
        wanted: impl FnOnce() -> bool,
    ) {
        if self.ttl.is_zero() {
            return;
        }
        let weight = snapshot.weight();
        let mut directories = lock(&self.directories);
        if !wanted() {
            return;
        }
        if directories
            .get(&key)
            .is_some_and(|held| held.built > snapshot.built)
        {
            return;
        }
        directories.insert(key, snapshot, weight);
    }

    /// Records that a change took the entry `removed` from the directory
    /// `dir` and gave it `added`. The caller holds the lock of the directory,
    /// or the tree lock exclusively, and has made the change in the inner
    /// backend. The change count goes up and the snapshot held, if any, follows
    /// the change, both while the cache is locked, so a listing that began
    /// before the change is not kept over it. The snapshot is changed in place
    /// unless a reader still holds it, and its weight follows its names.
    pub(super) fn patch(&self, dir: &DirLock, removed: Option<&Entry>, added: Option<Entry>) {
        let mut directories = lock(&self.directories);
        dir.count_change();
        directories.modify(dir.key(), |names| {
            let names = Arc::make_mut(names);
            if let Some(entry) = removed {
                names.remove(entry);
            }
            if let Some(entry) = added {
                names.put(entry);
            }
            names.weight()
        });
    }

    pub(super) fn forget(&self, key: &str) {
        lock(&self.directories).remove(key);
    }

    /// Drops the snapshots of the directory `key` and the directories below
    /// it, and counts a change on each of `dirs`, the lock entries of those
    /// directories, in the same step, so a listing of one of them that began
    /// earlier is not kept.
    pub(super) fn forget_below(&self, key: &str, dirs: &[Arc<DirLock>]) {
        let mut directories = lock(&self.directories);
        for dir in dirs {
            dir.count_change();
        }
        directories.remove_where(|held| is_at_or_below(held, key));
    }

    /// The directories held, least recently used first.
    #[cfg(test)]
    pub(super) fn keys(&self) -> Vec<String> {
        lock(&self.directories).keys()
    }

    /// Names held, counting an empty directory as one.
    #[cfg(test)]
    pub(super) fn weight(&self) -> usize {
        lock(&self.directories).weight()
    }
}

/// The plaintext of verified long entries, by stored name. An entry is the
/// hash of its side object, so what it decodes to does not change.
pub(super) struct LongNames {
    names: Mutex<Lru<String>>,
}

impl LongNames {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            names: Mutex::new(Lru::new(limit)),
        }
    }

    pub(super) fn get(&self, entry: &str) -> Option<String> {
        lock(&self.names).get(entry)
    }

    pub(super) fn insert(&self, entry: String, plain: &str) {
        lock(&self.names).insert(entry, plain.to_string(), 1);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        lock(&self.names).len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::locks::Locks;
    use super::super::testing::many_names;
    use super::*;

    fn entry(plain: &str, stored: &str, directory: bool) -> Entry {
        Entry {
            plain: plain.to_string(),
            stored: stored.to_string(),
            directory,
        }
    }

    fn snapshot(entries: Vec<Entry>) -> Snapshot {
        Snapshot::new(entries, Instant::now())
    }

    fn install(cache: &NameCache, key: &str, names: Arc<Snapshot>) {
        cache.install_if(key.to_string(), names, || true);
    }

    #[test]
    fn the_canonical_entry_wins_then_the_spelling_then_the_smallest_stored_name() {
        let names = snapshot(vec![
            entry("Foo", "s3", false),
            entry("FOO", "s2", false),
            entry("foo", "s4", false),
            entry("fOO", "s1", false),
            entry("other", "s5", false),
        ]);
        assert_eq!(names.len(), 5);
        assert_eq!(names.entry("foo", "s3").unwrap().stored, "s3");
        assert_eq!(names.entry("foo", "s9").unwrap().stored, "s4");
        assert_eq!(names.entry("FOO", "s9").unwrap().stored, "s2");
        assert_eq!(names.entry("fOo", "s9").unwrap().stored, "s1");
        assert_eq!(names.entry("Other", "s9").unwrap().plain, "other");
        assert_eq!(names.entry("missing", "s9"), None);
    }

    #[test]
    fn two_stored_names_for_one_name_give_the_smaller() {
        let names = snapshot(vec![
            entry("a", "s2", false),
            entry("a", "s1", false),
            entry("A", "s0", false),
        ]);
        assert_eq!(names.entry("a", "s9").unwrap().stored, "s1");
        assert_eq!(names.entry("a", "s2").unwrap().stored, "s2");
    }

    #[test]
    fn a_directory_lookup_skips_files() {
        let names = snapshot(vec![
            entry("Docs", "s1", false),
            entry("DOCS", "s3", true),
            entry("docs", "s2", true),
        ]);
        assert_eq!(names.directory("docs", "s9").unwrap().stored, "s2");
        assert_eq!(names.directory("docs", "s3").unwrap().stored, "s3");
        assert_eq!(names.directory("Docs", "s9").unwrap().stored, "s2");
        let files_only = snapshot(vec![entry("a", "s1", false)]);
        assert_eq!(files_only.directory("a", "s1"), None);
        assert_eq!(files_only.entry("A", "s9").unwrap().stored, "s1");
    }

    #[test]
    fn non_ascii_names_fold_with_unicode_lowercase() {
        let names = snapshot(vec![entry("\u{c9}COLE", "s1", false)]);
        assert_eq!(names.entry("\u{e9}cole", "s9").unwrap().plain, "\u{c9}COLE");
        let dotted = snapshot(vec![entry("\u{130}", "s1", false)]);
        assert!(dotted.entry("i", "s9").is_none());
    }

    #[test]
    fn a_put_entry_is_found_in_any_case_and_replaces_its_stored_twin() {
        let mut names = snapshot(vec![entry("a", "s2", false)]);
        names.put(entry("A", "s1", false));
        names.put(entry("B", "s3", false));
        assert_eq!(names.len(), 3);
        assert_eq!(names.entry("a", "s9").unwrap().stored, "s2");
        assert_eq!(names.entry("Ab", "s9"), None);
        assert_eq!(names.entry("b", "s9").unwrap().plain, "B");
        assert_eq!(names.entry("A", "s1").unwrap().stored, "s1");

        names.put(entry("a", "s2", true));
        assert_eq!(names.len(), 3, "the same stored name is one entry");
        assert!(names.directory("a", "s2").unwrap().directory);
    }

    #[test]
    fn a_removed_entry_is_gone_and_the_others_of_its_name_stay() {
        let mut names = snapshot(vec![
            entry("a", "s2", false),
            entry("A", "s1", false),
            entry("b", "s3", false),
        ]);
        names.remove(&entry("A", "s1", false));
        assert_eq!(names.len(), 2);
        assert_eq!(names.entry("a", "s9").unwrap().stored, "s2");

        names.remove(&entry("a", "s9", false));
        names.remove(&entry("zz", "s2", false));
        assert_eq!(names.len(), 2, "an entry that is not there changes nothing");

        names.remove(&entry("a", "s2", false));
        assert_eq!(names.len(), 1);
        assert_eq!(names.entry("a", "s2"), None);
        assert_eq!(names.weight(), 1);
        names.remove(&entry("b", "s3", false));
        assert_eq!((names.len(), names.weight()), (0, 1));
        assert_eq!(names.entry("b", "s3"), None);
    }

    #[test]
    fn a_put_entry_keeps_its_group_in_the_order_of_stored_names() {
        let mut names = snapshot(vec![entry("a", "s2", false), entry("A", "s4", false)]);
        names.put(entry("a", "s3", false));
        names.put(entry("A", "s1", false));
        assert_eq!(names.entry("a", "s9").unwrap().stored, "s2");
        assert_eq!(names.entry("A", "s9").unwrap().stored, "s1");
        assert_eq!(names.entry("aa", "s9"), None);
        assert_eq!(names.entry("a", "s3").unwrap().stored, "s3");
    }

    #[tokio::test(start_paused = true)]
    async fn a_patch_adds_the_entry_counts_a_change_and_weighs_the_new_name() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        let locks = Locks::new();
        let dir = locks.directory("d".to_string());
        install(&cache, "d", many_names(3));

        cache.patch(&dir, None, Some(entry("New", "sn", false)));
        assert_eq!(dir.changes(), 1);
        assert_eq!(cache.weight(), 4);
        let names = cache.fresh("d").unwrap();
        assert_eq!(names.len(), 4);
        assert_eq!(names.entry("new", "s9").unwrap().stored, "sn");

        cache.patch(&dir, None, Some(entry("New", "sn", true)));
        assert_eq!(dir.changes(), 2);
        assert_eq!(cache.weight(), 4, "a stored name already there is replaced");
    }

    #[tokio::test(start_paused = true)]
    async fn a_patch_removes_and_adds_in_one_step() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        let dir = Locks::new().directory("d".to_string());
        let old = entry("Old", "so", false);
        let other = entry("Other", "sp", false);
        install(
            &cache,
            "d",
            Arc::new(snapshot(vec![old.clone(), other.clone()])),
        );

        cache.patch(&dir, Some(&old), Some(entry("New", "sn", true)));
        assert_eq!(dir.changes(), 1);
        assert_eq!(cache.weight(), 2);
        let names = cache.fresh("d").unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names.entry("old", "so"), None);
        assert!(names.directory("new", "sn").is_some());
        assert!(names.entry("other", "sp").is_some());
        drop(names);

        cache.patch(&dir, Some(&other), None);
        cache.patch(&dir, Some(&entry("New", "sn", true)), None);
        assert_eq!(dir.changes(), 3);
        assert_eq!(cache.fresh("d").unwrap().len(), 0);
        assert_eq!(cache.weight(), 1, "an empty directory weighs one name");
    }

    #[tokio::test(start_paused = true)]
    async fn forgetting_below_a_directory_drops_it_and_what_is_under_it_and_counts_a_change() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        let locks = Locks::new();
        let keys = ["a", "a\\b", "a\\b\\c", "ab", "b"];
        let held: Vec<_> = keys.map(|key| locks.directory(key.to_string())).into();
        for key in keys {
            install(&cache, key, many_names(2));
        }

        cache.forget_below("a", &locks.directories_below("a"));
        let mut kept = cache.keys();
        kept.sort();
        assert_eq!(kept, ["ab", "b"]);
        assert_eq!(cache.weight(), 4);
        let changes: Vec<_> = held.iter().map(|dir| dir.changes()).collect();
        assert_eq!(changes, [1, 1, 1, 0, 0]);

        cache.forget_below("zz", &[]);
        assert_eq!(cache.keys().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_patch_of_a_directory_nobody_cached_counts_a_change_and_holds_nothing() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        let dir = Locks::new().directory("d".to_string());
        cache.patch(&dir, None, Some(entry("a", "s1", false)));
        assert_eq!(dir.changes(), 1);
        assert!(cache.keys().is_empty());
        assert_eq!(cache.weight(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reader_keeps_the_snapshot_it_holds_through_a_patch() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        let dir = Locks::new().directory("d".to_string());
        install(&cache, "d", many_names(2));
        let held = cache.fresh("d").unwrap();

        cache.patch(&dir, None, Some(entry("a", "s1", false)));
        assert_eq!(held.len(), 2);
        assert_eq!(cache.fresh("d").unwrap().len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_patch_does_not_extend_the_time_to_live() {
        let ttl = Duration::from_secs(30);
        let cache = NameCache::new(ttl, 100);
        let dir = Locks::new().directory("d".to_string());
        install(&cache, "d", many_names(1));
        tokio::time::advance(Duration::from_secs(20)).await;
        cache.patch(&dir, None, Some(entry("a", "s1", false)));
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(cache.fresh("d").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_patch_that_passes_the_cap_drops_the_older_directories() {
        let cache = NameCache::new(Duration::from_secs(30), 10);
        let locks = Locks::new();
        let dir = locks.directory("b".to_string());
        install(&cache, "a", many_names(6));
        install(&cache, "b", many_names(4));
        assert_eq!(cache.keys(), ["a", "b"]);
        assert_eq!(cache.weight(), 10);

        cache.patch(&dir, None, Some(entry("x", "sx", false)));
        assert_eq!(cache.keys(), ["b"]);
        assert_eq!(cache.weight(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn a_snapshot_is_fresh_for_the_time_to_live() {
        let ttl = Duration::from_secs(30);
        let cache = NameCache::new(ttl, 100);
        install(&cache, "d", many_names(2));
        assert!(cache.fresh("d").is_some());
        tokio::time::advance(ttl - Duration::from_nanos(1)).await;
        assert!(cache.fresh("d").is_some());
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(cache.fresh("d").is_none());
        assert!(cache.keys().is_empty(), "a stale snapshot is dropped");
        assert_eq!(cache.weight(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_snapshot_dates_from_when_its_listing_began() {
        let ttl = Duration::from_secs(30);
        let cache = NameCache::new(ttl, 100);
        let began = Instant::now();
        tokio::time::advance(Duration::from_secs(20)).await;
        install(&cache, "d", Arc::new(Snapshot::new(Vec::new(), began)));
        assert!(cache.fresh("d").is_some());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(cache.fresh("d").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn an_install_that_is_not_wanted_changes_nothing() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        cache.install_if("a".to_string(), many_names(2), || false);
        assert!(cache.fresh("a").is_none());
        install(&cache, "a", many_names(2));
        cache.install_if("a".to_string(), many_names(5), || false);
        assert_eq!(cache.weight(), 2);
        assert_eq!(cache.fresh("a").unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn forgetting_a_directory_drops_it() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        install(&cache, "a", many_names(2));
        install(&cache, "b", many_names(3));
        cache.forget("a");
        cache.forget("zz");
        assert!(cache.fresh("a").is_none());
        assert!(cache.fresh("b").is_some());
        assert_eq!(cache.weight(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_directory_weighs_one_name() {
        let cache = NameCache::new(Duration::from_secs(30), 100);
        install(&cache, "a", many_names(0));
        assert_eq!(cache.weight(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_least_recently_used_directory_goes_first_at_the_cap() {
        let cache = NameCache::new(Duration::from_secs(30), 1_000);
        install(&cache, "a", many_names(400));
        install(&cache, "b", many_names(400));
        assert!(cache.fresh("a").is_some(), "a is the more recent now");
        install(&cache, "c", many_names(300));
        assert_eq!(cache.keys(), ["a", "c"]);
        assert_eq!(cache.weight(), 700);
        assert!(cache.fresh("b").is_none());

        install(&cache, "d", many_names(500));
        assert_eq!(cache.keys(), ["c", "d"], "only a, the oldest, goes");
        assert_eq!(cache.weight(), 800);
    }

    #[tokio::test(start_paused = true)]
    async fn a_directory_over_the_cap_is_kept_alone() {
        let cache = NameCache::new(Duration::from_secs(30), 1_000);
        install(&cache, "a", many_names(10));
        install(&cache, "b", many_names(10));
        install(&cache, "huge", many_names(1_500));
        assert_eq!(cache.keys(), ["huge"]);
        assert!(cache.fresh("huge").is_some(), "built, not dropped");

        install(&cache, "small", many_names(5));
        assert_eq!(cache.keys(), ["small"], "the next one makes room");
    }
}
