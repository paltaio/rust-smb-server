//! The entries and tombstones of a backend: its view of the paths whose
//! state differs from the bucket's, or may.
//!
//! Lock order: the index of the [`Overlay`], then the state of one
//! [`Entry`], then the locks of the read-ahead chunks. The metadata cache
//! lock is never taken while any of them is held. None is held across an
//! await or around disk or network I/O.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use super::entry::Entry;
use super::keys::{dir_prefix, slot};
use super::lookup::Found;
use super::readahead::ReadAhead;
use super::record::TombstoneRecord;

#[derive(Default)]
struct Index {
    /// The entries by key, folded when names ignore case.
    entries: BTreeMap<String, Arc<Entry>>,
    /// The keys to delete from the bucket, as the index spells them.
    tombstones: HashSet<String>,
}

/// The entries below a directory.
#[derive(Default)]
pub(super) struct Below {
    /// Entries named in the directory itself.
    pub(super) direct: Vec<Arc<Entry>>,
    /// Names of directories that only entries below them imply.
    pub(super) implied: Vec<String>,
}

pub(super) struct Overlay {
    fold: bool,
    index: Mutex<Index>,
}

/// A hold on an entry. The entry stays in the overlay while a hold is on it,
/// and leaves with the last one if it has nothing to keep.
pub(super) struct Held {
    overlay: Arc<Overlay>,
    pub(super) entry: Arc<Entry>,
}

impl Held {
    /// Another hold on the entry, for a task that acts for this one.
    pub(super) fn another(&self) -> Held {
        self.entry.state().handles += 1;
        Held {
            overlay: Arc::clone(&self.overlay),
            entry: Arc::clone(&self.entry),
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.overlay.release(&self.entry);
    }
}

impl Overlay {
    /// An overlay whose names match without regard to case when
    /// `case_insensitive`.
    pub(super) fn new(case_insensitive: bool) -> Arc<Overlay> {
        Arc::new(Overlay {
            fold: case_insensitive,
            index: Mutex::new(Index::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `key` as the index spells it.
    pub(super) fn slot(&self, key: &str) -> String {
        slot(key, self.fold)
    }

    /// The index prefix of the keys below the directory `key`, and how many
    /// names `key` has.
    fn below_bounds(&self, key: &str) -> (String, usize) {
        let depth = if key.is_empty() {
            0
        } else {
            key.split('/').count()
        };
        (self.slot(&dir_prefix(key)), depth)
    }

    fn held(self: &Arc<Self>, entry: Arc<Entry>) -> Held {
        Held {
            overlay: Arc::clone(self),
            entry,
        }
    }

    /// A hold on the entry for `key` if it holds something that is not in
    /// the bucket.
    pub(super) fn take_pending(self: &Arc<Self>, key: &str) -> Option<Held> {
        let slot = self.slot(key);
        let index = self.lock();
        let entry = Arc::clone(index.entries.get(&slot)?);
        let mut state = entry.state();
        if !state.pending() {
            return None;
        }
        state.handles += 1;
        drop(state);
        Some(self.held(entry))
    }

    /// The entry for `key`, if there is one that holds something that is not
    /// in the bucket.
    pub(super) fn peek(&self, key: &str) -> Option<Arc<Entry>> {
        let entry = self.lock().entries.get(&self.slot(key)).cloned()?;
        let pending = entry.state().pending();
        pending.then_some(entry)
    }

    /// A hold on the entry for what a lookup found. An entry for the name
    /// that has nothing to keep follows the lookup; one that has is kept as
    /// it is.
    pub(super) fn take_found(self: &Arc<Self>, found: Found, ahead: &Arc<ReadAhead>) -> Held {
        let (key, is_dir) = match &found {
            Found::File(file) => (file.key.clone(), false),
            Found::Dir(dir) => (dir.key.clone(), true),
        };
        let slot = self.slot(&key);
        let mut index = self.lock();
        if let Some(entry) = index.entries.get(&slot).cloned() {
            let mut state = entry.state();
            if state.pending() || entry.is_dir() == is_dir {
                if !state.pending() {
                    state.follow(found, ahead);
                }
                state.handles += 1;
                drop(state);
                return self.held(entry);
            }
            // What was a file is a directory, or the other way round. Handles
            // that stay open on it can change nothing.
            state.detached = state.handles > 0;
            drop(state);
            index.entries.remove(&slot);
        }
        let entry = Entry::found(found, ahead);
        entry.state().handles = 1;
        index.entries.insert(slot, Arc::clone(&entry));
        self.held(entry)
    }

    /// Puts `entry` in the overlay with a hold on it, unless an entry for
    /// the name is there. Looking and putting are one step, so two creates of
    /// one name never both succeed. A key to delete from the bucket may be
    /// there still, so the entry's key may exist.
    pub(super) fn insert_new(self: &Arc<Self>, entry: Arc<Entry>) -> Option<Held> {
        let slot = self.slot(&entry.state().key);
        let mut index = self.lock();
        if index.entries.contains_key(&slot) {
            return None;
        }
        {
            let mut state = entry.state();
            state.handles = 1;
            state.may_exist |= index.tombstones.contains(&slot);
        }
        index.entries.insert(slot, Arc::clone(&entry));
        Some(self.held(entry))
    }

    /// Ends one hold on `entry`.
    fn release(&self, entry: &Arc<Entry>) {
        let mut index = self.lock();
        let mut state = entry.state();
        state.handles = state.handles.saturating_sub(1);
        state.changed = Instant::now();
        if state.handles == 0 && !state.pending() {
            let slot = self.slot(&state.key);
            drop(state);
            if index
                .entries
                .get(&slot)
                .is_some_and(|held| Arc::ptr_eq(held, entry))
            {
                index.entries.remove(&slot);
            }
        }
    }

    /// The spelling of the directory `key` in the keys of the entries below
    /// it that hold something that is not in the bucket, if there are any.
    pub(super) fn spelling(&self, key: &str) -> Option<String> {
        let (prefix, depth) = self.below_bounds(key);
        let index = self.lock();
        index
            .entries
            .range(prefix.clone()..)
            .take_while(|(slot, _)| slot.starts_with(&prefix))
            .find_map(|(_, entry)| {
                let state = entry.state();
                state.pending().then(|| {
                    state
                        .key
                        .split('/')
                        .take(depth)
                        .collect::<Vec<_>>()
                        .join("/")
                })
            })
    }

    /// The entries below the directory `key` that hold something that is not
    /// in the bucket.
    pub(super) fn below(&self, key: &str) -> Below {
        let (prefix, depth) = self.below_bounds(key);
        let entries: Vec<Arc<Entry>> = {
            let index = self.lock();
            index
                .entries
                .range(prefix.clone()..)
                .take_while(|(slot, _)| slot.starts_with(&prefix))
                .map(|(_, entry)| Arc::clone(entry))
                .collect()
        };
        let mut below = Below::default();
        for entry in entries {
            let (key, pending) = {
                let state = entry.state();
                (state.key.clone(), state.pending())
            };
            if !pending {
                continue;
            }
            let mut names = key.split('/').skip(depth);
            let Some(name) = names.next() else {
                continue;
            };
            if names.next().is_none() {
                below.direct.push(entry);
            } else if !below.implied.iter().any(|seen| self.same(seen, name)) {
                below.implied.push(name.to_owned());
            }
        }
        below
    }

    /// Whether two names are one name.
    pub(super) fn same(&self, a: &str, b: &str) -> bool {
        self.slot(a) == self.slot(b)
    }

    /// Whether the key `key` is to be deleted from the bucket.
    pub(super) fn tombstoned(&self, key: &str) -> bool {
        self.lock().tombstones.contains(&self.slot(key))
    }

    /// Puts what was read from the cache directory in the overlay, which has
    /// no two entries of one name. Returns how many entries it put.
    pub(super) fn install(
        &self,
        entries: Vec<Arc<Entry>>,
        tombstones: Vec<TombstoneRecord>,
    ) -> usize {
        let mut index = self.lock();
        let count = entries.len();
        for entry in entries {
            let slot = self.slot(&entry.state().key);
            let taken = index.entries.insert(slot, entry);
            debug_assert!(taken.is_none(), "two recovered entries have one name");
        }
        for tombstone in tombstones {
            index
                .tombstones
                .extend(tombstone.keys.iter().map(|key| self.slot(key)));
        }
        count
    }

    /// The entries held.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.lock().entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::entry::State;
    use crate::s3::lookup::DirRef;
    use crate::s3::record::RecordId;

    fn plain(key: &str) -> Arc<Entry> {
        Entry::from_state(State::new(key.to_owned(), false))
    }

    fn dir(key: &str) -> Arc<Entry> {
        Entry::created_dir(key.to_owned(), 1)
    }

    fn kept(key: &str) -> Arc<Entry> {
        let entry = plain(key);
        entry.state().recorded = true;
        entry
    }

    fn keys(entries: &[Arc<Entry>]) -> Vec<String> {
        let mut keys: Vec<String> = entries.iter().map(|e| e.state().key.clone()).collect();
        keys.sort();
        keys
    }

    #[test]
    fn two_inserts_of_one_name_never_both_succeed() {
        let overlay = Overlay::new(false);
        let first = overlay.insert_new(plain("a"));
        assert!(first.is_some());
        assert!(overlay.insert_new(plain("a")).is_none());
        let upper = overlay.insert_new(plain("A"));
        assert!(upper.is_some());
        assert_eq!(overlay.len(), 2);
    }

    #[test]
    fn names_that_differ_in_case_are_one_name_when_case_is_ignored() {
        let overlay = Overlay::new(true);
        let held = overlay.insert_new(kept("Dir/File.TXT")).unwrap();
        assert!(overlay.insert_new(plain("dir/file.txt")).is_none());
        let found = overlay.take_pending("DIR/FILE.txt").unwrap();
        assert!(Arc::ptr_eq(&found.entry, &held.entry));
        assert_eq!(found.entry.state().key, "Dir/File.TXT");
        assert!(overlay.take_pending("dir/other").is_none());
    }

    #[test]
    fn names_that_differ_in_case_are_two_names_when_case_counts() {
        let overlay = Overlay::new(false);
        let _held = overlay.insert_new(kept("a")).unwrap();
        assert!(overlay.peek("A").is_none());
        assert!(overlay.peek("a").is_some());
    }

    #[test]
    fn the_last_release_drops_an_entry_with_nothing_to_keep() {
        let overlay = Overlay::new(false);
        let first = overlay.insert_new(plain("f")).unwrap();
        let second = first.another();
        assert_eq!(first.entry.state().handles, 2);
        drop(first);
        assert_eq!(overlay.len(), 1);
        drop(second);
        assert_eq!(overlay.len(), 0);
        assert!(overlay.peek("f").is_none());
    }

    #[test]
    fn an_entry_with_something_to_keep_stays_after_its_last_release() {
        let overlay = Overlay::new(false);
        drop(overlay.insert_new(kept("f")).unwrap());
        assert_eq!(overlay.len(), 1);
        let held = overlay.take_pending("f").unwrap();
        assert_eq!(held.entry.state().handles, 1);

        drop(overlay.insert_new(dir("g")).unwrap());
        assert_eq!(overlay.len(), 2);
    }

    #[test]
    fn entries_with_nothing_to_keep_do_not_count_as_below_a_directory() {
        let overlay = Overlay::new(false);
        let _held = overlay.insert_new(plain("d/f")).unwrap();
        assert_eq!(overlay.spelling("d"), None);
        let _kept = overlay.insert_new(kept("d/g")).unwrap();
        assert_eq!(overlay.spelling("d").as_deref(), Some("d"));
    }

    #[test]
    fn an_entry_with_nothing_to_keep_is_not_taken_as_pending() {
        let overlay = Overlay::new(false);
        let held = overlay.insert_new(plain("f")).unwrap();
        assert!(overlay.take_pending("f").is_none());
        drop(held);
    }

    #[test]
    fn a_release_changes_the_time_of_the_last_change() {
        let overlay = Overlay::new(false);
        let held = overlay.insert_new(kept("f")).unwrap();
        let entry = Arc::clone(&held.entry);
        let before = entry.state().changed;
        std::thread::sleep(std::time::Duration::from_millis(2));
        drop(held);
        assert!(entry.state().changed > before);
    }

    #[test]
    fn a_release_of_an_entry_another_took_the_place_of_leaves_that_one() {
        let overlay = Overlay::new(false);
        let old = overlay.insert_new(plain("f")).unwrap();
        overlay.lock().entries.clear();
        let new = overlay.insert_new(plain("f")).unwrap();
        drop(old);
        assert_eq!(overlay.len(), 1);
        let held = Arc::clone(overlay.lock().entries.get("f").unwrap());
        assert!(Arc::ptr_eq(&held, &new.entry));
    }

    #[test]
    fn entries_below_a_directory_are_direct_or_imply_a_directory() {
        let overlay = Overlay::new(false);
        let entries = vec![
            kept("p/a.txt"),
            kept("p/sub/b.txt"),
            kept("p/sub/deep/c.txt"),
            kept("p/other/d.txt"),
            dir("p/made"),
            kept("p2/x"),
            kept("q"),
            dir("p"),
            plain("p/clean"),
            plain("p/clean_dir/x"),
        ];
        assert_eq!(overlay.install(entries, Vec::new()), 10);
        let below = overlay.below("p");
        assert_eq!(keys(&below.direct), ["p/a.txt", "p/made"]);
        let mut implied = below.implied;
        implied.sort();
        assert_eq!(implied, ["other", "sub"]);

        let sub = overlay.below("p/sub");
        assert_eq!(keys(&sub.direct), ["p/sub/b.txt"]);
        assert_eq!(sub.implied, ["deep"]);

        let root = overlay.below("");
        assert_eq!(keys(&root.direct), ["p", "q"]);
        let mut implied = root.implied;
        implied.sort();
        assert_eq!(implied, ["p", "p2"]);
        assert!(overlay.below("nothing").direct.is_empty());
    }

    #[test]
    fn a_directory_is_spelled_as_the_entries_below_it_spell_it() {
        let overlay = Overlay::new(true);
        overlay.install(vec![kept("Up/Down/c.txt"), dir("Up")], Vec::new());
        assert_eq!(overlay.spelling("up").as_deref(), Some("Up"));
        assert_eq!(overlay.spelling("UP/down").as_deref(), Some("Up/Down"));
        assert_eq!(overlay.spelling("up/down/c.txt"), None);
        assert_eq!(overlay.spelling("upp"), None);
        assert_eq!(overlay.spelling("").as_deref(), Some(""));
        let below = overlay.below("up");
        assert_eq!(below.implied, ["Down"]);
    }

    #[test]
    fn implied_names_that_differ_in_case_count_once() {
        let overlay = Overlay::new(true);
        overlay.install(vec![kept("p/Sub/a"), kept("p/sub/b")], Vec::new());
        let below = overlay.below("p");
        assert_eq!(below.implied.len(), 1);
    }

    fn tombstone(keys: &[&str]) -> TombstoneRecord {
        TombstoneRecord {
            id: RecordId::parse(&"0".repeat(32)).unwrap(),
            keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        }
    }

    #[test]
    fn tombstones_are_found_by_key_as_the_names_compare() {
        let overlay = Overlay::new(true);
        overlay.install(Vec::new(), vec![tombstone(&["Gone/x", "other"])]);
        assert!(overlay.tombstoned("gone/X"));
        assert!(overlay.tombstoned("OTHER"));
        assert!(!overlay.tombstoned("gone"));
        let exact = Overlay::new(false);
        exact.install(Vec::new(), vec![tombstone(&["Gone/x"])]);
        assert!(exact.tombstoned("Gone/x"));
        assert!(!exact.tombstoned("gone/x"));
    }

    #[test]
    fn a_new_entry_at_a_key_to_delete_may_exist_in_the_bucket() {
        let overlay = Overlay::new(false);
        overlay.install(Vec::new(), vec![tombstone(&["gone"])]);
        let over = overlay.insert_new(plain("gone")).unwrap();
        assert!(over.entry.state().may_exist);
        let fresh = overlay.insert_new(plain("fresh")).unwrap();
        assert!(!fresh.entry.state().may_exist);
    }

    #[test]
    fn an_entry_that_a_lookup_of_another_kind_replaces_is_detached_while_held() {
        let overlay = Overlay::new(false);
        let held = overlay.insert_new(plain("x")).unwrap();
        let ahead = Arc::new(ReadAhead::new());
        let dir = Found::Dir(DirRef {
            key: "x".to_owned(),
            name: "x".to_owned(),
            marker: None,
        });
        let new = overlay.take_found(dir, &ahead);
        assert!(!Arc::ptr_eq(&held.entry, &new.entry));
        assert!(held.entry.state().detached);
        assert!(held.entry.state().attached().is_err());
        assert!(!new.entry.state().detached);
        drop(held);
        assert_eq!(overlay.len(), 1);
    }
}
