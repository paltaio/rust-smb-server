//! A map with a weight limit that drops its least recently used entries
//! first.

use std::collections::{BTreeMap, HashMap};

struct Slot<V> {
    value: V,
    weight: usize,
    /// The tick of the last use, which is the entry's key in `order`.
    used: u64,
}

/// Entries by key, each with a weight. Inserting past the limit drops the
/// least recently used entries until the total fits, or only the new entry
/// is left: an entry heavier than the limit is kept alone.
pub(super) struct Lru<V> {
    limit: usize,
    weight: usize,
    clock: u64,
    slots: HashMap<String, Slot<V>>,
    /// Keys by tick of last use, oldest first.
    order: BTreeMap<u64, String>,
}

impl<V: Clone> Lru<V> {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            weight: 0,
            clock: 0,
            slots: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    /// The value at `key`, which becomes the most recently used entry.
    pub(super) fn get(&mut self, key: &str) -> Option<V> {
        self.touch(key).map(|slot| slot.value.clone())
    }

    /// The slot at `key`, which becomes the most recently used entry.
    fn touch(&mut self, key: &str) -> Option<&mut Slot<V>> {
        let slot = self.slots.get_mut(key)?;
        self.clock += 1;
        if let Some(key) = self.order.remove(&slot.used) {
            self.order.insert(self.clock, key);
        }
        slot.used = self.clock;
        Some(slot)
    }

    /// Stores `value` at `key` as the most recently used entry, replacing
    /// the value there.
    pub(super) fn insert(&mut self, key: String, value: V, weight: usize) {
        self.remove(&key);
        self.clock += 1;
        self.weight += weight;
        self.order.insert(self.clock, key.clone());
        self.slots.insert(
            key,
            Slot {
                value,
                weight,
                used: self.clock,
            },
        );
        self.evict();
    }

    /// Changes the value at `key` in place. `change` returns the entry's new
    /// weight. The entry becomes the most recently used one, and older entries
    /// go as for an insert. Returns false when `key` holds nothing.
    pub(super) fn modify(&mut self, key: &str, change: impl FnOnce(&mut V) -> usize) -> bool {
        let Some(slot) = self.touch(key) else {
            return false;
        };
        let weight = change(&mut slot.value);
        let before = slot.weight;
        slot.weight = weight;
        self.weight = self.weight - before + weight;
        self.evict();
        true
    }

    /// Drops the least recently used entries until the total fits, or one
    /// entry is left.
    fn evict(&mut self) {
        while self.weight > self.limit && self.order.len() > 1 {
            let (_, oldest) = self.order.pop_first().expect("more than one key is held");
            let slot = self.slots.remove(&oldest).expect("every key has a slot");
            self.weight -= slot.weight;
        }
    }

    pub(super) fn remove(&mut self, key: &str) {
        if let Some(slot) = self.slots.remove(key) {
            self.order.remove(&slot.used);
            self.weight -= slot.weight;
        }
    }

    /// Drops the entries whose key `matches` accepts.
    pub(super) fn remove_where(&mut self, matches: impl Fn(&str) -> bool) {
        let keys: Vec<String> = self
            .slots
            .keys()
            .filter(|key| matches(key))
            .cloned()
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.slots.len()
    }

    #[cfg(test)]
    pub(super) fn weight(&self) -> usize {
        self.weight
    }

    /// The keys, least recently used first.
    #[cfg(test)]
    pub(super) fn keys(&self) -> Vec<String> {
        self.order.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lru(limit: usize) -> Lru<u32> {
        Lru::new(limit)
    }

    #[test]
    fn the_least_recently_used_entry_goes_first() {
        let mut cache = lru(3);
        for (key, value) in [("a", 1), ("b", 2), ("c", 3)] {
            cache.insert(key.to_string(), value, 1);
        }
        assert_eq!(cache.get("a"), Some(1));
        cache.insert("d".to_string(), 4, 1);
        assert_eq!(cache.get("b"), None, "b was the oldest after a was used");
        assert_eq!(cache.keys(), ["c", "a", "d"]);
        assert_eq!((cache.len(), cache.weight()), (3, 3));
    }

    #[test]
    fn an_insert_replaces_the_value_and_the_weight() {
        let mut cache = lru(10);
        cache.insert("a".to_string(), 1, 4);
        cache.insert("b".to_string(), 2, 3);
        cache.insert("a".to_string(), 9, 2);
        assert_eq!(cache.get("a"), Some(9));
        assert_eq!((cache.len(), cache.weight()), (2, 5));
        assert_eq!(cache.keys(), ["b", "a"]);
    }

    #[test]
    fn an_entry_heavier_than_the_limit_is_kept_alone() {
        let mut cache = lru(10);
        cache.insert("a".to_string(), 1, 4);
        cache.insert("b".to_string(), 2, 4);
        cache.insert("big".to_string(), 3, 25);
        assert_eq!(cache.keys(), ["big"]);
        assert_eq!(cache.weight(), 25);

        cache.insert("c".to_string(), 4, 1);
        assert_eq!(cache.keys(), ["c"], "the next entry pushes it out");
        assert_eq!(cache.weight(), 1);
    }

    #[test]
    fn a_change_in_place_updates_the_value_the_weight_and_the_recency() {
        let mut cache = lru(10);
        cache.insert("a".to_string(), 1, 4);
        cache.insert("b".to_string(), 2, 4);
        assert!(cache.modify("a", |value| {
            *value = 7;
            5
        }));
        assert_eq!(cache.get("a"), Some(7));
        assert_eq!((cache.len(), cache.weight()), (2, 9));
        assert_eq!(cache.keys(), ["b", "a"], "a change is a use");
        assert!(!cache.modify("missing", |_| 1));
        assert_eq!(cache.weight(), 9);
    }

    #[test]
    fn a_change_that_overflows_the_limit_drops_older_entries_and_never_the_changed_one() {
        let mut cache = lru(10);
        cache.insert("a".to_string(), 1, 4);
        cache.insert("b".to_string(), 2, 4);
        cache.insert("c".to_string(), 3, 2);
        cache.modify("b", |_| 5);
        assert_eq!(cache.keys(), ["c", "b"]);
        assert_eq!(cache.weight(), 7);

        cache.modify("b", |_| 25);
        assert_eq!(cache.keys(), ["b"], "kept alone over the limit");
        assert_eq!(cache.weight(), 25);
        cache.modify("b", |_| 3);
        assert_eq!(cache.weight(), 3);
    }

    #[test]
    fn removing_an_entry_frees_its_weight() {
        let mut cache = lru(10);
        cache.insert("a".to_string(), 1, 4);
        cache.insert("b".to_string(), 2, 4);
        cache.remove("a");
        cache.remove("missing");
        assert_eq!((cache.len(), cache.weight()), (1, 4));
        cache.insert("c".to_string(), 3, 6);
        assert_eq!(cache.keys(), ["b", "c"]);
    }

    #[test]
    fn entries_that_match_are_dropped_with_their_weight() {
        let mut cache = lru(100);
        for (key, weight) in [("a", 1), ("ab", 2), ("b", 4), ("abc", 8)] {
            cache.insert(key.to_string(), 0, weight);
        }
        cache.remove_where(|key| key.starts_with('a'));
        assert_eq!(cache.keys(), ["b"]);
        assert_eq!((cache.len(), cache.weight()), (1, 4));
        cache.remove_where(|_| false);
        assert_eq!(cache.len(), 1);
    }
}
