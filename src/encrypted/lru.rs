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
        let slot = self.slots.get_mut(key)?;
        self.clock += 1;
        if let Some(key) = self.order.remove(&slot.used) {
            self.order.insert(self.clock, key);
        }
        slot.used = self.clock;
        Some(slot.value.clone())
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
}
