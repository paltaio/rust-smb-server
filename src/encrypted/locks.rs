//! The locks that order the operations of a backend and its clones.
//!
//! Order of acquisition: the tree lock, a directory lock, a file lock (on a
//! node), then the std mutexes of the tables, which are never held across an
//! await and never two at once.

use std::collections::HashMap;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Locks `m`, whether or not a thread panicked while holding it.
pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Awaits `acquire` on `lock` when there is one.
pub(super) async fn acquire_some<'a, L, F: Future>(
    lock: Option<&'a L>,
    acquire: impl FnOnce(&'a L) -> F,
) -> Option<F::Output> {
    match lock {
        Some(lock) => Some(acquire(lock).await),
        None => None,
    }
}

/// The tree lock and the directory locks.
pub(super) struct Locks {
    /// A rename holds it exclusively for the whole call. Opens and unlinks
    /// hold it shared.
    pub(super) tree: RwLock<()>,
    directories: Arc<DirTable>,
}

#[derive(Default)]
struct DirTable {
    entries: Mutex<HashMap<String, Weak<DirLock>>>,
}

/// The lock of one directory. An open that creates an entry and an unlink
/// hold it exclusively; an open of an existing entry holds it shared.
pub(super) struct DirLock {
    key: String,
    table: Arc<DirTable>,
    lock: RwLock<()>,
}

/// A directory lock, held until dropped.
pub(super) enum DirGuard<'a> {
    Shared { _held: RwLockReadGuard<'a, ()> },
    Exclusive { _held: RwLockWriteGuard<'a, ()> },
}

impl Locks {
    pub(super) fn new() -> Self {
        Self {
            tree: RwLock::new(()),
            directories: Arc::default(),
        }
    }

    /// The lock of the directory `key`. All callers that ask for one key
    /// while it is in use get the same lock; one that nobody holds is
    /// dropped.
    pub(super) fn directory(&self, key: String) -> Arc<DirLock> {
        let mut entries = lock(&self.directories.entries);
        if let Some(dir) = entries.get(&key).and_then(Weak::upgrade) {
            return dir;
        }
        let dir = Arc::new(DirLock {
            key: key.clone(),
            table: Arc::clone(&self.directories),
            lock: RwLock::new(()),
        });
        entries.insert(key, Arc::downgrade(&dir));
        dir
    }

    /// Directory locks in use.
    #[cfg(test)]
    pub(super) fn directory_count(&self) -> usize {
        lock(&self.directories.entries).len()
    }
}

impl DirLock {
    /// Waits for the lock, exclusive when `exclusive`.
    pub(super) async fn acquire(&self, exclusive: bool) -> DirGuard<'_> {
        if exclusive {
            DirGuard::Exclusive {
                _held: self.lock.write().await,
            }
        } else {
            DirGuard::Shared {
                _held: self.lock.read().await,
            }
        }
    }

    /// No one holds the lock.
    #[cfg(test)]
    pub(super) fn is_free(&self) -> bool {
        self.lock.try_write().is_ok()
    }

    /// Someone holds the lock exclusively, or waits for it.
    #[cfg(test)]
    pub(super) fn is_exclusive(&self) -> bool {
        self.lock.try_read().is_err()
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let mut entries = lock(&self.table.entries);
        if entries
            .get(&self.key)
            .is_some_and(|entry| ptr::eq(entry.as_ptr(), self))
        {
            entries.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_key_is_one_lock_while_it_is_in_use() {
        let locks = Locks::new();
        let first = locks.directory("a".to_string());
        let again = locks.directory("a".to_string());
        let other = locks.directory("b".to_string());
        assert!(Arc::ptr_eq(&first, &again));
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(locks.directory_count(), 2);
    }

    #[tokio::test]
    async fn a_lock_nobody_holds_leaves_the_table() {
        let locks = Locks::new();
        let first = locks.directory("a".to_string());
        let again = locks.directory("a".to_string());
        drop(first);
        assert_eq!(locks.directory_count(), 1);
        drop(again);
        assert_eq!(locks.directory_count(), 0);
    }

    #[tokio::test]
    async fn shared_holders_share_and_an_exclusive_holder_is_alone() {
        let locks = Locks::new();
        let dir = locks.directory(String::new());
        assert!(dir.is_free() && !dir.is_exclusive());
        let first = dir.acquire(false).await;
        let second = dir.acquire(false).await;
        assert!(!dir.is_free() && !dir.is_exclusive());
        drop((first, second));
        let exclusive = dir.acquire(true).await;
        assert!(!dir.is_free() && dir.is_exclusive());
        drop(exclusive);
        assert!(dir.is_free());
    }
}
