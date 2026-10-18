//! Opens of each file on a share, across every connection, keyed by file
//! identity. This holds the state MS-FSA keeps per file rather than per
//! open: sharing modes (2.1.5.1.2.2), the delete-pending flag (2.1.5.15.3)
//! and byte-range locks (2.1.5.8).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tracing::{debug, warn};

use crate::access_mask::{DELETE, FILE_APPEND_DATA, FILE_EXECUTE, FILE_READ_DATA, FILE_WRITE_DATA};
use crate::backend::FileInfo;
use crate::error::SmbError;
use crate::ntstatus;
use crate::path::{SmbPath, rebase, same_path};
use crate::server::ShareBindings;

// ShareAccess (MS-SMB2 2.2.13)
pub(crate) const FILE_SHARE_READ: u32 = 0x0000_0001;
pub(crate) const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub(crate) const FILE_SHARE_DELETE: u32 = 0x0000_0004;

const READ_ACCESS: u32 = FILE_READ_DATA | FILE_EXECUTE;
const WRITE_ACCESS: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA;
/// Access that takes part in the sharing check. An open holding none of
/// these never conflicts.
const SHARED_ACCESS: u32 = READ_ACCESS | WRITE_ACCESS | DELETE;

/// Identity of a file in a [`FileTable`]: the backend's file id, or the
/// path when the backend reports none.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FileKey {
    Index(u64),
    Path(String),
}

impl FileKey {
    fn new(file_index: u64, path: &SmbPath, case_sensitive: bool) -> Self {
        if file_index != 0 {
            Self::Index(file_index)
        } else {
            Self::Path(path_key(path, case_sensitive))
        }
    }
}

fn path_key(path: &SmbPath, case_sensitive: bool) -> String {
    let joined = path.display_backslash();
    if case_sensitive {
        joined
    } else {
        joined.to_lowercase()
    }
}

/// Access and sharing mode of an open, as CREATE requested them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sharing {
    /// Open.GrantedAccess.
    pub access: u32,
    /// ShareAccess of the CREATE request.
    pub share: u32,
}

impl Sharing {
    /// True if this open and `other` cannot both be open on one file.
    fn conflicts_with(self, other: Sharing) -> bool {
        let denies = |access: u32, share: u32| {
            (access & READ_ACCESS != 0 && share & FILE_SHARE_READ == 0)
                || (access & WRITE_ACCESS != 0 && share & FILE_SHARE_WRITE == 0)
                || (access & DELETE != 0 && share & FILE_SHARE_DELETE == 0)
        };
        self.access & SHARED_ACCESS != 0
            && other.access & SHARED_ACCESS != 0
            && (denies(self.access, other.share) || denies(other.access, self.share))
    }
}

/// Every file on one share that has an open.
#[derive(Default)]
pub(crate) struct FileTable {
    files: Mutex<HashMap<FileKey, Arc<FileNode>>>,
    next_open: AtomicU64,
    renames: tokio::sync::Mutex<()>,
}

struct FileNode {
    state: Mutex<FileState>,
}

struct FileState {
    key: FileKey,
    opens: Vec<OpenEntry>,
    /// The name to remove once the last open closes, while the file is
    /// delete-pending.
    delete_pending: Option<SmbPath>,
    locks: Vec<RangeLock>,
}

struct OpenEntry {
    id: u64,
    sharing: Sharing,
    path: SmbPath,
}

#[derive(Debug, Clone, Copy)]
struct RangeLock {
    owner: u64,
    offset: u64,
    length: u64,
    exclusive: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FileNode {
    fn state(&self) -> MutexGuard<'_, FileState> {
        lock(&self.state)
    }
}

impl FileState {
    /// MS-FSA 2.1.5.1: a delete-pending file opens for nobody; otherwise the
    /// sharing check of 2.1.5.1.2.2 runs against every open on the file.
    fn admit(&self, sharing: Sharing) -> Result<(), u32> {
        if self.delete_pending.is_some() {
            return Err(ntstatus::STATUS_DELETE_PENDING);
        }
        if self.opens.iter().any(|e| e.sharing.conflicts_with(sharing)) {
            return Err(ntstatus::STATUS_SHARING_VIOLATION);
        }
        Ok(())
    }

    fn entry(&self, id: u64) -> Option<&OpenEntry> {
        self.opens.iter().find(|e| e.id == id)
    }

    /// MS-FSA 2.1.4.10: whether the range conflicts with a lock. `exclusive`
    /// is the intent of the access (a write, or an exclusive lock) and
    /// `lock_intent` tells a lock request from a read or write.
    fn range_conflicts(
        &self,
        owner: u64,
        offset: u64,
        length: u64,
        exclusive: bool,
        lock_intent: bool,
    ) -> bool {
        if offset == 0 && length == 0 {
            return false;
        }
        self.locks.iter().any(|l| {
            overlaps(l.offset, l.length, offset, length)
                && if l.exclusive {
                    l.owner != owner || (exclusive && lock_intent)
                } else {
                    exclusive
                }
        })
    }
}

/// Offset of the last byte of a range. A zero-length range ends just before
/// its offset.
fn last_byte(offset: u64, length: u64) -> u64 {
    if length == 0 {
        offset.wrapping_sub(1)
    } else {
        offset.saturating_add(length - 1)
    }
}

fn overlaps(a_offset: u64, a_length: u64, b_offset: u64, b_length: u64) -> bool {
    if (a_offset == 0 && a_length == 0) || (b_offset == 0 && b_length == 0) {
        return false;
    }
    a_offset <= last_byte(b_offset, b_length) && last_byte(a_offset, a_length) >= b_offset
}

impl FileTable {
    fn files(&self) -> MutexGuard<'_, HashMap<FileKey, Arc<FileNode>>> {
        lock(&self.files)
    }

    /// Serializes renames on the share: a rename holds this while it checks
    /// the target, renames in the backend and moves the open names.
    pub(crate) async fn rename_lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.renames.lock().await
    }

    /// True if an open on the share currently has `path` as its name.
    pub(crate) fn path_is_open(&self, path: &SmbPath, case_sensitive: bool) -> bool {
        self.files().values().any(|node| {
            node.state()
                .opens
                .iter()
                .any(|e| same_path(&e.path, path, case_sensitive))
        })
    }

    /// True if the file named `path` is delete-pending.
    pub(crate) fn delete_pending_at(&self, path: &SmbPath, case_sensitive: bool) -> bool {
        self.files().values().any(|node| {
            let state = node.state();
            state.delete_pending.as_ref().is_some_and(|pending| {
                same_path(pending, path, case_sensitive)
                    || state
                        .opens
                        .iter()
                        .any(|e| same_path(&e.path, path, case_sensitive))
            })
        })
    }

    /// Moves every open whose name is `from`, or lies below it, to the
    /// matching name under `to`.
    pub(crate) fn rename_paths(&self, from: &SmbPath, to: &SmbPath, case_sensitive: bool) {
        let mut files = self.files();
        let mut rekeyed = Vec::new();
        for node in files.values() {
            let mut state = node.state();
            for entry in &mut state.opens {
                if let Some(path) = rebase(&entry.path, from, to, case_sensitive) {
                    entry.path = path;
                }
            }
            if let Some(path) = state
                .delete_pending
                .as_ref()
                .and_then(|p| rebase(p, from, to, case_sensitive))
            {
                state.delete_pending = Some(path);
            }
            if matches!(state.key, FileKey::Path(_))
                && let Some(entry) = state.opens.first()
            {
                let key = FileKey::Path(path_key(&entry.path, case_sensitive));
                if key != state.key {
                    rekeyed.push((state.key.clone(), key));
                }
            }
        }
        for (old, new) in rekeyed {
            if files.contains_key(&new) {
                continue;
            }
            if let Some(node) = files.remove(&old) {
                node.state().key = new.clone();
                files.insert(new, node);
            }
        }
    }
}

/// One open's entry in its share's [`FileTable`]. Dropping it removes the
/// entry and its locks; [`FileRef::release`] does the same and hands back a
/// delete still to be done.
pub(crate) struct FileRef {
    share: Arc<ShareBindings>,
    node: Arc<FileNode>,
    id: u64,
    released: bool,
}

impl FileRef {
    /// Adds an open with `sharing` of the file `info` describes, reached
    /// through `path`. Fails with STATUS_DELETE_PENDING or
    /// STATUS_SHARING_VIOLATION when the opens already on the file do not
    /// allow it.
    pub(crate) fn register(
        share: &Arc<ShareBindings>,
        info: &FileInfo,
        path: &SmbPath,
        sharing: Sharing,
    ) -> Result<Self, u32> {
        let case_sensitive = share.backend.capabilities().case_sensitive;
        let key = FileKey::new(info.file_index, path, case_sensitive);
        let table = &share.files;
        let mut files = table.files();
        let node = files
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(FileNode {
                    state: Mutex::new(FileState {
                        key,
                        opens: Vec::new(),
                        delete_pending: None,
                        locks: Vec::new(),
                    }),
                })
            })
            .clone();
        let mut state = node.state();
        state.admit(sharing)?;
        let id = table.next_open.fetch_add(1, Ordering::Relaxed);
        state.opens.push(OpenEntry {
            id,
            sharing,
            path: path.clone(),
        });
        drop(state);
        Ok(Self {
            share: Arc::clone(share),
            node,
            id,
            released: false,
        })
    }

    /// The open's current name.
    pub(crate) fn path(&self) -> SmbPath {
        self.node
            .state()
            .entry(self.id)
            .map(|e| e.path.clone())
            .unwrap_or_default()
    }

    /// True if this is an entry for the file `info` describes, reached
    /// through `path`.
    pub(crate) fn is_for(&self, info: &FileInfo, path: &SmbPath) -> bool {
        let case_sensitive = self.share.backend.capabilities().case_sensitive;
        FileKey::new(info.file_index, path, case_sensitive) == self.node.state().key
    }

    /// Whether the file is delete-pending (MS-FSA Link.IsDeleted).
    pub(crate) fn delete_pending(&self) -> bool {
        self.node.state().delete_pending.is_some()
    }

    /// Sets or clears the delete-pending flag of the file (MS-FSA
    /// 2.1.5.15.3). The file is removed under this open's name when its last
    /// open closes.
    pub(crate) fn set_delete_pending(&self, delete: bool) {
        let mut state = self.node.state();
        state.delete_pending = if delete {
            state.entry(self.id).map(|e| e.path.clone())
        } else {
            None
        };
    }

    /// Takes a byte-range lock for this open (MS-FSA 2.1.5.8). Fails with
    /// STATUS_INVALID_LOCK_RANGE when the range passes the largest offset,
    /// STATUS_INSUFFICIENT_RESOURCES when the open already holds `limit`
    /// locks, and STATUS_LOCK_NOT_GRANTED when it conflicts with a lock
    /// already held.
    pub(crate) fn lock_range(
        &self,
        offset: u64,
        length: u64,
        exclusive: bool,
        limit: usize,
    ) -> Result<(), u32> {
        if length != 0 && offset.checked_add(length - 1).is_none() {
            return Err(ntstatus::STATUS_INVALID_LOCK_RANGE);
        }
        let mut state = self.node.state();
        if state.locks.iter().filter(|l| l.owner == self.id).count() >= limit {
            return Err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        if state.range_conflicts(self.id, offset, length, exclusive, true) {
            return Err(ntstatus::STATUS_LOCK_NOT_GRANTED);
        }
        state.locks.push(RangeLock {
            owner: self.id,
            offset,
            length,
            exclusive,
        });
        Ok(())
    }

    /// Releases a lock this open holds on exactly this range, an exclusive
    /// one first (MS-FSA 2.1.5.9). Fails with STATUS_RANGE_NOT_LOCKED when it
    /// holds none.
    pub(crate) fn unlock_range(&self, offset: u64, length: u64) -> Result<(), u32> {
        let mut state = self.node.state();
        let matches = |l: &RangeLock, exclusive: bool| {
            l.owner == self.id
                && l.offset == offset
                && l.length == length
                && l.exclusive == exclusive
        };
        let at = state
            .locks
            .iter()
            .position(|l| matches(l, true))
            .or_else(|| state.locks.iter().position(|l| matches(l, false)))
            .ok_or(ntstatus::STATUS_RANGE_NOT_LOCKED)?;
        state.locks.remove(at);
        Ok(())
    }

    /// Releases the lock [`FileRef::lock_range`] took last with these
    /// arguments.
    pub(crate) fn undo_lock(&self, offset: u64, length: u64, exclusive: bool) {
        let mut state = self.node.state();
        if let Some(at) = state.locks.iter().rposition(|l| {
            l.owner == self.id
                && l.offset == offset
                && l.length == length
                && l.exclusive == exclusive
        }) {
            state.locks.remove(at);
        }
    }

    /// Fails with STATUS_FILE_LOCK_CONFLICT when a read (or a write, if
    /// `write`) of the range through this open conflicts with a byte-range
    /// lock (MS-FSA 2.1.5.3, 2.1.5.4).
    pub(crate) fn check_io(&self, offset: u64, length: u64, write: bool) -> Result<(), u32> {
        if self
            .node
            .state()
            .range_conflicts(self.id, offset, length, write, false)
        {
            return Err(ntstatus::STATUS_FILE_LOCK_CONFLICT);
        }
        Ok(())
    }

    /// Removes the open and its byte-range locks from the table (MS-FSA
    /// 2.1.5.5). With `delete_on_close` the file becomes delete-pending.
    /// When that leaves a delete-pending file with no opens, returns the
    /// removal still to be done; until that is dropped, the file opens for
    /// nobody.
    pub(crate) fn release(mut self, delete_on_close: bool) -> Option<PendingDelete> {
        self.detach(delete_on_close)
    }

    fn detach(&mut self, delete_on_close: bool) -> Option<PendingDelete> {
        if std::mem::replace(&mut self.released, true) {
            return None;
        }
        let mut files = self.share.files.files();
        let mut state = self.node.state();
        let entry = state
            .opens
            .iter()
            .position(|e| e.id == self.id)
            .map(|at| state.opens.remove(at));
        state.locks.retain(|l| l.owner != self.id);
        if delete_on_close && let Some(entry) = entry {
            state.delete_pending = Some(entry.path);
        }
        if !state.opens.is_empty() {
            return None;
        }
        if let Some(path) = state.delete_pending.clone() {
            drop(state);
            drop(files);
            return Some(PendingDelete {
                share: Arc::clone(&self.share),
                node: Arc::clone(&self.node),
                path,
            });
        }
        let key = state.key.clone();
        drop(state);
        remove_node(&mut files, &key, &self.node);
        None
    }
}

impl Drop for FileRef {
    /// An entry dropped without a release still leaves the table. When it
    /// was the last open of a delete-pending file, the removal runs on the
    /// current runtime; without one, the name is freed and the file stays.
    fn drop(&mut self) {
        let Some(pending) = self.detach(false) else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(pending.run());
        }
    }
}

fn remove_node(files: &mut HashMap<FileKey, Arc<FileNode>>, key: &FileKey, node: &Arc<FileNode>) {
    if files.get(key).is_some_and(|n| Arc::ptr_eq(n, node)) {
        files.remove(key);
    }
}

/// A delete-pending file whose last open has closed. Dropping it frees the
/// name in the table, whether or not the removal ran.
pub(crate) struct PendingDelete {
    share: Arc<ShareBindings>,
    node: Arc<FileNode>,
    path: SmbPath,
}

impl PendingDelete {
    /// Removes the file from the share, then frees its name in the table. A
    /// failed delete does not fail the close (MS-SMB2 3.3.4.17); a
    /// directory that gained entries stays (MS-FSA 2.1.5.5).
    pub(crate) async fn run(self) {
        match self.share.backend.unlink(&self.path).await {
            Ok(()) => {}
            Err(SmbError::NotEmpty) => {
                debug!(path = %self.path, "delete-on-close skipped a non-empty directory");
            }
            Err(e) => warn!(error = %e, path = %self.path, "delete-on-close failed"),
        }
    }
}

impl Drop for PendingDelete {
    fn drop(&mut self) {
        let mut files = self.share.files.files();
        let key = self.node.state().key.clone();
        remove_node(&mut files, &key, &self.node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::OpenOptions;
    use crate::server::{ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;

    const RW: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
    const ALL: u32 = RW | FILE_SHARE_DELETE;
    const CAP: usize = super::super::DEFAULT_MAX_LOCKS_PER_OPEN;

    fn share() -> Arc<ShareBindings> {
        share_on(MemFsBackend::new())
    }

    fn share_on(backend: MemFsBackend) -> Arc<ShareBindings> {
        ShareBindings::new(
            "s".to_string(),
            Arc::new(backend),
            ShareMode::Public,
            HashMap::new(),
            false,
        )
    }

    fn info(file_index: u64) -> FileInfo {
        let mut info = FileInfo::new("");
        info.file_index = file_index;
        info
    }

    fn p(s: &str) -> SmbPath {
        s.parse().unwrap()
    }

    fn open(
        share: &Arc<ShareBindings>,
        name: &str,
        access: u32,
        share_access: u32,
    ) -> Result<FileRef, u32> {
        FileRef::register(
            share,
            &info(7),
            &p(name),
            Sharing {
                access,
                share: share_access,
            },
        )
    }

    #[test]
    fn sharing_modes_are_checked_both_ways() {
        let s = share();
        let a = open(&s, "f", FILE_READ_DATA | FILE_WRITE_DATA, 0).unwrap();
        assert_eq!(
            open(&s, "f", FILE_READ_DATA, ALL).err(),
            Some(ntstatus::STATUS_SHARING_VIOLATION)
        );
        // Attribute-only access never conflicts.
        let attrs = open(&s, "f", 0x80, 0).unwrap();
        assert!(a.release(false).is_none());
        let b = open(&s, "f", FILE_READ_DATA, FILE_SHARE_READ).unwrap();
        assert_eq!(
            open(&s, "f", FILE_WRITE_DATA, ALL).err(),
            Some(ntstatus::STATUS_SHARING_VIOLATION)
        );
        assert_eq!(
            open(&s, "f", FILE_READ_DATA, FILE_SHARE_WRITE).err(),
            Some(ntstatus::STATUS_SHARING_VIOLATION)
        );
        let c = open(&s, "f", FILE_READ_DATA, ALL).unwrap();
        for f in [attrs, b, c] {
            assert!(f.release(false).is_none());
        }
        assert!(s.files.files().is_empty());
    }

    #[test]
    fn identity_not_name_decides_the_file() {
        let s = share();
        let _a = open(&s, "one", FILE_WRITE_DATA, 0).unwrap();
        assert_eq!(
            open(&s, "other-link", FILE_READ_DATA, ALL).err(),
            Some(ntstatus::STATUS_SHARING_VIOLATION)
        );
    }

    #[test]
    fn delete_pending_blocks_opens_until_the_last_close() {
        let s = share();
        let a = open(&s, "f", DELETE, ALL).unwrap();
        let b = open(&s, "f", FILE_READ_DATA, ALL).unwrap();
        a.set_delete_pending(true);
        assert!(b.delete_pending());
        assert_eq!(
            open(&s, "f", FILE_READ_DATA, ALL).err(),
            Some(ntstatus::STATUS_DELETE_PENDING)
        );
        assert!(a.release(false).is_none());
        let pending = b.release(false).expect("last close removes the file");
        assert_eq!(pending.path, p("f"));
        assert_eq!(
            open(&s, "f", FILE_READ_DATA, ALL).err(),
            Some(ntstatus::STATUS_DELETE_PENDING)
        );
        drop(pending);
        assert!(open(&s, "f", FILE_READ_DATA, ALL).is_ok());
    }

    #[test]
    fn a_pending_delete_dropped_before_it_runs_frees_the_name() {
        let s = share();
        let a = open(&s, "f", DELETE, ALL).unwrap();
        a.set_delete_pending(true);
        let pending = a.release(false).expect("last close removes the file");
        drop(pending.run());
        assert!(s.files.files().is_empty());
        assert!(open(&s, "f", FILE_READ_DATA, ALL).is_ok());
    }

    #[test]
    fn a_dropped_open_leaves_the_table() {
        let s = share();
        let a = open(&s, "f", FILE_READ_DATA | FILE_WRITE_DATA, 0).unwrap();
        a.lock_range(0, 10, true, CAP).unwrap();
        drop(a);
        assert!(s.files.files().is_empty());
        let b = open(&s, "f", FILE_READ_DATA, ALL).unwrap();
        b.lock_range(0, 10, true, CAP).unwrap();
    }

    #[tokio::test]
    async fn dropping_the_last_open_of_a_delete_pending_file_removes_it() {
        let s = share_on(MemFsBackend::new().with_file("f", b"x"));
        let a = open(&s, "f", DELETE, ALL).unwrap();
        a.set_delete_pending(true);
        drop(a);
        for _ in 0..100 {
            if s.files.files().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(s.files.files().is_empty());
        let missing = s.backend.open(&p("f"), OpenOptions::default()).await;
        assert!(matches!(missing, Err(SmbError::NotFound)));
    }

    #[test]
    fn byte_range_locks_follow_the_conflict_rules() {
        let s = share();
        let a = open(&s, "f", FILE_READ_DATA | FILE_WRITE_DATA, ALL).unwrap();
        let b = open(&s, "f", FILE_READ_DATA | FILE_WRITE_DATA, ALL).unwrap();
        a.lock_range(0, 50, true, CAP).unwrap();
        assert_eq!(
            b.lock_range(10, 5, true, CAP),
            Err(ntstatus::STATUS_LOCK_NOT_GRANTED)
        );
        assert_eq!(
            b.lock_range(49, 1, false, CAP),
            Err(ntstatus::STATUS_LOCK_NOT_GRANTED)
        );
        assert_eq!(
            a.lock_range(0, 50, true, CAP),
            Err(ntstatus::STATUS_LOCK_NOT_GRANTED)
        );
        // The owner reads and writes its own exclusive range.
        assert_eq!(a.check_io(0, 10, true), Ok(()));
        assert_eq!(
            b.check_io(0, 10, false),
            Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
        );
        assert_eq!(b.check_io(50, 10, true), Ok(()));

        b.lock_range(100, 10, false, CAP).unwrap();
        a.lock_range(105, 10, false, CAP).unwrap();
        assert_eq!(a.check_io(100, 1, false), Ok(()));
        // A shared lock blocks writes from every open, its owner included.
        assert_eq!(
            b.check_io(100, 1, true),
            Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
        );

        assert_eq!(
            b.unlock_range(0, 50),
            Err(ntstatus::STATUS_RANGE_NOT_LOCKED)
        );
        assert_eq!(
            a.unlock_range(0, 49),
            Err(ntstatus::STATUS_RANGE_NOT_LOCKED)
        );
        a.unlock_range(0, 50).unwrap();
        assert_eq!(b.check_io(0, 10, false), Ok(()));

        assert_eq!(
            a.lock_range(u64::MAX, 2, true, CAP),
            Err(ntstatus::STATUS_INVALID_LOCK_RANGE)
        );
        a.lock_range(u64::MAX, 1, true, CAP).unwrap();
        // Closing an open drops its locks.
        assert!(a.release(false).is_none());
        b.lock_range(105, 10, true, CAP).unwrap_err();
        b.lock_range(0, 100, true, CAP).unwrap();
    }

    #[test]
    fn locks_per_open_stop_at_the_limit() {
        let s = share();
        let a = open(&s, "f", FILE_WRITE_DATA, ALL).unwrap();
        let b = open(&s, "f", FILE_WRITE_DATA, ALL).unwrap();
        a.lock_range(0, 10, true, 2).unwrap();
        a.lock_range(10, 10, true, 2).unwrap();
        assert_eq!(
            a.lock_range(20, 10, true, 2),
            Err(ntstatus::STATUS_INSUFFICIENT_RESOURCES)
        );
        // The limit counts this open's locks only.
        b.lock_range(20, 10, true, 2).unwrap();
        a.unlock_range(0, 10).unwrap();
        a.lock_range(30, 10, true, 2).unwrap();
    }

    #[test]
    fn zero_length_ranges() {
        let s = share();
        let a = open(&s, "f", FILE_WRITE_DATA, ALL).unwrap();
        let b = open(&s, "f", FILE_WRITE_DATA, ALL).unwrap();
        a.lock_range(0, 0, true, CAP).unwrap();
        b.lock_range(0, 0, true, CAP).unwrap();
        assert_eq!(b.check_io(0, 10, true), Ok(()));
        a.lock_range(10, 0, true, CAP).unwrap();
        assert_eq!(b.check_io(10, 0, true), Ok(()));
        assert_eq!(
            b.check_io(5, 10, true),
            Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
        );
    }

    #[test]
    fn renames_move_names_and_path_keys() {
        let s = share();
        let a = FileRef::register(
            &s,
            &info(0),
            &p("d\\f"),
            Sharing {
                access: FILE_WRITE_DATA,
                share: 0,
            },
        )
        .unwrap();
        s.files.rename_paths(&p("d"), &p("e"), false);
        assert!(s.files.path_is_open(&p("E\\F"), false));
        assert!(!s.files.path_is_open(&p("d\\f"), false));
        let conflict = FileRef::register(
            &s,
            &info(0),
            &p("e\\f"),
            Sharing {
                access: FILE_READ_DATA,
                share: ALL,
            },
        );
        assert_eq!(conflict.err(), Some(ntstatus::STATUS_SHARING_VIOLATION));
        a.set_delete_pending(true);
        assert!(s.files.delete_pending_at(&p("e\\f"), false));
        let pending = a.release(false).expect("pending removal");
        assert_eq!(pending.path, p("e\\f"));
        drop(pending);
        assert!(s.files.files().is_empty());
    }
}
