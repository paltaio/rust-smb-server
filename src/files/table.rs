//! Opens of each file on a share, across every connection, keyed by file
//! identity. This holds the state MS-FSA keeps per file rather than per
//! open: sharing modes (2.1.5.1.2.2), the delete-pending flag (2.1.5.15.3),
//! byte-range locks (2.1.5.8) and leases (MS-SMB2 3.3.1.4).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use tracing::{debug, warn};

use crate::access_mask::{DELETE, FILE_APPEND_DATA, FILE_EXECUTE, FILE_READ_DATA, FILE_WRITE_DATA};
use crate::backend::FileInfo;
use crate::conn::outbound::Outbound;
use crate::error::SmbError;
use crate::ntstatus;
use crate::path::{SmbPath, rebase, same_path};
use crate::server::ShareBindings;

use super::lease::{
    Breaking, Current, FileLease, FileView, Granted, LeaseId, LeaseRequest, LeaseState, OpenView,
    Trigger, break_to, grant, needs_ack, stat_only,
};
use super::leases::{AckWait, BreakWait, GrantGuard, LeaseRef, Notices, break_notification};

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
#[derive(Debug, Clone, Copy, Default)]
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

/// Source of [`FileLease::serial`].
static NEXT_LEASE_SERIAL: AtomicU64 = AtomicU64::new(1);

/// Source of [`Breaking::seq`].
static NEXT_BREAK_SEQ: AtomicU64 = AtomicU64::new(1);

/// Every file on one share that has an open.
#[derive(Default)]
pub(crate) struct FileTable {
    files: Mutex<HashMap<FileKey, Arc<FileNode>>>,
    next_open: AtomicU64,
    renames: tokio::sync::Mutex<()>,
}

pub(super) struct FileNode {
    state: Mutex<FileState>,
}

struct FileState {
    /// The node holding this state.
    me: Weak<FileNode>,
    key: FileKey,
    opens: Vec<OpenEntry>,
    /// The name to remove once the last open closes, while the file is
    /// delete-pending.
    delete_pending: Option<SmbPath>,
    locks: Vec<RangeLock>,
    /// Leases held by the opens, one per LeaseId.
    leases: Vec<FileLease>,
    /// Counts changes that can unblock an operation waiting on the file: a
    /// lease break that completed, a lease that ended, an open that left.
    changed: tokio::sync::watch::Sender<u64>,
}

struct OpenEntry {
    id: u64,
    sharing: Sharing,
    path: SmbPath,
    /// The lease the open holds.
    lease: Option<LeaseId>,
    /// The connection the open belongs to, where breaks of its lease go.
    owner: Weak<Outbound>,
}

/// A new open, as [`FileRef::register`] enters it.
#[derive(Default)]
pub(crate) struct OpenRequest {
    pub sharing: Sharing,
    /// The connection the open belongs to.
    pub owner: Weak<Outbound>,
    /// The lease the CREATE asks for. Its own lease is not broken by the
    /// open (MS-FSA 2.1.4.12.2).
    pub lease: Option<LeaseId>,
    /// The CREATE supersedes or overwrites the file.
    pub overwrite: bool,
    /// On a sharing violation, break the handle caching of the leases on
    /// the file so their clients can close the handles they keep open
    /// (MS-FSA 2.1.5.1.2). Without it, a violation still waits while such a
    /// break is in progress.
    pub break_handles: bool,
}

/// Why [`FileRef::register`] refused an open.
#[derive(Debug)]
pub(crate) struct Refused {
    pub status: u32,
    /// Set when the refusal was a sharing violation that broke handle
    /// caching: once it completes, the open may succeed.
    pub wait: Option<BreakWait>,
}

impl From<u32> for Refused {
    fn from(status: u32) -> Self {
        Self { status, wait: None }
    }
}

#[cfg(test)]
impl From<Sharing> for OpenRequest {
    fn from(sharing: Sharing) -> Self {
        Self {
            sharing,
            ..Self::default()
        }
    }
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

    /// Whether the lease `id` is held on this file.
    pub(super) fn has_lease(&self, id: LeaseId) -> bool {
        self.state().leases.iter().any(|l| l.id == id)
    }

    /// The names of the opens holding the lease `id`, or `None` when the
    /// lease is not held on this file.
    pub(super) fn lease_paths(&self, id: LeaseId) -> Option<Vec<SmbPath>> {
        let state = self.state();
        state.leases.iter().any(|l| l.id == id).then(|| {
            state
                .opens
                .iter()
                .filter(|e| e.lease == Some(id))
                .map(|e| e.path.clone())
                .collect()
        })
    }

    /// MS-SMB2 3.3.5.22.2: completes the break of the lease `id` with the
    /// state `bits` the client acknowledged, and returns that state. When a
    /// later trigger needs less than that, the lease breaks on at once.
    /// Fails with STATUS_OBJECT_NAME_NOT_FOUND when the lease is not held
    /// here, STATUS_UNSUCCESSFUL when no break is in progress and
    /// STATUS_REQUEST_NOT_ACCEPTED when the state is not within the one
    /// notified.
    pub(super) fn acknowledge(&self, id: LeaseId, bits: u32) -> Result<(LeaseState, Notices), u32> {
        let mut state = self.state();
        let at = state
            .leases
            .iter()
            .position(|l| l.id == id)
            .ok_or(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)?;
        let lease = &mut state.leases[at];
        let breaking = lease
            .breaking
            .as_ref()
            .ok_or(ntstatus::STATUS_UNSUCCESSFUL)?;
        if bits & !breaking.to.bits() != 0 {
            return Err(ntstatus::STATUS_REQUEST_NOT_ACCEPTED);
        }
        let required = breaking.required;
        let acked = LeaseState::from_bits(bits);
        lease.breaking = None;
        lease.state = acked;
        debug!(key = ?id.key, state = ?acked, "lease break acknowledged");
        let mut notices = Notices::default();
        if !required.contains(acked) {
            state.start_break(at, acked.and(required), &mut notices);
        }
        state.bump();
        Ok((acked, notices))
    }

    /// Ends the break `seq` of the lease `id` with NONE, when it is still in
    /// progress: the client did not acknowledge in time (MS-SMB2 3.3.6.5),
    /// or no connection took the notification (MS-SMB2 3.3.4.7).
    pub(super) fn drop_break(&self, id: LeaseId, seq: u64) {
        let mut state = self.state();
        let Some(lease) = state
            .leases
            .iter_mut()
            .find(|l| l.id == id && l.breaking.as_ref().is_some_and(|b| b.seq == seq))
        else {
            return;
        };
        lease.breaking = None;
        lease.state = LeaseState::NONE;
        debug!(key = ?id.key, "lease break not acknowledged; lease dropped to none");
        state.bump();
    }

    /// Keeps `timer` as the acknowledgment timer of the break `seq` of the
    /// lease `id`, or stops it when that break is over.
    pub(super) fn set_timer(&self, id: LeaseId, seq: u64, timer: tokio::task::AbortHandle) {
        let mut state = self.state();
        let breaking = state
            .leases
            .iter_mut()
            .find(|l| l.id == id)
            .and_then(|l| l.breaking.as_mut())
            .filter(|b| b.seq == seq);
        match breaking {
            Some(breaking) => {
                breaking.timer = Some(timer);
                state.bump();
            }
            None => timer.abort(),
        }
    }

    /// Ends one CREATE response's hold on the lease `id` created as
    /// `serial`, and returns the break notification held back for it once
    /// no response is pending. The notification goes first to `sender`,
    /// whose response was just queued, so it follows that response on the
    /// same connection. A hold on a lease that has since ended does nothing.
    pub(super) fn end_grant(&self, id: LeaseId, serial: u64, sender: &Weak<Outbound>) -> Notices {
        let mut state = self.state();
        let me = state.me.clone();
        let mut notices = Notices::default();
        let Some(lease) = state
            .leases
            .iter_mut()
            .find(|l| l.id == id && l.serial == serial)
        else {
            return notices;
        };
        lease.grants_in_flight -= 1;
        if lease.grants_in_flight == 0
            && let Some(bytes) = lease.unsent.take()
        {
            let ack = lease.breaking.as_ref().map(|b| AckWait {
                node: me,
                id,
                seq: b.seq,
            });
            let mut owners = state.owners(id);
            if let Some(at) = owners.iter().position(|o| o.ptr_eq(sender)) {
                owners[..=at].rotate_right(1);
            }
            notices.push(bytes, owners, ack);
        }
        notices
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

    /// The connections of the opens holding the lease `id`, each once, in
    /// open order: where a break of the lease may go (MS-SMB2 3.3.4.7).
    fn owners(&self, id: LeaseId) -> Vec<Weak<Outbound>> {
        let mut owners: Vec<Weak<Outbound>> = Vec::new();
        for entry in self.opens.iter().filter(|e| e.lease == Some(id)) {
            if !owners.iter().any(|o| o.ptr_eq(&entry.owner)) {
                owners.push(entry.owner.clone());
            }
        }
        owners
    }

    /// Breaks every lease but `exempt` that `trigger` conflicts with
    /// (MS-FSA 2.1.4.12, MS-SMB2 3.3.4.7). Returns the notifications to send
    /// once the file is unlocked, and whether the operation has to wait for
    /// a break to complete. A lease already breaking gets no second
    /// notification: what the server needs is lowered instead, and the
    /// acknowledgment breaks on to it.
    fn break_for(&mut self, trigger: Trigger, exempt: Option<LeaseId>) -> (Notices, bool) {
        let mut notices = Notices::default();
        let mut wait = false;
        for at in 0..self.leases.len() {
            let lease = &mut self.leases[at];
            if Some(lease.id) == exempt {
                continue;
            }
            let Some(to) = break_to(trigger, lease.state) else {
                continue;
            };
            wait |= to.wait;
            match &mut lease.breaking {
                Some(breaking) => breaking.required = breaking.required.and(to.to),
                None => self.start_break(at, to.to, &mut notices),
            }
        }
        (notices, wait)
    }

    /// Breaks the lease at `at` to `to`. A read lease drops at once; one
    /// caching more keeps its state until the client acknowledges, the
    /// acknowledgment times out, or no connection takes the notification.
    /// A notification for a lease whose grant is not yet sent waits for it.
    fn start_break(&mut self, at: usize, to: LeaseState, notices: &mut Notices) {
        let lease = &mut self.leases[at];
        let from = lease.state;
        let ack = needs_ack(from);
        let mut wait = None;
        if ack {
            lease.bump_epoch();
            let seq = NEXT_BREAK_SEQ.fetch_add(1, Ordering::Relaxed);
            lease.breaking = Some(Breaking {
                to,
                required: to,
                seq,
                timer: None,
            });
            wait = Some(AckWait {
                node: self.me.clone(),
                id: lease.id,
                seq,
            });
        } else {
            lease.set_state(to);
        }
        debug!(key = ?lease.id.key, ?from, ?to, ack, "lease broken");
        let bytes = break_notification(lease, from, to, ack);
        if lease.grants_in_flight > 0 {
            lease.unsent = Some(bytes);
        } else {
            let id = lease.id;
            notices.push(bytes, self.owners(id), wait);
        }
    }

    /// Whether a lease other than `exempt` still caches handles while a
    /// break of it is in progress.
    fn handle_break_pending(&self, exempt: Option<LeaseId>) -> bool {
        self.leases.iter().any(|l| {
            Some(l.id) != exempt && l.breaking.is_some() && l.state.contains(LeaseState::H)
        })
    }

    /// Wakes operations waiting on the file.
    fn bump(&self) {
        self.changed.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// A wait for the next change on the file.
    fn wait(&self) -> BreakWait {
        BreakWait::new(self.changed.subscribe())
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

    /// Breaks the handle caching of the leases on the file open as `path`,
    /// all but `exempt` (MS-FSA 2.1.4.12, SET_INFORMATION rename), when
    /// `start`. Returns a wait for the break to complete while one is in
    /// progress.
    pub(crate) fn break_handles_at(
        &self,
        path: &SmbPath,
        case_sensitive: bool,
        exempt: Option<LeaseId>,
        start: bool,
    ) -> Option<BreakWait> {
        let mut all = Vec::new();
        let mut wait = None;
        let files = self.files();
        for node in files.values() {
            let mut state = node.state();
            if !state
                .opens
                .iter()
                .any(|e| same_path(&e.path, path, case_sensitive))
            {
                continue;
            }
            let waits = if start {
                let (notices, waits) = state.break_for(Trigger::Handle, exempt);
                all.push(notices);
                waits
            } else {
                state.handle_break_pending(exempt)
            };
            if waits && wait.is_none() {
                wait = Some(state.wait());
            }
        }
        drop(files);
        drop(all);
        wait
    }

    /// Breaks the handle caching of every lease on a file open below the
    /// directory `dir`, which is being renamed (MS-SMB2 3.3.1.4). Nothing
    /// waits for these breaks: the opens stay valid under the new name.
    pub(crate) fn break_handles_below(&self, dir: &SmbPath, case_sensitive: bool) {
        let mut all = Vec::new();
        let files = self.files();
        for node in files.values() {
            let mut state = node.state();
            let below = state.opens.iter().any(|e| {
                e.path.components().len() > dir.components().len()
                    && rebase(&e.path, dir, dir, case_sensitive).is_some()
            });
            if below {
                all.push(state.break_for(Trigger::Handle, None).0);
            }
        }
        drop(files);
        drop(all);
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
    /// The binding of this open's lease, released after the entry leaves
    /// the table.
    lease: Option<LeaseRef>,
    released: bool,
}

impl FileRef {
    /// Adds the open `req` describes of the file `info` describes, reached
    /// through `path`. Fails with STATUS_DELETE_PENDING or
    /// STATUS_SHARING_VIOLATION when the opens already on the file do not
    /// allow it. An open that is not attribute-only breaks the leases it
    /// conflicts with.
    pub(crate) fn register(
        share: &Arc<ShareBindings>,
        info: &FileInfo,
        path: &SmbPath,
        req: OpenRequest,
    ) -> Result<Self, Refused> {
        let case_sensitive = share.backend.capabilities().case_sensitive;
        let key = FileKey::new(info.file_index, path, case_sensitive);
        let table = &share.files;
        let mut files = table.files();
        let node = files
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new_cyclic(|me| FileNode {
                    state: Mutex::new(FileState {
                        me: me.clone(),
                        key,
                        opens: Vec::new(),
                        delete_pending: None,
                        locks: Vec::new(),
                        leases: Vec::new(),
                        changed: tokio::sync::watch::Sender::new(0),
                    }),
                })
            })
            .clone();
        let mut state = node.state();
        if let Err(status) = state.admit(req.sharing) {
            let mut wait = None;
            let mut notices = Notices::default();
            if status == ntstatus::STATUS_SHARING_VIOLATION {
                if req.break_handles {
                    let (sent, waits) = state.break_for(Trigger::SharingViolation, req.lease);
                    notices = sent;
                    wait = waits.then(|| state.wait());
                } else if state.handle_break_pending(req.lease) {
                    wait = Some(state.wait());
                }
            }
            drop(state);
            drop(files);
            drop(notices);
            return Err(Refused { status, wait });
        }
        let id = table.next_open.fetch_add(1, Ordering::Relaxed);
        state.opens.push(OpenEntry {
            id,
            sharing: req.sharing,
            path: path.clone(),
            lease: None,
            owner: req.owner,
        });
        let notices = if stat_only(req.sharing.access) {
            Notices::default()
        } else {
            let trigger = Trigger::Open {
                overwrite: req.overwrite,
            };
            state.break_for(trigger, req.lease).0
        };
        drop(state);
        drop(files);
        drop(notices);
        Ok(Self {
            share: Arc::clone(share),
            node,
            id,
            lease: None,
            released: false,
        })
    }

    /// Whether this open's file is `node`.
    pub(super) fn is_on(&self, node: &Arc<FileNode>) -> bool {
        Arc::ptr_eq(&self.node, node)
    }

    pub(super) fn node(&self) -> &Arc<FileNode> {
        &self.node
    }

    pub(super) fn share(&self) -> &Arc<ShareBindings> {
        &self.share
    }

    /// Makes this open a holder of the lease `req` asks for and grants it
    /// the best state within `grantable` that the file allows (MS-SMB2
    /// 3.3.5.9.8, 3.3.5.9.11). Lease breaks held back until the CREATE
    /// response is queued wait for the returned guard.
    pub(super) fn grant_lease(
        &self,
        req: &LeaseRequest,
        grantable: LeaseState,
    ) -> (Granted, GrantGuard) {
        let mut state = self.node.state();
        let mut sender = Weak::new();
        if let Some(entry) = state.opens.iter_mut().find(|e| e.id == self.id) {
            entry.lease = Some(req.id);
            sender = entry.owner.clone();
        }
        let opens: Vec<OpenView> = state
            .opens
            .iter()
            .map(|e| OpenView {
                lease: e.lease,
                stat_only: stat_only(e.sharing.access),
            })
            .collect();
        let leases: Vec<(LeaseId, LeaseState)> =
            state.leases.iter().map(|l| (l.id, l.state)).collect();
        let file = FileView {
            opens: &opens,
            leases: &leases,
            has_locks: !state.locks.is_empty(),
            delete_pending: state.delete_pending.is_some(),
        };
        let existing = state.leases.iter().position(|l| l.id == req.id);
        let current = existing.map(|at| Current {
            state: state.leases[at].state,
            breaking: state.leases[at].breaking.is_some(),
        });
        let (granted, breaking) = grant(req.id, req.state, current, &file, grantable);
        let lease = match existing {
            Some(at) => {
                let lease = &mut state.leases[at];
                lease.set_state(granted);
                lease
            }
            None => {
                let serial = NEXT_LEASE_SERIAL.fetch_add(1, Ordering::Relaxed);
                state.leases.push(FileLease::new(req, granted, serial));
                state.leases.last_mut().expect("just pushed")
            }
        };
        lease.grants_in_flight += 1;
        debug!(key = ?req.id.key, state = ?lease.state, "lease granted");
        let serial = lease.serial;
        let snapshot = Granted {
            id: lease.id,
            state: lease.state,
            breaking,
            epoch: lease.epoch,
            version: lease.version,
            parent: lease.parent,
        };
        drop(state);
        let guard = GrantGuard::new(Arc::clone(&self.node), req.id, serial, sender);
        (snapshot, guard)
    }

    /// Keeps the lease binding for as long as this open lasts.
    pub(super) fn keep_lease(&mut self, lease: LeaseRef) {
        self.lease = Some(lease);
    }

    /// Breaks the leases on the file that `trigger` through this open
    /// conflicts with: every lease but the one this open holds, whichever
    /// client holds it.
    pub(crate) fn break_leases(&self, trigger: Trigger) {
        let notices = {
            let mut state = self.node.state();
            let exempt = state.entry(self.id).and_then(|e| e.lease);
            state.break_for(trigger, exempt).0
        };
        drop(notices);
    }

    /// The lease this open holds.
    pub(crate) fn lease_id(&self) -> Option<LeaseId> {
        self.node.state().entry(self.id).and_then(|e| e.lease)
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
    ///
    /// Marking the file breaks the handle caching of its leases, all but
    /// this open's, under the same lock, so no lease caches handles to a
    /// delete-pending file (MS-FSA 2.1.4.12, 2.1.5.18).
    pub(crate) fn set_delete_pending(&self, delete: bool) {
        let notices = {
            let mut state = self.node.state();
            if delete {
                let entry = state.entry(self.id).map(|e| (e.lease, e.path.clone()));
                let exempt = entry.as_ref().and_then(|e| e.0);
                state.delete_pending = entry.map(|e| e.1);
                state.break_for(Trigger::Handle, exempt).0
            } else {
                state.delete_pending = None;
                Notices::default()
            }
        };
        drop(notices);
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
        // MS-FSA 2.1.5.8: a lock breaks the leases on the file, all but the
        // one this open holds, wherever the range lies. Under the same lock
        // no lease can be granted between the two.
        let exempt = state.entry(self.id).and_then(|e| e.lease);
        let notices = state.break_for(Trigger::Write, exempt).0;
        drop(state);
        drop(notices);
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
        // MS-SMB2 3.3.4.17: a lease ends with its last open, without a
        // notification; a break in progress completes with it.
        if let Some(id) = entry.as_ref().and_then(|e| e.lease)
            && !state.opens.iter().any(|e| e.lease == Some(id))
        {
            state.leases.retain(|l| l.id != id);
        }
        if entry.is_some() {
            state.bump();
        }
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
            true,
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
            }
            .into(),
        )
        .map_err(|r| r.status)
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
            }
            .into(),
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
            }
            .into(),
        );
        assert_eq!(
            conflict.err().map(|r| r.status),
            Some(ntstatus::STATUS_SHARING_VIOLATION)
        );
        a.set_delete_pending(true);
        assert!(s.files.delete_pending_at(&p("e\\f"), false));
        let pending = a.release(false).expect("pending removal");
        assert_eq!(pending.path, p("e\\f"));
        drop(pending);
        assert!(s.files.files().is_empty());
    }
}
