//! Opens of each file on a share, across every connection, keyed by file
//! identity. This holds the state MS-FSA keeps per file or per stream
//! rather than per open: sharing modes (2.1.5.1.2.1, 2.1.5.1.2.2), the
//! delete-pending flags (2.1.5.15.3), byte-range locks (2.1.5.8) and
//! leases (MS-SMB2 3.3.1.4). An open on a named stream is on the file's
//! node with the stream's name. A lease is on one stream, and its grant
//! and breaks count the opens, locks and leases of that stream only
//! (MS-FSA 2.1.1.5 Stream.Oplock).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use tracing::{debug, warn};

use crate::access_mask::{
    DELETE, FILE_APPEND_DATA, FILE_EXECUTE, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA,
};
use crate::backend::FileInfo;
use crate::conn::outbound::Outbound;
use crate::error::SmbError;
use crate::ntstatus;
use crate::path::{SmbPath, rebase, same_path};
use crate::proto::messages::change_notify::{
    FILE_ACTION_REMOVED, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
};
use crate::server::ShareBindings;
use crate::stream::{StreamName, same_stream, stream_error};

use super::durable::DurableTable;
use super::lease::{
    Breaking, Current, FileLease, FileView, Granted, LeaseId, LeaseRequest, LeaseState, OpenView,
    Trigger, break_to, grant, needs_ack, stat_only,
};
use super::leases::{AckWait, BreakWait, GrantGuard, LeaseRef, Notices, break_notification};
use super::watch::Change;

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

    /// The file id the key holds, `0` for a file known by its path.
    fn file_index(&self) -> u64 {
        match self {
            Self::Index(index) => *index,
            Self::Path(_) => 0,
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
    /// True if this open and `other` cannot both be open on one stream.
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
    renames: tokio::sync::RwLock<()>,
}

pub(super) struct FileNode {
    state: Mutex<FileState>,
    /// Held across a read, check and set of the file's extended
    /// attributes, so sets through different opens run one at a time.
    eas: tokio::sync::Mutex<()>,
}

struct FileState {
    /// The node holding this state.
    me: Weak<FileNode>,
    key: FileKey,
    /// The name the file was last opened by, moved by renames.
    name: SmbPath,
    is_directory: bool,
    opens: Vec<OpenEntry>,
    /// The name to remove once the last open closes, while the file is
    /// delete-pending.
    delete_pending: Option<SmbPath>,
    /// Named streams marked for deletion, each removed once the last open
    /// on it closes (MS-FSA Stream.IsDeleted).
    deleted_streams: Vec<StreamName>,
    locks: Vec<RangeLock>,
    /// Leases held by the opens, one per LeaseId.
    leases: Vec<FileLease>,
    /// Counts changes that can unblock an operation waiting on the file: a
    /// lease break that completed, a lease that ended, an open that left.
    changed: tokio::sync::watch::Sender<u64>,
    /// Counts sets of the file's extended attributes while it is open.
    ea_changes: u64,
}

struct OpenEntry {
    id: u64,
    sharing: Sharing,
    path: SmbPath,
    /// The named stream the open is on; `None` for the default stream or
    /// the directory.
    stream: Option<StreamName>,
    /// The open supersedes the file.
    supersedes: bool,
    /// The lease the open holds.
    lease: Option<LeaseId>,
    /// The connection the open belongs to, where breaks of its lease go.
    owner: Weak<Outbound>,
    /// A CREATE waiting for other clients to give up write caching. It
    /// counts against their write caching but not in the sharing check of
    /// other opens; it runs its own sharing check once the wait ends
    /// (MS-FSA 2.1.5.1 checks for oplock breaks before the open joins the
    /// file's opens).
    waiting: bool,
    /// Set on a durable open.
    durable: Option<DurableMark>,
}

/// The durable side of an open's entry: where the open is registered,
/// whether it is kept without a connection, and whether a lease break
/// already decided to close it.
#[derive(Debug, Clone)]
pub(crate) struct DurableMark {
    pub table: Weak<DurableTable>,
    pub id: u64,
    pub detached: bool,
    pub doomed: bool,
}

/// A new open, as [`FileRef::register`] enters it.
#[derive(Default)]
pub(crate) struct OpenRequest {
    pub sharing: Sharing,
    /// The named stream to open; `None` for the default stream or the
    /// directory.
    pub stream: Option<StreamName>,
    /// The connection the open belongs to.
    pub owner: Weak<Outbound>,
    /// The lease the CREATE asks for. Its own lease is not broken by the
    /// open (MS-FSA 2.1.4.12.2).
    pub lease: Option<LeaseId>,
    /// The CREATE supersedes or overwrites the file.
    pub overwrite: bool,
    /// The CREATE supersedes the file, which the opens of its named
    /// streams have to share delete access for.
    pub supersede: bool,
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

#[derive(Debug, Clone)]
struct RangeLock {
    owner: u64,
    /// The stream of the owner, whose locks conflict only with locks and
    /// I/O on the same stream.
    stream: Option<StreamName>,
    offset: u64,
    length: u64,
    exclusive: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The leases of a file an operation breaks.
#[derive(Debug, Clone, Copy)]
enum On<'a> {
    /// The leases of one stream; `None` is the default stream or the
    /// directory.
    Stream(Option<&'a StreamName>),
    /// Every lease of the file.
    File,
}

impl On<'_> {
    /// Whether the lease on `stream` is one of these.
    fn reaches(self, stream: Option<&StreamName>) -> bool {
        match self {
            On::Stream(on) => same_stream(on, stream),
            On::File => true,
        }
    }
}

/// MS-FSA 2.1.5.1.2.1: deleting the default stream deletes every stream of
/// the file, so an open that may delete it, `deleter` on the default stream
/// when `on_default`, and an open on any stream of the file that does not
/// share delete access and uses its data or deletes, `other`, exclude each
/// other.
fn blocks_deletion(deleter: Sharing, on_default: bool, other: Sharing) -> bool {
    on_default
        && deleter.access & DELETE != 0
        && other.share & FILE_SHARE_DELETE == 0
        && other.access & SHARED_ACCESS != 0
}

impl OpenEntry {
    /// True if this open and the open `sharing` describes, on `stream`,
    /// cannot both be open on the file: the share modes conflict on one
    /// stream (MS-FSA 2.1.5.1.2.2), or one of them may delete the file
    /// while the other does not allow it (MS-FSA 2.1.5.1.2.1).
    fn conflicts_with(&self, sharing: Sharing, stream: Option<&StreamName>) -> bool {
        (same_stream(self.stream.as_ref(), stream) && self.sharing.conflicts_with(sharing))
            || blocks_deletion(self.sharing, self.stream.is_none(), sharing)
            || blocks_deletion(sharing, stream.is_none(), self.sharing)
    }
}

impl FileNode {
    fn state(&self) -> MutexGuard<'_, FileState> {
        lock(&self.state)
    }

    /// Whether the lease `id` is held on this file.
    pub(super) fn has_lease(&self, id: LeaseId) -> bool {
        self.state().leases.iter().any(|l| l.id == id)
    }

    /// Whether the lease `id` is held on this file, on a stream other than
    /// `stream`.
    pub(super) fn has_lease_off(&self, id: LeaseId, stream: Option<&StreamName>) -> bool {
        self.state()
            .leases
            .iter()
            .any(|l| l.id == id && !same_stream(l.stream.as_ref(), stream))
    }

    /// The names and streams of the opens holding the lease `id`, or
    /// `None` when the lease is not held on this file.
    pub(super) fn lease_names(&self, id: LeaseId) -> Option<Vec<(SmbPath, Option<StreamName>)>> {
        let state = self.state();
        state.leases.iter().any(|l| l.id == id).then(|| {
            state
                .holders(id)
                .map(|e| (e.path.clone(), e.stream.clone()))
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
        let doomed = state.doom_uncovered(id);
        notices.close(doomed);
        state.bump();
        Ok((acked, notices))
    }

    /// Ends the break `seq` of the lease `id` with NONE, when it is still in
    /// progress: the client did not acknowledge in time (MS-SMB2 3.3.6.5),
    /// or no connection took the notification (MS-SMB2 3.3.4.7). Returns the
    /// closes of the opens kept for reconnect under the lease, which can no
    /// longer be taken back.
    pub(super) fn drop_break(&self, id: LeaseId, seq: u64) -> Notices {
        let mut state = self.state();
        let mut notices = Notices::default();
        let Some(lease) = state
            .leases
            .iter_mut()
            .find(|l| l.id == id && l.breaking.as_ref().is_some_and(|b| b.seq == seq))
        else {
            return notices;
        };
        lease.breaking = None;
        lease.state = LeaseState::NONE;
        debug!(key = ?id.key, "lease break not acknowledged; lease dropped to none");
        let doomed = state.doom_uncovered(id);
        notices.close(doomed);
        state.bump();
        notices
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
            if state.held_only_detached(id) {
                let doomed = state.doom_detached(id, |_| true);
                notices.close(doomed);
                return notices;
            }
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
    /// MS-FSA 2.1.5.1: a delete-pending file, or a named stream marked for
    /// deletion, opens for nobody; otherwise the sharing checks of
    /// 2.1.5.1.2.1 and 2.1.5.1.2.2 run against every open on the file for
    /// an open on `stream`. Waiting CREATEs and the open `except` take no
    /// part.
    ///
    /// A supersede also fails while an open of a named stream does not
    /// share delete access; an overwrite does not.
    fn admit(
        &self,
        sharing: Sharing,
        stream: Option<&StreamName>,
        supersede: bool,
        except: Option<u64>,
    ) -> Result<(), u32> {
        if self.delete_pending.is_some() || stream.is_some_and(|s| self.stream_deleted(s)) {
            return Err(ntstatus::STATUS_DELETE_PENDING);
        }
        let blocks_supersede = |e: &OpenEntry| {
            supersede
                && e.stream.is_some()
                && e.sharing.access & SHARED_ACCESS != 0
                && e.sharing.share & FILE_SHARE_DELETE == 0
        };
        if self.opens.iter().any(|e| {
            !e.waiting
                && Some(e.id) != except
                && (e.conflicts_with(sharing, stream) || blocks_supersede(e))
        }) {
            return Err(ntstatus::STATUS_SHARING_VIOLATION);
        }
        Ok(())
    }

    /// Whether the named stream `stream` is marked for deletion.
    fn stream_deleted(&self, stream: &StreamName) -> bool {
        self.deleted_streams.iter().any(|s| s.matches(stream))
    }

    /// Whether an open is on the named stream `stream`.
    fn stream_open(&self, stream: &StreamName) -> bool {
        self.opens
            .iter()
            .any(|e| e.stream.as_ref().is_some_and(|s| s.matches(stream)))
    }

    fn entry(&self, id: u64) -> Option<&OpenEntry> {
        self.opens.iter().find(|e| e.id == id)
    }

    /// The stream the lease `id` is on, `None` when it is not held here.
    fn lease_stream(&self, id: LeaseId) -> Option<Option<&StreamName>> {
        self.leases
            .iter()
            .find(|l| l.id == id)
            .map(|l| l.stream.as_ref())
    }

    /// The opens holding the lease `id`: those with its key on its stream.
    /// A CREATE with the key on another stream of the file holds nothing,
    /// and its grant fails.
    fn holders(&self, id: LeaseId) -> impl Iterator<Item = &OpenEntry> {
        let stream = self.lease_stream(id);
        self.opens.iter().filter(move |e| {
            e.lease == Some(id) && stream.is_some_and(|s| same_stream(e.stream.as_ref(), s))
        })
    }

    /// The connections of the opens holding the lease `id`, each once, in
    /// open order: where a break of the lease may go (MS-SMB2 3.3.4.7).
    fn owners(&self, id: LeaseId) -> Vec<Weak<Outbound>> {
        let mut owners: Vec<Weak<Outbound>> = Vec::new();
        for entry in self.holders(id) {
            if !owners.iter().any(|o| o.ptr_eq(&entry.owner)) {
                owners.push(entry.owner.clone());
            }
        }
        owners
    }

    /// Breaks every lease `on` reaches but `exempt` that `trigger`
    /// conflicts with (MS-FSA 2.1.4.12, MS-SMB2 3.3.4.7). Returns the
    /// notifications to send once the file is unlocked, and whether the
    /// operation has to wait for a break to complete. A lease already
    /// breaking gets no second notification: what the server needs is
    /// lowered instead, and the acknowledgment breaks on to it.
    fn break_for(
        &mut self,
        trigger: Trigger,
        exempt: Option<LeaseId>,
        on: On<'_>,
    ) -> (Notices, bool) {
        let mut notices = Notices::default();
        let mut wait = false;
        for at in 0..self.leases.len() {
            let lease = &mut self.leases[at];
            if Some(lease.id) == exempt || !on.reaches(lease.stream.as_ref()) {
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
    ///
    /// A lease held only by opens kept for reconnect has no connection to
    /// take the notification: those opens are closed instead (MS-SMB2
    /// 3.3.4.7), and the break completes when the last of them leaves the
    /// file. That includes a break that keeps handle caching, for which no
    /// other connection of the same client is tried.
    fn start_break(&mut self, at: usize, to: LeaseState, notices: &mut Notices) {
        let id = self.leases[at].id;
        let orphaned = self.held_only_detached(id);
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
        if orphaned && lease.grants_in_flight == 0 {
            let doomed = self.doom_detached(id, |_| true);
            notices.close(doomed);
            return;
        }
        let bytes = break_notification(lease, from, to, ack);
        if lease.grants_in_flight > 0 {
            lease.unsent = Some(bytes);
        } else {
            notices.push(bytes, self.owners(id), wait);
        }
    }

    /// Whether the lease `id` is held, and only by opens kept for reconnect.
    fn held_only_detached(&self, id: LeaseId) -> bool {
        let mut holders = self.holders(id).peekable();
        holders.peek().is_some() && holders.all(|e| e.durable.as_ref().is_some_and(|d| d.detached))
    }

    /// Marks the opens kept for reconnect under the lease `id` that the
    /// lease no longer covers to be closed: every one once it stops caching
    /// handles, and the ones holding byte-range locks once it stops caching
    /// writes. MS-SMB2 3.3.7.1 keeps no others, and a lock left behind would
    /// block other clients' reads and writes, which break nothing.
    fn doom_uncovered(&mut self, id: LeaseId) -> Vec<DurableMark> {
        let state = self
            .leases
            .iter()
            .find(|l| l.id == id)
            .map_or(LeaseState::NONE, |l| l.state);
        if !state.contains(LeaseState::H) {
            return self.doom_detached(id, |_| true);
        }
        if state.contains(LeaseState::W) {
            return Vec::new();
        }
        let locked: Vec<u64> = self.locks.iter().map(|l| l.owner).collect();
        self.doom_detached(id, |open| locked.contains(&open))
    }

    /// Marks the opens kept for reconnect under the lease `id` that `pick`
    /// accepts, by entry id, to be closed, and returns the ones not marked
    /// before.
    fn doom_detached(&mut self, id: LeaseId, pick: impl Fn(u64) -> bool) -> Vec<DurableMark> {
        let mut doomed = Vec::new();
        let Some(stream) = self.lease_stream(id).map(|s| s.cloned()) else {
            return doomed;
        };
        let holds =
            |e: &OpenEntry| e.lease == Some(id) && same_stream(e.stream.as_ref(), stream.as_ref());
        for entry in self.opens.iter_mut().filter(|e| holds(e)) {
            if !pick(entry.id) {
                continue;
            }
            if let Some(mark) = entry.durable.as_mut().filter(|d| d.detached && !d.doomed) {
                mark.doomed = true;
                doomed.push(mark.clone());
            }
        }
        doomed
    }

    /// Marks the opens kept for reconnect under the leases of the file's
    /// named streams to be closed, with `alone` only those whose lease no
    /// connected open holds, and returns the ones not marked before.
    fn doom_kept_on_streams(&mut self, alone: bool) -> Vec<DurableMark> {
        let ids: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|l| l.stream.is_some() && (!alone || self.held_only_detached(l.id)))
            .map(|l| l.id)
            .collect();
        ids.into_iter()
            .flat_map(|id| self.doom_detached(id, |_| true))
            .collect()
    }

    /// Whether a lease `on` reaches other than `exempt` still caches
    /// handles while a break of it is in progress.
    fn handle_break_pending(&self, exempt: Option<LeaseId>, on: On<'_>) -> bool {
        self.leases.iter().any(|l| {
            Some(l.id) != exempt
                && on.reaches(l.stream.as_ref())
                && l.breaking.is_some()
                && l.state.contains(LeaseState::H)
        })
    }

    /// Whether a lease `on` reaches other than `exempt` still caches
    /// writes while a break of it is in progress.
    fn write_break_pending(&self, exempt: Option<LeaseId>, on: On<'_>) -> bool {
        self.leases.iter().any(|l| {
            Some(l.id) != exempt
                && on.reaches(l.stream.as_ref())
                && l.breaking.is_some()
                && l.state.contains(LeaseState::W)
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

    /// MS-FSA 2.1.4.10: whether the range of `stream` conflicts with a
    /// lock. `exclusive` is the intent of the access (a write, or an
    /// exclusive lock) and `lock_intent` tells a lock request from a read or
    /// write.
    fn range_conflicts(
        &self,
        owner: u64,
        stream: Option<&StreamName>,
        offset: u64,
        length: u64,
        exclusive: bool,
        lock_intent: bool,
    ) -> bool {
        if offset == 0 && length == 0 {
            return false;
        }
        self.locks.iter().any(|l| {
            same_stream(l.stream.as_ref(), stream)
                && overlaps(l.offset, l.length, offset, length)
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
    /// the target, renames in the backend, moves the open names and the
    /// change notification watches, and reports the rename.
    pub(crate) async fn rename_lock(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.renames.write().await
    }

    /// Keeps renames out while a CREATE runs from its first backend call
    /// until its open is in the table, while a delete calls the backend and
    /// reports the removal, and while a CHANGE_NOTIFY arms a watch. Each
    /// then uses, and reports, the path the entry has on the share.
    pub(crate) async fn names_lock(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.renames.read().await
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

    /// For each of `paths`, whether an open on the share that may write
    /// the file's data, attributes or extended attributes currently has it
    /// as its name. The opens are looked at once for all of them.
    pub(crate) fn open_to_change(&self, paths: &[SmbPath], case_sensitive: bool) -> Vec<bool> {
        if paths.is_empty() {
            return Vec::new();
        }
        let mut open = HashSet::new();
        for node in self.files().values() {
            for entry in &node.state().opens {
                if entry.sharing.access & (WRITE_ACCESS | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)
                    != 0
                {
                    open.insert(path_key(&entry.path, case_sensitive));
                }
            }
        }
        paths
            .iter()
            .map(|path| open.contains(&path_key(path, case_sensitive)))
            .collect()
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

    /// Whether the file `info` describes, reached through `path`, has an
    /// open on the share.
    pub(crate) fn has_opens(&self, info: &FileInfo, path: &SmbPath, case_sensitive: bool) -> bool {
        let key = FileKey::new(info.file_index, path, case_sensitive);
        self.files()
            .get(&key)
            .is_some_and(|node| !node.state().opens.is_empty())
    }

    /// Whether a new open of the named stream `stream` of the file `info`
    /// describes, reached through `path`, is refused because the file or
    /// the stream is marked for deletion.
    pub(crate) fn stream_delete_pending(
        &self,
        info: &FileInfo,
        path: &SmbPath,
        stream: &StreamName,
        case_sensitive: bool,
    ) -> bool {
        let key = FileKey::new(info.file_index, path, case_sensitive);
        let Some(node) = self.files().get(&key).cloned() else {
            return false;
        };
        let state = node.state();
        state.delete_pending.is_some() || state.stream_deleted(stream)
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
                let (notices, waits) = state.break_for(Trigger::Handle, exempt, On::File);
                all.push(notices);
                waits
            } else {
                state.handle_break_pending(exempt, On::File)
            };
            if waits && wait.is_none() {
                wait = Some(state.wait());
            }
        }
        drop(files);
        drop(all);
        wait
    }

    /// True if an open on the share has a name below the directory `dir`
    /// (MS-FSA 2.1.4.2).
    pub(crate) fn open_below(&self, dir: &SmbPath, case_sensitive: bool) -> bool {
        self.files().values().any(|node| {
            node.state()
                .opens
                .iter()
                .any(|e| is_below(&e.path, dir, case_sensitive))
        })
    }

    /// Breaks the handle caching of every lease on a file open below the
    /// directory `dir`, which is being renamed, when `start` (MS-FSA 2.1.4.2,
    /// MS-SMB2 3.3.1.4). Returns a wait for a break to complete while one is
    /// in progress.
    pub(crate) fn break_handles_below(
        &self,
        dir: &SmbPath,
        case_sensitive: bool,
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
                .any(|e| is_below(&e.path, dir, case_sensitive))
            {
                continue;
            }
            let waits = if start {
                let (notices, waits) = state.break_for(Trigger::Handle, None, On::File);
                all.push(notices);
                waits
            } else {
                state.handle_break_pending(None, On::File)
            };
            if waits && wait.is_none() {
                wait = Some(state.wait());
            }
        }
        drop(files);
        drop(all);
        wait
    }

    /// Stops every acknowledgment timer on the share, as if they were lost.
    #[cfg(test)]
    pub(crate) fn stop_timers(&self) {
        for node in self.files().values() {
            for lease in &mut node.state().leases {
                if let Some(timer) = lease.breaking.as_mut().and_then(|b| b.timer.take()) {
                    timer.abort();
                }
            }
        }
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
            if let Some(path) = rebase(&state.name, from, to, case_sensitive) {
                state.name = path;
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
    /// through `path`, holding the lease it asks for. Fails with
    /// STATUS_DELETE_PENDING or STATUS_SHARING_VIOLATION when the opens
    /// already on the file do not allow it. An open that is not
    /// attribute-only breaks the leases it conflicts with, and returns a
    /// wait when other clients have to write back what they cache first
    /// (MS-FSA 2.1.4.12, OPEN).
    pub(crate) fn register(
        share: &Arc<ShareBindings>,
        info: &FileInfo,
        path: &SmbPath,
        req: OpenRequest,
    ) -> Result<(Self, Option<BreakWait>), Refused> {
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
                        name: path.clone(),
                        is_directory: info.is_directory,
                        opens: Vec::new(),
                        delete_pending: None,
                        deleted_streams: Vec::new(),
                        locks: Vec::new(),
                        leases: Vec::new(),
                        changed: tokio::sync::watch::Sender::new(0),
                        ea_changes: 0,
                    }),
                    eas: tokio::sync::Mutex::new(()),
                })
            })
            .clone();
        let mut state = node.state();
        if let Err(status) = state.admit(req.sharing, req.stream.as_ref(), req.supersede, None) {
            let mut wait = None;
            let mut notices = Notices::default();
            // MS-FSA 2.1.5.1.2: a violation breaks the handle caching of
            // the stream being opened.
            let on = On::Stream(req.stream.as_ref());
            if status == ntstatus::STATUS_SHARING_VIOLATION {
                if req.break_handles {
                    let (sent, waits) = state.break_for(Trigger::SharingViolation, req.lease, on);
                    notices = sent;
                    wait = waits.then(|| state.wait());
                } else if state.handle_break_pending(req.lease, on) {
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
            stream: req.stream.clone(),
            supersedes: req.supersede,
            lease: req.lease,
            owner: req.owner,
            waiting: false,
            durable: None,
        });
        let (notices, wait) = if stat_only(req.sharing.access) {
            (Notices::default(), None)
        } else {
            let trigger = Trigger::Open {
                overwrite: req.overwrite,
            };
            let on = On::Stream(req.stream.as_ref());
            let (notices, waits) = state.break_for(trigger, req.lease, on);
            if waits && let Some(entry) = state.opens.last_mut() {
                entry.waiting = true;
            }
            (notices, waits.then(|| state.wait()))
        };
        drop(state);
        drop(files);
        drop(notices);
        let file = Self {
            share: Arc::clone(share),
            node,
            id,
            lease: None,
            released: false,
        };
        Ok((file, wait))
    }

    /// Ends the wait of a CREATE that waited for other clients to give up
    /// write caching: `Ok(None)` once it may go ahead, after it passes the
    /// delete-pending and sharing checks the opens on the file now ask
    /// for; a wait while a write break is still in progress; or the
    /// status the CREATE fails with.
    pub(crate) fn end_wait(&self) -> Result<Option<BreakWait>, u32> {
        let mut state = self.node.state();
        let Some(entry) = state.entry(self.id) else {
            return Err(ntstatus::STATUS_FILE_CLOSED);
        };
        let (lease, sharing, stream) = (entry.lease, entry.sharing, entry.stream.clone());
        let supersede = entry.supersedes;
        if state.write_break_pending(lease, On::Stream(stream.as_ref())) {
            return Ok(Some(state.wait()));
        }
        state.admit(sharing, stream.as_ref(), supersede, Some(self.id))?;
        if let Some(entry) = state.opens.iter_mut().find(|e| e.id == self.id) {
            entry.waiting = false;
        }
        Ok(None)
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
        let mut stream = None;
        if let Some(entry) = state.opens.iter_mut().find(|e| e.id == self.id) {
            entry.lease = Some(req.id);
            sender = entry.owner.clone();
            stream = entry.stream.clone();
        }
        // The lease caches the stream this open is on: opens, locks and
        // leases of the file's other streams take no part.
        let here = |s: &Option<StreamName>| same_stream(s.as_ref(), stream.as_ref());
        let opens: Vec<OpenView> = state
            .opens
            .iter()
            .filter(|e| here(&e.stream))
            .map(|e| OpenView {
                lease: e.lease,
                stat_only: stat_only(e.sharing.access),
            })
            .collect();
        let leases: Vec<(LeaseId, LeaseState)> = state
            .leases
            .iter()
            .filter(|l| here(&l.stream))
            .map(|l| (l.id, l.state))
            .collect();
        let deleted = match &stream {
            Some(stream) => state.stream_deleted(stream),
            None => false,
        };
        let file = FileView {
            opens: &opens,
            leases: &leases,
            has_locks: state.locks.iter().any(|l| here(&l.stream)),
            delete_pending: state.delete_pending.is_some() || deleted,
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
                state
                    .leases
                    .push(FileLease::new(req, stream, granted, serial));
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

    /// Marks the open durable, registered as `id` in `table`.
    pub(crate) fn mark_durable(&self, table: &Arc<DurableTable>, id: u64) {
        let mut state = self.node.state();
        if let Some(entry) = state.opens.iter_mut().find(|e| e.id == self.id) {
            entry.durable = Some(DurableMark {
                table: Arc::downgrade(table),
                id,
                detached: false,
                doomed: false,
            });
        }
    }

    /// Takes a durable open off its connection to keep it for reconnect
    /// (MS-SMB2 3.3.7.1): only while its lease caches handles with no break
    /// in progress (Open.OplockState Held), and while its byte-range locks,
    /// if it holds any, are covered by write caching. From then on breaks of
    /// the lease close it instead of going to a client. Returns whether the
    /// open is kept.
    pub(crate) fn try_detach(&self) -> bool {
        let mut state = self.node.state();
        let Some(at) = state.opens.iter().position(|e| e.id == self.id) else {
            return false;
        };
        let entry = &state.opens[at];
        let Some(lease) = entry
            .lease
            .and_then(|id| state.leases.iter().find(|l| l.id == id))
        else {
            return false;
        };
        let has_locks = state.locks.iter().any(|l| l.owner == self.id);
        let keeps = entry
            .durable
            .as_ref()
            .is_some_and(|d| !d.detached && !d.doomed)
            && lease.state.contains(LeaseState::H)
            && lease.breaking.is_none()
            && (!has_locks || lease.state.contains(LeaseState::W));
        if !keeps {
            return false;
        }
        let entry = &mut state.opens[at];
        entry.owner = Weak::new();
        if let Some(mark) = entry.durable.as_mut() {
            mark.detached = true;
        }
        true
    }

    /// Whether a lease break decided to close this open while it was kept
    /// for reconnect.
    pub(crate) fn is_doomed(&self) -> bool {
        self.node
            .state()
            .entry(self.id)
            .and_then(|e| e.durable.as_ref())
            .is_some_and(|d| d.doomed)
    }

    /// Puts an open kept for reconnect back on the connection `owner`
    /// (MS-SMB2 3.3.5.9.7): only while it is still kept, no break decided to
    /// close it, and its lease caches handles. Returns the lease as the
    /// CREATE response reports it, and a guard that holds back break
    /// notifications for the lease until that response is queued.
    pub(crate) fn reattach(&self, owner: Weak<Outbound>) -> Option<(Granted, GrantGuard)> {
        let mut state = self.node.state();
        let at = state.opens.iter().position(|e| e.id == self.id)?;
        let entry = &state.opens[at];
        let id = entry.lease?;
        if !entry
            .durable
            .as_ref()
            .is_some_and(|d| d.detached && !d.doomed)
        {
            return None;
        }
        let lease = state.leases.iter_mut().find(|l| l.id == id)?;
        if !lease.state.contains(LeaseState::H) {
            return None;
        }
        lease.grants_in_flight += 1;
        let serial = lease.serial;
        let granted = Granted {
            id,
            state: lease.state,
            breaking: lease.breaking.is_some(),
            epoch: lease.epoch,
            version: lease.version,
            parent: lease.parent,
        };
        let entry = &mut state.opens[at];
        entry.owner = owner.clone();
        if let Some(mark) = entry.durable.as_mut() {
            mark.detached = false;
        }
        drop(state);
        let guard = GrantGuard::new(Arc::clone(&self.node), id, serial, owner);
        Some((granted, guard))
    }

    /// Breaks the leases on the stream of this open that `trigger` through
    /// it conflicts with: every lease of the stream but the one this open
    /// holds, whichever client holds it.
    pub(crate) fn break_leases(&self, trigger: Trigger) {
        let notices = {
            let mut state = self.node.state();
            match state.entry(self.id) {
                Some(entry) => {
                    let (exempt, stream) = (entry.lease, entry.stream.clone());
                    state
                        .break_for(trigger, exempt, On::Stream(stream.as_ref()))
                        .0
                }
                None => Notices::default(),
            }
        };
        drop(notices);
    }

    /// Closes the opens kept for reconnect on the file's named streams, as
    /// a rename of the file does: their names moved, so no reconnect names
    /// them. Connected opens of the streams keep their leases.
    pub(crate) fn close_kept_stream_opens(&self) {
        let mut notices = Notices::default();
        notices.close(self.node.state().doom_kept_on_streams(false));
        drop(notices);
    }

    /// The lease this open holds.
    pub(crate) fn lease_id(&self) -> Option<LeaseId> {
        self.node.state().entry(self.id).and_then(|e| e.lease)
    }

    /// The file id the backend reported for the file, `0` if none.
    pub(crate) fn file_index(&self) -> u64 {
        self.node.state().key.file_index()
    }

    /// The open's current name.
    pub(crate) fn path(&self) -> SmbPath {
        self.node
            .state()
            .entry(self.id)
            .map(|e| e.path.clone())
            .unwrap_or_default()
    }

    /// The names the opens of this file have, each once: every path a
    /// watch of it can be armed under.
    pub(crate) fn open_paths(&self) -> Vec<SmbPath> {
        let state = self.node.state();
        let mut paths: Vec<SmbPath> = Vec::new();
        for entry in &state.opens {
            if !paths.contains(&entry.path) {
                paths.push(entry.path.clone());
            }
        }
        paths
    }

    /// True if this is an entry for the file `info` describes, reached
    /// through `path`.
    pub(crate) fn is_for(&self, info: &FileInfo, path: &SmbPath) -> bool {
        let case_sensitive = self.share.backend.capabilities().case_sensitive;
        FileKey::new(info.file_index, path, case_sensitive) == self.node.state().key
    }

    /// True if the backend's file id `file_index` is this file's.
    pub(crate) fn has_index(&self, file_index: u64) -> bool {
        file_index != 0 && self.node.state().key == FileKey::Index(file_index)
    }

    /// Whether the file is delete-pending (MS-FSA Link.IsDeleted).
    #[cfg(test)]
    pub(crate) fn delete_pending(&self) -> bool {
        self.node.state().delete_pending.is_some()
    }

    pub(crate) fn is_directory(&self) -> bool {
        self.node.state().is_directory
    }

    /// How many times the file's extended attributes were set while it
    /// has been open.
    pub(crate) fn ea_changes(&self) -> u64 {
        self.node.state().ea_changes
    }

    /// Counts a set of the file's extended attributes.
    pub(crate) fn count_ea_change(&self) {
        self.node.state().ea_changes += 1;
    }

    /// Waits for the sets of the file's extended attributes in progress
    /// through other opens, and keeps others out until dropped.
    pub(crate) async fn lock_eas(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.node.eas.lock().await
    }

    /// Whether the stream this open is on is marked for deletion: the
    /// file for an open on its default stream or directory, the named
    /// stream for an open on one (MS-FSA Stream.IsDeleted).
    pub(crate) fn stream_delete_pending(&self) -> bool {
        let state = self.node.state();
        match state.entry(self.id).and_then(|e| e.stream.as_ref()) {
            Some(stream) => state.stream_deleted(stream),
            None => state.delete_pending.is_some(),
        }
    }

    /// The named stream this open is on, under its current name; `None`
    /// for the default stream or the directory.
    pub(crate) fn stream(&self) -> Option<StreamName> {
        self.node
            .state()
            .entry(self.id)
            .and_then(|e| e.stream.clone())
    }

    /// Whether an open is on the named stream `stream` of the file, or the
    /// stream is marked for deletion.
    pub(crate) fn stream_in_use(&self, stream: &StreamName) -> bool {
        let state = self.node.state();
        state.stream_open(stream) || state.stream_deleted(stream)
    }

    /// Whether an open other than this one is on `stream` of the file, the
    /// default stream when `None`.
    pub(crate) fn others_on(&self, stream: Option<&StreamName>) -> bool {
        self.node
            .state()
            .opens
            .iter()
            .any(|e| e.id != self.id && same_stream(e.stream.as_ref(), stream))
    }

    /// Whether this open, moved onto the default stream, passes the
    /// sharing checks against the file's other opens (MS-FSA 2.1.5.1.2.1,
    /// 2.1.5.1.2.2).
    pub(crate) fn admitted_on_default(&self) -> bool {
        let state = self.node.state();
        let Some(sharing) = state.entry(self.id).map(|e| e.sharing) else {
            return false;
        };
        !state
            .opens
            .iter()
            .any(|e| e.id != self.id && !e.waiting && e.conflicts_with(sharing, None))
    }

    /// Moves the opens on the stream `from` of the file, their byte-range
    /// locks and the stream's mark for deletion to `to`, which the backend
    /// just renamed it to; `None` is the default stream (MS-FSA
    /// 2.1.5.15.12.1). A named stream renamed to the default stream leaves
    /// its mark behind: the file is not deleted for it.
    ///
    /// The leases of the moved opens move with them. An open moved off
    /// the default stream is no longer durable, and its lease breaks to
    /// NONE: the file it cached is empty now. A named stream renamed to
    /// another name breaks the handle caching of the leases on it, all but
    /// this open's (MS-FSA 2.1.5.15.12).
    pub(crate) fn rename_stream(&self, from: Option<&StreamName>, to: Option<&StreamName>) {
        let notices = {
            let mut state = self.node.state();
            let state = &mut *state;
            let own = state.entry(self.id).and_then(|e| e.lease);
            let moved = |stream: &Option<StreamName>| same_stream(stream.as_ref(), from);
            let mut leases = Vec::new();
            for entry in state.opens.iter_mut().filter(|e| moved(&e.stream)) {
                entry.stream = to.cloned();
                leases.extend(entry.lease);
                if from.is_none() {
                    entry.durable = None;
                }
            }
            for lock in state.locks.iter_mut().filter(|l| moved(&l.stream)) {
                lock.stream = to.cloned();
            }
            for lease in state.leases.iter_mut().filter(|l| leases.contains(&l.id)) {
                lease.stream = to.cloned();
            }
            if let Some(from) = from {
                let marked = state.stream_deleted(from);
                state.deleted_streams.retain(|s| !s.matches(from));
                if let Some(to) = to.filter(|_| marked) {
                    state.deleted_streams.push(to.clone());
                }
            }
            let mut notices = Notices::default();
            if from.is_none() {
                for id in leases {
                    let Some(at) = state.leases.iter().position(|l| l.id == id) else {
                        continue;
                    };
                    match &mut state.leases[at].breaking {
                        Some(breaking) => breaking.required = LeaseState::NONE,
                        None => state.start_break(at, LeaseState::NONE, &mut notices),
                    }
                }
            } else if to.is_some() {
                notices = state.break_for(Trigger::Handle, own, On::Stream(to)).0;
            }
            notices
        };
        drop(notices);
    }

    /// Sets or clears the delete-pending flag of the stream this open is on
    /// (MS-FSA 2.1.5.15.3). On the default stream or the directory that is
    /// the file's flag: the file is removed under this open's name when its
    /// last open closes. A named stream is removed when the last open on it
    /// closes.
    ///
    /// Marking the file or the stream breaks the handle caching of the
    /// leases on the stream this open is on, all but this open's, under the
    /// same lock, so no lease caches handles to it once it is marked
    /// (MS-FSA 2.1.4.12, 2.1.5.18). The leases on the file's named streams
    /// keep theirs when the file is marked; opens kept for reconnect under
    /// one no connected open holds are closed, so they do not keep the file.
    pub(crate) fn set_delete_pending(&self, delete: bool) {
        let notices = {
            let mut state = self.node.state();
            let Some(entry) = state.entry(self.id) else {
                return;
            };
            let (lease, path, stream) = (entry.lease, entry.path.clone(), entry.stream.clone());
            match stream {
                Some(stream) => {
                    state.deleted_streams.retain(|s| !s.matches(&stream));
                    if delete {
                        let notices = state
                            .break_for(Trigger::Handle, lease, On::Stream(Some(&stream)))
                            .0;
                        state.deleted_streams.push(stream);
                        notices
                    } else {
                        Notices::default()
                    }
                }
                None if delete => {
                    state.delete_pending = Some(path);
                    let mut notices = state.break_for(Trigger::Handle, lease, On::Stream(None)).0;
                    notices.close(state.doom_kept_on_streams(true));
                    notices
                }
                None => {
                    state.delete_pending = None;
                    Notices::default()
                }
            }
        };
        drop(notices);
    }

    /// Marks the named streams `streams` of the file for deletion after an
    /// overwrite of the file through this open: one an open is on goes when
    /// the last open on it closes, and keeps serving the opens already on it
    /// meanwhile, whose leases give up handle caching.
    /// Returns the streams no open is on, for [`FileRef::remove_streams`].
    pub(crate) fn delete_streams(&self, streams: Vec<StreamName>) -> Vec<StreamName> {
        let mut state = self.node.state();
        let mut unopened = Vec::new();
        let mut notices = Vec::new();
        for stream in streams {
            notices.push(
                state
                    .break_for(Trigger::Handle, None, On::Stream(Some(&stream)))
                    .0,
            );
            if !state.stream_deleted(&stream) {
                state.deleted_streams.push(stream.clone());
            }
            if !state.stream_open(&stream) {
                unopened.push(stream);
            }
        }
        drop(state);
        drop(notices);
        unopened
    }

    /// Removes the named streams `streams`, which
    /// [`FileRef::delete_streams`] marked, from the file. No CREATE runs
    /// meanwhile, so none can make a stream again before its mark is
    /// cleared.
    pub(crate) async fn remove_streams(&self, streams: Vec<StreamName>) {
        if streams.is_empty() {
            return;
        }
        let _renames = self.share.files.rename_lock().await;
        let path = self.path();
        let file_index = self.file_index();
        for stream in &streams {
            if let Err(e) = self
                .share
                .backend
                .remove_stream(&path, file_index, stream)
                .await
            {
                let e = stream_error(e);
                debug!(error = %e, path = %path, stream = ?stream.as_str(), "stream removal failed");
            }
        }
        let mut state = self.node.state();
        state
            .deleted_streams
            .retain(|d| !streams.iter().any(|s| s.matches(d)));
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
        let stream = state.entry(self.id).and_then(|e| e.stream.clone());
        if state.range_conflicts(self.id, stream.as_ref(), offset, length, exclusive, true) {
            return Err(ntstatus::STATUS_LOCK_NOT_GRANTED);
        }
        // MS-FSA 2.1.5.8: a lock breaks the leases on the stream, all but
        // the one this open holds, wherever the range lies. Under the same
        // lock no lease can be granted between the two. While another lease
        // still caches writes, which only an attribute-only open allows,
        // the lock is refused: a lock taken now would keep that client from
        // writing back. Lock requests do not wait, so the client retries.
        let exempt = state.entry(self.id).and_then(|e| e.lease);
        let on = On::Stream(stream.as_ref());
        let caching_writes = state.leases.iter().any(|l| {
            Some(l.id) != exempt && on.reaches(l.stream.as_ref()) && l.state.contains(LeaseState::W)
        });
        let notices = state.break_for(Trigger::Write, exempt, on).0;
        if !caching_writes {
            state.locks.push(RangeLock {
                owner: self.id,
                stream,
                offset,
                length,
                exclusive,
            });
        }
        drop(state);
        drop(notices);
        if caching_writes {
            return Err(ntstatus::STATUS_LOCK_NOT_GRANTED);
        }
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
        let state = self.node.state();
        let stream = state.entry(self.id).and_then(|e| e.stream.as_ref());
        if state.range_conflicts(self.id, stream, offset, length, write, false) {
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
        let mut doomed = Notices::default();
        let pending = self.detach_entry(delete_on_close, &mut doomed);
        drop(doomed);
        pending
    }

    /// [`FileRef::detach`] under the table's locks; the kept opens it
    /// dooms go to `doomed`, to close once the locks are released.
    fn detach_entry(
        &mut self,
        delete_on_close: bool,
        doomed: &mut Notices,
    ) -> Option<PendingDelete> {
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
            && state.holders(id).next().is_none()
        {
            state.leases.retain(|l| l.id != id);
        }
        if entry.is_some() {
            state.bump();
        }
        let entry = entry?;
        if delete_on_close {
            match &entry.stream {
                Some(stream) if !state.stream_deleted(stream) => {
                    state.deleted_streams.push(stream.clone());
                }
                Some(_) => {}
                None => {
                    state.delete_pending = Some(entry.path.clone());
                    doomed.close(state.doom_kept_on_streams(true));
                }
            }
        }
        let is_directory = state.is_directory;
        let pending = |path, stream| PendingDelete {
            share: Arc::clone(&self.share),
            node: Arc::clone(&self.node),
            path,
            stream,
            is_directory,
        };
        if state.opens.is_empty()
            && let Some(path) = state.delete_pending.clone()
        {
            return Some(pending(path, None));
        }
        if let Some(stream) = entry.stream
            && state.stream_deleted(&stream)
            && !state.stream_open(&stream)
        {
            return Some(pending(entry.path, Some(stream)));
        }
        // A stream removal still running keeps the node until it is done.
        if !state.opens.is_empty() || !state.deleted_streams.is_empty() {
            return None;
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

/// True if `path` lies below the directory `dir`.
fn is_below(path: &SmbPath, dir: &SmbPath, case_sensitive: bool) -> bool {
    path.components().len() > dir.components().len()
        && rebase(path, dir, dir, case_sensitive).is_some()
}

fn remove_node(files: &mut HashMap<FileKey, Arc<FileNode>>, key: &FileKey, node: &Arc<FileNode>) {
    if files.get(key).is_some_and(|n| Arc::ptr_eq(n, node)) {
        files.remove(key);
    }
}

/// A delete-pending file whose last open has closed, or a named stream
/// marked for deletion whose last open has closed. Dropping it frees the
/// name, or the stream, in the table, whether or not the removal ran.
pub(crate) struct PendingDelete {
    share: Arc<ShareBindings>,
    node: Arc<FileNode>,
    path: SmbPath,
    /// The named stream to remove; `None` to remove the file.
    stream: Option<StreamName>,
    is_directory: bool,
}

impl PendingDelete {
    /// Whether this removes a named stream, not the file.
    pub(crate) fn is_stream(&self) -> bool {
        self.stream.is_some()
    }

    /// Removes the file from the share, reports the removal to the share's
    /// watchers (MS-FSA 2.1.5.5), then frees its name in the table. A
    /// failed delete does not fail the close (MS-SMB2 3.3.4.17); a
    /// directory that gained entries stays (MS-FSA 2.1.5.5). A named
    /// stream is removed from the file its opens are on.
    pub(crate) async fn run(self) {
        if let Some(stream) = self.stream.clone() {
            // No CREATE runs until the mark is cleared, so none can make the
            // stream again in between, and no rename moves the file.
            let share = Arc::clone(&self.share);
            let _renames = share.files.rename_lock().await;
            let (path, file_index) = {
                let state = self.node.state();
                (state.name.clone(), state.key.file_index())
            };
            if let Err(e) = share
                .backend
                .remove_stream(&path, file_index, &stream)
                .await
            {
                let e = stream_error(e);
                debug!(error = %e, path = %path, stream = ?stream.as_str(), "stream removal failed");
            }
            drop(self);
            return;
        }
        let _names = self.share.files.names_lock().await;
        // A rename that ran while this waited moved the name.
        let path = self
            .node
            .state()
            .delete_pending
            .clone()
            .unwrap_or_else(|| self.path.clone());
        let filter = if self.is_directory {
            FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            FILE_NOTIFY_CHANGE_FILE_NAME
        };
        let removed = [Change {
            path: &path,
            stream: None,
            action: FILE_ACTION_REMOVED,
            filter,
            seen: true,
        }];
        let expected = self.share.watches.expect(&removed, None);
        match self.share.backend.unlink(&path).await {
            Ok(()) => expected.report(&self.share.watches, &removed),
            Err(SmbError::NotEmpty) => {
                debug!(path = %path, "delete-on-close skipped a non-empty directory");
            }
            Err(e) => warn!(error = %e, path = %path, "delete-on-close failed"),
        }
    }
}

impl Drop for PendingDelete {
    fn drop(&mut self) {
        let mut files = self.share.files.files();
        let mut state = self.node.state();
        if let Some(stream) = &self.stream {
            state.deleted_streams.retain(|s| !s.matches(stream));
            if !state.opens.is_empty()
                || state.delete_pending.is_some()
                || !state.deleted_streams.is_empty()
            {
                return;
            }
        }
        let key = state.key.clone();
        drop(state);
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
        .map(|(file, _)| file)
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
        .unwrap()
        .0;
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
