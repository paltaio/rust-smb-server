//! Leases across the server: which file each lease is bound to (MS-SMB2
//! 3.3.1.11), and delivery of lease break notifications (MS-SMB2 3.3.4.7).
//!
//! Lock order: the durable table, then `LeaseTable` bindings, then a
//! share's file table, then a file, then a connection's outbound queue.
//! Notifications are delivered after every file lock is released.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use tracing::debug;

use crate::conn::outbound::Outbound;
use crate::conn::writer::NoticeError;
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
use crate::proto::header::{Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
use crate::proto::messages::LeaseBreakNotification;
use crate::server::ShareBindings;

use super::lease::{FileLease, Granted, LeaseId, LeaseRequest, LeaseState, LeaseVersion};
use super::table::{DurableMark, FileNode, FileRef};

/// How long a client has to acknowledge a lease break before the lease
/// drops to NONE (MS-SMB2 3.3.2.5; Windows servers wait 35 seconds).
pub(crate) const LEASE_BREAK_TIMEOUT: Duration = Duration::from_secs(35);

/// Extra time an operation waiting for a break allows past
/// [`LEASE_BREAK_TIMEOUT`] before it gives up, in case a timer was lost.
const WAIT_SLACK: Duration = Duration::from_secs(5);

/// The longest a request waits for lease breaks: a handle break and then a
/// write break, each up to [`LEASE_BREAK_TIMEOUT`], plus slack.
pub(crate) const MAX_BREAK_WAIT: Duration =
    Duration::from_secs(2 * LEASE_BREAK_TIMEOUT.as_secs() + WAIT_SLACK.as_secs());

/// Every lease on the server, by client and key.
#[derive(Default)]
pub(crate) struct LeaseTable {
    bindings: Mutex<HashMap<LeaseId, Binding>>,
}

struct Binding {
    /// The share of the file the lease was last bound to.
    share: Weak<ShareBindings>,
    /// The file the lease was last bound to. The lease is held there only
    /// while that file has it; otherwise the binding is free to move.
    node: Option<Arc<FileNode>>,
    /// Opens holding the lease and CREATEs in progress with its key.
    refs: usize,
}

/// One open's or one CREATE's use of a lease binding. Dropping the last
/// one removes the binding.
pub(crate) struct LeaseRef {
    table: Arc<LeaseTable>,
    id: LeaseId,
}

impl LeaseTable {
    fn bindings(&self) -> MutexGuard<'_, HashMap<LeaseId, Binding>> {
        self.bindings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes a use of the lease `id` for a CREATE of `path` on `share`.
    /// Fails with STATUS_INVALID_PARAMETER when the lease is held on
    /// another file, by name or by share (MS-SMB2 3.3.5.9.8, 3.3.5.9.11).
    pub(crate) fn acquire(
        self: &Arc<Self>,
        id: LeaseId,
        share: &Arc<ShareBindings>,
        path: &SmbPath,
    ) -> Result<LeaseRef, u32> {
        let mut bindings = self.bindings();
        let binding = bindings.entry(id).or_insert_with(|| Binding {
            share: Weak::new(),
            node: None,
            refs: 0,
        });
        if let Some(paths) = binding.node.as_ref().and_then(|n| n.lease_paths(id)) {
            let case_sensitive = share.backend.capabilities().case_sensitive;
            let same_share = binding
                .share
                .upgrade()
                .is_some_and(|s| Arc::ptr_eq(&s, share));
            if !same_share || !paths.iter().any(|p| same_path(p, path, case_sensitive)) {
                return Err(ntstatus::STATUS_INVALID_PARAMETER);
            }
        }
        binding.refs += 1;
        Ok(LeaseRef {
            table: Arc::clone(self),
            id,
        })
    }

    /// Binds `lease` to the file `file` opened and grants the state `req`
    /// asks for, within `grantable`. The open keeps `lease`. Fails with
    /// STATUS_INVALID_PARAMETER when the lease is held on another file.
    pub(crate) fn grant(
        &self,
        lease: LeaseRef,
        file: &mut FileRef,
        req: &LeaseRequest,
        grantable: LeaseState,
    ) -> Result<(Granted, GrantGuard), u32> {
        let granted = {
            let mut bindings = self.bindings();
            let binding = bindings
                .get_mut(&req.id)
                .expect("a LeaseRef keeps its binding");
            match &binding.node {
                Some(node) if !file.is_on(node) && node.has_lease(req.id) => {
                    Err(ntstatus::STATUS_INVALID_PARAMETER)
                }
                _ => {
                    binding.node = Some(Arc::clone(file.node()));
                    binding.share = Arc::downgrade(file.share());
                    Ok(file.grant_lease(req, grantable))
                }
            }
        };
        match granted {
            Ok(granted) => {
                file.keep_lease(lease);
                Ok(granted)
            }
            Err(status) => {
                drop(lease);
                Err(status)
            }
        }
    }

    /// MS-SMB2 3.3.5.22.2: completes a break of the lease `id` with the
    /// state `bits` the client acknowledged; see [`FileNode::acknowledge`].
    /// A further break it starts is returned to send after the response.
    pub(crate) fn acknowledge(&self, id: LeaseId, bits: u32) -> Result<(LeaseState, Notices), u32> {
        let node = self
            .bindings()
            .get(&id)
            .and_then(|b| b.node.clone())
            .ok_or(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)?;
        node.acknowledge(id, bits)
    }

    /// Whether the lease `id` is held on a file.
    #[cfg(test)]
    pub(crate) fn exists(&self, id: LeaseId) -> bool {
        self.bindings()
            .get(&id)
            .and_then(|b| b.node.as_ref())
            .is_some_and(|n| n.has_lease(id))
    }
}

impl Drop for LeaseRef {
    fn drop(&mut self) {
        let mut bindings = self.table.bindings();
        if let Some(binding) = bindings.get_mut(&self.id) {
            binding.refs -= 1;
            if binding.refs == 0 {
                bindings.remove(&self.id);
            }
        }
    }
}

/// Something held until a response is queued: a [`GrantGuard`] or
/// [`Notices`]. Dropping it sends the lease breaks that have to follow the
/// response on the wire.
pub(crate) type AfterSend = Box<dyn Send + Sync>;

/// Holds back break notifications for a lease until the CREATE response
/// that granted it is queued; dropping it sends what was held back.
pub(crate) struct GrantGuard {
    node: Arc<FileNode>,
    id: LeaseId,
    /// The lease the grant was made on, not a later one with its id.
    serial: u64,
    /// The connection the CREATE response goes out on.
    sender: Weak<Outbound>,
}

impl GrantGuard {
    pub(super) fn new(
        node: Arc<FileNode>,
        id: LeaseId,
        serial: u64,
        sender: Weak<Outbound>,
    ) -> Self {
        Self {
            node,
            id,
            serial,
            sender,
        }
    }
}

impl Drop for GrantGuard {
    fn drop(&mut self) {
        drop(self.node.end_grant(self.id, self.serial, &self.sender));
    }
}

/// A break the client has to acknowledge: the lease and which break.
#[derive(Debug)]
pub(crate) struct AckWait {
    pub node: Weak<FileNode>,
    pub id: LeaseId,
    pub seq: u64,
}

/// A wait for a file's leases or opens to change, bounded by the
/// acknowledgment timeout and some slack in case a timer was lost.
#[derive(Debug)]
pub(crate) struct BreakWait {
    rx: watch::Receiver<u64>,
    deadline: Instant,
}

impl BreakWait {
    pub(super) fn new(rx: watch::Receiver<u64>) -> Self {
        Self {
            rx,
            deadline: Instant::now() + LEASE_BREAK_TIMEOUT + WAIT_SLACK,
        }
    }

    /// Resolves at the next change or once the file is gone, returning
    /// true, or at the deadline, returning false. Starting a break's
    /// acknowledgment timer counts as a change, so a wait begun before then
    /// outlasts the timer.
    pub(crate) async fn changed(&mut self) -> bool {
        tokio::select! {
            _ = self.rx.changed() => true,
            () = tokio::time::sleep_until(self.deadline) => false,
        }
    }
}

/// Lease break notifications to send, each with the connections it may go
/// to, and opens kept for reconnect that a break closes. Dropping it sends
/// and closes them, so it is dropped only after every file lock is released.
#[derive(Default)]
pub(crate) struct Notices(Vec<Notice>);

enum Notice {
    /// One break notification, the connections it may go to in order, and
    /// the acknowledgment it needs.
    Send {
        bytes: Vec<u8>,
        owners: Vec<Weak<Outbound>>,
        ack: Option<AckWait>,
    },
    /// Opens kept for reconnect that no client can take back any more.
    Close(Vec<DurableMark>),
}

impl Notices {
    pub(super) fn push(
        &mut self,
        bytes: Vec<u8>,
        owners: Vec<Weak<Outbound>>,
        ack: Option<AckWait>,
    ) {
        self.0.push(Notice::Send { bytes, owners, ack });
    }

    pub(super) fn close(&mut self, opens: Vec<DurableMark>) {
        if !opens.is_empty() {
            self.0.push(Notice::Close(opens));
        }
    }
}

impl Drop for Notices {
    /// Sends each notification on the first connection that takes it
    /// (MS-SMB2 3.3.4.7). A connection whose queue of unsolicited messages
    /// is full has not read for a long time and is closed. A sent break that
    /// needs an acknowledgment starts its timer; one no connection took
    /// drops the lease to NONE. Kept opens to close are closed on tasks of
    /// the current runtime.
    fn drop(&mut self) {
        for notice in self.0.drain(..) {
            let (bytes, owners, ack) = match notice {
                Notice::Send { bytes, owners, ack } => (bytes, owners, ack),
                Notice::Close(opens) => {
                    for mark in opens {
                        if let Some(table) = mark.table.upgrade() {
                            table.purge(mark.id);
                        }
                    }
                    continue;
                }
            };
            let delivered = owners
                .iter()
                .filter_map(Weak::upgrade)
                .any(|outbound| match outbound.try_send_notice(bytes.clone()) {
                    Ok(()) => true,
                    Err(NoticeError::Full) => {
                        outbound.kill();
                        false
                    }
                    Err(NoticeError::Closed) => false,
                });
            if delivered {
                debug!("lease break sent");
            } else {
                debug!("lease break not delivered; no connection took it");
            }
            match ack {
                Some(ack) if delivered => start_timer(ack),
                Some(ack) => {
                    if let Some(node) = ack.node.upgrade() {
                        drop(node.drop_break(ack.id, ack.seq));
                    }
                }
                None => {}
            }
        }
    }
}

/// Starts the acknowledgment timer of a sent break (MS-SMB2 3.3.6.5).
fn start_timer(ack: AckWait) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let AckWait { node, id, seq } = ack;
    let timer = runtime.spawn({
        let node = node.clone();
        async move {
            tokio::time::sleep(LEASE_BREAK_TIMEOUT).await;
            if let Some(node) = node.upgrade() {
                drop(node.drop_break(id, seq));
            }
        }
    });
    match node.upgrade() {
        Some(node) => node.set_timer(id, seq, timer.abort_handle()),
        None => timer.abort(),
    }
}

/// Lease Break Notification for `lease` breaking from `from` to `to`
/// (MS-SMB2 2.2.23.2, 3.3.4.7): unsigned, SessionId and TreeId 0,
/// MessageId all ones, no credits.
pub(super) fn break_notification(
    lease: &FileLease,
    from: LeaseState,
    to: LeaseState,
    ack: bool,
) -> Vec<u8> {
    let hdr = Smb2Header {
        command: Command::OplockBreak,
        flags: SMB2_FLAGS_SERVER_TO_REDIR,
        message_id: u64::MAX,
        tail: HeaderTail::sync(0),
        ..Smb2Header::default()
    };
    let body = LeaseBreakNotification {
        structure_size: 44,
        new_epoch: match lease.version {
            LeaseVersion::V1 => 0,
            LeaseVersion::V2 => lease.epoch,
        },
        flags: if ack {
            LeaseBreakNotification::FLAG_ACK_REQUIRED
        } else {
            0
        },
        lease_key: lease.id.key,
        current_lease_state: from.bits(),
        new_lease_state: to.bits(),
        break_reason: 0,
        access_mask_hint: 0,
        share_mask_hint: 0,
    };
    let mut out = Vec::with_capacity(64 + 44);
    hdr.write(&mut out)
        .expect("encoding into a Vec cannot fail");
    body.write_to(&mut out)
        .expect("encoding into a Vec cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use super::*;
    use crate::access_mask::{FILE_READ_DATA, FILE_WRITE_DATA};
    use crate::backend::FileInfo;
    use crate::conn::writer::{ResponseReceiver, response_queue};
    use crate::files::durable::DurableTable;
    use crate::files::lease::Trigger;
    use crate::files::table::{OpenRequest, Refused, Sharing};
    use crate::server::ShareMode;
    use crate::tests::memfs::MemFsBackend;

    const ALL: u32 = 7;

    fn share() -> Arc<ShareBindings> {
        ShareBindings::new(
            "s".to_string(),
            Arc::new(MemFsBackend::new()),
            ShareMode::Public,
            HashMap::new(),
            false,
            true,
            true,
        )
    }

    fn id(n: u8) -> LeaseId {
        LeaseId {
            client: Uuid::nil(),
            key: [n; 16],
        }
    }

    fn req(n: u8) -> LeaseRequest {
        LeaseRequest {
            id: id(n),
            state: LeaseState::requested(7),
            version: LeaseVersion::V2,
            epoch: 0,
            parent: None,
        }
    }

    fn p(s: &str) -> SmbPath {
        s.parse().unwrap()
    }

    fn connection() -> (Arc<Outbound>, ResponseReceiver) {
        let (tx, rx) = response_queue();
        let outbound = Arc::new(Outbound::default());
        outbound.attach(tx);
        (outbound, rx)
    }

    /// Registers a read-write open of file `index` named `name`.
    fn open(
        share: &Arc<ShareBindings>,
        index: u64,
        name: &str,
        owner: &Arc<Outbound>,
        lease: Option<LeaseId>,
    ) -> FileRef {
        let mut info = FileInfo::new("");
        info.file_index = index;
        let req = OpenRequest {
            sharing: Sharing {
                access: FILE_READ_DATA | FILE_WRITE_DATA,
                share: ALL,
            },
            owner: Arc::downgrade(owner),
            lease,
            overwrite: false,
            break_handles: false,
        };
        FileRef::register(share, &info, &p(name), req).unwrap().0
    }

    /// Opens file `index` as `name` holding the lease `n`.
    fn leased(
        table: &Arc<LeaseTable>,
        share: &Arc<ShareBindings>,
        index: u64,
        name: &str,
        owner: &Arc<Outbound>,
        n: u8,
    ) -> Result<(FileRef, Granted, GrantGuard), u32> {
        let lease_ref = table.acquire(id(n), share, &p(name))?;
        let mut file = open(share, index, name, owner, Some(id(n)));
        let (granted, guard) = table.grant(lease_ref, &mut file, &req(n), LeaseState::R)?;
        Ok((file, granted, guard))
    }

    /// Opens file 7 as `f` holding RH under the lease `n`, sharing read and
    /// write only.
    fn hold_rh(
        table: &Arc<LeaseTable>,
        share: &Arc<ShareBindings>,
        owner: &Arc<Outbound>,
        n: u8,
    ) -> FileRef {
        let lease_ref = table.acquire(id(n), share, &p("f")).unwrap();
        let mut info = FileInfo::new("");
        info.file_index = 7;
        let req = OpenRequest {
            sharing: Sharing {
                access: FILE_READ_DATA | FILE_WRITE_DATA,
                share: 3,
            },
            owner: Arc::downgrade(owner),
            lease: Some(id(n)),
            overwrite: false,
            break_handles: true,
        };
        let mut file = FileRef::register(share, &info, &p("f"), req).unwrap().0;
        let (granted, _) = table
            .grant(lease_ref, &mut file, &req_state(n, 7), LeaseState::RH)
            .unwrap();
        assert_eq!(granted.state, LeaseState::RH);
        file
    }

    fn req_state(n: u8, bits: u32) -> LeaseRequest {
        LeaseRequest {
            state: LeaseState::requested(bits),
            ..req(n)
        }
    }

    /// A DELETE open of file 7 that the RH holder's sharing refuses.
    fn conflicting(share: &Arc<ShareBindings>, owner: &Arc<Outbound>) -> Refused {
        let mut info = FileInfo::new("");
        info.file_index = 7;
        let req = OpenRequest {
            sharing: Sharing {
                access: crate::access_mask::DELETE,
                share: ALL,
            },
            owner: Arc::downgrade(owner),
            lease: None,
            overwrite: false,
            break_handles: true,
        };
        FileRef::register(share, &info, &p("f"), req).err().unwrap()
    }

    fn ack(table: &LeaseTable, id: LeaseId, bits: u32) -> Result<LeaseState, u32> {
        table.acknowledge(id, bits).map(|(state, _)| state)
    }

    fn notification(frame: &[u8]) -> LeaseBreakNotification {
        LeaseBreakNotification::parse(&frame[64..]).unwrap()
    }

    #[test]
    fn acknowledgments_are_checked_and_settle_the_lease() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, mut rx) = connection();
        let _held = hold_rh(&table, &s, &holder, 1);
        let writer = open(&s, 7, "f", &holder, None);
        writer.break_leases(Trigger::Write);
        let n = notification(&rx.try_recv().unwrap());
        assert_eq!(n.flags, LeaseBreakNotification::FLAG_ACK_REQUIRED);
        assert_eq!((n.current_lease_state, n.new_lease_state), (3, 0));
        assert_eq!(n.new_epoch, 2);

        assert_eq!(
            ack(&table, id(1), 1),
            Err(ntstatus::STATUS_REQUEST_NOT_ACCEPTED)
        );
        assert_eq!(
            ack(&table, id(2), 0),
            Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(ack(&table, id(1), 0), Ok(LeaseState::NONE));
        assert_eq!(ack(&table, id(1), 0), Err(ntstatus::STATUS_UNSUCCESSFUL));
        assert!(rx.try_recv().is_none());
    }

    #[test]
    fn a_later_trigger_lowers_what_the_acknowledgment_settles_on() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, mut rx) = connection();
        let _held = hold_rh(&table, &s, &holder, 1);
        let refused = conflicting(&s, &holder);
        assert_eq!(refused.status, ntstatus::STATUS_SHARING_VIOLATION);
        assert!(refused.wait.is_some());
        let n = notification(&rx.try_recv().unwrap());
        assert_eq!((n.current_lease_state, n.new_lease_state), (3, 1));

        // A second violation during the break waits without a notification.
        assert!(conflicting(&s, &holder).wait.is_some());
        let writer = open(&s, 7, "f", &holder, None);
        writer.break_leases(Trigger::Write);
        assert!(rx.try_recv().is_none());

        let (state, breaks) = table.acknowledge(id(1), 1).unwrap();
        assert_eq!(state, LeaseState::R);
        assert!(
            rx.try_recv().is_none(),
            "the further break waits for the response"
        );
        drop(breaks);
        let n = notification(&rx.try_recv().unwrap());
        assert_eq!(n.flags, 0);
        assert_eq!((n.current_lease_state, n.new_lease_state), (1, 0));
        // Over now: a violation fails without waiting.
        drop(writer);
        assert!(conflicting(&s, &holder).wait.is_none());
    }

    #[test]
    fn a_stale_timer_changes_nothing() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, _rx) = connection();
        let held = hold_rh(&table, &s, &holder, 1);
        open(&s, 7, "f", &holder, None).break_leases(Trigger::Write);
        // Break sequence numbers start at 1.
        drop(held.node().drop_break(id(1), 0));
        assert_eq!(ack(&table, id(1), 0), Ok(LeaseState::NONE));
    }

    #[test]
    fn a_break_no_connection_takes_drops_the_lease_to_none() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, rx) = connection();
        let _held = hold_rh(&table, &s, &holder, 1);
        drop(rx);
        let refused = conflicting(&s, &holder);
        assert!(refused.wait.is_some());
        assert_eq!(ack(&table, id(1), 1), Err(ntstatus::STATUS_UNSUCCESSFUL));
    }

    #[test]
    fn an_open_beside_write_caching_waits_for_the_write_back() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, mut rx) = connection();
        let lease_ref = table.acquire(id(1), &s, &p("f")).unwrap();
        let mut held = open(&s, 7, "f", &holder, Some(id(1)));
        let (granted, _) = table
            .grant(lease_ref, &mut held, &req(1), LeaseState::RWH)
            .unwrap();
        assert_eq!(granted.state, LeaseState::RWH);

        let mut info = FileInfo::new("");
        info.file_index = 7;
        let request = OpenRequest {
            sharing: Sharing {
                access: FILE_READ_DATA,
                share: ALL,
            },
            owner: Arc::downgrade(&holder),
            lease: None,
            overwrite: false,
            break_handles: true,
        };
        let (other, wait) = FileRef::register(&s, &info, &p("f"), request).unwrap();
        assert!(wait.is_some());
        let n = notification(&rx.try_recv().unwrap());
        assert_eq!(n.flags, LeaseBreakNotification::FLAG_ACK_REQUIRED);
        assert_eq!((n.current_lease_state, n.new_lease_state), (7, 3));
        assert!(matches!(other.end_wait(), Ok(Some(_))));

        assert_eq!(ack(&table, id(1), 3), Ok(LeaseState::RH));
        // The waiting open keeps the holder from taking write caching back
        // before it has run its own checks.
        let lease_ref = table.acquire(id(1), &s, &p("f")).unwrap();
        let mut early = open(&s, 7, "f", &holder, Some(id(1)));
        let (granted, _) = table
            .grant(lease_ref, &mut early, &req(1), LeaseState::RWH)
            .unwrap();
        assert_eq!(granted.state, LeaseState::RH);
        assert!(matches!(other.end_wait(), Ok(None)));
        // The other open keeps the holder from taking write caching back.
        let lease_ref = table.acquire(id(1), &s, &p("f")).unwrap();
        let mut again = open(&s, 7, "f", &holder, Some(id(1)));
        let (granted, _) = table
            .grant(lease_ref, &mut again, &req(1), LeaseState::RWH)
            .unwrap();
        assert_eq!(granted.state, LeaseState::RH);
    }

    #[test]
    fn handle_caching_is_refused_on_a_delete_pending_file() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (owner, _rx) = connection();
        // The file turns delete-pending between the open and its grant.
        let lease_ref = table.acquire(id(1), &s, &p("f")).unwrap();
        let mut file = open(&s, 7, "f", &owner, Some(id(1)));
        open(&s, 7, "f", &owner, None).set_delete_pending(true);
        let (granted, _) = table
            .grant(lease_ref, &mut file, &req(1), LeaseState::RH)
            .unwrap();
        assert_eq!(granted.state, LeaseState::R);
    }

    #[test]
    fn marking_a_file_delete_pending_breaks_handle_caching() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, mut rx) = connection();
        let _held = hold_rh(&table, &s, &holder, 1);
        let deleter = open(&s, 7, "f", &holder, None);
        deleter.set_delete_pending(true);
        let n = notification(&rx.try_recv().unwrap());
        assert_eq!((n.current_lease_state, n.new_lease_state), (3, 1));
        assert!(deleter.delete_pending());
    }

    #[tokio::test]
    async fn a_waiting_open_wakes_when_the_holder_closes() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, _rx) = connection();
        let held = hold_rh(&table, &s, &holder, 1);
        // The first refusal starts the break, whose timer counts as a
        // change; the second waits on the break in progress.
        let mut started = conflicting(&s, &holder).wait.unwrap();
        assert!(started.changed().await);
        let mut wait = conflicting(&s, &holder).wait.unwrap();
        let woke = tokio::spawn(async move { wait.changed().await });
        tokio::task::yield_now().await;
        assert!(!woke.is_finished());
        drop(held);
        woke.await.unwrap();
        assert!(!table.exists(id(1)));
    }

    #[test]
    fn opens_with_one_key_share_one_lease_until_the_last_closes() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (owner, _rx) = connection();
        let (a, granted, _) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        assert_eq!(granted.state, LeaseState::R);
        assert_eq!(granted.epoch, 1);
        let (b, again, _) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        assert_eq!((again.state, again.epoch), (LeaseState::R, 1));
        assert!(table.exists(id(1)));
        drop(a);
        assert!(table.exists(id(1)));
        drop(b);
        assert!(!table.exists(id(1)));
        assert!(table.bindings().is_empty());
    }

    #[test]
    fn a_held_key_fails_on_another_name_file_or_share() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (owner, _rx) = connection();
        let (_a, _, _) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        let invalid = Some(ntstatus::STATUS_INVALID_PARAMETER);
        assert_eq!(table.acquire(id(1), &s, &p("g")).err(), invalid);
        assert_eq!(table.acquire(id(1), &share(), &p("f")).err(), invalid);
        assert_eq!(table.bindings()[&id(1)].refs, 1);
    }

    #[test]
    fn of_two_creates_racing_with_one_key_the_second_bind_fails() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (owner, _rx) = connection();
        let first = table.acquire(id(1), &s, &p("f")).unwrap();
        let second = table.acquire(id(1), &s, &p("g")).unwrap();
        let mut f = open(&s, 7, "f", &owner, Some(id(1)));
        let mut g = open(&s, 8, "g", &owner, Some(id(1)));
        let (_, guard) = table.grant(first, &mut f, &req(1), LeaseState::R).unwrap();
        drop(guard);
        let lost = table.grant(second, &mut g, &req(1), LeaseState::R);
        assert!(matches!(lost, Err(ntstatus::STATUS_INVALID_PARAMETER)));
        drop(g);
        assert_eq!(table.bindings()[&id(1)].refs, 1);
        drop(f);
        assert!(table.bindings().is_empty());
    }

    #[test]
    fn a_key_whose_lease_ended_binds_again_elsewhere() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (owner, _rx) = connection();
        let held = table.acquire(id(1), &s, &p("f")).unwrap();
        let (f, _, _) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        drop(f);
        // `held` keeps the binding alive, but the lease has no open left.
        let (_g, granted, _) = leased(&table, &s, 8, "g", &owner, 1).unwrap();
        assert_eq!(granted.state, LeaseState::R);
        drop(held);
        assert!(table.exists(id(1)));
    }

    #[test]
    fn a_break_waits_for_the_grant_to_be_sent() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (holder, mut holder_rx) = connection();
        let (writer, mut writer_rx) = connection();
        let (_a, _, guard) = leased(&table, &s, 7, "f", &holder, 1).unwrap();
        let b = open(&s, 7, "f", &writer, None);
        b.break_leases(Trigger::Write);
        assert!(holder_rx.try_recv().is_none(), "held back for the grant");
        drop(guard);
        let frame = holder_rx.try_recv().expect("break after the grant");
        let (hdr, body) = Smb2Header::parse(&frame).unwrap();
        assert_eq!(hdr.command, Command::OplockBreak);
        assert_eq!(hdr.message_id, u64::MAX);
        assert_eq!(hdr.session_id, 0);
        let notification = LeaseBreakNotification::parse(body).unwrap();
        assert_eq!(notification.lease_key, [1; 16]);
        assert_eq!(notification.flags, 0);
        assert_eq!(notification.current_lease_state, LeaseState::R.bits());
        assert_eq!(notification.new_lease_state, 0);
        assert_eq!(notification.new_epoch, 2);
        assert!(writer_rx.try_recv().is_none());

        // Broken to NONE, the lease breaks no further.
        b.break_leases(Trigger::Write);
        assert!(holder_rx.try_recv().is_none());
    }

    #[test]
    fn a_hold_on_an_ended_lease_leaves_its_successor_alone() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (owner, mut rx) = connection();
        let plain = open(&s, 7, "f", &owner, None);
        let (first, _, first_guard) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        drop(first);
        let (_second, _, second_guard) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        plain.break_leases(Trigger::Write);
        drop(first_guard);
        assert!(rx.try_recv().is_none(), "still held for the second grant");
        drop(second_guard);
        assert!(rx.try_recv().is_some());
    }

    #[test]
    fn a_held_back_break_goes_to_the_connection_of_the_grant() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (first, mut first_rx) = connection();
        let (second, mut second_rx) = connection();
        let (_a, _, guard) = leased(&table, &s, 7, "f", &first, 1).unwrap();
        drop(guard);
        let (_b, _, guard) = leased(&table, &s, 7, "f", &second, 1).unwrap();
        let plain = open(&s, 7, "f", &first, None);
        plain.break_leases(Trigger::Write);
        drop(guard);
        assert!(second_rx.try_recv().is_some());
        assert!(first_rx.try_recv().is_none());
    }

    #[test]
    fn an_open_with_the_same_key_breaks_nothing() {
        let table = Arc::new(LeaseTable::default());
        let s = share();
        let (owner, mut rx) = connection();
        let (a, _, guard) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        drop(guard);
        let (b, _, guard) = leased(&table, &s, 7, "f", &owner, 1).unwrap();
        drop(guard);
        a.break_leases(Trigger::Write);
        b.break_leases(Trigger::Open { overwrite: true });
        assert!(rx.try_recv().is_none());
    }

    /// Opens file `index` as `name` holding the lease `n` with what `bits`
    /// asks for, sharing everything.
    fn lease_state(
        table: &Arc<LeaseTable>,
        share: &Arc<ShareBindings>,
        index: u64,
        name: &str,
        owner: &Arc<Outbound>,
        n: u8,
        bits: u32,
    ) -> FileRef {
        let lease_ref = table.acquire(id(n), share, &p(name)).unwrap();
        let mut file = open(share, index, name, owner, Some(id(n)));
        let (granted, _) = table
            .grant(lease_ref, &mut file, &req_state(n, bits), LeaseState::RWH)
            .unwrap();
        assert_eq!(granted.state, LeaseState::requested(bits));
        file
    }

    fn durable_table() -> Arc<DurableTable> {
        Arc::new(DurableTable::new(Duration::from_secs(60), 8))
    }

    #[test]
    fn only_a_durable_open_whose_lease_quietly_caches_handles_is_kept() {
        let table = Arc::new(LeaseTable::default());
        let durable = durable_table();
        let s = share();
        let (holder, _rx) = connection();

        let plain = lease_state(&table, &s, 1, "a", &holder, 1, 3);
        assert!(!plain.try_detach(), "not durable");

        let read = lease_state(&table, &s, 2, "b", &holder, 2, 1);
        read.mark_durable(&durable, 2);
        assert!(!read.try_detach(), "no handle caching");

        let locked = lease_state(&table, &s, 3, "c", &holder, 3, 3);
        locked.lock_range(0, 10, true, 8).unwrap();
        locked.mark_durable(&durable, 3);
        assert!(!locked.try_detach(), "locks without write caching");

        let writing = lease_state(&table, &s, 4, "d", &holder, 4, 7);
        writing.lock_range(0, 10, true, 8).unwrap();
        writing.mark_durable(&durable, 4);
        assert!(writing.try_detach(), "locks under write caching");
        assert!(!writing.try_detach(), "kept once");

        let breaking = lease_state(&table, &s, 5, "e", &holder, 5, 3);
        breaking.mark_durable(&durable, 5);
        open(&s, 5, "e", &holder, None).break_leases(Trigger::Write);
        assert!(!breaking.try_detach(), "break in progress");
    }

    #[test]
    fn a_break_of_a_lease_only_kept_opens_hold_sends_nothing() {
        let table = Arc::new(LeaseTable::default());
        let durable = durable_table();
        let s = share();
        let (holder, mut rx) = connection();
        let held = hold_rh(&table, &s, &holder, 1);
        held.mark_durable(&durable, 1);
        assert!(held.try_detach());

        let refused = conflicting(&s, &holder);
        assert_eq!(refused.status, ntstatus::STATUS_SHARING_VIOLATION);
        assert!(refused.wait.is_some(), "the break completes once it closes");
        assert!(rx.try_recv().is_none());
        // Nothing more goes out while the break is in progress.
        let writer = open(&s, 7, "f", &holder, None);
        writer.break_leases(Trigger::Write);
        assert!(rx.try_recv().is_none());
        drop(writer);
        drop(held);
        assert!(!table.exists(id(1)));
    }

    #[test]
    fn a_break_of_a_lease_with_an_attached_holder_goes_to_it() {
        let table = Arc::new(LeaseTable::default());
        let durable = durable_table();
        let s = share();
        let (first, mut first_rx) = connection();
        let (second, mut second_rx) = connection();
        let kept = hold_rh(&table, &s, &first, 1);
        let _attached = hold_rh(&table, &s, &second, 1);
        kept.mark_durable(&durable, 1);
        assert!(kept.try_detach());
        assert!(conflicting(&s, &second).wait.is_some());
        assert!(first_rx.try_recv().is_none());
        let n = notification(&second_rx.try_recv().expect("break"));
        assert_eq!((n.current_lease_state, n.new_lease_state), (3, 1));
    }

    #[test]
    fn a_full_connection_is_killed_and_the_next_one_tried() {
        let s = share();
        let table = Arc::new(LeaseTable::default());
        let (first, _first_rx) = connection();
        let (second, mut second_rx) = connection();
        let (_a, _, guard) = leased(&table, &s, 7, "f", &first, 1).unwrap();
        drop(guard);
        let (_b, _, guard) = leased(&table, &s, 7, "f", &second, 1).unwrap();
        drop(guard);
        while first.try_send_notice(vec![0; 64 * 1024]).is_ok() {}
        let writer = open(&s, 7, "f", &second, None);
        writer.break_leases(Trigger::Write);
        assert!(second_rx.try_recv().is_some());
        let killed = first.killed();
        tokio::pin!(killed);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(killed.as_mut().poll(&mut cx).is_ready());
    }
}
