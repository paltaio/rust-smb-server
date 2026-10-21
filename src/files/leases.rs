//! Leases across the server: which file each lease is bound to (MS-SMB2
//! 3.3.1.11), and delivery of lease break notifications (MS-SMB2 3.3.4.7).
//!
//! Lock order: `LeaseTable` bindings, then a share's file table, then a
//! file, then a connection's outbound queue. Notifications are delivered
//! after every file lock is released.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use tracing::debug;

use crate::conn::outbound::Outbound;
use crate::conn::writer::NoticeError;
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
use crate::proto::header::{Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
use crate::proto::messages::LeaseBreakNotification;
use crate::server::ShareBindings;

use super::lease::{FileLease, Granted, LeaseId, LeaseRequest, LeaseState, LeaseVersion};
use super::table::{FileNode, FileRef};

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

    /// Whether the lease `id` is held on a file.
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

/// Lease break notifications to send, each with the connections it may go
/// to. Dropping it sends them, so it is dropped only after every file lock
/// is released.
#[derive(Default)]
pub(crate) struct Notices(Vec<(Vec<u8>, Vec<Weak<Outbound>>)>);

impl Notices {
    pub(super) fn push(&mut self, bytes: Vec<u8>, owners: Vec<Weak<Outbound>>) {
        self.0.push((bytes, owners));
    }
}

impl Drop for Notices {
    /// Sends each notification on the first connection that takes it
    /// (MS-SMB2 3.3.4.7). A connection whose queue of unsolicited messages
    /// is full has not read for a long time and is closed.
    fn drop(&mut self) {
        for (bytes, owners) in self.0.drain(..) {
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
        }
    }
}

/// Lease Break Notification for `lease`, just moved from `from` to its
/// current state (MS-SMB2 2.2.23.2, 3.3.4.7): unsigned, SessionId and
/// TreeId 0, MessageId all ones, no credits. A read lease needs no
/// acknowledgment.
pub(super) fn break_notification(lease: &FileLease, from: LeaseState) -> Vec<u8> {
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
        flags: 0,
        lease_key: lease.id.key,
        current_lease_state: from.bits(),
        new_lease_state: lease.state.bits(),
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
    use crate::files::lease::Trigger;
    use crate::files::table::{OpenRequest, Sharing};
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
        };
        FileRef::register(share, &info, &p(name), req).unwrap()
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
