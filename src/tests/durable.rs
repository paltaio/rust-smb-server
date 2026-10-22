//! Durable opens kept after their session ends: expiry, breaks that close
//! them, and the session teardown paths, driven through the dispatcher with
//! time paused where the timers matter.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Notify, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;

use crate::Access;
use crate::dispatch::dispatch_frame;
use crate::error::SmbError;
use crate::files::{LEASE_BREAK_TIMEOUT, LeaseId};
use crate::ntstatus;
use crate::proto::crypto::{SigningAlgo, sign};
use crate::proto::header::SMB2_FLAGS_REPLAY_OPERATION;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    CreateContext, CreateRequest, CreateResponse, FileId, LeaseBreakAck, LeaseBreakNotification,
    LeaseContext, LockElement, LockRequest, ReadRequest, ReadResponse, WriteRequest,
};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{KEY, Peer, header, status};
use crate::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenOptions, Share,
    ShareBackend, SmbPath, SmbResult, SmbServer,
};

const CLIENT: Uuid = Uuid::from_bytes([0xC1; 16]);
const LEASE_KEY: [u8; 16] = [0xD1; 16];
const TIMEOUT: Duration = Duration::from_secs(60);

const READ_WRITE: u32 = 0x3;
const READ_ATTRIBUTES: u32 = 0x80;
const DELETE: u32 = 0x0001_0000;
const SHARE_READ_WRITE: u32 = 0x3;
const SHARE_ALL: u32 = 0x7;
const R: u32 = 0x1;
const RH: u32 = 0x3;
const RWH: u32 = 0x7;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

/// A server whose public share `home` holds f.txt, and a view of its files.
async fn server() -> (Arc<ServerState>, MemFsBackend) {
    let files = MemFsBackend::new().with_file("f.txt", b"data");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .durable_handle_timeout(TIMEOUT)
        .share(Share::new("home", files.clone()).public())
        .build()
        .expect("build");
    (server.state(), files)
}

/// The fields of a CREATE of f.txt these tests vary.
#[derive(Clone, Copy)]
struct Open {
    access: u32,
    share: u32,
    /// The lease state to ask for under `LEASE_KEY`.
    lease: Option<u32>,
    durable: bool,
    options: u32,
    /// The kept open to reconnect.
    reconnect: Option<FileId>,
    /// Ask for a version 2 durable handle, or reconnect one, with this
    /// CreateGuid and, for a request, this timeout in milliseconds.
    v2: Option<([u8; 16], u32)>,
    /// The name to open, when not f.txt.
    name: Option<&'static str>,
}

impl Default for Open {
    fn default() -> Self {
        Self {
            access: READ_WRITE,
            share: SHARE_ALL,
            lease: None,
            durable: false,
            options: 0,
            reconnect: None,
            v2: None,
            name: None,
        }
    }
}

impl Open {
    /// A durable open asking for `lease`.
    fn durable(lease: u32) -> Self {
        Self {
            lease: Some(lease),
            durable: true,
            ..Self::default()
        }
    }

    /// A reconnect of `file_id`, naming the lease it holds.
    fn reconnect(file_id: FileId, lease: u32) -> Self {
        Self {
            lease: Some(lease),
            reconnect: Some(file_id),
            ..Self::default()
        }
    }

    fn body(self) -> Vec<u8> {
        let name = crate::utils::utf16le(self.name.unwrap_or("f.txt"));
        let mut list = Vec::new();
        if let Some(state) = self.lease {
            list.push(CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: LeaseContext {
                    key: LEASE_KEY,
                    state,
                    ..LeaseContext::default()
                }
                .encode(),
            });
        }
        match (self.durable, self.v2) {
            (true, None) => list.push(CreateContext {
                name: CreateContext::NAME_DHNQ.to_vec(),
                data: vec![0; 16],
            }),
            (true, Some((guid, timeout))) => {
                let mut data = timeout.to_le_bytes().to_vec();
                data.extend_from_slice(&[0; 12]);
                data.extend_from_slice(&guid);
                list.push(CreateContext {
                    name: CreateContext::NAME_DH2Q.to_vec(),
                    data,
                });
            }
            (false, _) => {}
        }
        if let Some(file_id) = self.reconnect {
            let mut data = file_id.persistent.to_le_bytes().to_vec();
            data.extend_from_slice(&file_id.volatile.to_le_bytes());
            let name = match self.v2 {
                Some((guid, _)) => {
                    data.extend_from_slice(&guid);
                    data.extend_from_slice(&0u32.to_le_bytes());
                    CreateContext::NAME_DH2C
                }
                None => CreateContext::NAME_DHNC,
            };
            list.push(CreateContext {
                name: name.to_vec(),
                data,
            });
        }
        let mut contexts = Vec::new();
        CreateContext::encode_chain(&list, &mut contexts).expect("contexts");
        let mut name_padded = name.clone();
        name_padded.resize(name.len().next_multiple_of(8), 0);
        let mut body = Vec::new();
        CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: if self.lease.is_some() { 0xFF } else { 0 },
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: self.access,
            file_attributes: 0,
            share_access: self.share,
            create_disposition: 1,
            create_options: self.options,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: if contexts.is_empty() {
                0
            } else {
                0x78 + name_padded.len() as u32
            },
            create_contexts_length: contexts.len() as u32,
            name: name_padded,
            create_contexts: contexts,
        }
        .write_to(&mut body)
        .expect("create");
        body
    }
}

/// Opens f.txt as `open` asks; returns the response.
async fn create(peer: &mut Peer, state: &Arc<ServerState>, open: Open) -> CreateResponse {
    let (_, reply) = peer.request(state, Command::Create, &open.body()).await;
    assert_eq!(status(&reply), 0);
    CreateResponse::parse(&reply[SMB2_HEADER_LEN..]).expect("create response")
}

/// alice's connection from `CLIENT` with a durable open of f.txt that
/// holds `lease`, kept once the connection drops.
async fn kept(state: &Arc<ServerState>, open: Open) -> (Peer, FileId) {
    let mut peer = Peer::from_client(state, true, CLIENT).await;
    let resp = create(&mut peer, state, open).await;
    assert!(is_durable(&resp), "durable granted");
    peer.drop_connection(state).await;
    (peer, resp.file_id)
}

fn is_durable(resp: &CreateResponse) -> bool {
    CreateContext::parse_chain(&resp.create_contexts)
        .expect("contexts")
        .iter()
        .any(|c| c.name == CreateContext::NAME_DHNQ && c.data == [0; 8])
}

/// Lets spawned closes run.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

async fn f_is_open(state: &Arc<ServerState>) -> bool {
    let share = state.find_share("home").await.expect("share");
    share.files.path_is_open(&"f.txt".parse().unwrap(), false)
}

fn write_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 1,
        offset: 0,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: vec![b'x'],
    }
    .write_to(&mut body)
    .expect("write");
    body
}

/// An exclusive lock on bytes 0 to 9.
fn lock_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    LockRequest {
        structure_size: 48,
        lock_count: 1,
        lock_sequence: 0,
        file_id,
        locks: vec![LockElement {
            offset: 0,
            length: 10,
            flags: LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
            reserved: 0,
        }],
    }
    .write_to(&mut body)
    .expect("lock");
    body
}

fn read_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 4,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    }
    .write_to(&mut body)
    .expect("read");
    body
}

fn ack_body(state: u32) -> Vec<u8> {
    let mut body = Vec::new();
    LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: LEASE_KEY,
        lease_state: state,
        lease_duration: 0,
    }
    .write_to(&mut body)
    .expect("ack");
    body
}

/// The final response of a CREATE that may have gone asynchronous.
async fn final_reply(peer: &mut Peer, reply: Vec<u8>) -> Vec<u8> {
    if status(&reply) == ntstatus::STATUS_PENDING {
        peer.next().await
    } else {
        reply
    }
}

#[tokio::test(start_paused = true)]
async fn a_kept_open_closes_when_its_time_runs_out() {
    let (state, files) = server().await;
    let open = Open {
        access: READ_WRITE | DELETE,
        options: FILE_DELETE_ON_CLOSE,
        ..Open::durable(RWH)
    };
    let (_peer, file_id) = kept(&state, open).await;
    assert_ne!(file_id.persistent, file_id.volatile);
    let lease = LeaseId {
        client: CLIENT,
        key: LEASE_KEY,
    };

    tokio::time::sleep(TIMEOUT - Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(files.open_handles(), 1, "kept up to the deadline");
    assert!(f_is_open(&state).await);
    assert!(state.leases.exists(lease));

    tokio::time::sleep(Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(files.open_handles(), 0);
    assert!(!f_is_open(&state).await);
    assert!(!state.leases.exists(lease));
    let path: SmbPath = "f.txt".parse().unwrap();
    assert!(
        files.open(&path, OpenOptions::default()).await.is_err(),
        "closed as CLOSE would, delete-on-close included"
    );
}

#[tokio::test(start_paused = true)]
async fn a_kept_open_that_wrote_reports_the_write_when_it_expires() {
    let (state, _files) = server().await;
    let mut watcher = Peer::new(&state, false).await;
    let root = Open {
        access: 0x0012_0089,
        options: 0x1,
        name: Some(""),
        ..Open::default()
    };
    let root = create(&mut watcher, &state, root).await.file_id;
    let mut notify = Vec::new();
    crate::proto::messages::ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 4096,
        file_id: root,
        completion_filter: 0x10,
        reserved: 0,
    }
    .write_to(&mut notify)
    .expect("change notify");
    let (_, interim) = watcher
        .request(&state, Command::ChangeNotify, &notify)
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);

    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let resp = create(&mut peer, &state, Open::durable(RWH)).await;
    assert!(is_durable(&resp), "durable granted");
    let (_, reply) = peer
        .request(&state, Command::Write, &write_body(resp.file_id))
        .await;
    assert_eq!(status(&reply), 0);
    peer.drop_connection(&state).await;
    settle().await;
    assert!(watcher.rx.try_recv().is_none(), "kept, not closed");

    tokio::time::sleep(TIMEOUT).await;
    let last = watcher.next().await;
    assert_eq!(status(&last), 0);
    let entries = crate::proto::messages::ChangeNotifyResponse::parse(&last[SMB2_HEADER_LEN..])
        .expect("notify response")
        .buffer;
    // MODIFIED f.txt.
    assert_eq!(entries[4..8], 3u32.to_le_bytes());
    assert_eq!(entries[12..], crate::utils::utf16le("f.txt"));
}

#[tokio::test(start_paused = true)]
async fn a_sharing_violation_closes_a_kept_open_without_waiting() {
    let (state, files) = server().await;
    let open = Open {
        share: SHARE_READ_WRITE,
        ..Open::durable(RH)
    };
    let (mut peer, _) = kept(&state, open).await;
    let started = Instant::now();
    let mut other = Peer::new(&state, false).await;
    let (_, reply) = other
        .request(
            &state,
            Command::Create,
            &Open {
                access: DELETE | READ_ATTRIBUTES,
                ..Open::default()
            }
            .body(),
        )
        .await;
    assert_eq!(status(&final_reply(&mut other, reply).await), 0);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(peer.rx.try_recv().is_none(), "no break went out");
    assert!(other.rx.try_recv().is_none());
    assert_eq!(files.open_handles(), 1, "only the new open is left");
}

#[tokio::test(start_paused = true)]
async fn an_open_that_needs_write_caching_gone_closes_a_kept_open_without_waiting() {
    let (state, files) = server().await;
    let (mut peer, _) = kept(&state, Open::durable(RWH)).await;
    let started = Instant::now();
    let mut other = Peer::new(&state, false).await;
    let (_, reply) = other
        .request(&state, Command::Create, &Open::default().body())
        .await;
    assert_eq!(status(&final_reply(&mut other, reply).await), 0);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(peer.rx.try_recv().is_none());
    assert_eq!(files.open_handles(), 1);
}

#[tokio::test]
async fn a_write_closes_a_kept_open() {
    let (state, files) = server().await;
    let (_peer, _) = kept(&state, Open::durable(RH)).await;
    let mut other = Peer::new(&state, false).await;
    // An open breaks only write caching, which RH does not hold.
    let opened = create(&mut other, &state, Open::default()).await;
    settle().await;
    assert_eq!(files.open_handles(), 2);
    let (_, reply) = other
        .request(&state, Command::Write, &write_body(opened.file_id))
        .await;
    assert_eq!(status(&reply), 0);
    settle().await;
    assert_eq!(files.open_handles(), 1);
}

#[tokio::test]
async fn an_attribute_only_open_leaves_a_kept_open_alone() {
    let (state, files) = server().await;
    let (_peer, _) = kept(&state, Open::durable(RWH)).await;
    let mut other = Peer::new(&state, false).await;
    create(
        &mut other,
        &state,
        Open {
            access: READ_ATTRIBUTES,
            share: 0,
            ..Open::default()
        },
    )
    .await;
    settle().await;
    assert_eq!(files.open_handles(), 2);
}

#[tokio::test(start_paused = true)]
async fn an_open_whose_lease_is_breaking_is_not_kept() {
    let (state, files) = server().await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let open = Open {
        share: SHARE_READ_WRITE,
        ..Open::durable(RH)
    };
    assert!(is_durable(&create(&mut peer, &state, open).await));
    let mut other = Peer::new(&state, false).await;
    let deleter = Open {
        access: DELETE | READ_ATTRIBUTES,
        ..Open::default()
    };
    let (_, interim) = other
        .request(&state, Command::Create, &deleter.body())
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert!(peer.rx.try_recv().is_some(), "break sent");

    // MS-SMB2 3.3.7.1 keeps only an open whose lease is held, not breaking.
    let started = Instant::now();
    peer.drop_connection(&state).await;
    assert!(state.durable.take_for(None, None).is_empty());
    assert_eq!(status(&other.next().await), 0);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(files.open_handles(), 1);
}

#[tokio::test]
async fn logoff_keeps_a_durable_open_and_tree_disconnect_closes_it() {
    let (state, files) = server().await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    assert!(is_durable(
        &create(&mut peer, &state, Open::durable(RH)).await
    ));
    let (_, reply) = peer.request(&state, Command::Logoff, &[4, 0, 0, 0]).await;
    assert_eq!(status(&reply), 0);
    assert_eq!(files.open_handles(), 1);
    assert!(f_is_open(&state).await);
    assert_eq!(state.durable.take_for(None, None).len(), 1);

    let (state, files) = server().await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    assert!(is_durable(
        &create(&mut peer, &state, Open::durable(RH)).await
    ));
    let (_, reply) = peer
        .request(&state, Command::TreeDisconnect, &[4, 0, 0, 0])
        .await;
    assert_eq!(status(&reply), 0);
    assert_eq!(files.open_handles(), 0);
    assert!(!f_is_open(&state).await);
}

#[tokio::test]
async fn a_connection_ended_without_keeping_closes_durable_opens() {
    let (state, files) = server().await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    assert!(is_durable(
        &create(&mut peer, &state, Open::durable(RH)).await
    ));
    peer.conn.close_all(None).await;
    assert_eq!(files.open_handles(), 0);
    assert!(state.durable.take_for(None, None).is_empty());
}

#[tokio::test]
async fn anonymous_and_unidentified_clients_get_no_durable_open() {
    let (state, _files) = server().await;
    for (signed, client) in [(false, CLIENT), (true, Uuid::nil())] {
        let mut peer = Peer::from_client(&state, signed, client).await;
        let resp = create(&mut peer, &state, Open::durable(RH)).await;
        assert!(!is_durable(&resp));
        assert_eq!(resp.file_id.persistent, resp.file_id.volatile);
        peer.conn.close_all(None).await;
    }
}

/// alice's two connections from `CLIENT` with the same lease on f.txt; the
/// first is kept after it drops. Then another client's open breaks the
/// lease and waits, and the second connection gets the notification.
/// Returns the second connection, the other client's, and the kept open.
async fn kept_beside_a_sibling(
    state: &Arc<ServerState>,
    holder: u32,
    opener: Open,
) -> (Peer, Peer, FileId) {
    let mut first = Peer::from_client(state, true, CLIENT).await;
    let open = Open {
        share: SHARE_READ_WRITE,
        ..Open::durable(holder)
    };
    let kept = create(&mut first, state, open).await;
    assert!(is_durable(&kept));
    let mut second = Peer::from_client(state, true, CLIENT).await;
    create(&mut second, state, open).await;
    first.drop_connection(state).await;

    let mut other = Peer::new(state, false).await;
    let (_, interim) = other.request(state, Command::Create, &opener.body()).await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert!(second.rx.try_recv().is_some(), "break sent to the sibling");
    (second, other, kept.file_id)
}

#[tokio::test]
async fn an_acknowledgment_without_handle_caching_closes_kept_siblings() {
    let (state, files) = server().await;
    let deleter = Open {
        access: DELETE | READ_ATTRIBUTES,
        ..Open::default()
    };
    let (mut second, mut other, _) = kept_beside_a_sibling(&state, RH, deleter).await;
    assert_eq!(files.open_handles(), 2);
    let (_, reply) = second
        .request(&state, Command::OplockBreak, &ack_body(R))
        .await;
    assert_eq!(status(&reply), 0);
    // The second connection still holds its open.
    assert_eq!(
        status(&other.next().await),
        ntstatus::STATUS_SHARING_VIOLATION
    );
    settle().await;
    assert_eq!(files.open_handles(), 1, "the kept open is closed");
}

#[tokio::test]
async fn an_acknowledgment_keeping_handle_caching_keeps_kept_siblings() {
    let (state, files) = server().await;
    let (mut second, mut other, _) = kept_beside_a_sibling(&state, RWH, Open::default()).await;
    let (_, reply) = second
        .request(&state, Command::OplockBreak, &ack_body(RH))
        .await;
    assert_eq!(status(&reply), 0);
    assert_eq!(status(&other.next().await), 0);
    settle().await;
    // Both of alice's opens and the new one.
    assert_eq!(files.open_handles(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_break_that_times_out_closes_kept_siblings() {
    let (state, files) = server().await;
    let deleter = Open {
        access: DELETE | READ_ATTRIBUTES,
        ..Open::default()
    };
    let (_second, mut other, _) = kept_beside_a_sibling(&state, RH, deleter).await;
    tokio::time::sleep(LEASE_BREAK_TIMEOUT).await;
    assert_eq!(
        status(&other.next().await),
        ntstatus::STATUS_SHARING_VIOLATION
    );
    settle().await;
    assert_eq!(files.open_handles(), 1, "the kept open is closed");
}

#[tokio::test]
async fn a_lease_that_stops_caching_writes_closes_kept_opens_holding_locks() {
    let (state, files) = server().await;
    let mut first = Peer::from_client(&state, true, CLIENT).await;
    let held = create(&mut first, &state, Open::durable(RWH)).await;
    assert!(is_durable(&held));
    let (_, reply) = first
        .request(&state, Command::Lock, &lock_body(held.file_id))
        .await;
    assert_eq!(status(&reply), 0);
    first.drop_connection(&state).await;
    // The client opens the file again under the same lease key.
    let mut second = Peer::from_client(&state, true, CLIENT).await;
    create(&mut second, &state, Open::durable(RWH)).await;

    let mut other = Peer::new(&state, false).await;
    let (_, interim) = other
        .request(&state, Command::Create, &Open::default().body())
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert!(second.rx.try_recv().is_some(), "write break sent");
    let (_, reply) = second
        .request(&state, Command::OplockBreak, &ack_body(RH))
        .await;
    assert_eq!(status(&reply), 0);
    let last = other.next().await;
    assert_eq!(status(&last), 0);
    let opened = CreateResponse::parse(&last[SMB2_HEADER_LEN..]).expect("create response");
    settle().await;
    assert_eq!(files.open_handles(), 2, "the kept open is closed");
    // Its lock went with it: a read, which breaks nothing, goes through.
    let (_, reply) = other
        .request(&state, Command::Read, &read_body(opened.file_id))
        .await;
    assert_eq!(status(&reply), 0);
}

/// What a [`Held`] backend's handles wait for.
struct Gates {
    /// Set once the first handle is opened; only that one waits on
    /// `close`.
    opened: AtomicBool,
    /// When set, the first handle closes only once it gives a permit.
    close: Option<Semaphore>,
    /// While set, a stat announces itself on `stat_entered`, waits for a
    /// permit from `stat`, and fails when `stat_fails` is set.
    stat_held: AtomicBool,
    stat_entered: Notify,
    stat: Semaphore,
    stat_fails: AtomicBool,
}

impl Default for Gates {
    fn default() -> Self {
        Self {
            opened: AtomicBool::new(false),
            close: None,
            stat_held: AtomicBool::new(false),
            stat_entered: Notify::new(),
            stat: Semaphore::new(0),
            stat_fails: AtomicBool::new(false),
        }
    }
}

/// Memory backend whose handles wait on `gates`.
struct Held {
    inner: MemFsBackend,
    gates: Arc<Gates>,
}

struct HeldHandle {
    inner: Box<dyn Handle>,
    gates: Arc<Gates>,
    first: bool,
}

#[async_trait]
impl ShareBackend for Held {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let (inner, action) = self.inner.open(path, opts).await?;
        let first = !self.gates.opened.swap(true, Ordering::AcqRel);
        let gates = Arc::clone(&self.gates);
        Ok((
            Box::new(HeldHandle {
                inner,
                gates,
                first,
            }),
            action,
        ))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.inner.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        self.inner.rename(from, to, replace).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }
}

#[async_trait]
impl Handle for HeldHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.inner.read(offset, len).await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.inner.write(offset, data).await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.inner.flush().await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let gates = &self.gates;
        if gates.stat_held.load(Ordering::Acquire) {
            gates.stat_entered.notify_one();
            gates.stat.acquire().await.expect("gate").forget();
            if gates.stat_fails.load(Ordering::Acquire) {
                return Err(SmbError::AccessDenied);
            }
        }
        self.inner.stat().await
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.inner.set_times(times).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.inner.set_attributes(attributes).await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.inner.truncate(len).await
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        self.inner.list_dir(pattern).await
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        if self.first
            && let Some(gate) = &self.gates.close
        {
            gate.acquire().await.expect("gate").forget();
        }
        self.inner.close().await
    }
}

/// A server whose public share `home` holds f.txt on a [`Held`] backend
/// with `gates`.
async fn held_server(gates: &Arc<Gates>) -> (SmbServer, Arc<ServerState>, MemFsBackend) {
    let files = MemFsBackend::new().with_file("f.txt", b"data");
    let backend = Held {
        inner: files.clone(),
        gates: Arc::clone(gates),
    };
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .durable_handle_timeout(TIMEOUT)
        .share(Share::new("home", backend).public())
        .build()
        .expect("build");
    let state = server.state();
    (server, state, files)
}

/// Sends a reconnect of `file_id` on `peer` on a task of its own, and
/// returns once the reconnect has claimed the open and waits in its stat.
async fn reconnect_held(
    state: &Arc<ServerState>,
    gates: &Gates,
    peer: &mut Peer,
    file_id: FileId,
) -> tokio::task::JoinHandle<Vec<u8>> {
    gates.stat_held.store(true, Ordering::Release);
    let (_, msg) = peer.message(Command::Create, &Open::reconnect(file_id, RWH).body());
    let (state, conn) = (Arc::clone(state), Arc::clone(&peer.conn));
    let task = tokio::spawn(async move {
        let out = dispatch_frame(&state, &conn, &msg)
            .await
            .expect("a response");
        out.bytes
    });
    gates.stat_entered.notified().await;
    gates.stat_held.store(false, Ordering::Release);
    task
}

#[tokio::test]
async fn serve_returns_after_kept_open_closes_already_running() {
    let gates = Arc::new(Gates {
        close: Some(Semaphore::new(0)),
        ..Gates::default()
    });
    let (server, state, files) = held_server(&gates).await;
    let shutdown = server.shutdown_handle();
    server.bind().await.expect("bind");
    let serving = tokio::spawn(server.serve());

    let (_peer, _) = kept(&state, Open::durable(RWH)).await;
    // Breaking write caching starts the close of the kept open, which
    // waits on the gate.
    let mut other = Peer::new(&state, false).await;
    let (_, interim) = other
        .request(&state, Command::Create, &Open::default().body())
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    settle().await;
    assert_eq!(files.open_handles(), 2);

    shutdown.shutdown();
    settle().await;
    assert!(!serving.is_finished(), "serve waits for the close");
    gates.close.as_ref().unwrap().add_permits(1);
    serving.await.expect("serve task").expect("serve");
    assert_eq!(files.open_handles(), 1, "the kept open is closed");
}

/// Sets the access the tree of `peer` grants.
async fn set_tree_access(peer: &Peer, access: Access) {
    let session = peer.conn.sessions.read().await[&1].clone();
    let tree = session.read().await.trees.read().await[&1].clone();
    tree.write().await.granted_access = access;
}

#[tokio::test]
async fn a_reconnect_waits_for_the_old_connection_to_finish_closing() {
    let (state, files) = server().await;
    let mut old = Peer::from_client(&state, true, CLIENT).await;
    let held = create(&mut old, &state, Open::durable(RWH)).await;
    // The old connection stopped reading but has not ended its sessions.
    old.conn.mark_closing();
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let (_, interim) = new
        .request(
            &state,
            Command::Create,
            &Open::reconnect(held.file_id, RWH).body(),
        )
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    old.drop_connection(&state).await;
    let last = new.next().await;
    assert_eq!(status(&last), 0);
    let resp = CreateResponse::parse(&last[SMB2_HEADER_LEN..]).expect("create response");
    assert_eq!(resp.file_id.persistent, held.file_id.persistent);
    assert_eq!(files.open_handles(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_reconnect_gives_up_on_a_connection_that_does_not_finish_closing() {
    let (state, files) = server().await;
    let mut old = Peer::from_client(&state, true, CLIENT).await;
    let held = create(&mut old, &state, Open::durable(RWH)).await;
    old.conn.mark_closing();
    let started = Instant::now();
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let (_, interim) = new
        .request(
            &state,
            Command::Create,
            &Open::reconnect(held.file_id, RWH).body(),
        )
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert_eq!(
        status(&new.next().await),
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert_eq!(files.open_handles(), 1, "the old open is left alone");
}

#[tokio::test(start_paused = true)]
async fn a_reconnect_just_before_the_deadline_keeps_the_open() {
    let (state, files) = server().await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    tokio::time::sleep(TIMEOUT - Duration::from_millis(1)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let body = Open::reconnect(file_id, RWH).body();
    let (_, reply) = new.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0);
    tokio::time::sleep(TIMEOUT * 2).await;
    settle().await;
    assert_eq!(
        files.open_handles(),
        1,
        "a reconnected open does not expire"
    );
    assert!(f_is_open(&state).await);
}

#[tokio::test(start_paused = true)]
async fn a_reconnect_just_after_the_deadline_finds_nothing() {
    let (state, files) = server().await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    tokio::time::sleep(TIMEOUT + Duration::from_millis(1)).await;
    settle().await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let body = Open::reconnect(file_id, RWH).body();
    let (_, reply) = new.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(files.open_handles(), 0);
}

#[tokio::test]
async fn a_reconnect_into_a_tree_that_grants_less_closes_the_open() {
    let (state, files) = server().await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    set_tree_access(&new, Access::Read).await;
    let (_, reply) = new
        .request(
            &state,
            Command::Create,
            &Open::reconnect(file_id, RWH).body(),
        )
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(files.open_handles(), 0);
    assert!(!f_is_open(&state).await);
}

#[tokio::test]
async fn a_reconnect_past_the_open_limit_leaves_the_open_kept() {
    let (state, files) = server().await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let body = Open::reconnect(file_id, RWH).body();
    state
        .max_opens_per_connection
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let (_, reply) = new.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    assert_eq!(files.open_handles(), 1);
    state
        .max_opens_per_connection
        .store(16, std::sync::atomic::Ordering::Relaxed);
    let (_, reply) = new.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0);
    assert_eq!(
        new.conn
            .open_count
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn a_break_after_a_reconnect_goes_to_the_new_connection() {
    let (state, _files) = server().await;
    let (mut old, file_id) = kept(&state, Open::durable(RWH)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let (_, reply) = new
        .request(
            &state,
            Command::Create,
            &Open::reconnect(file_id, RWH).body(),
        )
        .await;
    assert_eq!(status(&reply), 0);
    let mut other = Peer::new(&state, false).await;
    let (_, interim) = other
        .request(&state, Command::Create, &Open::default().body())
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    let frame = new.rx.try_recv().expect("break on the new connection");
    let n = LeaseBreakNotification::parse(&frame[SMB2_HEADER_LEN..]).expect("lease break");
    assert_eq!(header(&frame).command, Command::OplockBreak);
    assert_eq!(n.lease_key, LEASE_KEY);
    assert_eq!((n.current_lease_state, n.new_lease_state), (RWH, RH));
    assert!(old.rx.try_recv().is_none());
}

#[tokio::test(start_paused = true)]
async fn a_sweep_during_a_reconnect_that_fails_closes_the_open() {
    let gates = Arc::new(Gates::default());
    let (_server, state, files) = held_server(&gates).await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    gates.stat_fails.store(true, Ordering::Release);
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let reconnect = reconnect_held(&state, &gates, &mut new, file_id).await;
    // The sweep cannot see the claimed open.
    assert!(state.durable.take_for(None, Some("alice")).is_empty());
    gates.stat.add_permits(1);
    let reply = reconnect.await.expect("reconnect task");
    assert_eq!(status(&reply), ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    settle().await;
    assert_eq!(files.open_handles(), 0, "closed, not kept again");
    assert!(state.durable.take_for(None, None).is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_break_during_a_reconnect_that_fails_closes_the_open() {
    let gates = Arc::new(Gates::default());
    let (_server, state, files) = held_server(&gates).await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    gates.stat_fails.store(true, Ordering::Release);
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let reconnect = reconnect_held(&state, &gates, &mut new, file_id).await;
    let started = Instant::now();
    let mut other = Peer::new(&state, false).await;
    let (_, interim) = other
        .request(&state, Command::Create, &Open::default().body())
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    gates.stat.add_permits(1);
    let reply = reconnect.await.expect("reconnect task");
    assert_eq!(status(&reply), ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(status(&other.next().await), 0);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(files.open_handles(), 1, "only the new open is left");
}

#[tokio::test]
async fn of_two_reconnects_at_once_one_takes_the_open() {
    let gates = Arc::new(Gates::default());
    let (_server, state, files) = held_server(&gates).await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    let mut first = Peer::from_client(&state, true, CLIENT).await;
    let winner = reconnect_held(&state, &gates, &mut first, file_id).await;
    let mut second = Peer::from_client(&state, true, CLIENT).await;
    let body = Open::reconnect(file_id, RWH).body();
    let (_, reply) = second.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    gates.stat.add_permits(1);
    assert_eq!(status(&winner.await.expect("reconnect task")), 0);
    assert_eq!(files.open_handles(), 1);
}

#[tokio::test]
async fn a_logoff_during_a_reconnect_keeps_the_open_again() {
    let gates = Arc::new(Gates::default());
    let (_server, state, files) = held_server(&gates).await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let reconnect = reconnect_held(&state, &gates, &mut new, file_id).await;
    let (_, reply) = new.request(&state, Command::Logoff, &[4, 0, 0, 0]).await;
    assert_eq!(status(&reply), 0);
    gates.stat.add_permits(1);
    let reply = reconnect.await.expect("reconnect task");
    assert_eq!(status(&reply), ntstatus::STATUS_NETWORK_NAME_DELETED);
    assert_eq!(files.open_handles(), 1, "kept again");

    let mut again = Peer::from_client(&state, true, CLIENT).await;
    let body = Open::reconnect(file_id, RWH).body();
    let (_, reply) = again.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0);
}

#[tokio::test]
async fn a_tree_disconnect_during_a_reconnect_closes_the_open() {
    let gates = Arc::new(Gates::default());
    let (_server, state, files) = held_server(&gates).await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let reconnect = reconnect_held(&state, &gates, &mut new, file_id).await;
    let (_, reply) = new
        .request(&state, Command::TreeDisconnect, &[4, 0, 0, 0])
        .await;
    assert_eq!(status(&reply), 0);
    gates.stat.add_permits(1);
    let reply = reconnect.await.expect("reconnect task");
    assert_eq!(status(&reply), ntstatus::STATUS_NETWORK_NAME_DELETED);
    assert_eq!(files.open_handles(), 0);
}

#[tokio::test]
async fn a_kept_open_comes_back_after_its_sibling_acknowledged_rh() {
    let (state, files) = server().await;
    let (mut second, mut other, kept) = kept_beside_a_sibling(&state, RWH, Open::default()).await;
    let (_, reply) = second
        .request(&state, Command::OplockBreak, &ack_body(RH))
        .await;
    assert_eq!(status(&reply), 0);
    assert_eq!(status(&other.next().await), 0);
    let mut again = Peer::from_client(&state, true, CLIENT).await;
    let (_, reply) = again
        .request(&state, Command::Create, &Open::reconnect(kept, RWH).body())
        .await;
    assert_eq!(status(&reply), 0);
    let resp = CreateResponse::parse(&reply[SMB2_HEADER_LEN..]).expect("create response");
    let lease = CreateContext::parse_chain(&resp.create_contexts)
        .expect("contexts")
        .into_iter()
        .find(|c| c.name == CreateContext::NAME_RQLS)
        .map(|c| LeaseContext::parse(&c.data).expect("lease"))
        .expect("lease context");
    assert_eq!((lease.key, lease.state), (LEASE_KEY, RH));
    assert_eq!(files.open_handles(), 3);
}

const CREATE_GUID: [u8; 16] = [0xE1; 16];

/// A version 2 durable open asking for `lease` and `timeout_ms`.
fn durable_v2(lease: u32, timeout_ms: u32) -> Open {
    Open {
        v2: Some((CREATE_GUID, timeout_ms)),
        ..Open::durable(lease)
    }
}

/// The Timeout of the DH2Q response context.
fn granted_timeout(resp: &CreateResponse) -> Option<u32> {
    CreateContext::parse_chain(&resp.create_contexts)
        .expect("contexts")
        .into_iter()
        .find(|c| c.name == CreateContext::NAME_DH2Q)
        .map(|c| {
            assert_eq!(c.data.len(), 8);
            assert_eq!(c.data[4..], [0; 4], "never persistent");
            u32::from_le_bytes(c.data[..4].try_into().unwrap())
        })
}

#[tokio::test(start_paused = true)]
async fn a_version_2_open_is_kept_for_the_time_it_was_granted() {
    for (asked, granted) in [(0, 60_000), (1_000, 1_000), (600_000, 300_000)] {
        let (state, files) = server().await;
        let mut peer = Peer::from_client(&state, true, CLIENT).await;
        let resp = create(&mut peer, &state, durable_v2(RWH, asked)).await;
        assert_eq!(granted_timeout(&resp), Some(granted), "asked {asked}");
        peer.drop_connection(&state).await;
        let granted = Duration::from_millis(u64::from(granted));
        tokio::time::sleep(granted - Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(files.open_handles(), 1, "kept, asked {asked}");
        tokio::time::sleep(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(files.open_handles(), 0, "expired, asked {asked}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_version_2_reconnect_is_bound_by_the_granted_time() {
    let (state, files) = server().await;
    let mut old = Peer::from_client(&state, true, CLIENT).await;
    let held = create(&mut old, &state, durable_v2(RWH, 2_000)).await;
    old.drop_connection(&state).await;
    let reconnect = Open {
        v2: Some((CREATE_GUID, 0)),
        ..Open::reconnect(held.file_id, RWH)
    };
    tokio::time::sleep(Duration::from_millis(2_001)).await;
    settle().await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let (_, reply) = new
        .request(&state, Command::Create, &reconnect.body())
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(files.open_handles(), 0);
}

/// `body` as a CREATE on `peer` marked as a replay.
async fn replayed(peer: &mut Peer, state: &Arc<ServerState>, body: &[u8]) -> Vec<u8> {
    let (_, mut msg) = peer.message(Command::Create, body);
    let flags = u32::from_le_bytes(msg[16..20].try_into().unwrap()) | SMB2_FLAGS_REPLAY_OPERATION;
    msg[16..20].copy_from_slice(&flags.to_le_bytes());
    msg[48..64].fill(0);
    sign(&mut msg, &KEY, SigningAlgo::AesCmac).expect("sign");
    peer.dispatch(state, &msg).await.expect("a response")
}

#[tokio::test]
async fn a_create_guid_of_a_live_open_is_refused_unless_replayed() {
    let (state, files) = server().await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    create(&mut peer, &state, durable_v2(RH, 0)).await;
    let body = durable_v2(RH, 0).body();
    let (_, reply) = peer.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), ntstatus::STATUS_DUPLICATE_OBJECTID);
    // Another client may use the same CreateGuid.
    let mut other = Peer::from_client(&state, true, Uuid::from_bytes([0xC2; 16])).await;
    let (_, reply) = other.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0);
    // A replay opens the file anew.
    assert_eq!(status(&replayed(&mut peer, &state, &body).await), 0);
    assert_eq!(files.open_handles(), 3);
    // Kept, the open still holds its CreateGuid; once closed it does not.
    peer.drop_connection(&state).await;
    let mut again = Peer::from_client(&state, true, CLIENT).await;
    let (_, reply) = again.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), ntstatus::STATUS_DUPLICATE_OBJECTID);
    assert_eq!(state.durable.take_for(None, None).len(), 2);
    let (_, reply) = again.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0);
}

#[tokio::test]
async fn a_wrong_name_is_refused_before_lowered_access_closes_the_open() {
    let (state, files) = server().await;
    let (_old, file_id) = kept(&state, Open::durable(RWH)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    set_tree_access(&new, Access::Read).await;
    let renamed = Open {
        name: Some("g.txt"),
        ..Open::reconnect(file_id, RWH)
    };
    let (_, reply) = new.request(&state, Command::Create, &renamed.body()).await;
    assert_eq!(status(&reply), ntstatus::STATUS_INVALID_PARAMETER);
    assert_eq!(files.open_handles(), 1, "still kept");
    let (_, reply) = new
        .request(
            &state,
            Command::Create,
            &Open::reconnect(file_id, RWH).body(),
        )
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(files.open_handles(), 0, "closed for the access it lost");
}

#[tokio::test(start_paused = true)]
async fn a_version_2_open_comes_back_by_either_reconnect_and_keeps_its_time() {
    let (state, files) = server().await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let held = create(&mut peer, &state, durable_v2(RWH, 2_000)).await;
    peer.drop_connection(&state).await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let resp = create(&mut peer, &state, Open::reconnect(held.file_id, RWH)).await;
    assert_eq!(resp.file_id.persistent, held.file_id.persistent);
    peer.drop_connection(&state).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let by_guid = Open {
        v2: Some((CREATE_GUID, 0)),
        ..Open::reconnect(held.file_id, RWH)
    };
    create(&mut peer, &state, by_guid).await;
    peer.drop_connection(&state).await;
    tokio::time::sleep(Duration::from_millis(1_999)).await;
    settle().await;
    assert_eq!(files.open_handles(), 1);
    tokio::time::sleep(Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(files.open_handles(), 0, "kept for its 2 seconds each time");
}

#[tokio::test(start_paused = true)]
async fn a_version_2_open_put_back_keeps_its_own_deadline() {
    let (state, files) = server().await;
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let held = create(&mut peer, &state, durable_v2(RWH, 2_000)).await;
    peer.drop_connection(&state).await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let mut new = Peer::from_client(&state, true, CLIENT).await;
    let by_guid = Open {
        v2: Some((CREATE_GUID, 0)),
        ..Open::reconnect(held.file_id, RWH)
    };
    state.max_opens_per_connection.store(0, Ordering::Relaxed);
    let (_, reply) = new.request(&state, Command::Create, &by_guid.body()).await;
    assert_eq!(status(&reply), ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    tokio::time::sleep(Duration::from_millis(999)).await;
    settle().await;
    assert_eq!(files.open_handles(), 1);
    tokio::time::sleep(Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(files.open_handles(), 0);
}
