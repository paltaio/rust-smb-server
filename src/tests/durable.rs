//! Durable opens kept after their session ends: expiry, breaks that close
//! them, and the session teardown paths, driven through the dispatcher with
//! time paused where the timers matter.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use uuid::Uuid;

use crate::files::{LEASE_BREAK_TIMEOUT, LeaseId};
use crate::ntstatus;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    CreateContext, CreateRequest, CreateResponse, FileId, LeaseBreakAck, LeaseContext, LockElement,
    LockRequest, ReadRequest, ReadResponse, WriteRequest,
};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{Peer, status};
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
}

impl Default for Open {
    fn default() -> Self {
        Self {
            access: READ_WRITE,
            share: SHARE_ALL,
            lease: None,
            durable: false,
            options: 0,
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

    fn body(self) -> Vec<u8> {
        let name = crate::utils::utf16le("f.txt");
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
        if self.durable {
            list.push(CreateContext {
                name: CreateContext::NAME_DHNQ.to_vec(),
                data: vec![0; 16],
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
/// Returns the second connection and the other client's.
async fn kept_beside_a_sibling(
    state: &Arc<ServerState>,
    holder: u32,
    opener: Open,
) -> (Peer, Peer) {
    let mut first = Peer::from_client(state, true, CLIENT).await;
    let open = Open {
        share: SHARE_READ_WRITE,
        ..Open::durable(holder)
    };
    assert!(is_durable(&create(&mut first, state, open).await));
    let mut second = Peer::from_client(state, true, CLIENT).await;
    create(&mut second, state, open).await;
    first.drop_connection(state).await;

    let mut other = Peer::new(state, false).await;
    let (_, interim) = other.request(state, Command::Create, &opener.body()).await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert!(second.rx.try_recv().is_some(), "break sent to the sibling");
    (second, other)
}

#[tokio::test]
async fn an_acknowledgment_without_handle_caching_closes_kept_siblings() {
    let (state, files) = server().await;
    let deleter = Open {
        access: DELETE | READ_ATTRIBUTES,
        ..Open::default()
    };
    let (mut second, mut other) = kept_beside_a_sibling(&state, RH, deleter).await;
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
    let (mut second, mut other) = kept_beside_a_sibling(&state, RWH, Open::default()).await;
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
    let (_second, mut other) = kept_beside_a_sibling(&state, RH, deleter).await;
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

/// Memory backend whose first handle closes only once `gate` gives a
/// permit.
struct GatedClose {
    inner: MemFsBackend,
    gate: Arc<Semaphore>,
    gated: AtomicBool,
}

struct GatedHandle {
    inner: Box<dyn Handle>,
    gate: Arc<Semaphore>,
}

#[async_trait]
impl ShareBackend for GatedClose {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let (inner, action) = self.inner.open(path, opts).await?;
        if self.gated.swap(true, Ordering::AcqRel) {
            return Ok((inner, action));
        }
        let gate = Arc::clone(&self.gate);
        Ok((Box::new(GatedHandle { inner, gate }), action))
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
impl Handle for GatedHandle {
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
        self.gate.acquire().await.expect("gate").forget();
        self.inner.close().await
    }
}

#[tokio::test]
async fn serve_returns_after_kept_open_closes_already_running() {
    let files = MemFsBackend::new().with_file("f.txt", b"data");
    let gate = Arc::new(Semaphore::new(0));
    let backend = GatedClose {
        inner: files.clone(),
        gate: Arc::clone(&gate),
        gated: AtomicBool::new(false),
    };
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("home", backend).public())
        .build()
        .expect("build");
    let state = server.state();
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
    gate.add_permits(1);
    serving.await.expect("serve task").expect("serve");
    assert_eq!(files.open_handles(), 1, "the kept open is closed");
}
