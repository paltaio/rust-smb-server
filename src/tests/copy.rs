//! Server-side copy over the dispatcher: resume keys, COPYCHUNK and
//! COPYCHUNK_WRITE within a share and between shares, the limits, rights,
//! byte-range locks, leases, change reports, named streams, shares that
//! turn copies off, Apple's whole-file copy, and backends with their own
//! copy path.

use std::any::Any;
use std::future::poll_fn;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

use crate::access_mask::FILE_APPEND_DATA;
use crate::backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenOptions,
    ShareBackend, VolumeInfo,
};
use crate::conn::pending::MAX_PENDING_REQUESTS;
use crate::conn::state::{Open, Session, TreeConnect};
use crate::ea::Ea;
use crate::error::{SmbError, SmbResult};
use crate::handlers::shared::lookup_open;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::auth::ntlm::Identity;
use crate::proto::header::{Command, SMB2_HEADER_LEN, Smb2Header};
use crate::proto::messages::copychunk::resume_key;
use crate::proto::messages::{
    ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CreateContext, CreateRequest,
    CreateResponse, FileId, Fsctl, IoctlRequest, IoctlResponse, LeaseBreakAck,
    LeaseBreakNotification, LeaseContext, LockElement, LockRequest, ReadRequest, ReadResponse,
    SetInfoRequest, WriteRequest,
};
use crate::server::{ServerState, ShareBindings};
use crate::stream::{StreamInfo, StreamName};
use crate::tests::aapl;
use crate::tests::data::pattern;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{Peer, header, status};
use crate::{Access, Share, SmbServer};

mod clone;

const READ: u32 = 0x0012_0089;
const WRITE: u32 = 0x0012_0116;
const RW: u32 = READ | WRITE;
const READ_ATTRIBUTES: u32 = 0x80;
const SHARE_ALL: u32 = 0x7;
const SHARE_READ: u32 = 0x1;

const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_WRITE_THROUGH: u32 = 0x2;

const LEASE_R: u32 = 0x1;
const LEASE_RH: u32 = 0x3;
const LEASE_NONE: u32 = 0;

const MODIFIED: u32 = 3;
const ADDED_STREAM: u32 = 6;
const MODIFIED_STREAM: u32 = 8;

const COPYCHUNK: u32 = Fsctl::SRV_COPYCHUNK;
const COPYCHUNK_WRITE: u32 = Fsctl::SRV_COPYCHUNK_WRITE;
const RESUME_KEY: u32 = Fsctl::SRV_REQUEST_RESUME_KEY;

const OK: u32 = ntstatus::STATUS_SUCCESS;
const INVALID: u32 = ntstatus::STATUS_INVALID_PARAMETER;
const NOT_FOUND: u32 = ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
const DENIED: u32 = ntstatus::STATUS_ACCESS_DENIED;
const VIEW_SIZE: u32 = ntstatus::STATUS_INVALID_VIEW_SIZE;
const LOCKED: u32 = ntstatus::STATUS_FILE_LOCK_CONFLICT;
const DEVICE: u32 = ntstatus::STATUS_INVALID_DEVICE_REQUEST;
const UNSUPPORTED: u32 = ntstatus::STATUS_NOT_SUPPORTED;
const DISK_FULL: u32 = ntstatus::STATUS_DISK_FULL;
const SHARING: u32 = ntstatus::STATUS_SHARING_VIOLATION;
const CANCELLED: u32 = ntstatus::STATUS_CANCELLED;
const SESSION_DELETED: u32 = ntstatus::STATUS_USER_SESSION_DELETED;
const TREE_DELETED: u32 = ntstatus::STATUS_NETWORK_NAME_DELETED;
const FILE_CLOSED: u32 = ntstatus::STATUS_FILE_CLOSED;

const MIB: u32 = 1 << 20;

/// ChunksWritten, ChunkBytesWritten and TotalBytesWritten of a reply.
type Counts = [u32; 3];

/// The limits a request that breaks one is answered with.
const LIMITS: Counts = [256, MIB, 16 * MIB];

/// Where a request goes: the session and the tree it names.
#[derive(Clone, Copy, PartialEq, Eq)]
struct At {
    session: u64,
    tree: u32,
}

/// Tree 1 of session 1, on the share `home`.
const HOME: At = At {
    session: 1,
    tree: 1,
};
/// Tree 2 of session 1, on the share `other`.
const OTHER: At = At {
    session: 1,
    tree: 2,
};
/// Tree 1 of session 2, on the share `home`.
const SECOND: At = At {
    session: 2,
    tree: 1,
};

/// A CREATE request, opening an existing file for reading and writing and
/// sharing everything unless set otherwise.
#[derive(Clone, Copy)]
struct Create<'a> {
    name: &'a str,
    access: u32,
    disposition: u32,
    options: u32,
    lease: Option<(u8, u32)>,
    durable: bool,
    reconnect: Option<FileId>,
    share: u32,
    aapl: bool,
}

impl<'a> Create<'a> {
    fn new(name: &'a str) -> Self {
        Self {
            name,
            access: RW,
            disposition: FILE_OPEN,
            options: 0,
            lease: None,
            durable: false,
            reconnect: None,
            share: SHARE_ALL,
            aapl: false,
        }
    }

    /// Shares only `share` with other opens.
    fn share(self, share: u32) -> Self {
        Self { share, ..self }
    }

    /// Carries the `AAPL` server query a macOS client sends when it mounts.
    fn aapl(self) -> Self {
        Self { aapl: true, ..self }
    }

    fn access(self, access: u32) -> Self {
        Self { access, ..self }
    }

    fn disposition(self, disposition: u32) -> Self {
        Self {
            disposition,
            ..self
        }
    }

    fn options(self, options: u32) -> Self {
        Self { options, ..self }
    }

    /// Asks for `state` under the lease key of all `key` bytes.
    fn lease(self, key: u8, state: u32) -> Self {
        Self {
            lease: Some((key, state)),
            ..self
        }
    }

    fn body(&self) -> Vec<u8> {
        let name = crate::utils::utf16le(self.name);
        let mut padded = name.clone();
        padded.resize(padded.len().next_multiple_of(8), 0);
        let mut list = Vec::new();
        if let Some((key, state)) = self.lease {
            list.push(CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: LeaseContext {
                    key: [key; 16],
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
        if let Some(id) = self.reconnect {
            let mut data = id.persistent.to_le_bytes().to_vec();
            data.extend_from_slice(&id.volatile.to_le_bytes());
            list.push(CreateContext {
                name: CreateContext::NAME_DHNC.to_vec(),
                data,
            });
        }
        if self.aapl {
            list.push(CreateContext {
                name: CreateContext::NAME_AAPL.to_vec(),
                data: aapl::QUERY.to_vec(),
            });
        }
        let mut contexts = Vec::new();
        CreateContext::encode_chain(&list, &mut contexts).expect("contexts");
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
            create_disposition: self.disposition,
            create_options: self.options,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: if contexts.is_empty() {
                0
            } else {
                0x78 + padded.len() as u32
            },
            create_contexts_length: contexts.len() as u32,
            name: padded,
            create_contexts: contexts,
        }
        .write_to(&mut body)
        .expect("create");
        body
    }
}

/// One connection to the server `state`.
struct Client {
    peer: Peer,
    state: Arc<ServerState>,
    signed: bool,
}

impl Client {
    /// An unsigned connection with session 1 on the share `home`, to which
    /// other sessions and trees can be added.
    async fn new(state: &Arc<ServerState>) -> Self {
        Self {
            peer: Peer::new(state, false).await,
            state: Arc::clone(state),
            signed: false,
        }
    }

    /// A signed connection from the client `client`, which can hold leases
    /// and durable opens. It sends to [`HOME`] only.
    async fn from_client(state: &Arc<ServerState>, client: u128) -> Self {
        Self {
            peer: Peer::from_client(state, true, Uuid::from_u128(client)).await,
            state: Arc::clone(state),
            signed: true,
        }
    }

    /// Tree 2 of session 1, on the share `other`, with `access`.
    async fn with_other_share(self, access: Access) -> Self {
        let share = self.state.find_share("other").await.expect("share other");
        self.with_second_tree(share, access).await
    }

    /// Tree 2 of session 1, on `share`, with `access`.
    async fn with_second_tree(self, share: Arc<ShareBindings>, access: Access) -> Self {
        let session = self.peer.conn.sessions.read().await[&1].clone();
        session
            .read()
            .await
            .trees
            .write()
            .await
            .insert(2, Arc::new(RwLock::new(TreeConnect::new(2, share, access))));
        self
    }

    /// Session 2, with tree 1 on the share `home`.
    async fn with_second_session(self) -> Self {
        let share = self.state.find_share("home").await.expect("share home");
        let session = Session::new(Identity::Anonymous, [0; 16], [0; 16], false, None);
        session.trees.write().await.insert(
            1,
            Arc::new(RwLock::new(TreeConnect::new(1, share, Access::ReadWrite))),
        );
        self.peer
            .conn
            .sessions
            .write()
            .await
            .insert(2, Arc::new(RwLock::new(session)));
        self
    }

    /// Sends one request to `at`; returns the status and body of the frame
    /// that answers it.
    async fn send_at(&mut self, at: At, command: Command, body: &[u8]) -> (u32, Vec<u8>) {
        let (_, mut msg) = self.peer.message(command, body);
        if at != HOME {
            assert!(!self.signed, "a signed client sends to HOME only");
            msg[36..40].copy_from_slice(&at.tree.to_le_bytes());
            msg[40..48].copy_from_slice(&at.session.to_le_bytes());
        }
        let reply = self
            .peer
            .dispatch(&self.state, &msg)
            .await
            .expect("a response");
        (status(&reply), reply[SMB2_HEADER_LEN..].to_vec())
    }

    async fn send(&mut self, command: Command, body: &[u8]) -> (u32, Vec<u8>) {
        self.send_at(HOME, command, body).await
    }

    async fn create_at(&mut self, at: At, create: Create<'_>) -> Result<CreateResponse, u32> {
        match self.send_at(at, Command::Create, &create.body()).await {
            (0, body) => Ok(CreateResponse::parse(&body).expect("create response")),
            (status, _) => Err(status),
        }
    }

    async fn open_at(&mut self, at: At, create: Create<'_>) -> FileId {
        let name = create.name;
        match self.create_at(at, create).await {
            Ok(created) => created.file_id,
            Err(status) => panic!("open {name}: {status:#x}"),
        }
    }

    async fn open(&mut self, create: Create<'_>) -> FileId {
        self.open_at(HOME, create).await
    }

    async fn close_at(&mut self, at: At, file_id: FileId) {
        let mut body = Vec::new();
        CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        }
        .write_to(&mut body)
        .expect("close");
        assert_eq!(self.send_at(at, Command::Close, &body).await.0, 0);
    }

    async fn close(&mut self, file_id: FileId) {
        self.close_at(HOME, file_id).await;
    }

    async fn read(&mut self, file_id: FileId, offset: u64, length: u32) -> Vec<u8> {
        let mut body = Vec::new();
        ReadRequest {
            structure_size: 49,
            padding: ReadResponse::STANDARD_DATA_OFFSET,
            flags: 0,
            length,
            offset,
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
        let (status, body) = self.send(Command::Read, &body).await;
        assert_eq!(status, 0, "read");
        ReadResponse::parse(&body).expect("read response").data
    }

    async fn write(&mut self, file_id: FileId, offset: u64, data: &[u8]) {
        let mut body = Vec::new();
        WriteRequest {
            structure_size: 49,
            data_offset: WriteRequest::STANDARD_DATA_OFFSET,
            length: data.len() as u32,
            offset,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: data.to_vec(),
        }
        .write_to(&mut body)
        .expect("write");
        assert_eq!(self.send(Command::Write, &body).await.0, 0, "write");
    }

    /// A LOCK of `length` bytes at `offset`: exclusive, or an unlock.
    async fn lock(&mut self, file_id: FileId, offset: u64, length: u64, unlock: bool) -> u32 {
        let flags = if unlock {
            LockElement::FLAG_UNLOCK
        } else {
            LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY
        };
        let mut body = Vec::new();
        LockRequest {
            structure_size: 48,
            lock_count: 1,
            lock_sequence: 0,
            file_id,
            locks: vec![LockElement {
                offset,
                length,
                flags,
                reserved: 0,
            }],
        }
        .write_to(&mut body)
        .expect("lock");
        self.send(Command::Lock, &body).await.0
    }

    /// An IOCTL on `file_id` at `at`: the status, and the output buffer when
    /// the reply is an IOCTL response.
    async fn fsctl(
        &mut self,
        at: At,
        ctl_code: u32,
        file_id: FileId,
        input: &[u8],
        max_output: u32,
    ) -> (u32, Option<Vec<u8>>) {
        let body = ioctl_body(ctl_code, file_id, input, max_output);
        let (status, body) = self.send_at(at, Command::Ioctl, &body).await;
        (status, ioctl_output(ctl_code, file_id, &body))
    }

    /// The resume key of the open `file_id` on [`HOME`].
    async fn key(&mut self, file_id: FileId) -> [u8; 24] {
        self.key_at(HOME, file_id).await
    }

    /// The resume key of the open `file_id` at `at`.
    async fn key_at(&mut self, at: At, file_id: FileId) -> [u8; 24] {
        let (status, out) = self.fsctl(at, RESUME_KEY, file_id, &[], 32).await;
        assert_eq!(status, OK, "resume key");
        let out = out.expect("a resume key");
        assert_eq!(out.len(), 32);
        out[..24].try_into().unwrap()
    }

    /// Sends the copy FSCTL `code` for `chunks` of the source `key` to the
    /// open `target` at `at`; returns the status and the counts of the
    /// reply, `None` for a reply without them.
    async fn copy_at(
        &mut self,
        at: At,
        code: u32,
        target: FileId,
        key: &[u8; 24],
        chunks: &[(u64, u64, u32)],
    ) -> (u32, Option<Counts>) {
        let input = copy_input(key, chunks.len() as u32, chunks);
        self.copy_raw(at, code, target, &input, 12).await
    }

    /// [`Client::copy_at`] with COPYCHUNK to [`HOME`].
    async fn copy(
        &mut self,
        target: FileId,
        key: &[u8; 24],
        chunks: &[(u64, u64, u32)],
    ) -> (u32, Option<Counts>) {
        self.copy_at(HOME, COPYCHUNK, target, key, chunks).await
    }

    /// A copy FSCTL with `input` as it is, and `max_output`.
    async fn copy_raw(
        &mut self,
        at: At,
        code: u32,
        target: FileId,
        input: &[u8],
        max_output: u32,
    ) -> (u32, Option<Counts>) {
        let (status, out) = self.fsctl(at, code, target, input, max_output).await;
        (status, out.map(counts_of))
    }

    /// Sends a COPYCHUNK without chunks to the open `target` at `at`, which
    /// the server answers asynchronously: the MessageId of the request and
    /// the AsyncId of its interim response.
    async fn start_whole_file(&mut self, at: At, target: FileId, key: &[u8; 24]) -> (u64, u64) {
        let input = copy_input(key, 0, &[]);
        let body = ioctl_body(COPYCHUNK, target, &input, 12);
        let (mid, mut msg) = self.peer.message(Command::Ioctl, &body);
        if at != HOME {
            msg[36..40].copy_from_slice(&at.tree.to_le_bytes());
        }
        let interim = self
            .peer
            .dispatch(&self.state, &msg)
            .await
            .expect("a response");
        assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
        let async_id = header(&interim).async_id().expect("an AsyncId");
        (mid, async_id)
    }

    /// The final responses to the requests that went asynchronous, in the
    /// order they come: `(AsyncId, target)` for each. Returns the status and
    /// the counts of each, in the order given.
    async fn whole_files_done(&mut self, copies: &[(u64, FileId)]) -> Vec<(u32, Option<Counts>)> {
        let mut done = vec![None; copies.len()];
        for _ in copies {
            let frame = tokio::time::timeout(Duration::from_secs(5), self.peer.next())
                .await
                .expect("a final response in time");
            let hdr = header(&frame);
            assert_eq!(hdr.command, Command::Ioctl);
            let at = copies
                .iter()
                .position(|&(async_id, _)| hdr.async_id() == Some(async_id))
                .expect("the response of a copy that was started");
            let body = &frame[SMB2_HEADER_LEN..];
            let counts = ioctl_output(COPYCHUNK, copies[at].1, body).map(counts_of);
            assert!(done[at].replace((status(&frame), counts)).is_none());
        }
        done.into_iter().flatten().collect()
    }

    /// The final response to the request `async_id` that went asynchronous:
    /// the status, and the counts when it carries them.
    async fn whole_file_done(&mut self, target: FileId, async_id: u64) -> (u32, Option<Counts>) {
        self.whole_files_done(&[(async_id, target)]).await.remove(0)
    }

    /// A whole-file copy of the source `key` into `target` at `at`, run to
    /// its end.
    async fn copy_whole_file_at(
        &mut self,
        at: At,
        target: FileId,
        key: &[u8; 24],
    ) -> (u32, Option<Counts>) {
        let (_, async_id) = self.start_whole_file(at, target, key).await;
        self.whole_file_done(target, async_id).await
    }

    /// [`Client::copy_whole_file_at`] to [`HOME`].
    async fn copy_whole_file(&mut self, target: FileId, key: &[u8; 24]) -> (u32, Option<Counts>) {
        self.copy_whole_file_at(HOME, target, key).await
    }

    /// Mounts the share with an `AAPL` server query; returns the server caps
    /// of the reply.
    async fn mount(&mut self) -> u64 {
        let root = Create::new("")
            .access(READ_ATTRIBUTES)
            .options(FILE_DIRECTORY_FILE)
            .aapl();
        let created = self.create_at(HOME, root).await.expect("the share root");
        self.close(created.file_id).await;
        let contexts = CreateContext::parse_chain(&created.create_contexts).expect("contexts");
        aapl::server_caps(&contexts)
    }

    /// Cancels the request `mid`.
    async fn cancel(&mut self, mid: u64) {
        let cancel = self
            .peer
            .message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
        assert!(self.peer.dispatch(&self.state, &cancel).await.is_none());
    }

    /// The open `file_id` of [`HOME`].
    async fn open_of(&self, file_id: FileId) -> Arc<RwLock<Open>> {
        let session = self.peer.conn.sessions.read().await[&1].clone();
        let tree = session.read().await.trees.read().await[&1].clone();
        lookup_open(&tree, file_id).await.expect("an open")
    }

    /// Whether a WRITE or a copy changed the file through the open
    /// `file_id` of [`HOME`].
    async fn wrote(&self, file_id: FileId) -> bool {
        let open = self.open_of(file_id).await;
        let open = open.read().await;
        open.wrote.load(Ordering::Acquire)
    }

    /// Sends a CHANGE_NOTIFY on the directory `dir` for all changes, which
    /// has to wait; returns its AsyncId.
    async fn watch(&mut self, dir: FileId) -> u64 {
        let mut body = Vec::new();
        ChangeNotifyRequest {
            structure_size: 32,
            flags: 0,
            output_buffer_length: 4096,
            file_id: dir,
            completion_filter: 0xFFF,
            reserved: 0,
        }
        .write_to(&mut body)
        .expect("change notify");
        let (_, interim) = self
            .peer
            .request(&self.state, Command::ChangeNotify, &body)
            .await;
        assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
        header(&interim).async_id().expect("an AsyncId")
    }

    /// The actions and names the final response to the CHANGE_NOTIFY
    /// `async_id` reports.
    async fn events(&mut self, async_id: u64) -> Vec<(u32, String)> {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.peer.next())
            .await
            .expect("a final response in time");
        assert_eq!(header(&frame).async_id(), Some(async_id));
        assert_eq!(status(&frame), 0);
        parse_events(&frame)
    }

    /// The changes the watch of `dir` kept while no request waited: a
    /// CHANGE_NOTIFY that is answered at once.
    async fn kept_events(&mut self, dir: FileId) -> Vec<(u32, String)> {
        let mut body = Vec::new();
        ChangeNotifyRequest {
            structure_size: 32,
            flags: 0,
            output_buffer_length: 4096,
            file_id: dir,
            completion_filter: 0xFFF,
            reserved: 0,
        }
        .write_to(&mut body)
        .expect("change notify");
        let (_, frame) = self
            .peer
            .request(&self.state, Command::ChangeNotify, &body)
            .await;
        assert_eq!(status(&frame), 0, "changes were kept");
        parse_events(&frame)
    }

    /// Asserts that nothing was sent to this connection outside its
    /// responses.
    async fn quiet(&mut self) {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(self.peer.rx.try_recv().is_none(), "nothing sent");
    }

    /// Asserts that the next lease break sent to this connection is of the
    /// lease `key` from `from` to `to`; returns its flags.
    async fn breaks(&mut self, key: u8, from: u32, to: u32) -> u32 {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.peer.next())
            .await
            .expect("a lease break in time");
        assert_eq!(header(&frame).command, Command::OplockBreak);
        let n = LeaseBreakNotification::parse(&frame[SMB2_HEADER_LEN..]).expect("lease break");
        assert_eq!(
            (n.lease_key, n.current_lease_state, n.new_lease_state),
            ([key; 16], from, to)
        );
        n.flags
    }

    /// A SET_INFO of FileBasicInformation with the four `times` and no
    /// attributes.
    async fn set_times(&mut self, file_id: FileId, times: [i64; 4]) -> u32 {
        let mut buffer: Vec<u8> = times.iter().flat_map(|t| t.to_le_bytes()).collect();
        buffer.extend_from_slice(&[0; 8]);
        let mut body = Vec::new();
        SetInfoRequest {
            structure_size: 33,
            info_type: 1,
            file_information_class: 0x04,
            buffer_length: buffer.len() as u32,
            buffer_offset: 0x60,
            reserved: 0,
            additional_information: 0,
            file_id,
            buffer,
        }
        .write_to(&mut body)
        .expect("set info");
        self.send(Command::SetInfo, &body).await.0
    }

    /// Acknowledges a break of the lease `key` with `state`.
    async fn ack(&mut self, key: u8, state: u32) {
        let mut body = Vec::new();
        LeaseBreakAck {
            structure_size: 36,
            reserved: 0,
            flags: 0,
            lease_key: [key; 16],
            lease_state: state,
            lease_duration: 0,
        }
        .write_to(&mut body)
        .expect("ack");
        assert_eq!(self.send(Command::OplockBreak, &body).await.0, 0);
    }
}

/// The actions and names a CHANGE_NOTIFY response frame reports.
fn parse_events(frame: &[u8]) -> Vec<(u32, String)> {
    let buf = ChangeNotifyResponse::parse(&frame[SMB2_HEADER_LEN..])
        .expect("notify response")
        .buffer;
    let u32_at = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
    let mut events = Vec::new();
    let mut at = 0;
    loop {
        let next = u32_at(at) as usize;
        let len = u32_at(at + 8) as usize;
        let units: Vec<u16> = buf[at + 12..at + 12 + len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        events.push((u32_at(at + 4), String::from_utf16(&units).unwrap()));
        if next == 0 {
            return events;
        }
        at += next;
    }
}

/// An IOCTL request body.
fn ioctl_body(ctl_code: u32, file_id: FileId, input: &[u8], max_output: u32) -> Vec<u8> {
    let mut body = Vec::new();
    IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code,
        file_id,
        input_offset: 0x78,
        input_count: input.len() as u32,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: max_output,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: input.to_vec(),
    }
    .write_to(&mut body)
    .expect("ioctl");
    body
}

/// The output buffer of an IOCTL response `body`, `None` for the body of an
/// error response.
fn ioctl_output(ctl_code: u32, file_id: FileId, body: &[u8]) -> Option<Vec<u8>> {
    let response = IoctlResponse::parse(body)
        .ok()
        .filter(|r| r.structure_size == 49)?;
    assert_eq!(response.ctl_code, ctl_code);
    assert_eq!(response.file_id, file_id);
    assert_eq!(response.flags, 0);
    assert_eq!(response.output_count as usize, response.output.len());
    Some(response.output)
}

/// The counts of a copy response's output buffer.
fn counts_of(out: Vec<u8>) -> Counts {
    assert_eq!(out.len(), 12);
    [0, 4, 8].map(|at| u32::from_le_bytes(out[at..at + 4].try_into().unwrap()))
}

/// The input of a copy FSCTL that says it holds `count` chunks and holds
/// `chunks`, each as (source offset, target offset, length).
fn copy_input(key: &[u8; 24], count: u32, chunks: &[(u64, u64, u32)]) -> Vec<u8> {
    let mut input = key.to_vec();
    input.extend_from_slice(&count.to_le_bytes());
    input.extend_from_slice(&[0; 4]);
    for &(source, target, length) in chunks {
        input.extend_from_slice(&source.to_le_bytes());
        input.extend_from_slice(&target.to_le_bytes());
        input.extend_from_slice(&length.to_le_bytes());
        input.extend_from_slice(&[0; 4]);
    }
    input
}

/// The lease state a CREATE response grants, `None` without a lease.
fn lease_state(response: &CreateResponse) -> Option<u32> {
    CreateContext::parse_chain(&response.create_contexts)
        .expect("contexts")
        .iter()
        .find(|c| c.name == CreateContext::NAME_RQLS)
        .map(|c| LeaseContext::parse(&c.data).expect("lease").state)
}

fn server_on(shares: Vec<Share>) -> Arc<ServerState> {
    let mut builder = SmbServer::builder().listen("127.0.0.1:0".parse().unwrap());
    for share in shares {
        builder = builder.share(share);
    }
    builder.build().expect("build").state()
}

/// A server whose public share `home` is `files`.
fn server(files: &MemFsBackend) -> Arc<ServerState> {
    server_on(vec![Share::new("home", files.clone()).public()])
}

/// A server with the public shares `home` and `other`.
fn server_of_two(home: &MemFsBackend, other: &MemFsBackend) -> Arc<ServerState> {
    server_on(vec![
        Share::new("home", home.clone()).public(),
        Share::new("other", other.clone()).public(),
    ])
}

/// Files `s` and `t`, the data of `s` being `len` bytes, and a client with
/// both open for reading and writing.
async fn pair(len: usize) -> (MemFsBackend, Client, FileId, FileId, Vec<u8>) {
    let data = pattern(len, 0x11);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_file("t", &[]);
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    (files, c, source, target, data)
}

// ---------------------------------------------------------------------------
// Resume keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_resume_key_needs_room_for_32_bytes() {
    let (_, mut c, source, _, _) = pair(10).await;
    let (status, out) = c.fsctl(HOME, RESUME_KEY, source, &[], 31).await;
    assert_eq!((status, out), (INVALID, None));
    let (status, out) = c.fsctl(HOME, RESUME_KEY, source, &[], 32).await;
    assert_eq!(status, OK);
    assert_eq!(out.map(|o| o.len()), Some(32));
}

#[tokio::test]
async fn a_resume_key_for_an_open_without_a_handle_fails() {
    let (_, mut c, source, _, _) = pair(10).await;
    c.open_of(source).await.write().await.handle = None;
    let (status, _) = c.fsctl(HOME, RESUME_KEY, source, &[], 32).await;
    assert_eq!(status, ntstatus::STATUS_FILE_CLOSED);
}

// ---------------------------------------------------------------------------
// Copies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_chunk_is_copied_to_its_target_offset() {
    let (files, mut c, source, target, data) = pair(4096).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(300, 700, 1000)]).await,
        (OK, Some([1, 0, 1000]))
    );
    let mut expected = vec![0; 700];
    expected.extend_from_slice(&data[300..1300]);
    assert_eq!(files.contents("t"), Some(expected));
    assert_eq!(files.contents("s"), Some(data));
}

#[tokio::test]
async fn the_most_chunks_are_copied() {
    let (files, mut c, source, target, data) = pair(256 * 64).await;
    let key = c.key(source).await;
    let chunks: Vec<_> = (0..256u64).map(|i| (i * 64, i * 64, 64)).collect();
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (OK, Some([256, 0, 256 * 64]))
    );
    assert_eq!(files.contents("t"), Some(data));
}

#[tokio::test]
async fn a_later_chunk_overwrites_the_target_range_of_an_earlier_one() {
    let (files, mut c, source, target, data) = pair(200).await;
    let key = c.key(source).await;
    let chunks = [(0, 0, 100), (100, 50, 100)];
    assert_eq!(c.copy(target, &key, &chunks).await, (OK, Some([2, 0, 200])));
    let mut expected = data[..50].to_vec();
    expected.extend_from_slice(&data[100..200]);
    assert_eq!(files.contents("t"), Some(expected));
}

#[tokio::test]
async fn an_empty_chunk_list_succeeds_and_copies_nothing() {
    let (files, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    assert_eq!(c.copy(target, &key, &[]).await, (OK, Some([0, 0, 0])));
    assert_eq!(files.contents("t"), Some(Vec::new()));
    let unknown = [0x55; 24];
    assert_eq!(
        c.copy(target, &unknown, &[]).await,
        (NOT_FOUND, None),
        "the key is looked up first"
    );
}

#[tokio::test]
async fn a_copy_between_shares_of_one_session() {
    let data = pattern(5000, 9);
    let home = MemFsBackend::new().with_file("s", &data);
    let other = MemFsBackend::new().with_file("t", &[1, 2, 3]);
    let state = server_of_two(&home, &other);
    let mut c = Client::new(&state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    let source = c.open(Create::new("s")).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let key = c.key(source).await;
    let chunks = [(0, 0, 3000), (3000, 3000, 2000)];
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, target, &key, &chunks).await,
        (OK, Some([2, 0, 5000]))
    );
    assert_eq!(other.contents("t"), Some(data.clone()));
    assert_eq!(home.contents("s"), Some(data));

    let back = c.open_at(OTHER, Create::new("t")).await;
    let source_key = c.key_at(OTHER, back).await;
    let into_home = c.open(Create::new("s")).await;
    assert_eq!(
        c.copy(into_home, &source_key, &[(100, 0, 50)]).await,
        (OK, Some([1, 0, 50]))
    );
    assert_eq!(
        home.contents("s").unwrap()[..50],
        pattern(5000, 9)[100..150]
    );
}

#[tokio::test]
async fn a_copy_between_shares_with_different_backends_reads_and_writes() {
    let spy = Spy::new(Fast::Unsupported);
    let data = pattern(3000, 4);
    let home = MemFsBackend::new().with_file("s", &data);
    let other = MemFsBackend::new().with_file("t", &[]);
    let state = server_on(vec![
        Share::new("home", home.clone()).public(),
        Share::new("other", SpyFs::new(&other, &spy)).public(),
    ]);
    let mut c = Client::new(&state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    let source = c.open(Create::new("s")).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, target, &key, &[(0, 0, 3000)])
            .await,
        (OK, Some([1, 0, 3000]))
    );
    assert_eq!(other.contents("t"), Some(data));
    assert_eq!(
        spy.copy_calls(),
        [(0, 0, 3000)],
        "the target's backend is asked"
    );
}

// ---------------------------------------------------------------------------
// One file as source and target
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_overlapping_range_copies_as_if_moved_through_a_buffer() {
    for two_opens in [false, true] {
        let data = pattern(10_000, 6);
        let files = MemFsBackend::new().with_file("f", &data);
        let state = server(&files);
        let mut c = Client::new(&state).await;
        let source = c.open(Create::new("f")).await;
        let target = if two_opens {
            c.open(Create::new("f")).await
        } else {
            source
        };
        let key = c.key(source).await;
        assert_eq!(
            c.copy(target, &key, &[(0, 2048, 8192)]).await,
            (OK, Some([1, 0, 8192])),
            "two opens {two_opens}"
        );
        let mut expected = data.clone();
        expected.resize(2048 + 8192, 0);
        expected.copy_within(0..8192, 2048);
        assert_eq!(files.contents("f"), Some(expected), "two opens {two_opens}");

        let mut expected = files.contents("f").unwrap();
        assert_eq!(
            c.copy(target, &key, &[(4096, 1000, 4000)]).await,
            (OK, Some([1, 0, 4000]))
        );
        expected.copy_within(4096..8096, 1000);
        assert_eq!(
            files.contents("f"),
            Some(expected),
            "backwards, {two_opens}"
        );
    }
}

// ---------------------------------------------------------------------------
// Source ranges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_chunk_past_the_end_of_the_source_fails_with_nothing_written() {
    let (files, mut c, source, target, _) = pair(4096).await;
    let key = c.key(source).await;
    for chunk in [(4096, 0, 100), (4000, 0, 100), (u64::MAX - 3, 0, 10)] {
        assert_eq!(
            c.copy(target, &key, &[chunk]).await,
            (VIEW_SIZE, Some([0, 0, 0])),
            "{chunk:?}"
        );
    }
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn earlier_chunks_stay_when_a_later_one_passes_the_source_end() {
    let (files, mut c, source, target, data) = pair(4096).await;
    let key = c.key(source).await;
    let chunks = [(0, 0, 4096), (4096, 4096, 100), (0, 8192, 10)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (VIEW_SIZE, Some([1, 0, 4096]))
    );
    assert_eq!(files.contents("t"), Some(data));
}

#[tokio::test]
async fn a_chunk_may_read_what_an_earlier_chunk_wrote() {
    let data = pattern(100, 12);
    let files = MemFsBackend::new().with_file("f", &data);
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f")).await;
    let key = c.key(f).await;
    let chunks = [(0, 100, 100), (100, 200, 100)];
    assert_eq!(c.copy(f, &key, &chunks).await, (OK, Some([2, 0, 200])));
    assert_eq!(
        files.contents("f"),
        Some([data.clone(), data.clone(), data].concat())
    );
}

#[tokio::test]
async fn a_target_offset_of_all_ones_passes_the_limits_and_fails_the_chunk() {
    let (files, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, u64::MAX, 10)]).await,
        (DEVICE, Some([0, 0, 0])),
        "never STATUS_INVALID_PARAMETER with a body, which is the limits reply"
    );
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

// ---------------------------------------------------------------------------
// Limits and malformed requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_that_breaks_a_limit_gets_the_limits() {
    let (files, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    let chunk = (0, 0, 10);
    let cases = [
        ("257 chunks", copy_input(&key, 257, &vec![chunk; 257])),
        ("no header", key[..23].to_vec()),
    ];
    for (name, input) in cases {
        assert_eq!(
            c.copy_raw(HOME, COPYCHUNK, target, &input, 12).await,
            (INVALID, Some(LIMITS)),
            "{name}"
        );
    }
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn a_reply_that_does_not_fit_fails_with_a_bare_invalid_parameter() {
    let (files, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    let input = copy_input(&key, 1, &[(0, 0, 10)]);
    assert_eq!(
        c.copy_raw(HOME, COPYCHUNK, target, &input, 11).await,
        (INVALID, None)
    );
    assert_eq!(
        c.copy_raw(
            HOME,
            COPYCHUNK,
            target,
            &copy_input(&key, 1, &[(0, 0, 0)]),
            11
        )
        .await,
        (INVALID, None),
        "a request over the limits"
    );
    assert_eq!(files.contents("t"), Some(Vec::new()));
    assert_eq!(
        c.copy_raw(
            HOME,
            COPYCHUNK,
            target,
            &copy_input(&[0; 24], 1, &[(0, 0, 10)]),
            11
        )
        .await,
        (NOT_FOUND, None),
        "the key is looked up before the reply size is checked"
    );
    assert_eq!(
        c.copy_raw(HOME, COPYCHUNK, target, &input, 12).await,
        (OK, Some([1, 0, 10]))
    );
}

// ---------------------------------------------------------------------------
// Keys that name nothing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_key_that_names_no_open_fails_with_object_name_not_found() {
    let (files, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    let mut wrong_tag = key;
    wrong_tag[23] ^= 1;
    let mut wrong_id = key;
    wrong_id[0] ^= 0x40;
    let mut wrong_persistent = key;
    wrong_persistent[8] ^= 1;
    let cases = [
        ("another tag", wrong_tag),
        ("another volatile id", wrong_id),
        ("another persistent id", wrong_persistent),
    ];
    for (name, key) in cases {
        assert_eq!(
            c.copy(target, &key, &[(0, 0, 10)]).await,
            (NOT_FOUND, None),
            "{name}"
        );
    }
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 10)]).await,
        (OK, Some([1, 0, 10])),
        "the key itself works"
    );
    assert_eq!(files.contents("t").map(|t| t.len()), Some(10));
}

#[tokio::test]
async fn a_key_of_another_server_names_nothing_here() {
    let files = MemFsBackend::new()
        .with_file("s", b"abc")
        .with_file("t", b"");
    let a = server(&files);
    let b = server(&files);
    assert_ne!(a.resume_tag, b.resume_tag);
    let mut on_a = Client::new(&a).await;
    let mut on_b = Client::new(&b).await;
    let source_a = on_a.open(Create::new("s")).await;
    let source_b = on_b.open(Create::new("s")).await;
    let target_b = on_b.open(Create::new("t")).await;
    let key_a = on_a.key(source_a).await;
    let forged = resume_key(source_b, &a.resume_tag);
    for key in [key_a, forged] {
        assert_eq!(
            on_b.copy(target_b, &key, &[(0, 0, 3)]).await,
            (NOT_FOUND, None)
        );
    }
    let key_b = on_b.key(source_b).await;
    assert_eq!(
        on_b.copy(target_b, &key_b, &[(0, 0, 3)]).await,
        (OK, Some([1, 0, 3]))
    );
}

#[tokio::test]
async fn a_key_of_another_session_names_nothing() {
    let files = MemFsBackend::new()
        .with_file("s", b"abcdef")
        .with_file("t", b"");
    let state = server(&files);
    let mut c = Client::new(&state).await.with_second_session().await;
    let target = c.open(Create::new("t")).await;
    let source_there = c.open_at(SECOND, Create::new("s")).await;
    let key = c.key_at(SECOND, source_there).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 6)]).await,
        (NOT_FOUND, None),
        "a target in session 1, a source in session 2"
    );
    let target_there = c.open_at(SECOND, Create::new("t")).await;
    assert_eq!(
        c.copy_at(SECOND, COPYCHUNK, target_there, &key, &[(0, 0, 6)])
            .await,
        (OK, Some([1, 0, 6])),
        "both in session 2"
    );
    assert_eq!(files.contents("t"), Some(b"abcdef".to_vec()));
}

#[tokio::test]
async fn a_key_of_a_closed_open_names_nothing() {
    let (files, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    c.close(source).await;
    assert_eq!(c.copy(target, &key, &[(0, 0, 10)]).await, (NOT_FOUND, None));
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn a_source_that_closes_while_the_copy_waits_for_it_is_not_found() {
    let (files, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    let open = c.open_of(source).await;
    let mut closing = open.write().await;
    let input = copy_input(&key, 1, &[(0, 0, 10)]);
    let mut copy = pin!(c.copy_raw(HOME, COPYCHUNK, target, &input, 12));
    let waiting = poll_fn(|cx| Poll::Ready(copy.as_mut().poll(cx).is_pending())).await;
    assert!(waiting, "the copy waits for the source");
    closing.handle = None;
    drop(closing);
    assert_eq!(copy.await, (NOT_FOUND, None));
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn a_reconnected_durable_source_needs_a_new_key() {
    let data = pattern(500, 2);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_file("t", &[]);
    let state = server(&files);
    let mut old = Client::from_client(&state, 1).await;
    let create = Create {
        durable: true,
        ..Create::new("s").lease(1, LEASE_RH)
    };
    let source = old.open(create).await;
    let old_key = old.key(source).await;
    old.peer.drop_connection(&state).await;

    let mut new = Client::from_client(&state, 1).await;
    let create = Create {
        reconnect: Some(source),
        ..Create::new("s").lease(1, LEASE_RH)
    };
    let back = new.open(create).await;
    assert_eq!(back.persistent, source.persistent);
    assert_ne!(back.volatile, source.volatile);
    let target = new.open(Create::new("t")).await;
    assert_eq!(
        new.copy(target, &old_key, &[(0, 0, 500)]).await,
        (NOT_FOUND, None),
        "the key names the old FileId"
    );
    let key = new.key(back).await;
    assert_eq!(
        new.copy(target, &key, &[(0, 0, 500)]).await,
        (OK, Some([1, 0, 500]))
    );
    assert_eq!(files.contents("t"), Some(data));
}

// ---------------------------------------------------------------------------
// Rights
// ---------------------------------------------------------------------------

#[tokio::test]
async fn each_open_needs_the_rights_a_copy_uses() {
    let data = pattern(100, 8);
    let files = MemFsBackend::new().with_file("s", &data);
    let cases = [
        // Source access, target access, FSCTL, whether it works.
        (READ_ATTRIBUTES, RW, COPYCHUNK, false),
        (READ, READ, COPYCHUNK, false),
        (READ, WRITE, COPYCHUNK, false),
        (READ, WRITE, COPYCHUNK_WRITE, true),
        (READ, RW, COPYCHUNK, true),
        (
            READ,
            FILE_APPEND_DATA | READ_ATTRIBUTES,
            COPYCHUNK_WRITE,
            true,
        ),
    ];
    for (at, (source_access, target_access, code, works)) in cases.into_iter().enumerate() {
        let name = format!("t{at}");
        let files = files.clone().with_file(&name, &[]);
        let state = server(&files);
        let mut c = Client::new(&state).await;
        let source = c.open(Create::new("s").access(source_access)).await;
        let target = c.open(Create::new(&name).access(target_access)).await;
        let key = c.key(source).await;
        let expected = if works {
            (OK, Some([1, 0, 100]))
        } else {
            (DENIED, None)
        };
        assert_eq!(
            c.copy_at(HOME, code, target, &key, &[(0, 0, 100)]).await,
            expected,
            "case {at}: {source_access:#x} to {target_access:#x} with {code:#x}"
        );
        let copied = files.contents(&name).unwrap();
        assert_eq!(
            copied,
            if works { data.clone() } else { Vec::new() },
            "case {at}"
        );
    }
}

#[tokio::test]
async fn a_directory_is_not_copied_from_or_to() {
    let files = MemFsBackend::new()
        .with_file("s", b"data")
        .with_file("t", b"")
        .with_dir("d");
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let dir = c.open(Create::new("d").options(FILE_DIRECTORY_FILE)).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    let dir_key = c.key(dir).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &dir_key, &[(0, 0, 1)]).await,
        (DENIED, None),
        "a directory as source"
    );
    assert_eq!(
        c.copy(dir, &key, &[(0, 0, 1)]).await,
        (DENIED, None),
        "a directory as target"
    );
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

// ---------------------------------------------------------------------------
// Byte-range locks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_lock_of_another_open_on_the_source_stops_the_copy() {
    let (files, mut c, source, target, data) = pair(300).await;
    let locker = c.open(Create::new("s")).await;
    assert_eq!(c.lock(locker, 150, 10, false).await, OK);
    let key = c.key(source).await;
    let chunks = [(0, 0, 100), (100, 100, 100)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (LOCKED, Some([0, 0, 0]))
    );
    assert_eq!(files.contents("t"), Some(Vec::new()), "no chunk is copied");
    assert_eq!(c.lock(locker, 150, 10, true).await, OK);
    assert_eq!(c.copy(target, &key, &chunks).await, (OK, Some([2, 0, 200])));
    assert_eq!(files.contents("t"), Some(data[..200].to_vec()));
}

#[tokio::test]
async fn a_lock_of_another_open_on_the_target_stops_the_copy() {
    let (files, mut c, source, target, data) = pair(300).await;
    let locker = c.open(Create::new("t")).await;
    assert_eq!(c.lock(locker, 120, 10, false).await, OK);
    let key = c.key(source).await;
    let chunks = [(0, 0, 100), (100, 100, 100)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (LOCKED, Some([0, 0, 0]))
    );
    assert_eq!(files.contents("t"), Some(Vec::new()));
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 100), (100, 200, 100)]).await,
        (OK, Some([2, 0, 200])),
        "a chunk outside the locked range copies"
    );
    let mut expected = data[..100].to_vec();
    expected.resize(200, 0);
    expected.extend_from_slice(&data[100..200]);
    assert_eq!(files.contents("t"), Some(expected));
}

#[tokio::test]
async fn the_locks_of_the_copying_opens_do_not_stop_it() {
    let (files, mut c, source, target, data) = pair(100).await;
    assert_eq!(c.lock(source, 0, 100, false).await, OK);
    assert_eq!(c.lock(target, 0, 100, false).await, OK);
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 100)]).await,
        (OK, Some([1, 0, 100]))
    );
    assert_eq!(files.contents("t"), Some(data));
}

#[tokio::test]
async fn a_lock_taken_between_chunks_stops_the_copy_there() {
    let data = pattern(300, 3);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_file("t", &[]);
    let spy = Spy::new(Fast::Unsupported);
    let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    let locker = c.open(Create::new("t")).await;
    let locker = c.open_of(locker).await;
    spy.after_write(move |writes| {
        if writes == 1 {
            let open = locker.try_read().expect("the locker is idle");
            let file = open.file.as_ref().expect("an open file");
            file.lock_range(100, 100, true, 1024).expect("a lock");
        }
    });
    let key = c.key(source).await;
    let chunks = [(0, 0, 100), (100, 100, 100), (200, 200, 100)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (LOCKED, Some([1, 0, 100]))
    );
    assert_eq!(files.contents("t"), Some(data[..100].to_vec()));
}

// ---------------------------------------------------------------------------
// Named streams
// ---------------------------------------------------------------------------

#[tokio::test]
async fn streams_copy_to_streams_and_between_streams_and_files() {
    let info = pattern(60, 0xA5);
    let files = MemFsBackend::new()
        .with_file("f", b"file data")
        .with_stream("f", "AFP_AfpInfo", &info)
        .with_file("g", b"");
    let state = server(&files);
    let mut c = Client::new(&state).await;

    // A stream to a stream of another file, created for the copy.
    let source = c.open(Create::new("f:AFP_AfpInfo")).await;
    let target = c
        .open(Create::new("g:AFP_AfpInfo").disposition(FILE_CREATE))
        .await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 60)]).await,
        (OK, Some([1, 0, 60]))
    );
    assert_eq!(c.read(target, 0, 100).await, info);
    assert_eq!(files.stream_names("g"), ["AFP_AfpInfo"]);
    assert_eq!(
        files.contents("g"),
        Some(Vec::new()),
        "the file is untouched"
    );

    // A file to a stream.
    let file = c.open(Create::new("f")).await;
    let into_stream = c.open(Create::new("g:data").disposition(FILE_CREATE)).await;
    let key = c.key(file).await;
    assert_eq!(
        c.copy(into_stream, &key, &[(0, 0, 9)]).await,
        (OK, Some([1, 0, 9]))
    );
    assert_eq!(c.read(into_stream, 0, 100).await, b"file data");

    // A stream to a file.
    let stream_key = c.key(into_stream).await;
    let h = c.open(Create::new("h").disposition(FILE_CREATE)).await;
    assert_eq!(
        c.copy(h, &stream_key, &[(0, 0, 9)]).await,
        (OK, Some([1, 0, 9]))
    );
    assert_eq!(files.contents("h"), Some(b"file data".to_vec()));

    // A stream onto itself, moved forward within the stream.
    assert_eq!(
        c.copy(into_stream, &stream_key, &[(0, 4, 5)]).await,
        (OK, Some([1, 0, 5]))
    );
    assert_eq!(c.read(into_stream, 0, 100).await, b"filefile ");
}

#[tokio::test]
async fn a_stream_and_its_file_are_different_data() {
    let files = MemFsBackend::new()
        .with_file("f", b"0123456789")
        .with_stream("f", "s", b"abcdefghij");
    let spy = Spy::new(Fast::Full);
    let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
    let mut c = Client::new(&state).await;
    let file = c.open(Create::new("f")).await;
    let stream = c.open(Create::new("f:s")).await;
    let key = c.key(stream).await;
    assert_eq!(
        c.copy(file, &key, &[(0, 3, 4)]).await,
        (OK, Some([1, 0, 4]))
    );
    assert_eq!(files.contents("f"), Some(b"012abcd789".to_vec()));
    assert_eq!(
        spy.copy_calls(),
        [(0, 3, 4)],
        "ranges of two streams do not overlap"
    );
}

#[tokio::test]
async fn a_failure_on_a_named_stream_target_never_answers_not_supported() {
    let data = pattern(100, 1);
    let home = MemFsBackend::new()
        .with_file("g", b"")
        .with_stream("g", "s", b"");
    let other = MemFsBackend::new().with_file("s", &data);
    let spy = Spy::new(Fast::Unsupported);
    *spy.read_error.lock().unwrap() = Some(Refusal::NotSupported);
    let state = server_on(vec![
        Share::new("home", home.clone()).public(),
        Share::new("other", SpyFs::new(&other, &spy)).public(),
    ]);
    let mut c = Client::new(&state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    let source = c.open_at(OTHER, Create::new("s")).await;
    let key = c.key_at(OTHER, source).await;
    let stream = c.open(Create::new("g:s")).await;
    let file = c.open(Create::new("g")).await;
    assert_eq!(
        c.copy(stream, &key, &[(0, 0, 100)]).await,
        (DENIED, Some([0, 0, 0]))
    );
    assert_eq!(
        c.copy(file, &key, &[(0, 0, 100)]).await,
        (UNSUPPORTED, Some([0, 0, 0])),
        "an open of the file answers what the backend said"
    );
}

// ---------------------------------------------------------------------------
// Shares that turn copies off
// ---------------------------------------------------------------------------

fn off(files: &MemFsBackend) -> Share {
    Share::new("home", files.clone())
        .public()
        .server_side_copy(false)
}

#[tokio::test]
async fn a_share_with_copies_off_refuses_the_three_fsctls() {
    let files = MemFsBackend::new()
        .with_file("f", b"data")
        .with_stream("f", "s", b"stream");
    let state = server_on(vec![off(&files)]);
    let mut c = Client::new(&state).await;
    let file = c.open(Create::new("f")).await;
    let stream = c.open(Create::new("f:s")).await;
    let input = copy_input(&[7; 24], 1, &[(0, 0, 4)]);
    for code in [RESUME_KEY, COPYCHUNK, COPYCHUNK_WRITE] {
        let input = if code == RESUME_KEY { &[][..] } else { &input };
        for (id, expected) in [(file, UNSUPPORTED), (stream, DEVICE)] {
            let (status, out) = c.fsctl(HOME, code, id, input, 32).await;
            assert_eq!(
                (status, out),
                (expected, None),
                "{code:#x} on {:#x}",
                id.volatile
            );
        }
    }
}

#[tokio::test]
async fn a_copy_needs_copies_on_for_both_shares() {
    let home = MemFsBackend::new().with_file("s", b"data");
    let other = MemFsBackend::new().with_file("t", b"");
    let state = server_on(vec![
        Share::new("home", home.clone()).public(),
        Share::new("other", other.clone())
            .public()
            .server_side_copy(false),
    ]);
    let mut c = Client::new(&state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    let source = c.open(Create::new("s")).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, target, &key, &[(0, 0, 4)])
            .await,
        (UNSUPPORTED, None),
        "a target on a share with copies off"
    );
    assert_eq!(other.contents("t"), Some(Vec::new()));

    // A key for the other direction cannot be asked for, but can be made.
    let off_source = c.open_at(OTHER, Create::new("t")).await;
    let forged = resume_key(off_source, &state.resume_tag);
    let into_home = c.open(Create::new("s")).await;
    assert_eq!(
        c.copy(into_home, &forged, &[(0, 0, 1)]).await,
        (UNSUPPORTED, None),
        "a source on a share with copies off"
    );
    assert_eq!(home.contents("s"), Some(b"data".to_vec()));
}

// ---------------------------------------------------------------------------
// Leases and change reports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_copy_breaks_the_read_lease_of_another_client_on_the_target() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(100, 1))
        .with_file("t", b"old");
    let state = server(&files);
    let mut reader = Client::from_client(&state, 1).await;
    let mut copier = Client::from_client(&state, 2).await;
    let cached = reader
        .open(Create::new("t").access(READ).lease(1, LEASE_R))
        .await;
    let source = copier.open(Create::new("s")).await;
    let target = copier.open(Create::new("t").lease(2, LEASE_R)).await;
    reader.quiet().await;

    let key = copier.key(source).await;
    assert_eq!(
        copier.copy(target, &key, &[(0, 0, 100)]).await,
        (OK, Some([1, 0, 100]))
    );
    let flags = reader.breaks(1, LEASE_R, LEASE_NONE).await;
    assert_eq!(flags & LeaseBreakNotification::FLAG_ACK_REQUIRED, 0);
    copier.quiet().await;
    reader.close(cached).await;
}

#[tokio::test]
async fn a_copy_marks_its_target_written_only_when_bytes_were_written() {
    let (_, mut c, source, target, _) = pair(100).await;
    let key = c.key(source).await;
    assert_eq!(c.copy(target, &key, &[(100, 0, 1)]).await.0, VIEW_SIZE);
    assert!(!c.wrote(target).await);
    assert_eq!(c.copy(target, &key, &[(0, 0, 1)]).await.0, OK);
    assert!(c.wrote(target).await);
}

#[tokio::test]
async fn a_lease_granted_while_a_copy_runs_is_broken_when_it_ends() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(300, 1))
        .with_file("t", b"");
    let spy = Spy::new(Fast::Unsupported);
    let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
    let mut copier = Client::from_client(&state, 2).await;
    let mut late = Client::from_client(&state, 1).await;
    let source = copier.open(Create::new("s")).await;
    let target = copier.open(Create::new("t")).await;
    let key = copier.key(source).await;
    let (reached, resume) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    spy.stall(1, &reached, &resume);

    let chunks = [(0, 0, 100), (100, 100, 100), (200, 200, 100)];
    let copy = copier.copy(target, &key, &chunks);
    let grant = async {
        reached.notified().await;
        let opened = late
            .create_at(HOME, Create::new("t").access(READ).lease(5, LEASE_R))
            .await
            .expect("an open");
        assert_eq!(lease_state(&opened), Some(LEASE_R));
        resume.notify_one();
        opened.file_id
    };
    let (copied, cached) = tokio::join!(copy, grant);
    assert_eq!(copied, (OK, Some([3, 0, 300])));
    late.breaks(5, LEASE_R, LEASE_NONE).await;
    late.close(cached).await;
}

#[tokio::test]
async fn a_copy_puts_back_the_write_time_its_target_fixed() {
    const FIXED: i64 = 133_000_000_000_000_000;
    let (_, spy, mut c, source, target, _) = spied(Fast::Unsupported, 100).await;
    assert_eq!(c.set_times(target, [0, 0, FIXED, 0]).await, OK);
    let fixed = FileTimes {
        last_write_time: Some(FIXED as u64),
        ..FileTimes::default()
    };
    assert_eq!(spy.times(), [fixed]);

    let key = c.key(source).await;
    assert_eq!(c.copy(target, &key, &[(100, 0, 1)]).await.0, VIEW_SIZE);
    assert_eq!(spy.times().len(), 1, "a copy that wrote nothing sets none");
    assert_eq!(c.copy(target, &key, &[(0, 0, 100)]).await.0, OK);
    assert_eq!(spy.times(), [fixed, fixed]);
}

#[tokio::test]
async fn the_target_reports_one_change_at_its_close_and_the_source_none() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(100, 1))
        .with_file("t", b"")
        .with_file("g", b"")
        .with_stream("g", "s", b"");
    let state = server(&files);
    let mut watcher = Client::new(&state).await;
    let mut c = Client::new(&state).await;
    let root = watcher
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let source = c.open(Create::new("s").access(READ)).await;
    let target = c.open(Create::new("t")).await;
    let key = c.key(source).await;

    let w = watcher.watch(root).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 100)]).await,
        (OK, Some([1, 0, 100]))
    );
    watcher.quiet().await;
    c.close(source).await;
    watcher.quiet().await;
    c.close(target).await;
    assert_eq!(watcher.events(w).await, [(MODIFIED, "t".to_string())]);

    let w = watcher.watch(root).await;
    let source = c.open(Create::new("s").access(READ)).await;
    let stream = c.open(Create::new("g:s")).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(stream, &key, &[(0, 0, 100)]).await,
        (OK, Some([1, 0, 100]))
    );
    watcher.quiet().await;
    c.close(stream).await;
    assert_eq!(
        watcher.events(w).await,
        [
            (MODIFIED, "g".to_string()),
            (MODIFIED_STREAM, "g:s".to_string())
        ]
    );
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// What a spying backend's `copy_range` does.
#[derive(Clone, Copy)]
enum Fast {
    /// Not supported, which is the default of the trait.
    Unsupported,
    /// Not on the same device.
    NotSameDevice,
    /// Copies everything asked.
    Full,
    /// Copies at most this many bytes of each call.
    AtMost(u64),
    /// Copies the first call and answers later ones as not supported.
    Once,
    /// Fails with a full disk.
    Fails,
}

/// What a spying backend's `clone_range` does.
#[derive(Clone, Copy)]
enum Cloning {
    /// Clones everything asked, by copying the bytes.
    Full,
    /// Not supported, which is the default of the trait.
    NotSupported,
    /// Not on the same device.
    NotSameDevice,
    /// Refuses the ranges.
    InvalidParameter,
    /// Fails with a full disk.
    DiskFull,
}

/// The error a spying backend's handles fail with.
#[derive(Clone, Copy)]
enum Refusal {
    DiskFull,
    InvalidParameter,
    NotSupported,
}

impl Refusal {
    fn error(self) -> SmbError {
        match self {
            Refusal::DiskFull => SmbError::DiskFull,
            Refusal::InvalidParameter => SmbError::InvalidParameter,
            Refusal::NotSupported => SmbError::NotSupported,
        }
    }
}

/// What runs after a write of a spying backend, given the number of
/// writes so far.
type AfterWrite = Box<dyn Fn(usize) + Send + Sync>;

/// A write of a spying backend that waits: it tells `reached` it is there
/// and goes on once `resume` is notified.
#[derive(Clone)]
struct Stall {
    at: usize,
    reached: Arc<Notify>,
    resume: Arc<Notify>,
}

/// What a spying backend saw, and how its handles misbehave.
struct Spy {
    fast: Fast,
    copy_calls: Mutex<Vec<(u64, u64, u64)>>,
    /// What `clone_range` does, `None` for a backend that does not clone.
    cloning: Mutex<Option<Cloning>>,
    clone_calls: Mutex<Vec<(u64, u64, u64)>>,
    reads: AtomicUsize,
    writes: AtomicUsize,
    flushes: AtomicUsize,
    /// The times set, in order.
    times: Mutex<Vec<FileTimes>>,
    /// Most bytes a read or a write moves.
    max_read: Mutex<Option<u32>>,
    max_write: Mutex<Option<u32>>,
    /// Bytes the target accepts before a write fails.
    space: Mutex<Option<(u64, Refusal)>>,
    /// Reads fail.
    read_error: Mutex<Option<Refusal>>,
    /// Bytes a stat reports beyond the size of the file.
    extra_size: Mutex<u64>,
    /// Runs after each write.
    after_write: Mutex<Option<AfterWrite>>,
    stall: Mutex<Option<Stall>>,
    /// Calls that copy, write, truncate or flush running now, and the most at
    /// once.
    busy: AtomicUsize,
    most_busy: AtomicUsize,
    /// Those calls give the other tasks a turn while they run.
    slow: AtomicBool,
    /// The file id every file reports, and the serial number of the volume.
    identity: Mutex<Option<(u64, u32)>>,
    /// Bytes in a sector of the volume, when not the default.
    sector: Mutex<Option<u32>>,
    /// The error opening a named stream fails with.
    open_stream_error: Mutex<Option<Refusal>>,
}

/// A call of a spying backend, counted until it is dropped.
struct Busy<'a>(&'a Spy);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.busy.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Spy {
    fn new(fast: Fast) -> Arc<Self> {
        Arc::new(Self {
            fast,
            copy_calls: Mutex::default(),
            cloning: Mutex::default(),
            clone_calls: Mutex::default(),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            flushes: AtomicUsize::new(0),
            times: Mutex::default(),
            max_read: Mutex::default(),
            max_write: Mutex::default(),
            space: Mutex::default(),
            read_error: Mutex::default(),
            extra_size: Mutex::default(),
            after_write: Mutex::default(),
            stall: Mutex::default(),
            busy: AtomicUsize::new(0),
            most_busy: AtomicUsize::new(0),
            slow: AtomicBool::new(false),
            identity: Mutex::default(),
            sector: Mutex::default(),
            open_stream_error: Mutex::default(),
        })
    }

    fn copy_calls(&self) -> Vec<(u64, u64, u64)> {
        self.copy_calls.lock().unwrap().clone()
    }

    fn clone_calls(&self) -> Vec<(u64, u64, u64)> {
        self.clone_calls.lock().unwrap().clone()
    }

    /// Makes the backend report block cloning and clone as `cloning` says.
    /// Call it before the server is built.
    fn clone_as(&self, cloning: Cloning) {
        *self.cloning.lock().unwrap() = Some(cloning);
    }

    /// Makes the sectors of the volume `bytes` long.
    fn sectors_of(&self, bytes: u32) {
        *self.sector.lock().unwrap() = Some(bytes);
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn flushes(&self) -> usize {
        self.flushes.load(Ordering::SeqCst)
    }

    fn times(&self) -> Vec<FileTimes> {
        self.times.lock().unwrap().clone()
    }

    fn most_calls_at_once(&self) -> usize {
        self.most_busy.load(Ordering::SeqCst)
    }

    /// Makes every file report the file id `file_index` and the volume the
    /// serial number `serial`.
    fn identify(&self, file_index: u64, serial: u32) {
        *self.identity.lock().unwrap() = Some((file_index, serial));
    }

    /// Makes the open of a named stream fail with `refusal`.
    fn refuse_streams(&self, refusal: Refusal) {
        *self.open_stream_error.lock().unwrap() = Some(refusal);
    }

    /// Makes each call that copies, writes, truncates or flushes give the
    /// other tasks a turn while it runs.
    fn slow_calls(&self) {
        self.slow.store(true, Ordering::SeqCst);
    }

    /// Counts a call that runs until the result is dropped.
    async fn begin_call(&self) -> Busy<'_> {
        let now = self.busy.fetch_add(1, Ordering::SeqCst) + 1;
        self.most_busy.fetch_max(now, Ordering::SeqCst);
        let busy = Busy(self);
        if self.slow.load(Ordering::SeqCst) {
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        }
        busy
    }

    /// Makes write number `at`, or clone number `at` of a backend that
    /// clones, wait until `resume` is notified, after notifying `reached`.
    fn stall(&self, at: usize, reached: &Arc<Notify>, resume: &Arc<Notify>) {
        *self.stall.lock().unwrap() = Some(Stall {
            at,
            reached: Arc::clone(reached),
            resume: Arc::clone(resume),
        });
    }

    fn after_write(&self, run: impl Fn(usize) + Send + Sync + 'static) {
        *self.after_write.lock().unwrap() = Some(Box::new(run));
    }
}

/// A memory backend whose handles count what they do, and whose
/// `copy_range` follows the spy's [`Fast`] mode.
struct SpyFs {
    files: MemFsBackend,
    spy: Arc<Spy>,
}

impl SpyFs {
    fn new(files: &MemFsBackend, spy: &Arc<Spy>) -> Self {
        Self {
            files: files.clone(),
            spy: Arc::clone(spy),
        }
    }

    fn wrap(&self, handle: Box<dyn Handle>) -> Box<dyn Handle> {
        Box::new(SpyHandle {
            inner: handle,
            spy: Arc::clone(&self.spy),
        })
    }
}

#[async_trait]
impl ShareBackend for SpyFs {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let (handle, action) = self.files.open(path, opts).await?;
        Ok((self.wrap(handle), action))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.files.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        self.files.rename(from, to, replace).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            block_cloning: self.spy.cloning.lock().unwrap().is_some(),
            ..self.files.capabilities()
        }
    }

    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        let identity = *self.spy.identity.lock().unwrap();
        let sector = *self.spy.sector.lock().unwrap();
        let mut info = VolumeInfo::default();
        if let Some((_, serial_number)) = identity {
            info.serial_number = serial_number;
        }
        if let Some(bytes) = sector {
            info.bytes_per_sector = bytes;
        }
        Ok(info)
    }

    async fn open_stream(
        &self,
        file: Box<dyn Handle>,
        path: &SmbPath,
        stream: &StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let refusal = *self.spy.open_stream_error.lock().unwrap();
        if let Some(refusal) = refusal {
            let _ = file.close().await;
            return Err(refusal.error());
        }
        let (handle, action) = self.files.open_stream(file, path, stream, opts).await?;
        Ok((self.wrap(handle), action))
    }

    async fn copy_range(
        &self,
        src: &dyn Handle,
        src_offset: u64,
        dst: &dyn Handle,
        dst_offset: u64,
        len: u64,
    ) -> SmbResult<u64> {
        let calls = {
            let mut calls = self.spy.copy_calls.lock().unwrap();
            calls.push((src_offset, dst_offset, len));
            calls.len()
        };
        let take = match self.spy.fast {
            Fast::Unsupported => return Err(SmbError::NotSupported),
            Fast::NotSameDevice => return Err(SmbError::NotSameDevice),
            Fast::Fails => return Err(SmbError::DiskFull),
            Fast::Once if calls > 1 => return Err(SmbError::NotSupported),
            Fast::Full | Fast::Once => len,
            Fast::AtMost(n) => len.min(n),
        };
        let _call = self.spy.begin_call().await;
        let (Some(src), Some(dst)) = (as_spy(src), as_spy(dst)) else {
            return Err(SmbError::NotSupported);
        };
        let data = src.inner.read(src_offset, take as u32).await?;
        dst.inner.write(dst_offset, &data).await?;
        Ok(data.len() as u64)
    }

    async fn clone_range(
        &self,
        src: &dyn Handle,
        src_offset: u64,
        dst: &dyn Handle,
        dst_offset: u64,
        len: u64,
    ) -> SmbResult<()> {
        let calls = {
            let mut calls = self.spy.clone_calls.lock().unwrap();
            calls.push((src_offset, dst_offset, len));
            calls.len()
        };
        let cloning = *self.spy.cloning.lock().unwrap();
        match cloning {
            None | Some(Cloning::NotSupported) => Err(SmbError::NotSupported),
            Some(Cloning::NotSameDevice) => Err(SmbError::NotSameDevice),
            Some(Cloning::InvalidParameter) => Err(SmbError::InvalidParameter),
            Some(Cloning::DiskFull) => Err(SmbError::DiskFull),
            Some(Cloning::Full) => {
                let (Some(src), Some(dst)) = (as_spy(src), as_spy(dst)) else {
                    return Err(SmbError::NotSameDevice);
                };
                let data = src.inner.read(src_offset, len as u32).await?;
                dst.inner.write(dst_offset, &data).await?;
                let stall = self
                    .spy
                    .stall
                    .lock()
                    .unwrap()
                    .clone()
                    .filter(|stall| stall.at == calls);
                if let Some(stall) = stall {
                    stall.reached.notify_one();
                    stall.resume.notified().await;
                }
                Ok(())
            }
        }
    }
}

/// `handle` as a handle of a spying backend.
fn as_spy(handle: &dyn Handle) -> Option<&SpyHandle> {
    handle.as_any()?.downcast_ref::<SpyHandle>()
}

struct SpyHandle {
    inner: Box<dyn Handle>,
    spy: Arc<Spy>,
}

#[async_trait]
impl Handle for SpyHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.spy.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(refusal) = *self.spy.read_error.lock().unwrap() {
            return Err(refusal.error());
        }
        let max = *self.spy.max_read.lock().unwrap();
        self.inner
            .read(offset, max.map_or(len, |m| len.min(m)))
            .await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        let writes = self.spy.writes.fetch_add(1, Ordering::SeqCst) + 1;
        let _call = self.spy.begin_call().await;
        let max = *self.spy.max_write.lock().unwrap();
        let data = &data[..max.map_or(data.len(), |m| data.len().min(m as usize))];
        let accepted = match self.spy.space.lock().unwrap().as_mut() {
            Some((0, refusal)) => return Err(refusal.error()),
            Some((left, _)) => {
                let n = (*left).min(data.len() as u64);
                *left -= n;
                n as usize
            }
            None => data.len(),
        };
        let written = self.inner.write(offset, &data[..accepted]).await?;
        self.run_after_write(writes);
        let stall = self
            .spy
            .stall
            .lock()
            .unwrap()
            .clone()
            .filter(|stall| stall.at == writes);
        if let Some(stall) = stall {
            stall.reached.notify_one();
            stall.resume.notified().await;
        }
        Ok(written)
    }

    async fn flush(&self) -> SmbResult<()> {
        self.spy.flushes.fetch_add(1, Ordering::SeqCst);
        let _call = self.spy.begin_call().await;
        self.inner.flush().await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let mut info = self.inner.stat().await?;
        info.end_of_file += *self.spy.extra_size.lock().unwrap();
        if let Some((file_index, _)) = *self.spy.identity.lock().unwrap() {
            info.file_index = file_index;
        }
        Ok(info)
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.spy.times.lock().unwrap().push(times);
        self.inner.set_times(times).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.inner.set_attributes(attributes).await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        let _call = self.spy.begin_call().await;
        self.inner.truncate(len).await
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        self.inner.list_dir(pattern).await
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        self.inner.close().await
    }

    async fn streams(&self) -> SmbResult<Vec<StreamInfo>> {
        self.inner.streams().await
    }

    async fn eas(&self) -> SmbResult<Vec<Ea>> {
        self.inner.eas().await
    }

    fn as_any(&self) -> Option<&(dyn Any + Send + Sync)> {
        Some(self)
    }
}

impl SpyHandle {
    fn run_after_write(&self, writes: usize) {
        if let Some(run) = self.spy.after_write.lock().unwrap().as_ref() {
            run(writes);
        }
    }
}

/// A spying share holding `s` with `len` bytes and an empty `t`, and a
/// client with both open.
async fn spied(
    fast: Fast,
    len: usize,
) -> (MemFsBackend, Arc<Spy>, Client, FileId, FileId, Vec<u8>) {
    let data = pattern(len, 0x42);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_file("t", &[]);
    let spy = Spy::new(fast);
    let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    (files, spy, c, source, target, data)
}

#[tokio::test]
async fn a_backend_that_copies_everything_does_the_whole_copy() {
    let (files, spy, mut c, source, target, data) = spied(Fast::Full, 3000).await;
    let key = c.key(source).await;
    let chunks = [(0, 0, 1000), (1000, 1000, 2000)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (OK, Some([2, 0, 3000]))
    );
    assert_eq!(files.contents("t"), Some(data));
    assert_eq!(spy.copy_calls(), [(0, 0, 1000), (1000, 1000, 2000)]);
    assert_eq!((spy.reads(), spy.writes()), (0, 0), "no read and no write");
}

#[tokio::test]
async fn what_a_backend_leaves_is_read_and_written() {
    let (files, spy, mut c, source, target, data) = spied(Fast::AtMost(300), 2000).await;
    let key = c.key(source).await;
    let chunks = [(0, 0, 1000), (1000, 1000, 1000)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (OK, Some([2, 0, 2000])),
        "a count below the length is never reported"
    );
    assert_eq!(files.contents("t"), Some(data));
    assert_eq!(spy.copy_calls(), [(0, 0, 1000), (1000, 1000, 1000)]);
}

#[tokio::test]
async fn a_backend_that_copies_only_the_first_chunk_leaves_the_rest_to_reads_and_writes() {
    let (files, spy, mut c, source, target, data) = spied(Fast::Once, 3000).await;
    let key = c.key(source).await;
    let chunks = [(0, 0, 1000), (1000, 1000, 1000), (2000, 2000, 1000)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (OK, Some([3, 0, 3000]))
    );
    assert_eq!(files.contents("t"), Some(data));
    assert_eq!(spy.copy_calls().len(), 3, "asked for every chunk");
    assert_eq!(spy.writes(), 2, "the first chunk is not written");
}

#[tokio::test]
async fn a_backend_that_cannot_copy_between_the_handles_is_read_and_written() {
    let (files, _, mut c, source, target, data) = spied(Fast::NotSameDevice, 1500).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 1500)]).await,
        (OK, Some([1, 0, 1500]))
    );
    assert_eq!(files.contents("t"), Some(data));
}

#[tokio::test]
async fn a_backend_error_fails_the_chunk() {
    let (files, spy, mut c, source, target, _) = spied(Fast::Fails, 100).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 100)]).await,
        (DISK_FULL, Some([0, 0, 0]))
    );
    assert_eq!(spy.copy_calls().len(), 1);
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn one_file_copies_without_the_backend_only_where_ranges_overlap() {
    let data = pattern(3000, 5);
    let files = MemFsBackend::new().with_file("f", &data);
    let spy = Spy::new(Fast::Full);
    let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("f")).await;
    let target = c.open(Create::new("f")).await;
    let key = c.key(source).await;

    let chunks = [(0, 1000, 1500), (2000, 0, 500), (2500, 500, 400)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (OK, Some([3, 0, 2400]))
    );
    assert_eq!(
        spy.copy_calls(),
        [(2000, 0, 500), (2500, 500, 400)],
        "only the chunks that do not overlap go to the backend"
    );
    let mut expected = data.clone();
    for (from, to, len) in [(0, 1000, 1500), (2000, 0, 500), (2500, 500, 400)] {
        expected.copy_within(from..from + len, to);
    }
    assert_eq!(files.contents("f"), Some(expected));
}

#[tokio::test]
async fn short_reads_are_completed() {
    let (files, spy, mut c, source, target, data) = spied(Fast::Unsupported, 1000).await;
    *spy.max_read.lock().unwrap() = Some(64);
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 1000), (0, 1000, 500)]).await,
        (OK, Some([2, 0, 1500]))
    );
    assert_eq!(
        files.contents("t"),
        Some([data.clone(), data[..500].to_vec()].concat())
    );
}

#[tokio::test]
async fn a_write_that_stops_short_is_continued_to_the_end_of_the_chunk() {
    let (files, spy, mut c, source, target, data) = spied(Fast::Unsupported, 1000).await;
    *spy.max_write.lock().unwrap() = Some(100);
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 1000), (0, 1000, 500)]).await,
        (OK, Some([2, 0, 1500]))
    );
    assert_eq!(
        files.contents("t"),
        Some([data.clone(), data[..500].to_vec()].concat())
    );
}

#[tokio::test]
async fn a_source_that_ends_during_a_chunk_fails_it_with_nothing_written() {
    let (files, spy, mut c, source, target, _) = spied(Fast::Unsupported, 1000).await;
    *spy.extra_size.lock().unwrap() = 500;
    let key = c.key(source).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 400), (800, 400, 600)]).await,
        (VIEW_SIZE, Some([1, 0, 400]))
    );
    assert_eq!(files.contents("t").map(|t| t.len()), Some(400));
}

#[tokio::test]
async fn a_write_through_target_is_flushed_once() {
    for (options, flushes) in [(0, 0), (FILE_WRITE_THROUGH, 1)] {
        let (_, spy, mut c, source, _, _) = spied(Fast::Full, 100).await;
        let target = c.open(Create::new("t").options(options)).await;
        let key = c.key(source).await;
        let chunks = [(0, 0, 50), (50, 50, 50)];
        assert_eq!(c.copy(target, &key, &chunks).await, (OK, Some([2, 0, 100])));
        assert_eq!(spy.flushes(), flushes, "options {options}");
    }
}

#[tokio::test]
async fn a_write_refused_as_an_invalid_parameter_is_not_answered_as_the_limits() {
    let (files, spy, mut c, source, target, data) = spied(Fast::Unsupported, 1000).await;
    *spy.space.lock().unwrap() = Some((700, Refusal::InvalidParameter));
    let key = c.key(source).await;
    let chunks = [(0, 0, 500), (500, 500, 500)];
    assert_eq!(
        c.copy(target, &key, &chunks).await,
        (DEVICE, Some([1, 200, 700]))
    );
    assert_eq!(files.contents("t"), Some(data[..700].to_vec()));
}

#[tokio::test]
async fn a_backend_that_copied_part_of_a_chunk_before_the_write_failed_is_counted() {
    let (files, spy, mut c, source, target, data) = spied(Fast::AtMost(300), 1000).await;
    *spy.space.lock().unwrap() = Some((200, Refusal::DiskFull));
    let mut watcher = Client::new(&c.state).await;
    let root = watcher
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let key = c.key(source).await;

    let w = watcher.watch(root).await;
    assert_eq!(
        c.copy(target, &key, &[(0, 0, 1000)]).await,
        (DISK_FULL, Some([0, 500, 500])),
        "300 bytes from the backend and 200 from the write"
    );
    assert_eq!(files.contents("t"), Some(data[..500].to_vec()));
    watcher.quiet().await;
    c.close(target).await;
    assert_eq!(watcher.events(w).await, [(MODIFIED, "t".to_string())]);
    assert_eq!(spy.copy_calls(), [(0, 0, 1000)]);
}

// ---------------------------------------------------------------------------
// Apple's whole-file copy
// ---------------------------------------------------------------------------

const CREATED_AT: u64 = 0x01DA_1111_0000_0001;
const WRITTEN_AT: u64 = 0x01DB_2222_0000_0002;

/// A file a macOS client copies: its data, Finder info and resource fork.
struct Apple {
    files: MemFsBackend,
    data: Vec<u8>,
    info: Vec<u8>,
    fork: Vec<u8>,
}

/// A source `s` of `len` bytes with `AFP_AfpInfo` and `AFP_Resource` and
/// times the empty target `t` does not have.
fn apple_files(len: usize) -> Apple {
    let data = pattern(len, 0x21);
    let info = pattern(60, 0x5A);
    let fork = pattern(300_000, 0x77);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_stream("s", "AFP_AfpInfo", &info)
        .with_stream("s", "AFP_Resource", &fork)
        .with_times("s", CREATED_AT, WRITTEN_AT)
        .with_file("t", b"");
    Apple {
        files,
        data,
        info,
        fork,
    }
}

/// A client that mounted the share `home` and has the share `other`
/// connected.
async fn mounted_with_other_share(state: &Arc<ServerState>) -> Client {
    let mut c = Client::new(state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    assert_ne!(c.mount().await & aapl::OSX_COPYFILE, 0);
    c
}

/// A client that mounted the share, with the source `s` open for read
/// sharing read, the target `t` open sharing nothing, and the source's
/// resume key.
async fn finder(state: &Arc<ServerState>) -> (Client, FileId, FileId, [u8; 24]) {
    let mut c = Client::new(state).await;
    assert_ne!(c.mount().await & aapl::OSX_COPYFILE, 0);
    let source = c
        .open(Create::new("s").access(READ).share(SHARE_READ))
        .await;
    let target = c.open(Create::new("t").share(0)).await;
    let key = c.key(source).await;
    (c, source, target, key)
}

#[tokio::test]
async fn a_whole_file_copy_carries_the_data_every_stream_and_the_times() {
    // Two whole pieces and a half.
    let a = apple_files(5 * MIB as usize / 2);
    let state = server(&a.files);
    let (mut c, source, target, key) = finder(&state).await;

    let (_, async_id) = c.start_whole_file(HOME, target, &key).await;
    assert_eq!(c.peer.conn.pending.len(), 1);
    assert_eq!(
        c.whole_file_done(target, async_id).await,
        (OK, Some([0, 0, 5 * MIB / 2]))
    );
    assert_eq!(c.peer.conn.pending.len(), 0);

    assert_eq!(a.files.contents("t"), Some(a.data.clone()));
    assert_eq!(a.files.stream_names("t"), ["AFP_AfpInfo", "AFP_Resource"]);
    assert_eq!(
        a.files.stream_contents("t", "AFP_AfpInfo"),
        Some(a.info.clone())
    );
    assert_eq!(
        a.files.stream_contents("t", "AFP_Resource"),
        Some(a.fork.clone())
    );
    assert_eq!(a.files.times("t"), (CREATED_AT, WRITTEN_AT));
    assert_eq!(a.files.contents("s"), Some(a.data));
    assert_eq!(a.files.stream_contents("s", "AFP_Resource"), Some(a.fork));
    assert_eq!(
        a.files.open_handles(),
        2,
        "the copy closed the streams it opened"
    );
    c.close(source).await;
    c.close(target).await;
}

#[tokio::test]
async fn a_copy_of_an_empty_file_is_answered_with_no_bytes() {
    let files = MemFsBackend::new()
        .with_file("s", b"")
        .with_times("s", CREATED_AT, WRITTEN_AT)
        .with_file("t", &pattern(3 * MIB as usize, 4));
    let state = server(&files);
    let (mut c, _, target, key) = finder(&state).await;
    assert_eq!(c.copy_whole_file(target, &key).await, (OK, Some([0, 0, 0])));
    assert_eq!(files.contents("t"), Some(Vec::new()));
    assert_eq!(files.times("t"), (CREATED_AT, WRITTEN_AT));
}

#[tokio::test]
async fn a_share_without_streams_gets_the_data_alone() {
    let home = MemFsBackend::new();
    let data = pattern(MIB as usize + 10, 8);
    let other = MemFsBackend::new()
        .with_file("s", &data)
        .with_stream("s", "AFP_AfpInfo", &pattern(60, 1))
        .with_times("s", CREATED_AT, WRITTEN_AT)
        .with_file("t", b"")
        .without_streams();
    let state = server_of_two(&home, &other);
    let mut c = mounted_with_other_share(&state).await;
    let source = c.open_at(OTHER, Create::new("s")).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let key = c.key_at(OTHER, source).await;
    assert_eq!(
        c.copy_whole_file_at(OTHER, target, &key).await,
        (OK, Some([0, 0, MIB + 10]))
    );
    assert_eq!(other.contents("t"), Some(data));
    assert!(other.stream_names("t").is_empty());
    assert_eq!(other.times("t"), (CREATED_AT, WRITTEN_AT));
}

#[tokio::test]
async fn a_whole_file_copy_between_shares_copies_the_streams() {
    let a = apple_files(1000);
    let home = a.files.clone();
    let other = MemFsBackend::new().with_file("t", b"");
    let state = server_of_two(&home, &other);
    let mut c = mounted_with_other_share(&state).await;
    let source = c.open(Create::new("s").access(READ)).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy_whole_file_at(OTHER, target, &key).await,
        (OK, Some([0, 0, 1000]))
    );
    assert_eq!(other.contents("t"), Some(a.data));
    assert_eq!(other.stream_contents("t", "AFP_AfpInfo"), Some(a.info));
    assert_eq!(other.stream_contents("t", "AFP_Resource"), Some(a.fork));
    assert_eq!(other.times("t"), (CREATED_AT, WRITTEN_AT));
}

#[tokio::test]
async fn a_file_copied_onto_itself_is_left_as_it_is() {
    let a = apple_files(1000);
    let state = server(&a.files);
    let mut c = Client::new(&state).await;
    c.mount().await;
    let source = c.open(Create::new("s")).await;
    let same = c.open(Create::new("s")).await;
    let key = c.key(source).await;
    assert_eq!(c.copy(same, &key, &[]).await, (OK, Some([0, 0, 1000])));
    assert_eq!(a.files.contents("s"), Some(a.data));
    assert_eq!(a.files.stream_contents("s", "AFP_Resource"), Some(a.fork));
}

#[tokio::test]
async fn a_whole_file_copy_is_denied_unless_both_opens_are_files_with_data_rights() {
    let files = MemFsBackend::new()
        .with_file("s", b"data")
        .with_stream("s", "x", b"stream")
        .with_file("t", b"")
        .with_stream("t", "x", b"")
        .with_dir("d");
    let state = server(&files);
    let mut c = Client::new(&state).await;
    c.mount().await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    let key = c.key(source).await;
    let append_only = c
        .open(Create::new("t").access(READ | FILE_APPEND_DATA))
        .await;
    let source_stream = c.open(Create::new("s:x").access(READ)).await;
    let target_stream = c.open(Create::new("t:x")).await;
    let dir = c
        .open(Create::new("d").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let stream_key = c.key(source_stream).await;
    let dir_key = c.key(dir).await;
    let denied = (DENIED, None);
    assert_eq!(c.copy(append_only, &key, &[]).await, denied);
    assert_eq!(c.copy(target_stream, &key, &[]).await, denied);
    assert_eq!(c.copy(target, &stream_key, &[]).await, denied);
    assert_eq!(c.copy(target, &dir_key, &[]).await, denied);
    assert_eq!(c.copy(dir, &key, &[]).await, denied);
    let attributes = c.open(Create::new("s").access(READ_ATTRIBUTES)).await;
    let attributes_key = c.key(attributes).await;
    assert_eq!(c.copy(target, &attributes_key, &[]).await, denied);
    assert_eq!(files.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn a_share_with_copies_off_refuses_a_whole_file_copy_the_cap_was_sent_for() {
    let home = MemFsBackend::new().with_file("s", b"data");
    let other = MemFsBackend::new()
        .with_file("t", b"")
        .with_stream("t", "x", b"");
    let state = server_on(vec![
        Share::new("home", home.clone()).public(),
        Share::new("other", other.clone())
            .public()
            .server_side_copy(false),
    ]);
    let mut c = Client::new(&state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    let source = c.open(Create::new("s")).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let target_stream = c.open_at(OTHER, Create::new("t:x")).await;
    let key = c.key(source).await;
    let forged = resume_key(target, &state.resume_tag);
    let into_home = c.open(Create::new("s")).await;
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, target, &key, &[]).await,
        (UNSUPPORTED, None),
        "without the cap"
    );

    assert_ne!(c.mount().await & aapl::OSX_COPYFILE, 0);
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, target, &key, &[]).await,
        (DENIED, None),
        "a target on a share with copies off"
    );
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, target_stream, &key, &[]).await,
        (DEVICE, None),
        "a named stream of it"
    );
    assert_eq!(
        c.copy(into_home, &forged, &[]).await,
        (DENIED, None),
        "a source on a share with copies off"
    );
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, target, &key, &[(0, 0, 4)])
            .await,
        (UNSUPPORTED, None),
        "a copy with chunks"
    );
    assert_eq!(other.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn the_cap_belongs_to_the_connection_it_was_sent_on() {
    let a = apple_files(100);
    let state = server(&a.files);
    let mut other = Client::new(&state).await;
    other.mount().await;
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    let key = c.key(source).await;
    assert_eq!(c.copy(target, &key, &[]).await, (OK, Some([0, 0, 0])));
    assert_eq!(a.files.contents("t"), Some(Vec::new()));
}

#[tokio::test]
async fn a_whole_file_copy_counts_against_the_pending_requests() {
    let a = apple_files(100);
    let state = server(&a.files);
    let (mut c, _, target, key) = finder(&state).await;
    let hdr = Smb2Header::default();
    let held: Vec<_> = (0..MAX_PENDING_REQUESTS)
        .map(|_| c.peer.conn.pending.reserve(&hdr, None, 0).expect("a slot"))
        .collect();
    assert_eq!(
        c.copy(target, &key, &[]).await,
        (ntstatus::STATUS_INSUFFICIENT_RESOURCES, None)
    );
    assert_eq!(a.files.contents("t"), Some(Vec::new()));
    for (op, _) in held {
        c.peer.conn.pending.finish(op.async_id);
    }
    assert_eq!(
        c.copy_whole_file(target, &key).await,
        (OK, Some([0, 0, 100]))
    );
}

/// A whole-file copy of three pieces and a little that is held in the
/// write of its first, and a second pair of files for another copy.
struct Stalled {
    files: MemFsBackend,
    spy: Arc<Spy>,
    state: Arc<ServerState>,
    c: Client,
    target: FileId,
    mid: u64,
    async_id: u64,
    resume: Arc<Notify>,
}

impl Stalled {
    async fn new() -> Self {
        let files = MemFsBackend::new()
            .with_file("s", &pattern(3 * MIB as usize + 100, 6))
            .with_file("t", b"")
            .with_file("s2", &pattern(MIB as usize + 5, 7))
            .with_file("t2", b"old");
        let spy = Spy::new(Fast::Unsupported);
        let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
        let (reached, resume) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        spy.stall(1, &reached, &resume);
        let (mut c, _, target, key) = finder(&state).await;
        let (mid, async_id) = c.start_whole_file(HOME, target, &key).await;
        reached.notified().await;
        Self {
            files,
            spy,
            state,
            c,
            target,
            mid,
            async_id,
            resume,
        }
    }

    /// The final response, once the held write goes on.
    async fn finish(mut self) -> ((u32, Option<Counts>), MemFsBackend, Arc<Spy>) {
        self.resume.notify_one();
        let done = self.c.whole_file_done(self.target, self.async_id).await;
        (done, self.files, self.spy)
    }
}

/// Lets the held write of a [`Stalled`] copy go on once `ended` holds. A
/// request that ends the copy's session, tree or target takes it away
/// first and then waits for the write.
async fn resume_once(resume: &Notify, ended: impl AsyncFn() -> bool) {
    let waiting = async {
        while !ended().await {
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the request takes away what it ends");
    resume.notify_one();
}

#[tokio::test]
async fn a_cancel_in_the_middle_ends_the_copy_with_status_cancelled() {
    let mut s = Stalled::new().await;
    s.c.cancel(s.mid).await;
    let ((status, counts), files, spy) = s.finish().await;
    assert_eq!((status, counts), (CANCELLED, None));
    assert_eq!(spy.writes(), 1, "no piece after the cancel");
    assert_eq!(files.contents("t").map(|t| t.len()), Some(MIB as usize));
}

#[tokio::test]
async fn a_logoff_in_the_middle_ends_the_copy_with_the_session() {
    let mut s = Stalled::new().await;
    let conn = Arc::clone(&s.c.peer.conn);
    let logoff = s.c.peer.request(&s.state, Command::Logoff, &[4, 0, 0, 0]);
    let resume = resume_once(&s.resume, async || {
        !conn.sessions.read().await.contains_key(&1)
    });
    let ((_, reply), ()) = tokio::join!(logoff, resume);
    assert_eq!(status(&reply), OK);
    let done = s.c.whole_file_done(s.target, s.async_id).await;
    assert_eq!(done, (SESSION_DELETED, None));
    assert_eq!(s.spy.writes(), 1);
    assert_eq!(s.files.open_handles(), 0);
}

#[tokio::test]
async fn a_tree_disconnect_in_the_middle_ends_the_copy_with_the_tree() {
    let mut s = Stalled::new().await;
    let conn = Arc::clone(&s.c.peer.conn);
    let disconnect =
        s.c.peer
            .request(&s.state, Command::TreeDisconnect, &[4, 0, 0, 0]);
    let resume = resume_once(&s.resume, async || {
        let session = conn.sessions.read().await[&1].clone();
        !session.read().await.trees.read().await.contains_key(&1)
    });
    let ((_, reply), ()) = tokio::join!(disconnect, resume);
    assert_eq!(status(&reply), OK);
    let done = s.c.whole_file_done(s.target, s.async_id).await;
    assert_eq!(done, (TREE_DELETED, None));
    assert_eq!(s.spy.writes(), 1);
    assert_eq!(s.files.open_handles(), 0);
}

#[tokio::test]
async fn closing_the_target_in_the_middle_ends_the_copy_with_a_closed_file() {
    let mut s = Stalled::new().await;
    let tree = {
        let session = s.c.peer.conn.sessions.read().await[&1].clone();
        session.read().await.trees.read().await[&1].clone()
    };
    let target = s.target;
    let close = s.c.close(target);
    let resume = resume_once(&s.resume, async || {
        lookup_open(&tree, target).await.is_none()
    });
    tokio::join!(close, resume);
    let done = s.c.whole_file_done(s.target, s.async_id).await;
    assert_eq!(done, (FILE_CLOSED, None));
    assert_eq!(s.spy.writes(), 1);
    assert_eq!(s.files.open_handles(), 1, "only the source is open");
}

#[tokio::test]
async fn a_copy_waiting_for_its_turn_is_cancelled_with_status_cancelled() {
    let mut s = Stalled::new().await;
    let source = s.c.open(Create::new("s2").access(READ)).await;
    let target = s.c.open(Create::new("t2")).await;
    let key = s.c.key(source).await;
    let (mid, async_id) = s.c.start_whole_file(HOME, target, &key).await;
    // It waits for the turn the held piece has, before it empties its target.
    s.c.quiet().await;
    s.c.cancel(mid).await;
    assert_eq!(
        s.c.whole_file_done(target, async_id).await,
        (CANCELLED, None)
    );
    assert_eq!(s.files.contents("t2"), Some(b"old".to_vec()));
    assert_eq!(s.spy.writes(), 1, "no piece of the cancelled copy");
    let ((status, counts), files, _) = s.finish().await;
    assert_eq!((status, counts), (OK, Some([0, 0, 3 * MIB + 100])));
    assert_eq!(
        files.contents("t"),
        Some(pattern(3 * MIB as usize + 100, 6))
    );
}

#[tokio::test]
async fn the_copies_of_a_connection_take_turns_to_empty_copy_and_flush() {
    let (first, second) = (
        pattern(3 * MIB as usize + 7, 1),
        pattern(2 * MIB as usize + 9, 2),
    );
    let files = MemFsBackend::new()
        .with_file("s1", &first)
        .with_file("t1", b"")
        .with_file("s2", &second)
        .with_file("t2", b"old");
    let spy = Spy::new(Fast::Unsupported);
    spy.slow_calls();
    let (reached, resume) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    spy.stall(1, &reached, &resume);
    let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
    let mut c = Client::new(&state).await;
    c.mount().await;
    let mut started = Vec::new();
    for (source, target) in [("s1", "t1"), ("s2", "t2")] {
        let source = c.open(Create::new(source).access(READ)).await;
        let target = c
            .open(Create::new(target).options(FILE_WRITE_THROUGH))
            .await;
        let key = c.key(source).await;
        let (_, async_id) = c.start_whole_file(HOME, target, &key).await;
        started.push((async_id, target));
        if started.len() == 1 {
            // The first copy is in the middle of a piece when the second starts.
            reached.notified().await;
        }
    }
    c.quiet().await;
    assert_eq!(
        files.contents("t2"),
        Some(b"old".to_vec()),
        "the second copy waits for its turn to empty its target"
    );
    resume.notify_one();
    assert_eq!(
        c.whole_files_done(&started).await,
        [
            (OK, Some([0, 0, 3 * MIB + 7])),
            (OK, Some([0, 0, 2 * MIB + 9]))
        ]
    );
    assert_eq!(files.contents("t1"), Some(first));
    assert_eq!(files.contents("t2"), Some(second));
    assert_eq!(spy.copy_calls().len(), 7, "four pieces and three");
    assert_eq!(spy.flushes(), 2);
    assert_eq!(spy.most_calls_at_once(), 1);
    assert_eq!(c.peer.conn.copy_turn.available_permits(), 1);
}

#[tokio::test]
async fn a_target_stream_held_open_without_share_write_fails_the_copy() {
    let a = apple_files(1000);
    let files = a.files.clone().with_stream("t", "AFP_Resource", b"old");
    let state = server(&files);
    let (mut c, _, target, key) = finder(&state).await;
    let holder = c
        .open(Create::new("t:AFP_Resource").access(READ).share(SHARE_READ))
        .await;
    assert_eq!(
        c.copy_whole_file(target, &key).await,
        (SHARING, Some([0, 0, 1000])),
        "the data is copied and the stream is not"
    );
    assert_eq!(
        files.stream_contents("t", "AFP_Resource"),
        Some(b"old".to_vec()),
        "the stream is not emptied first"
    );
    assert_eq!(files.stream_contents("t", "AFP_AfpInfo"), Some(a.info));
    assert_eq!(files.open_handles(), 3, "the copy closed its stream opens");
    c.close(holder).await;
}

#[tokio::test]
async fn a_source_stream_held_open_without_share_read_fails_the_copy() {
    let a = apple_files(1000);
    let state = server(&a.files);
    let (mut c, _, target, key) = finder(&state).await;
    let holder = c
        .open(Create::new("s:AFP_AfpInfo").access(READ).share(0))
        .await;
    assert_eq!(
        c.copy_whole_file(target, &key).await,
        (SHARING, Some([0, 0, 1000]))
    );
    assert!(a.files.stream_names("t").is_empty());
    c.close(holder).await;
}

/// A whole-file copy whose open of the target stream `AFP_Resource` waits
/// for another client to give up the handle it caches.
struct Waiting {
    files: MemFsBackend,
    state: Arc<ServerState>,
    cacher: Client,
    cached: FileId,
    copier: Client,
    target: FileId,
    mid: u64,
    async_id: u64,
    fork: Vec<u8>,
}

impl Waiting {
    async fn new() -> Self {
        let a = apple_files(100);
        let files = a.files.clone().with_stream("t", "AFP_Resource", b"old");
        let state = server(&files);
        let mut cacher = Client::from_client(&state, 1).await;
        let mut copier = Client::from_client(&state, 2).await;
        copier.mount().await;
        let cached = cacher
            .open(
                Create::new("t:AFP_Resource")
                    .access(READ)
                    .share(SHARE_READ)
                    .lease(3, LEASE_RH),
            )
            .await;
        let source = copier.open(Create::new("s").access(READ)).await;
        let target = copier.open(Create::new("t")).await;
        let key = copier.key(source).await;
        let (mid, async_id) = copier.start_whole_file(HOME, target, &key).await;
        let flags = cacher.breaks(3, LEASE_RH, LEASE_R).await;
        assert_eq!(
            flags & LeaseBreakNotification::FLAG_ACK_REQUIRED,
            LeaseBreakNotification::FLAG_ACK_REQUIRED
        );
        assert_eq!(
            files.stream_contents("t", "AFP_Resource"),
            Some(b"old".to_vec()),
            "the stream is not emptied while the copy waits"
        );
        Self {
            files,
            state,
            cacher,
            cached,
            copier,
            target,
            mid,
            async_id,
            fork: a.fork,
        }
    }

    async fn done(&mut self) -> (u32, Option<Counts>) {
        self.copier
            .whole_file_done(self.target, self.async_id)
            .await
    }
}

#[tokio::test]
async fn a_stream_open_waits_while_a_client_gives_up_a_cached_handle() {
    let mut w = Waiting::new().await;
    w.cacher.close(w.cached).await;
    assert_eq!(w.done().await, (OK, Some([0, 0, 100])));
    assert_eq!(w.files.stream_contents("t", "AFP_Resource"), Some(w.fork));
}

#[tokio::test]
async fn a_cancel_while_a_stream_open_waits_ends_the_copy_with_status_cancelled() {
    let mut w = Waiting::new().await;
    w.copier.cancel(w.mid).await;
    assert_eq!(w.done().await, (CANCELLED, None));
    assert_eq!(
        w.files.stream_contents("t", "AFP_Resource"),
        Some(b"old".to_vec())
    );
    assert_eq!(
        w.files.open_handles(),
        3,
        "the copy closed its stream opens"
    );
}

#[tokio::test]
async fn a_tree_disconnect_while_a_stream_open_waits_ends_the_copy_with_the_tree() {
    let mut w = Waiting::new().await;
    let (_, reply) = w
        .copier
        .peer
        .request(&w.state, Command::TreeDisconnect, &[4, 0, 0, 0])
        .await;
    assert_eq!(status(&reply), OK);
    assert_eq!(w.done().await, (TREE_DELETED, None));
}

#[tokio::test]
async fn a_whole_file_copy_reports_the_streams_it_adds_and_changes() {
    let a = apple_files(1000);
    let state = server(&a.files);
    let mut watcher = Client::new(&state).await;
    let root = watcher
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let (mut c, source, target, key) = finder(&state).await;

    let w = watcher.watch(root).await;
    assert_eq!(
        c.copy_whole_file(target, &key).await,
        (OK, Some([0, 0, 1000]))
    );
    c.close(source).await;
    c.close(target).await;
    let mut events = watcher.events(w).await;
    events.extend(watcher.kept_events(root).await);
    let stream = |action, name: &str| (action, format!("t:{name}"));
    for name in ["AFP_AfpInfo", "AFP_Resource"] {
        assert!(events.contains(&stream(ADDED_STREAM, name)), "{events:?}");
        assert!(
            events.contains(&stream(MODIFIED_STREAM, name)),
            "{events:?}"
        );
    }
    assert_eq!(
        events.last(),
        Some(&(MODIFIED, "t".to_string())),
        "the target reports its contents when it closes"
    );
    assert!(
        events.iter().all(|(_, name)| name.starts_with('t')),
        "the source reports nothing: {events:?}"
    );
}

#[tokio::test]
async fn a_stream_the_copy_empties_is_reported_changed_and_not_added() {
    let files = MemFsBackend::new()
        .with_file("s", b"data")
        .with_stream("s", "x", b"")
        .with_file("t", b"")
        .with_stream("t", "x", b"old");
    let state = server(&files);
    let mut watcher = Client::new(&state).await;
    let root = watcher
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let (mut c, source, target, key) = finder(&state).await;

    let w = watcher.watch(root).await;
    assert_eq!(c.copy_whole_file(target, &key).await, (OK, Some([0, 0, 4])));
    c.close(source).await;
    c.close(target).await;
    let mut events = watcher.events(w).await;
    events.extend(watcher.kept_events(root).await);
    assert!(
        events.contains(&(MODIFIED_STREAM, "t:x".to_string())),
        "{events:?}"
    );
    assert!(
        !events.contains(&(ADDED_STREAM, "t:x".to_string())),
        "{events:?}"
    );
    assert_eq!(files.stream_contents("t", "x"), Some(Vec::new()));
}

#[tokio::test]
async fn a_whole_file_copy_breaks_the_read_lease_of_another_client_on_the_target() {
    let files = MemFsBackend::new()
        .with_file("s", b"")
        .with_file("t", b"old");
    let state = server(&files);
    let mut reader = Client::from_client(&state, 1).await;
    let mut copier = Client::from_client(&state, 2).await;
    copier.mount().await;
    let cached = reader
        .open(Create::new("t").access(READ).lease(1, LEASE_R))
        .await;
    let source = copier.open(Create::new("s").access(READ)).await;
    let target = copier.open(Create::new("t").lease(2, LEASE_R)).await;
    reader.quiet().await;

    let key = copier.key(source).await;
    assert_eq!(
        copier.copy_whole_file(target, &key).await,
        (OK, Some([0, 0, 0]))
    );
    let flags = reader.breaks(1, LEASE_R, LEASE_NONE).await;
    assert_eq!(flags & LeaseBreakNotification::FLAG_ACK_REQUIRED, 0);
    copier.quiet().await;
    reader.close(cached).await;
}

#[tokio::test]
async fn the_copied_write_time_wins_over_the_one_the_target_fixed() {
    const FIXED: i64 = 0x01D5_0000_0000_0000;
    let a = apple_files(100);
    let state = server(&a.files);
    let (mut c, _, target, key) = finder(&state).await;
    assert_eq!(c.set_times(target, [0, 0, FIXED, 0]).await, OK);
    assert_eq!(a.files.times("t").1, FIXED as u64);

    assert_eq!(
        c.copy_whole_file(target, &key).await,
        (OK, Some([0, 0, 100]))
    );
    assert_eq!(a.files.times("t"), (CREATED_AT, WRITTEN_AT));
    c.close(target).await;
    assert_eq!(
        a.files.times("t"),
        (CREATED_AT, WRITTEN_AT),
        "the close does not put the fixed time back"
    );
}

#[tokio::test]
async fn data_is_copied_by_the_backend_in_pieces_and_streams_by_read_and_write() {
    let data = pattern(2 * MIB as usize + 5, 9);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_stream("s", "AFP_AfpInfo", &pattern(60, 2))
        .with_file("t", b"");
    let spy = Spy::new(Fast::Full);
    let state = server_on(vec![Share::new("home", SpyFs::new(&files, &spy)).public()]);
    let (mut c, _, target, key) = finder(&state).await;
    assert_eq!(
        c.copy_whole_file(target, &key).await,
        (OK, Some([0, 0, 2 * MIB + 5]))
    );
    let piece = u64::from(MIB);
    assert_eq!(
        spy.copy_calls(),
        [
            (0, 0, piece),
            (piece, piece, piece),
            (2 * piece, 2 * piece, 5),
            (0, 0, 60)
        ]
    );
    assert_eq!(files.contents("t"), Some(data));
    assert_eq!(
        files.stream_contents("t", "AFP_AfpInfo"),
        Some(pattern(60, 2))
    );
    assert_eq!(
        (spy.reads(), spy.writes()),
        (1, 1),
        "the stream is read and written"
    );
}

#[tokio::test]
async fn a_write_through_target_is_flushed_with_each_stream() {
    let a = apple_files(100);
    let spy = Spy::new(Fast::Unsupported);
    let state = server_on(vec![
        Share::new("home", SpyFs::new(&a.files, &spy)).public(),
    ]);
    let mut c = Client::new(&state).await;
    c.mount().await;
    let source = c.open(Create::new("s").access(READ)).await;
    let target = c.open(Create::new("t").options(FILE_WRITE_THROUGH)).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy_whole_file(target, &key).await,
        (OK, Some([0, 0, 100]))
    );
    assert_eq!(spy.flushes(), 3, "the data and two streams");
}

#[tokio::test]
async fn a_stream_open_that_fails_is_answered_as_a_stream_request_is() {
    for (refusal, expected) in [
        (Refusal::InvalidParameter, DEVICE),
        (Refusal::NotSupported, DENIED),
        (Refusal::DiskFull, DISK_FULL),
    ] {
        let a = apple_files(100);
        let spy = Spy::new(Fast::Unsupported);
        spy.refuse_streams(refusal);
        let state = server_on(vec![
            Share::new("home", SpyFs::new(&a.files, &spy)).public(),
        ]);
        let (mut c, _, target, key) = finder(&state).await;
        assert_eq!(
            c.copy_whole_file(target, &key).await,
            (expected, Some([0, 0, 100])),
            "{expected:#x}"
        );
    }
}

#[tokio::test]
async fn a_stream_opened_on_another_file_than_the_copy_names_fails_it() {
    let a = apple_files(100);
    let other = MemFsBackend::new()
        .with_file("t", b"")
        .with_stream("t", "AFP_AfpInfo", b"keep");
    let (home_spy, other_spy) = (Spy::new(Fast::Unsupported), Spy::new(Fast::Unsupported));
    home_spy.identify(7, 1);
    other_spy.identify(9, 1);
    // The file the target path names changes once data is written.
    let moved = Arc::downgrade(&other_spy);
    other_spy.after_write(move |_| {
        if let Some(spy) = moved.upgrade() {
            spy.identify(10, 1);
        }
    });
    let state = server_on(vec![
        Share::new("home", SpyFs::new(&a.files, &home_spy)).public(),
        Share::new("other", SpyFs::new(&other, &other_spy)).public(),
    ]);
    let mut c = mounted_with_other_share(&state).await;
    let source = c.open(Create::new("s").access(READ)).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy_whole_file_at(OTHER, target, &key).await,
        (NOT_FOUND, Some([0, 0, 100]))
    );
    assert_eq!(other.contents("t"), Some(a.data));
    assert_eq!(
        other.stream_contents("t", "AFP_AfpInfo"),
        Some(b"keep".to_vec()),
        "a stream of the file the path names is not emptied"
    );
    assert_eq!(
        (a.files.open_handles(), other.open_handles()),
        (1, 1),
        "the copy closed its stream opens"
    );
}

#[tokio::test]
async fn a_file_copied_onto_itself_through_two_shares_is_left_as_it_is() {
    let a = apple_files(1000);
    let spy = Spy::new(Fast::Full);
    spy.identify(7, 1);
    let state = server_on(vec![
        Share::new("home", SpyFs::new(&a.files, &spy)).public(),
        Share::new("other", SpyFs::new(&a.files, &spy)).public(),
    ]);
    let mut c = mounted_with_other_share(&state).await;
    let source = c.open(Create::new("s").access(READ)).await;
    let same = c.open_at(OTHER, Create::new("s")).await;
    let key = c.key(source).await;
    assert_eq!(
        c.copy_at(OTHER, COPYCHUNK, same, &key, &[]).await,
        (OK, Some([0, 0, 1000]))
    );
    assert_eq!(a.files.contents("s"), Some(a.data));
    assert_eq!(a.files.stream_contents("s", "AFP_Resource"), Some(a.fork));
    assert_eq!(a.files.times("s"), (CREATED_AT, WRITTEN_AT));
    assert_eq!((spy.reads(), spy.writes()), (0, 0));
}

#[tokio::test]
async fn files_of_two_shares_that_differ_in_id_or_volume_are_not_one_file() {
    let cases = [((7, 1), (7, 2)), ((7, 1), (8, 1)), ((0, 1), (0, 1))];
    for (home_identity, other_identity) in cases {
        let a = apple_files(1000);
        let other = MemFsBackend::new().with_file("t", b"old");
        let (home_spy, other_spy) = (Spy::new(Fast::Full), Spy::new(Fast::Full));
        home_spy.identify(home_identity.0, home_identity.1);
        other_spy.identify(other_identity.0, other_identity.1);
        let state = server_on(vec![
            Share::new("home", SpyFs::new(&a.files, &home_spy)).public(),
            Share::new("other", SpyFs::new(&other, &other_spy)).public(),
        ]);
        let mut c = mounted_with_other_share(&state).await;
        let source = c.open(Create::new("s").access(READ)).await;
        let target = c.open_at(OTHER, Create::new("t")).await;
        let key = c.key(source).await;
        assert_eq!(
            c.copy_whole_file_at(OTHER, target, &key).await,
            (OK, Some([0, 0, 1000])),
            "{home_identity:?} {other_identity:?}"
        );
        assert_eq!(other.contents("t"), Some(a.data), "{home_identity:?}");
    }
}

// ---------------------------------------------------------------------------
// Files on the host
// ---------------------------------------------------------------------------

#[cfg(feature = "localfs")]
mod local {
    use std::path::Path;

    use super::*;
    use crate::fs::LocalFsBackend;

    fn share(name: &str, dir: &Path) -> Share {
        Share::new(name, LocalFsBackend::new(dir).unwrap()).public()
    }

    #[tokio::test]
    async fn a_file_is_copied_chunk_by_chunk_within_its_share() {
        let td = tempfile::tempdir().unwrap();
        let data = pattern(2 * MIB as usize + 12_345, 0x21);
        std::fs::write(td.path().join("s"), &data).unwrap();
        std::fs::write(td.path().join("t"), []).unwrap();
        let state = server_on(vec![share("home", td.path())]);
        let mut c = Client::new(&state).await;
        let source = c.open(Create::new("s")).await;
        let target = c.open(Create::new("t")).await;
        let key = c.key(source).await;
        let mib = u64::from(MIB);
        let chunks = [(0, 0, MIB), (mib, mib, MIB), (2 * mib, 2 * mib, 12_345)];
        assert_eq!(
            c.copy(target, &key, &chunks).await,
            (OK, Some([3, 0, 2 * MIB + 12_345]))
        );
        assert_eq!(std::fs::read(td.path().join("t")).unwrap(), data);
    }

    #[tokio::test]
    async fn one_file_through_two_shares_copies_as_if_moved_through_a_buffer() {
        let td = tempfile::tempdir().unwrap();
        let data = pattern(10_000, 0x23);
        std::fs::write(td.path().join("f"), &data).unwrap();
        let state = server_on(vec![share("home", td.path()), share("other", td.path())]);
        let mut c = Client::new(&state)
            .await
            .with_other_share(Access::ReadWrite)
            .await;
        let source = c.open(Create::new("f")).await;
        let target = c.open_at(OTHER, Create::new("f")).await;
        let key = c.key(source).await;

        let mut expected = data.clone();
        expected.resize(2048 + 8192, 0);
        expected.copy_within(0..8192, 2048);
        assert_eq!(
            c.copy_at(OTHER, COPYCHUNK, target, &key, &[(0, 2048, 8192)])
                .await,
            (OK, Some([1, 0, 8192]))
        );
        assert_eq!(std::fs::read(td.path().join("f")).unwrap(), expected);

        expected.copy_within(4096..8096, 1000);
        assert_eq!(
            c.copy_at(OTHER, COPYCHUNK, target, &key, &[(4096, 1000, 4000)])
                .await,
            (OK, Some([1, 0, 4000]))
        );
        assert_eq!(std::fs::read(td.path().join("f")).unwrap(), expected);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_copy_between_two_filesystems_keeps_every_byte() {
        let Some((build, shm)) = crate::tests::filesystems::pair() else {
            return;
        };
        let data = pattern(MIB as usize + 451_424, 0x24);
        std::fs::write(build.path().join("s"), &data).unwrap();
        std::fs::write(shm.path().join("t"), []).unwrap();
        let state = server_on(vec![
            share("home", build.path()),
            share("other", shm.path()),
        ]);
        let mut c = Client::new(&state)
            .await
            .with_other_share(Access::ReadWrite)
            .await;
        let source = c.open(Create::new("s")).await;
        let target = c.open_at(OTHER, Create::new("t")).await;
        let key = c.key(source).await;
        let chunks = [(0, 0, MIB), (u64::from(MIB), u64::from(MIB), 451_424)];
        assert_eq!(
            c.copy_at(OTHER, COPYCHUNK, target, &key, &chunks).await,
            (OK, Some([2, 0, MIB + 451_424]))
        );
        assert_eq!(std::fs::read(shm.path().join("t")).unwrap(), data);
    }

    /// The first `len` bytes of the open `file_id`, read in pieces.
    async fn read_len(c: &mut Client, file_id: FileId, len: usize) -> Vec<u8> {
        let mut data = Vec::new();
        while data.len() < len {
            let want = (len - data.len()).min(60_000) as u32;
            data.extend(c.read(file_id, data.len() as u64, want).await);
        }
        data
    }

    #[tokio::test]
    async fn a_whole_file_copy_carries_the_streams_and_write_time_of_the_host() {
        use std::time::SystemTime;

        let exe = std::env::current_exe().unwrap();
        let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        if !backend.capabilities().named_streams {
            eprintln!("skipping: no named streams on {}", td.path().display());
            return;
        }
        let data = pattern(MIB as usize + 777, 0x31);
        let (source_path, target_path) = (td.path().join("s"), td.path().join("t"));
        std::fs::write(&source_path, &data).unwrap();
        std::fs::write(&target_path, b"old contents").unwrap();
        let state = server_on(vec![Share::new("home", backend).public()]);
        let mut c = Client::new(&state).await;
        // A macOS host reads AFP_AfpInfo back with version 0x100 and the
        // backup time "never" in its header.
        let mut info = vec![0; 60];
        info[..16].copy_from_slice(b"AFP\0\0\0\x01\0\0\0\0\0\x80\0\0\0");
        info[16..48].copy_from_slice(&pattern(32, 1));
        // The fork is more than one piece of the copy, and within the 16 MiB
        // a macOS host holds in AFP_Resource.
        let streams = [
            ("AFP_AfpInfo", info),
            ("AFP_Resource", pattern(1_286_166, 2)),
            ("note", pattern(500, 3)),
        ];
        for (name, bytes) in &streams {
            let name = format!("s:{name}");
            let stream = c.open(Create::new(&name).disposition(FILE_OPEN_IF)).await;
            for (at, piece) in bytes.chunks(60_000).enumerate() {
                c.write(stream, 60_000 * at as u64, piece).await;
            }
            c.close(stream).await;
        }
        let written = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(&source_path)
            .unwrap()
            .set_modified(written)
            .unwrap();

        assert_ne!(c.mount().await & aapl::OSX_COPYFILE, 0);
        let source = c.open(Create::new("s").access(READ)).await;
        let target = c.open(Create::new("t").share(0)).await;
        let key = c.key(source).await;
        assert_eq!(
            c.copy_whole_file(target, &key).await,
            (OK, Some([0, 0, MIB + 777]))
        );
        c.close(target).await;

        assert_eq!(std::fs::read(&target_path).unwrap(), data);
        assert_eq!(
            std::fs::metadata(&target_path).unwrap().modified().unwrap(),
            written
        );
        #[cfg(any(target_os = "macos", windows))]
        {
            let created = |path: &Path| {
                let since_epoch = std::fs::metadata(path)
                    .unwrap()
                    .created()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                since_epoch.as_nanos()
            };
            // The time travels as a FILETIME, in ticks of 100 ns.
            let two_ticks = 200;
            assert!(created(&source_path).abs_diff(created(&target_path)) < two_ticks);
        }
        for (name, bytes) in &streams {
            let to = c.open(Create::new(&format!("t:{name}")).access(READ)).await;
            let copied = read_len(&mut c, to, bytes.len()).await;
            assert_eq!(&copied, bytes, "{name}");
        }
    }

    #[tokio::test]
    async fn a_file_is_not_copied_onto_itself_through_two_shares_of_one_directory() {
        let exe = std::env::current_exe().unwrap();
        let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        if !backend.capabilities().named_streams {
            eprintln!("skipping: no named streams on {}", td.path().display());
            return;
        }
        let data = pattern(2 * MIB as usize + 3, 0x41);
        std::fs::write(td.path().join("f"), &data).unwrap();
        let state = server_on(vec![
            Share::new("home", backend).public(),
            share("other", td.path()),
        ]);
        let mut c = mounted_with_other_share(&state).await;
        let source = c.open(Create::new("f").access(READ)).await;
        let target = c.open_at(OTHER, Create::new("f")).await;
        let key = c.key(source).await;
        assert_eq!(
            c.copy_at(OTHER, COPYCHUNK, target, &key, &[]).await,
            (OK, Some([0, 0, 2 * MIB + 3]))
        );
        assert_eq!(std::fs::read(td.path().join("f")).unwrap(), data);
    }

    #[tokio::test]
    async fn a_named_stream_is_copied_from_and_to_a_file() {
        let exe = std::env::current_exe().unwrap();
        let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        if !backend.capabilities().named_streams {
            eprintln!("skipping: no named streams on {}", td.path().display());
            return;
        }
        std::fs::write(td.path().join("f"), b"file data").unwrap();
        std::fs::write(td.path().join("g"), []).unwrap();
        std::fs::write(td.path().join("h"), []).unwrap();
        let state = server_on(vec![Share::new("home", backend).public()]);
        let mut c = Client::new(&state).await;
        let file = c.open(Create::new("f")).await;
        let stream = c.open(Create::new("g:s").disposition(FILE_CREATE)).await;
        let key = c.key(file).await;
        assert_eq!(
            c.copy(stream, &key, &[(0, 0, 9)]).await,
            (OK, Some([1, 0, 9]))
        );
        assert_eq!(c.read(stream, 0, 100).await, b"file data");
        assert!(std::fs::read(td.path().join("g")).unwrap().is_empty());

        let key = c.key(stream).await;
        let target = c.open(Create::new("h")).await;
        assert_eq!(
            c.copy(target, &key, &[(0, 0, 9)]).await,
            (OK, Some([1, 0, 9]))
        );
        assert_eq!(std::fs::read(td.path().join("h")).unwrap(), b"file data");
    }
}
