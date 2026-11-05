//! Leases and durable opens on named streams, over the dispatcher: a lease
//! per stream and key, breaks counted among the opens of one stream, what
//! a rename, delete or overwrite of the file breaks, directory streams,
//! durable reconnects by stream name, and shares that turn leases or
//! durable handles off.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::ntstatus;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    CloseRequest, CreateContext, CreateRequest, CreateResponse, FileId, LeaseBreakAck,
    LeaseBreakNotification, LeaseContext, LockElement, LockRequest, ReadRequest, ReadResponse,
    SetInfoRequest, WriteRequest,
};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{Peer, header, status};
use crate::{Share, SmbServer};

const READ: u32 = 0x0012_0089;
const RW: u32 = 0x0012_019F;
const DELETE: u32 = 0x0001_0000;
const READ_ATTRIBUTES: u32 = 0x80;
const SHARE_READ: u32 = 0x1;
const SHARE_ALL: u32 = 0x7;

const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_DIRECTORY_FILE: u32 = 0x1;

const R: u32 = 0x1;
const RH: u32 = 0x3;
const RW_CACHING: u32 = 0x5;
const RWH: u32 = 0x7;

const RENAME: u8 = 0x0A;
const DISPOSITION: u8 = 0x0D;
const END_OF_FILE: u8 = 0x14;

const INVALID: u32 = ntstatus::STATUS_INVALID_PARAMETER;

/// The durable handle context of a CREATE.
#[derive(Clone, Copy)]
enum Durable {
    None,
    V1,
    V2([u8; 16]),
    ReconnectV1(FileId),
    ReconnectV2(FileId, [u8; 16]),
}

/// A CREATE opening an existing file for reading and writing, sharing
/// everything, unless set otherwise.
#[derive(Clone, Copy)]
struct Create<'a> {
    name: &'a str,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    lease: Option<(u8, u32)>,
    durable: Durable,
}

impl<'a> Create<'a> {
    fn new(name: &'a str) -> Self {
        Self {
            name,
            access: RW,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: 0,
            lease: None,
            durable: Durable::None,
        }
    }

    /// Asks for `state` under the lease key of all `key` bytes.
    fn lease(self, key: u8, state: u32) -> Self {
        Self {
            lease: Some((key, state)),
            ..self
        }
    }

    fn access(self, access: u32, share: u32) -> Self {
        Self {
            access,
            share,
            ..self
        }
    }

    fn durable(self, durable: Durable) -> Self {
        Self { durable, ..self }
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
        let file_id = |id: FileId| {
            let mut data = id.persistent.to_le_bytes().to_vec();
            data.extend_from_slice(&id.volatile.to_le_bytes());
            data
        };
        let durable = match self.durable {
            Durable::None => None,
            Durable::V1 => Some((CreateContext::NAME_DHNQ, vec![0; 16])),
            Durable::V2(guid) => {
                let mut data = vec![0; 16];
                data.extend_from_slice(&guid);
                Some((CreateContext::NAME_DH2Q, data))
            }
            Durable::ReconnectV1(id) => Some((CreateContext::NAME_DHNC, file_id(id))),
            Durable::ReconnectV2(id, guid) => {
                let mut data = file_id(id);
                data.extend_from_slice(&guid);
                data.extend_from_slice(&0u32.to_le_bytes());
                Some((CreateContext::NAME_DH2C, data))
            }
        };
        if let Some((name, data)) = durable {
            list.push(CreateContext {
                name: name.to_vec(),
                data,
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

/// One signed-in connection from its own client to the share `home`.
struct Client {
    peer: Peer,
    state: Arc<ServerState>,
}

impl Client {
    async fn new(state: &Arc<ServerState>, client: u128) -> Self {
        Self {
            peer: Peer::from_client(state, true, Uuid::from_u128(client)).await,
            state: Arc::clone(state),
        }
    }

    /// Sends one request; returns the status and body of the frame that
    /// answers it, which is an interim response for one that waits.
    async fn send(&mut self, command: Command, body: &[u8]) -> (u32, Vec<u8>) {
        let (_, reply) = self.peer.request(&self.state, command, body).await;
        (status(&reply), reply[SMB2_HEADER_LEN..].to_vec())
    }

    /// The final response to a request that went asynchronous.
    async fn finish(&mut self) -> (u32, Vec<u8>) {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.peer.next())
            .await
            .expect("a final response in time");
        assert_ne!(header(&frame).command, Command::OplockBreak);
        (status(&frame), frame[SMB2_HEADER_LEN..].to_vec())
    }

    async fn create(&mut self, create: Create<'_>) -> Result<CreateResponse, u32> {
        let (status, body) = self.send(Command::Create, &create.body()).await;
        assert_ne!(status, ntstatus::STATUS_PENDING, "{} waits", create.name);
        created(status, &body)
    }

    async fn open(&mut self, create: Create<'_>) -> CreateResponse {
        let name = create.name;
        match self.create(create).await {
            Ok(created) => created,
            Err(status) => panic!("open {name}: {status:#x}"),
        }
    }

    /// Sends a CREATE that has to wait; returns once it is answered with
    /// an interim response.
    async fn create_waiting(&mut self, create: Create<'_>) {
        let (status, _) = self.send(Command::Create, &create.body()).await;
        assert_eq!(status, ntstatus::STATUS_PENDING, "{} waits", create.name);
    }

    async fn close(&mut self, file_id: FileId) {
        let mut body = Vec::new();
        CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        }
        .write_to(&mut body)
        .expect("close");
        assert_eq!(self.send(Command::Close, &body).await.0, 0);
    }

    async fn read(&mut self, file_id: FileId) -> Vec<u8> {
        let mut body = Vec::new();
        ReadRequest {
            structure_size: 49,
            padding: ReadResponse::STANDARD_DATA_OFFSET,
            flags: 0,
            length: 64,
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
        let (status, body) = self.send(Command::Read, &body).await;
        assert_eq!(status, 0, "read");
        ReadResponse::parse(&body).expect("read response").data
    }

    async fn write(&mut self, file_id: FileId, data: &[u8]) -> u32 {
        let mut body = Vec::new();
        WriteRequest {
            structure_size: 49,
            data_offset: WriteRequest::STANDARD_DATA_OFFSET,
            length: data.len() as u32,
            offset: 0,
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
        self.send(Command::Write, &body).await.0
    }

    async fn lock(&mut self, file_id: FileId) -> u32 {
        let mut body = Vec::new();
        LockRequest {
            structure_size: 48,
            lock_count: 1,
            lock_sequence: 0,
            file_id,
            locks: vec![LockElement {
                offset: 0,
                length: 1,
                flags: LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
                reserved: 0,
            }],
        }
        .write_to(&mut body)
        .expect("lock");
        self.send(Command::Lock, &body).await.0
    }

    fn set_info_body(file_id: FileId, class: u8, buffer: Vec<u8>) -> Vec<u8> {
        let mut body = Vec::new();
        SetInfoRequest {
            structure_size: 33,
            info_type: 1,
            file_information_class: class,
            buffer_length: buffer.len() as u32,
            buffer_offset: 0x60,
            reserved: 0,
            additional_information: 0,
            file_id,
            buffer,
        }
        .write_to(&mut body)
        .expect("set info");
        body
    }

    async fn set_info(&mut self, file_id: FileId, class: u8, buffer: Vec<u8>) -> u32 {
        let body = Self::set_info_body(file_id, class, buffer);
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

    /// The next lease break sent to this connection.
    async fn next_break(&mut self) -> LeaseBreakNotification {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.peer.next())
            .await
            .expect("a lease break in time");
        assert_eq!(header(&frame).command, Command::OplockBreak);
        LeaseBreakNotification::parse(&frame[SMB2_HEADER_LEN..]).expect("lease break")
    }

    /// Asserts the next lease break is of `key` from `from` to `to`.
    async fn breaks(&mut self, key: u8, from: u32, to: u32) {
        let n = self.next_break().await;
        assert_eq!(
            (n.lease_key, n.current_lease_state, n.new_lease_state),
            ([key; 16], from, to)
        );
    }

    /// Asserts nothing was sent to this connection outside its responses.
    async fn quiet(&mut self) {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(self.peer.rx.try_recv().is_none(), "nothing sent");
    }
}

fn created(status: u32, body: &[u8]) -> Result<CreateResponse, u32> {
    match status {
        0 => Ok(CreateResponse::parse(body).expect("create response")),
        status => Err(status),
    }
}

/// The lease state a CREATE response grants, `None` without a lease.
fn lease(resp: &CreateResponse) -> Option<u32> {
    let contexts = CreateContext::parse_chain(&resp.create_contexts).expect("contexts");
    let lease = contexts
        .iter()
        .find(|c| c.name == CreateContext::NAME_RQLS)
        .map(|c| LeaseContext::parse(&c.data).expect("lease").state);
    assert_eq!(lease.is_some(), resp.oplock_level == 0xFF);
    lease
}

fn is_durable(resp: &CreateResponse) -> bool {
    CreateContext::parse_chain(&resp.create_contexts)
        .expect("contexts")
        .iter()
        .any(|c| c.name == CreateContext::NAME_DHNQ || c.name == CreateContext::NAME_DH2Q)
}

fn rename_to(to: &str) -> Vec<u8> {
    let name = crate::utils::utf16le(to);
    let mut buffer = vec![0; 16];
    buffer.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&name);
    buffer
}

/// A FileRenameInformation buffer naming `to`, replacing what is there.
fn rename_over(to: &str) -> Vec<u8> {
    let name = crate::utils::utf16le(to);
    let mut buffer = vec![1];
    buffer.resize(16, 0);
    buffer.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&name);
    buffer
}

fn server_on(share: Share) -> Arc<ServerState> {
    SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(share)
        .build()
        .expect("build")
        .state()
}

/// A server whose share `home` holds f.txt with the streams `s` and `t`.
async fn server(files: &MemFsBackend) -> Arc<ServerState> {
    let files = files.clone().with_file("f.txt", b"data");
    let state = server_on(Share::new("home", files).public());
    let mut c = Client::new(&state, 0xC0).await;
    for (name, data) in [("f.txt:s", b"stream"), ("f.txt:t", b"others")] {
        let f = c
            .open(Create {
                disposition: FILE_CREATE,
                ..Create::new(name)
            })
            .await;
        assert_eq!(c.write(f.file_id, data).await, 0);
        c.close(f.file_id).await;
    }
    state
}

#[tokio::test]
async fn a_stream_open_gets_a_lease_bound_to_its_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let s = a.open(Create::new("f.txt:s").lease(1, RWH)).await;
    assert_eq!(lease(&s), Some(RWH));
    let again = a.open(Create::new("f.txt:S").lease(1, RWH)).await;
    assert_eq!(lease(&again), Some(RWH), "the same lease");
    let typed = a.open(Create::new("f.txt:s:$DATA").lease(1, RWH)).await;
    assert_eq!(lease(&typed), Some(RWH), "the same lease");
    for other in ["f.txt", "f.txt::$DATA", "f.txt:t"] {
        assert_eq!(
            a.create(Create::new(other).lease(1, RWH)).await.err(),
            Some(INVALID),
            "{other}"
        );
    }
    // Lease keys are per client.
    let t = b.open(Create::new("f.txt:t").lease(1, RWH)).await;
    assert_eq!(lease(&t), Some(RWH));
    a.quiet().await;

    for id in [s.file_id, again.file_id, typed.file_id] {
        a.close(id).await;
    }
    let base = a.open(Create::new("f.txt").lease(1, RWH)).await;
    assert_eq!(lease(&base), Some(RWH), "free once its stream closed");
}

#[tokio::test]
async fn an_open_of_the_same_stream_breaks_its_lease() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let s = a.open(Create::new("f.txt:s").lease(1, RWH)).await;
    b.create_waiting(Create::new("f.txt:s").lease(2, RWH)).await;
    a.breaks(1, RWH, RH).await;
    a.ack(1, RH).await;
    let (status, body) = b.finish().await;
    assert_eq!(lease(&created(status, &body).unwrap()), Some(RH));
    // An attribute-only open breaks nothing.
    let stat = b
        .open(Create::new("f.txt:s").access(READ_ATTRIBUTES, SHARE_ALL))
        .await;
    b.close(stat.file_id).await;
    a.quiet().await;
    a.close(s.file_id).await;
}

#[tokio::test]
async fn other_streams_and_the_file_leave_a_stream_lease_alone() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let s = a.open(Create::new("f.txt:s").lease(1, RWH)).await;
    let t = b.open(Create::new("f.txt:t").lease(2, RWH)).await;
    assert_eq!(lease(&t), Some(RWH));
    let base = b.open(Create::new("f.txt").lease(3, RWH)).await;
    assert_eq!(lease(&base), Some(RWH));
    b.close(base.file_id).await;
    let plain = b.open(Create::new("f.txt")).await;
    assert_eq!(b.write(plain.file_id, b"x").await, 0);
    assert_eq!(
        b.set_info(plain.file_id, END_OF_FILE, 2u64.to_le_bytes().to_vec())
            .await,
        0
    );
    assert_eq!(b.lock(plain.file_id).await, 0);
    assert_eq!(b.write(t.file_id, b"y").await, 0);
    a.quiet().await;
    b.quiet().await;
    for id in [plain.file_id, t.file_id] {
        b.close(id).await;
    }
    a.close(s.file_id).await;

    // A lease on the file is left alone by opens, writes and locks of its
    // named streams.
    let base = a.open(Create::new("f.txt").lease(4, RWH)).await;
    let s = b.open(Create::new("f.txt:s").lease(5, RWH)).await;
    assert_eq!(lease(&s), Some(RWH));
    assert_eq!(b.write(s.file_id, b"z").await, 0);
    assert_eq!(b.lock(s.file_id).await, 0);
    a.quiet().await;
    b.close(s.file_id).await;
    a.close(base.file_id).await;
}

#[tokio::test]
async fn a_write_lock_or_resize_of_a_stream_breaks_its_other_leases() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let s = a.open(Create::new("f.txt:s").lease(1, RH)).await;
    let writer = b.open(Create::new("f.txt:s")).await;
    assert_eq!(b.write(writer.file_id, b"x").await, 0);
    a.breaks(1, RH, 0).await;
    a.close(s.file_id).await;

    let s = a.open(Create::new("f.txt:s").lease(1, R)).await;
    let body = Client::set_info_body(writer.file_id, END_OF_FILE, 1u64.to_le_bytes().to_vec());
    assert_eq!(b.send(Command::SetInfo, &body).await.0, 0);
    a.breaks(1, R, 0).await;
    a.close(s.file_id).await;

    let s = a.open(Create::new("f.txt:s").lease(1, RH)).await;
    assert_eq!(lease(&s), Some(RH));
    assert_eq!(b.lock(writer.file_id).await, 0);
    a.breaks(1, RH, 0).await;
    a.close(s.file_id).await;
    b.close(writer.file_id).await;
}

#[tokio::test]
async fn a_sharing_violation_on_a_stream_breaks_its_handle_caching() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let s = a
        .open(Create::new("f.txt:s").access(READ, SHARE_READ).lease(1, RH))
        .await;
    b.create_waiting(Create::new("f.txt:s")).await;
    a.breaks(1, RH, R).await;
    a.ack(1, R).await;
    assert_eq!(b.finish().await.0, ntstatus::STATUS_SHARING_VIOLATION);
    a.close(s.file_id).await;

    // A delete of the file that the stream open does not share fails at
    // once: the violation is on the file's default stream.
    let s = a
        .open(Create::new("f.txt:s").access(READ, SHARE_READ).lease(1, RH))
        .await;
    let deleter = Create::new("f.txt").access(DELETE | READ_ATTRIBUTES, SHARE_ALL);
    assert_eq!(
        b.create(deleter).await.err(),
        Some(ntstatus::STATUS_SHARING_VIOLATION)
    );
    a.quiet().await;
    a.close(s.file_id).await;
}

#[tokio::test]
async fn a_rename_of_the_file_leaves_its_stream_leases_alone() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let s = a.open(Create::new("f.txt:s").lease(1, RWH)).await;
    let base = a.open(Create::new("f.txt").lease(4, RH)).await;
    let renamer = b
        .open(Create::new("f.txt").access(DELETE | READ_ATTRIBUTES, SHARE_ALL))
        .await;
    assert_eq!(
        b.set_info(renamer.file_id, RENAME, rename_to("g.txt"))
            .await,
        0
    );
    // The file's own lease gives up handle caching; the stream's keeps it.
    a.breaks(4, RH, R).await;
    a.quiet().await;
    assert_eq!(files.stream_names("g.txt"), ["s", "t"]);
    assert_eq!(a.read(s.file_id).await, b"stream");
    // The lease went along with its stream.
    let again = a.open(Create::new("g.txt:s").lease(1, RWH)).await;
    assert_eq!(lease(&again), Some(RWH));
    for id in [s.file_id, base.file_id, again.file_id] {
        a.close(id).await;
    }
    b.close(renamer.file_id).await;
}

#[tokio::test]
async fn an_overwrite_of_the_file_breaks_stream_handle_caching_at_once() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let s = a.open(Create::new("f.txt:s").lease(1, RWH)).await;
    let deleter = b
        .open(Create::new("f.txt").access(DELETE | READ_ATTRIBUTES, SHARE_ALL))
        .await;
    // Marking the file for deletion leaves the stream's lease alone.
    assert_eq!(b.set_info(deleter.file_id, DISPOSITION, vec![1]).await, 0);
    a.quiet().await;
    assert_eq!(b.set_info(deleter.file_id, DISPOSITION, vec![0]).await, 0);
    b.close(deleter.file_id).await;
    a.close(s.file_id).await;

    // The overwrite marks the streams for deletion and does not wait for
    // their leases to give up handle caching.
    let s = a.open(Create::new("f.txt:s").lease(1, RWH)).await;
    let t = a.open(Create::new("f.txt:t").lease(2, RH)).await;
    let overwrite = b
        .open(Create {
            disposition: FILE_OVERWRITE_IF,
            ..Create::new("f.txt")
        })
        .await;
    let mut broken = [a.next_break().await, a.next_break().await]
        .map(|n| (n.lease_key[0], n.current_lease_state, n.new_lease_state));
    broken.sort();
    assert_eq!(broken, [(1, RWH, RW_CACHING), (2, RH, R)]);
    assert_eq!(
        b.create(Create::new("f.txt:s")).await.err(),
        Some(ntstatus::STATUS_DELETE_PENDING)
    );
    assert_eq!(a.read(s.file_id).await, b"stream");
    for id in [s.file_id, t.file_id] {
        a.close(id).await;
    }
    b.close(overwrite.file_id).await;
    assert!(files.stream_names("f.txt").is_empty());
}

#[tokio::test]
async fn deleting_or_renaming_a_stream_breaks_handle_caching_of_its_other_leases() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;

    let held = a.open(Create::new("f.txt:s").lease(1, RH)).await;
    let renamer = b
        .open(
            Create::new("f.txt:s")
                .access(RW | DELETE, SHARE_ALL)
                .lease(2, RH),
        )
        .await;
    assert_eq!(lease(&renamer), Some(RH));
    assert_eq!(
        b.set_info(renamer.file_id, RENAME, rename_to(":u")).await,
        0
    );
    a.breaks(1, RH, R).await;
    a.ack(1, R).await;
    b.quiet().await;
    // Both leases are on the stream under its new name.
    let again = b.open(Create::new("f.txt:u").lease(2, RH)).await;
    assert_eq!(lease(&again), Some(RH));
    assert_eq!(
        b.create(Create::new("f.txt:t").lease(2, RH)).await.err(),
        Some(INVALID)
    );

    assert_eq!(b.set_info(renamer.file_id, DISPOSITION, vec![1]).await, 0);
    let t = a.open(Create::new("f.txt:t").lease(3, RH)).await;
    let deleter = b
        .open(Create::new("f.txt:t").access(DELETE | READ_ATTRIBUTES, SHARE_ALL))
        .await;
    assert_eq!(b.set_info(deleter.file_id, DISPOSITION, vec![1]).await, 0);
    a.breaks(3, RH, R).await;
    for id in [renamer.file_id, again.file_id, deleter.file_id] {
        b.close(id).await;
    }
    for id in [held.file_id, t.file_id] {
        a.close(id).await;
    }
    assert!(files.stream_names("f.txt").is_empty());
}

#[tokio::test]
async fn directory_streams_follow_the_same_rules() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let mut b = Client::new(&state, 2).await;
    let dir = a
        .open(Create {
            disposition: FILE_CREATE,
            options: FILE_DIRECTORY_FILE,
            ..Create::new("d").access(READ, SHARE_ALL)
        })
        .await;
    a.close(dir.file_id).await;
    for name in ["d:ds", "d:dt"] {
        let made = a
            .open(Create {
                disposition: FILE_CREATE,
                ..Create::new(name)
            })
            .await;
        a.close(made.file_id).await;
    }

    let ds = a.open(Create::new("d:ds").lease(1, RWH)).await;
    assert_eq!(lease(&ds), Some(RWH));
    b.create_waiting(Create::new("d:ds").lease(2, RWH)).await;
    a.breaks(1, RWH, RH).await;
    a.ack(1, RH).await;
    let (status, body) = b.finish().await;
    let other = created(status, &body).unwrap();
    assert_eq!(lease(&other), Some(RH));
    b.close(other.file_id).await;
    // Another stream of the directory has leases of its own, and the key
    // held on `d:ds` opens the directory itself on neither path.
    let dt = b.open(Create::new("d:dt").lease(3, RWH)).await;
    assert_eq!(lease(&dt), Some(RWH));
    b.close(dt.file_id).await;
    for options in [0, FILE_DIRECTORY_FILE] {
        let create = Create {
            options,
            ..Create::new("d").access(READ, SHARE_ALL).lease(1, RH)
        };
        assert_eq!(a.create(create).await.err(), Some(INVALID), "{options}");
    }
    a.quiet().await;

    let renamer = b
        .open(Create {
            options: FILE_DIRECTORY_FILE,
            ..Create::new("d").access(DELETE | READ_ATTRIBUTES, SHARE_ALL)
        })
        .await;
    assert_eq!(b.set_info(renamer.file_id, RENAME, rename_to("e")).await, 0);
    a.quiet().await;
    assert_eq!(files.stream_names("e"), ["ds", "dt"]);
    b.close(renamer.file_id).await;
    a.close(ds.file_id).await;
}

#[tokio::test]
async fn a_durable_stream_open_comes_back_by_its_stream_name() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut old = Client::new(&state, 1).await;
    let v1 = old
        .open(Create::new("f.txt:s").lease(1, RH).durable(Durable::V1))
        .await;
    assert!(is_durable(&v1));
    let guid = [0x62; 16];
    let v2 = old
        .open(
            Create::new("f.txt:t")
                .lease(2, RWH)
                .durable(Durable::V2(guid)),
        )
        .await;
    assert!(is_durable(&v2));
    old.peer.drop_connection(&state).await;

    let mut new = Client::new(&state, 1).await;
    let reconnect = |name, id| {
        Create::new(name)
            .lease(1, RH)
            .durable(Durable::ReconnectV1(id))
    };
    for wrong in ["f.txt", "f.txt:t", "f.txt::$DATA"] {
        assert_eq!(
            new.create(reconnect(wrong, v1.file_id)).await.err(),
            Some(INVALID),
            "{wrong}"
        );
    }
    let back = new.open(reconnect("f.txt:S", v1.file_id)).await;
    assert_eq!(back.file_id.persistent, v1.file_id.persistent);
    assert_eq!(lease(&back), Some(RH));
    assert_eq!(back.end_of_file, 6, "the stream's size");
    assert_eq!(new.read(back.file_id).await, b"stream");

    let reconnect = |name| {
        Create::new(name)
            .lease(2, RWH)
            .durable(Durable::ReconnectV2(v2.file_id, guid))
    };
    assert_eq!(
        new.create(reconnect("f.txt:s")).await.err(),
        Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
    );
    let back = new.open(reconnect("f.txt:t:$DATA")).await;
    assert_eq!(lease(&back), Some(RWH));
    assert_eq!(new.read(back.file_id).await, b"others");
}

/// A durable open of `name` for reading, sharing `share`, holding RH under
/// the lease `key`, kept once its connection from client 1 drops.
async fn kept(state: &Arc<ServerState>, name: &str, key: u8, share: u32) {
    let mut c = Client::new(state, 1).await;
    let open = c
        .open(
            Create::new(name)
                .access(READ, share)
                .lease(key, RH)
                .durable(Durable::V1),
        )
        .await;
    assert!(is_durable(&open), "{name}");
    c.peer.drop_connection(state).await;
    assert_eq!(state.durable.registered(), 1, "{name} kept");
}

/// Waits for the kept opens to be closed.
async fn none_kept(state: &Arc<ServerState>) {
    for _ in 0..200 {
        if state.durable.registered() == 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("an open is still kept");
}

#[tokio::test]
async fn a_kept_stream_open_closes_when_its_file_or_stream_is_renamed_or_deleted() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 3).await;
    let mut b = Client::new(&state, 2).await;
    let shared = SHARE_READ | 0x4;

    // A rename of the file moves the kept open's name, so no reconnect
    // names it any more; a connected stream open keeps its lease.
    kept(&state, "f.txt:s", 1, shared).await;
    let t = a.open(Create::new("f.txt:t").lease(3, RH)).await;
    let renamer = b
        .open(Create::new("f.txt").access(DELETE | READ_ATTRIBUTES, SHARE_ALL))
        .await;
    assert_eq!(
        b.set_info(renamer.file_id, RENAME, rename_to("g.txt"))
            .await,
        0
    );
    none_kept(&state).await;
    // Its share mode went with it.
    let writer = b.open(Create::new("g.txt:s")).await;
    b.close(writer.file_id).await;

    // A delete of the file closes kept opens no connected open shares a
    // lease with, and the file goes with the last connected open.
    b.close(renamer.file_id).await;
    kept(&state, "g.txt:s", 4, SHARE_ALL).await;
    let deleter = b
        .open(Create::new("g.txt").access(DELETE | READ_ATTRIBUTES, SHARE_ALL))
        .await;
    assert_eq!(b.set_info(deleter.file_id, DISPOSITION, vec![1]).await, 0);
    none_kept(&state).await;
    b.close(deleter.file_id).await;
    a.quiet().await;
    assert_eq!(a.read(t.file_id).await, b"others");
    a.close(t.file_id).await;
    assert_eq!(files.contents("g.txt"), None);

    // An overwrite of the file, and a rename or delete of the stream,
    // break the kept open's handle caching, which closes it.
    for name in ["h.txt:s", "h.txt:t"] {
        let made = b
            .open(Create {
                disposition: FILE_CREATE,
                ..Create::new(name)
            })
            .await;
        b.close(made.file_id).await;
    }
    kept(&state, "h.txt:s", 5, SHARE_ALL).await;
    let renamer = b
        .open(Create::new("h.txt:s").access(RW | DELETE, SHARE_ALL))
        .await;
    assert_eq!(
        b.set_info(renamer.file_id, RENAME, rename_to(":u")).await,
        0
    );
    none_kept(&state).await;
    b.close(renamer.file_id).await;

    kept(&state, "h.txt:t", 6, SHARE_ALL).await;
    let deleter = b
        .open(Create::new("h.txt:t").access(DELETE | READ_ATTRIBUTES, SHARE_ALL))
        .await;
    assert_eq!(b.set_info(deleter.file_id, DISPOSITION, vec![1]).await, 0);
    none_kept(&state).await;
    b.close(deleter.file_id).await;

    kept(&state, "h.txt:u", 7, SHARE_ALL).await;
    let overwrite = b
        .open(Create {
            disposition: FILE_OVERWRITE_IF,
            ..Create::new("h.txt")
        })
        .await;
    none_kept(&state).await;
    b.close(overwrite.file_id).await;
    assert!(files.stream_names("h.txt").is_empty());
}

#[tokio::test]
async fn a_lease_moves_with_a_stream_renamed_onto_the_default_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state, 1).await;
    let made = a
        .open(Create {
            disposition: FILE_CREATE,
            ..Create::new("e.txt:s")
        })
        .await;
    assert_eq!(a.write(made.file_id, b"moved").await, 0);
    a.close(made.file_id).await;

    let s = a
        .open(
            Create::new("e.txt:s")
                .access(RW | DELETE, SHARE_ALL)
                .lease(1, RH),
        )
        .await;
    assert_eq!(
        a.set_info(s.file_id, RENAME, rename_over("::$DATA")).await,
        0
    );
    a.quiet().await;
    let base = a.open(Create::new("e.txt").lease(1, RH)).await;
    assert_eq!(lease(&base), Some(RH), "the same lease");
    assert_eq!(a.read(base.file_id).await, b"moved");
    assert_eq!(
        a.create(Create::new("e.txt:s").lease(1, RH)).await.err(),
        Some(INVALID)
    );
    for id in [s.file_id, base.file_id] {
        a.close(id).await;
    }
}
