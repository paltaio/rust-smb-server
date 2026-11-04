//! Named streams over the dispatcher, on a memory backend that stores
//! them: CREATE dispositions, share modes and locks per stream, deletion,
//! the stream list, and shares that serve none.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::backend::{BackendCapabilities, Handle, OpenAction, OpenOptions, ShareBackend};
use crate::error::SmbResult;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CreateContext, CreateRequest,
    CreateResponse, FileId, IoctlRequest, LeaseContext, LockElement, LockRequest, QueryInfoRequest,
    QueryInfoResponse, ReadRequest, ReadResponse, SetInfoRequest, WriteRequest,
};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{Peer, header, status};
use crate::{Share, SmbServer};

const READ: u32 = 0x0012_0089;
const WRITE: u32 = 0x0012_0116;
const RW: u32 = READ | WRITE;
const DELETE: u32 = 0x0001_0000;
const SHARE_READ: u32 = 0x1;
const SHARE_WRITE: u32 = 0x2;
const SHARE_ALL: u32 = 0x7;

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

const SUPERSEDED: u32 = 0;
const OPENED: u32 = 1;
const CREATED: u32 = 2;
const OVERWRITTEN: u32 = 3;

const BASIC: u8 = 0x04;
const STANDARD: u8 = 0x05;
const RENAME: u8 = 0x0A;
const LINK: u8 = 0x0B;
const DISPOSITION: u8 = 0x0D;
const ALLOCATION: u8 = 0x13;
const END_OF_FILE: u8 = 0x14;
const STREAMS: u8 = 0x16;
const FS_ATTRIBUTE: u8 = 0x05;
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

/// A CREATE request, opening an existing file for reading and writing and
/// sharing everything unless set otherwise.
#[derive(Clone, Copy)]
struct Create<'a> {
    name: &'a str,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    lease: bool,
    ea: bool,
}

impl<'a> Create<'a> {
    fn new(name: &'a str) -> Self {
        Self {
            name,
            access: RW,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: 0,
            lease: false,
            ea: false,
        }
    }

    fn access(self, access: u32, share: u32) -> Self {
        Self {
            access,
            share,
            ..self
        }
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

    fn body(&self) -> Vec<u8> {
        let name = crate::utils::utf16le(self.name);
        let mut padded = name.clone();
        padded.resize(padded.len().next_multiple_of(8), 0);
        let mut list = Vec::new();
        if self.lease {
            list.push(CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: LeaseContext {
                    key: [0x5C; 16],
                    state: 0x7,
                    ..LeaseContext::default()
                }
                .encode(),
            });
        }
        if self.ea {
            list.push(CreateContext {
                name: CreateContext::NAME_EXTA.to_vec(),
                data: vec![0; 12],
            });
        }
        let mut contexts = Vec::new();
        CreateContext::encode_chain(&list, &mut contexts).expect("contexts");
        let mut body = Vec::new();
        CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: if self.lease { 0xFF } else { 0 },
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

/// One connection to the share `home` of `state`.
struct Client {
    peer: Peer,
    state: Arc<ServerState>,
}

impl Client {
    async fn new(state: &Arc<ServerState>) -> Self {
        Self::from_client(state, Uuid::nil()).await
    }

    async fn from_client(state: &Arc<ServerState>, client: Uuid) -> Self {
        Self {
            peer: Peer::from_client(state, false, client).await,
            state: Arc::clone(state),
        }
    }

    async fn send(&mut self, command: Command, body: &[u8]) -> (u32, Vec<u8>) {
        let (_, reply) = self.peer.request(&self.state, command, body).await;
        (status(&reply), reply[SMB2_HEADER_LEN..].to_vec())
    }

    async fn create(&mut self, create: Create<'_>) -> Result<CreateResponse, u32> {
        match self.send(Command::Create, &create.body()).await {
            (0, body) => Ok(CreateResponse::parse(&body).expect("create response")),
            (status, _) => Err(status),
        }
    }

    async fn open(&mut self, create: Create<'_>) -> FileId {
        let name = create.name;
        match self.create(create).await {
            Ok(created) => created.file_id,
            Err(status) => panic!("open {name}: {status:#x}"),
        }
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

    async fn read(&mut self, file_id: FileId, offset: u64, length: u32) -> Result<Vec<u8>, u32> {
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
        match self.send(Command::Read, &body).await {
            (0, body) => Ok(ReadResponse::parse(&body).expect("read response").data),
            (status, _) => Err(status),
        }
    }

    async fn write(&mut self, file_id: FileId, offset: u64, data: &[u8]) -> u32 {
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
        self.send(Command::Write, &body).await.0
    }

    async fn set_info(&mut self, file_id: FileId, class: u8, buffer: Vec<u8>) -> u32 {
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
        self.send(Command::SetInfo, &body).await.0
    }

    async fn query(
        &mut self,
        file_id: FileId,
        info_type: u8,
        class: u8,
        len: u32,
    ) -> (u32, Vec<u8>) {
        let mut body = Vec::new();
        QueryInfoRequest {
            structure_size: 41,
            info_type,
            file_information_class: class,
            output_buffer_length: len,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id,
            input_buffer: vec![],
        }
        .write_to(&mut body)
        .expect("query info");
        let (status, body) = self.send(Command::QueryInfo, &body).await;
        let buffer = if matches!(status, 0 | ntstatus::STATUS_BUFFER_OVERFLOW) {
            QueryInfoResponse::parse(&body).expect("response").buffer
        } else {
            Vec::new()
        };
        (status, buffer)
    }

    async fn file_info(&mut self, file_id: FileId, class: u8) -> Vec<u8> {
        let (status, buffer) = self.query(file_id, 1, class, 4096).await;
        assert_eq!(status, 0, "class {class}");
        buffer
    }

    async fn lock(&mut self, file_id: FileId, offset: u64, length: u64) -> u32 {
        let mut body = Vec::new();
        LockRequest {
            structure_size: 48,
            lock_count: 1,
            lock_sequence: 0,
            file_id,
            locks: vec![LockElement {
                offset,
                length,
                flags: LockElement::FLAG_EXCLUSIVE_LOCK | LockElement::FLAG_FAIL_IMMEDIATELY,
                reserved: 0,
            }],
        }
        .write_to(&mut body)
        .expect("lock");
        self.send(Command::Lock, &body).await.0
    }

    /// Sends a CHANGE_NOTIFY on the directory `dir` for `filter`, which
    /// has to wait; returns its AsyncId.
    async fn watch(&mut self, dir: FileId, filter: u32) -> u64 {
        let mut body = Vec::new();
        ChangeNotifyRequest {
            structure_size: 32,
            flags: 0,
            output_buffer_length: 4096,
            file_id: dir,
            completion_filter: filter,
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

    /// The names the final response to the CHANGE_NOTIFY `async_id`
    /// reports.
    async fn changes(&mut self, async_id: u64) -> Vec<String> {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), self.peer.next())
            .await
            .expect("a final response in time");
        assert_eq!(header(&frame).async_id(), Some(async_id));
        assert_eq!(status(&frame), 0);
        let buf = ChangeNotifyResponse::parse(&frame[SMB2_HEADER_LEN..])
            .expect("notify response")
            .buffer;
        let mut names = Vec::new();
        let mut at = 0;
        loop {
            let next = u32_at(&buf, at) as usize;
            let len = u32_at(&buf, at + 8) as usize;
            let units: Vec<u16> = buf[at + 12..at + 12 + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            names.push(String::from_utf16(&units).unwrap());
            if next == 0 {
                return names;
            }
            at += next;
        }
    }

    async fn fsctl(&mut self, file_id: FileId, ctl_code: u32) -> u32 {
        let mut body = Vec::new();
        IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code,
            file_id,
            input_offset: 0x78,
            input_count: 0,
            max_input_response: 0,
            output_offset: 0x78,
            output_count: 0,
            max_output_response: 1024,
            flags: IoctlRequest::FLAG_IS_FSCTL,
            reserved2: 0,
            input: Vec::new(),
        }
        .write_to(&mut body)
        .expect("ioctl");
        self.send(Command::Ioctl, &body).await.0
    }

    /// The stream names, sizes and allocation sizes FileStreamInformation
    /// lists for `file_id`.
    async fn streams(&mut self, file_id: FileId) -> Vec<(String, u64, u64)> {
        stream_entries(&self.file_info(file_id, STREAMS).await)
    }
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

fn u64_at(buf: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(buf[at..at + 8].try_into().unwrap())
}

/// The entries of a FILE_STREAM_INFORMATION buffer, checking that each
/// starts on an 8-byte boundary and the last is not padded.
fn stream_entries(buf: &[u8]) -> Vec<(String, u64, u64)> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        assert_eq!(at % 8, 0);
        let next = u32_at(buf, at) as usize;
        let len = u32_at(buf, at + 4) as usize;
        let units: Vec<u16> = buf[at + 24..at + 24 + len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        entries.push((
            String::from_utf16(&units).unwrap(),
            u64_at(buf, at + 8),
            u64_at(buf, at + 16),
        ));
        if next == 0 {
            assert_eq!(at + 24 + len, buf.len(), "the last entry is not padded");
            break;
        }
        at += next;
    }
    entries
}

fn entry(name: &str, size: u64) -> (String, u64, u64) {
    (name.to_string(), size, size)
}

fn server_on(share: Share) -> Arc<ServerState> {
    SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(share)
        .build()
        .expect("build")
        .state()
}

/// A server whose public share `home` is `files`, holding `f.txt` with
/// "data" and the directory `d`.
async fn server(files: &MemFsBackend) -> Arc<ServerState> {
    let files = files.clone().with_file("f.txt", b"data");
    let state = server_on(Share::new("home", files).public());
    let mut c = Client::new(&state).await;
    let d = c
        .open(
            Create::new("d")
                .access(READ, SHARE_ALL)
                .disposition(FILE_CREATE)
                .options(FILE_DIRECTORY_FILE),
        )
        .await;
    c.close(d).await;
    state
}

/// Creates `name` holding `data`.
async fn make(c: &mut Client, name: &str, data: &[u8]) {
    let id = c
        .open(Create::new(name).disposition(FILE_OVERWRITE_IF))
        .await;
    assert_eq!(c.write(id, 0, data).await, 0);
    c.close(id).await;
}

#[tokio::test]
async fn a_stream_is_created_with_its_file_and_read_back_by_any_spelling() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut c = Client::new(&state).await;

    let created = c
        .create(Create::new("new.txt:s").disposition(FILE_OPEN_IF))
        .await
        .unwrap();
    assert_eq!(created.create_action, CREATED);
    assert_eq!(created.oplock_level, 0);
    assert_eq!(files.contents("new.txt"), Some(Vec::new()));
    assert_eq!(files.stream_names("new.txt"), ["s"]);
    assert_eq!(c.write(created.file_id, 0, b"abc").await, 0);
    c.close(created.file_id).await;

    let again = c.create(Create::new("new.txt:S:$data")).await.unwrap();
    assert_eq!(again.create_action, OPENED);
    assert_eq!(again.end_of_file, 3);
    assert_eq!(c.read(again.file_id, 0, 16).await.unwrap(), b"abc");
    c.close(again.file_id).await;
    let base = c.open(Create::new("new.txt")).await;
    assert_eq!(c.read(base, 0, 16).await, Err(ntstatus::STATUS_END_OF_FILE));
    assert_eq!(files.stream_names("new.txt"), ["s"]);
}

#[tokio::test]
async fn dispositions_apply_to_the_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut c = Client::new(&state).await;
    make(&mut c, "f.txt:s", b"abc").await;

    let fails = [
        (
            "f.txt:s",
            FILE_CREATE,
            0,
            ntstatus::STATUS_OBJECT_NAME_COLLISION,
        ),
        (
            "f.txt:t",
            FILE_OPEN,
            0,
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "f.txt:t",
            FILE_OVERWRITE,
            0,
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "gone.txt:s",
            FILE_OPEN,
            0,
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "gone.txt:s",
            FILE_OVERWRITE,
            0,
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "nodir\\f.txt:s",
            FILE_OPEN_IF,
            0,
            ntstatus::STATUS_OBJECT_PATH_NOT_FOUND,
        ),
        (
            "d:s",
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE,
            ntstatus::STATUS_NOT_A_DIRECTORY,
        ),
        (
            "f.txt:s:$INDEX_ALLOCATION",
            FILE_OPEN,
            0,
            ntstatus::STATUS_INVALID_PARAMETER,
        ),
    ];
    for (name, disposition, options, expected) in fails {
        let create = Create::new(name).disposition(disposition).options(options);
        assert_eq!(c.create(create).await.err(), Some(expected), "{name}");
    }
    assert_eq!(files.contents("gone.txt"), None);

    let opens = [
        ("f.txt:s", FILE_OPEN, OPENED, 3),
        ("f.txt:s", FILE_OPEN_IF, OPENED, 3),
        ("f.txt:s", FILE_OVERWRITE_IF, OVERWRITTEN, 0),
        ("f.txt:s", FILE_SUPERSEDE, SUPERSEDED, 0),
        ("f.txt:s", FILE_OVERWRITE, OVERWRITTEN, 0),
        ("f.txt:t", FILE_OPEN_IF, CREATED, 0),
        ("f.txt:u", FILE_CREATE, CREATED, 0),
        ("f.txt:v", FILE_OVERWRITE_IF, CREATED, 0),
        ("d:ds", FILE_OPEN_IF, CREATED, 0),
        (":root", FILE_OPEN_IF, CREATED, 0),
    ];
    for (name, disposition, action, size) in opens {
        let created = c
            .create(Create::new(name).disposition(disposition))
            .await
            .unwrap_or_else(|status| panic!("{name} {disposition}: {status:#x}"));
        assert_eq!(created.create_action, action, "{name} {disposition}");
        assert_eq!(created.end_of_file, size, "{name} {disposition}");
        c.close(created.file_id).await;
    }
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));
    assert_eq!(files.stream_names("f.txt"), ["s", "t", "u", "v"]);
    assert_eq!(files.stream_names("d"), ["ds"]);
    assert_eq!(files.stream_names(""), ["root"]);
}

#[tokio::test]
async fn an_overwrite_of_the_file_removes_its_streams() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut c = Client::new(&state).await;
    make(&mut c, "f.txt:s", b"abc").await;
    make(&mut c, "f.txt:t", b"x").await;
    let f = c
        .open(Create::new("f.txt").disposition(FILE_SUPERSEDE))
        .await;
    assert!(files.stream_names("f.txt").is_empty());
    assert_eq!(c.streams(f).await, [entry("::$DATA", 0)]);
    c.close(f).await;
    let f = c.open(Create::new("f.txt").disposition(FILE_OPEN_IF)).await;
    make(&mut c, "f.txt:s", b"abc").await;
    c.close(f).await;
    let f = c.open(Create::new("f.txt")).await;
    c.close(f).await;
    assert_eq!(files.stream_names("f.txt"), ["s"], "an open keeps them");
}

#[tokio::test]
async fn share_modes_apply_per_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;

    let base = a.open(Create::new("f.txt").access(RW, 0)).await;
    let stream = b.open(Create::new("f.txt:s").access(RW, 0)).await;
    let other = b
        .open(
            Create::new("f.txt:t")
                .access(RW, 0)
                .disposition(FILE_OPEN_IF),
        )
        .await;
    for name in [
        "f.txt:s",
        "f.txt:S",
        "f.txt:s:$DATA",
        "f.txt",
        "f.txt::$DATA",
    ] {
        let create = Create::new(name).access(READ, SHARE_ALL);
        assert_eq!(
            a.create(create).await.err(),
            Some(ntstatus::STATUS_SHARING_VIOLATION),
            "{name}"
        );
    }
    a.close(base).await;
    b.close(stream).await;
    b.close(other).await;
}

#[tokio::test]
async fn deleting_the_file_excludes_opens_that_do_not_share_delete_on_any_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;
    let violation = Some(ntstatus::STATUS_SHARING_VIOLATION);

    // An open that may delete the file, then streams that do not share it.
    let deleter = a.open(Create::new("f.txt").access(DELETE, SHARE_ALL)).await;
    let unshared = Create::new("f.txt:s").access(READ, SHARE_READ | SHARE_WRITE);
    assert_eq!(a.create(unshared).await.err(), violation);
    let shared = a.open(Create::new("f.txt:s").access(READ, SHARE_ALL)).await;
    let attributes = a.open(Create::new("f.txt:s").access(0x80, 0)).await;
    a.close(shared).await;
    a.close(attributes).await;
    a.close(deleter).await;

    // A stream that does not share delete, then opens that may delete.
    let holder = a
        .open(Create::new("f.txt:s").access(READ, SHARE_READ))
        .await;
    let delete_file = Create::new("f.txt").access(DELETE, SHARE_ALL);
    assert_eq!(a.create(delete_file).await.err(), violation);
    let delete_data = Create::new("f.txt::$DATA").access(DELETE, SHARE_ALL);
    assert_eq!(a.create(delete_data).await.err(), violation);
    let reader = a.open(Create::new("f.txt").access(READ, SHARE_ALL)).await;
    let other_stream = a
        .open(
            Create::new("f.txt:t")
                .access(DELETE | READ, SHARE_ALL)
                .disposition(FILE_OPEN_IF),
        )
        .await;
    for id in [holder, reader, other_stream] {
        a.close(id).await;
    }
}

#[tokio::test]
async fn a_file_deleted_with_a_stream_open_goes_once_the_stream_closes() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;

    let stream = a.open(Create::new("f.txt:s").access(READ, SHARE_ALL)).await;
    let deleter = a
        .open(
            Create::new("f.txt")
                .access(DELETE, SHARE_ALL)
                .options(FILE_DELETE_ON_CLOSE),
        )
        .await;
    a.close(deleter).await;
    for name in ["f.txt", "f.txt:s", "f.txt:t"] {
        let create = Create::new(name)
            .access(READ, SHARE_ALL)
            .disposition(FILE_OPEN_IF);
        assert_eq!(
            a.create(create).await.err(),
            Some(ntstatus::STATUS_DELETE_PENDING),
            "{name}"
        );
    }
    assert!(files.contents("f.txt").is_some());
    a.close(stream).await;
    assert_eq!(files.contents("f.txt"), None);
    assert!(files.stream_names("f.txt").is_empty());
    assert_eq!(
        a.create(Create::new("f.txt")).await.err(),
        Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
    );
}

#[tokio::test]
async fn a_deleted_stream_goes_at_its_last_close_and_leaves_the_file() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;
    make(&mut a, "f.txt:t", b"x").await;

    // Delete-on-close.
    let doomed = a
        .open(
            Create::new("f.txt:s")
                .access(DELETE | READ, SHARE_ALL)
                .options(FILE_DELETE_ON_CLOSE),
        )
        .await;
    let reader = a.open(Create::new("f.txt:s").access(READ, SHARE_ALL)).await;
    a.close(doomed).await;
    assert_eq!(files.stream_names("f.txt"), ["s", "t"], "still open");
    let create = Create::new("f.txt:S")
        .access(READ, SHARE_ALL)
        .disposition(FILE_CREATE);
    assert_eq!(
        a.create(create).await.err(),
        Some(ntstatus::STATUS_DELETE_PENDING)
    );
    a.close(reader).await;
    assert_eq!(files.stream_names("f.txt"), ["t"]);

    // A delete under another spelling removes the stream as created.
    make(&mut a, "f.txt:Zone", b"z").await;
    let doomed = a
        .open(
            Create::new("f.txt:ZONE")
                .access(DELETE | READ, SHARE_ALL)
                .options(FILE_DELETE_ON_CLOSE),
        )
        .await;
    a.close(doomed).await;
    assert_eq!(files.stream_names("f.txt"), ["t"]);

    // FileDispositionInformation, as macOS removes an extended attribute.
    let t = a
        .open(Create::new("f.txt:t").access(DELETE | READ, 0))
        .await;
    assert_eq!(a.set_info(t, DISPOSITION, vec![1]).await, 0);
    let standard = a.file_info(t, STANDARD).await;
    assert_eq!(standard[20], 1, "DeletePending");
    let base = a.open(Create::new("f.txt").access(READ, SHARE_ALL)).await;
    assert_eq!(a.file_info(base, STANDARD).await[20], 0, "the file stays");
    a.close(t).await;
    assert!(files.stream_names("f.txt").is_empty());
    assert_eq!(a.read(base, 0, 16).await.unwrap(), b"data");
    a.close(base).await;

    // Clearing the flag keeps the stream.
    make(&mut a, "f.txt:u", b"y").await;
    let u = a
        .open(Create::new("f.txt:u").access(DELETE | READ, 0))
        .await;
    assert_eq!(a.set_info(u, DISPOSITION, vec![1]).await, 0);
    assert_eq!(a.set_info(u, DISPOSITION, vec![0]).await, 0);
    a.close(u).await;
    assert_eq!(files.stream_names("f.txt"), ["u"]);
}

#[tokio::test]
async fn a_read_only_file_keeps_its_streams() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;
    let base = a
        .open(Create::new("f.txt").access(RW | 0x100, SHARE_ALL))
        .await;
    let mut basic = vec![0; 40];
    basic[32] = 0x1;
    assert_eq!(a.set_info(base, BASIC, basic).await, 0);
    a.close(base).await;

    let s = a
        .open(Create::new("f.txt:s").access(DELETE | READ, SHARE_ALL))
        .await;
    assert_eq!(
        a.set_info(s, DISPOSITION, vec![1]).await,
        ntstatus::STATUS_CANNOT_DELETE
    );
    a.close(s).await;
    let doomed = Create::new("f.txt:s")
        .access(DELETE | READ, SHARE_ALL)
        .options(FILE_DELETE_ON_CLOSE);
    assert_eq!(
        a.create(doomed).await.err(),
        Some(ntstatus::STATUS_CANNOT_DELETE)
    );

    // The attribute keeps every stream from being written or made.
    let refused = [
        Create::new("f.txt:s").access(WRITE, SHARE_ALL),
        Create::new("f.txt:s")
            .access(READ, SHARE_ALL)
            .disposition(FILE_OVERWRITE_IF),
        Create::new("f.txt:s")
            .access(READ, SHARE_ALL)
            .disposition(FILE_OVERWRITE),
        Create::new("f.txt:new")
            .access(READ, SHARE_ALL)
            .disposition(FILE_CREATE),
        Create::new("f.txt:new")
            .access(READ, SHARE_ALL)
            .disposition(FILE_OPEN_IF),
    ];
    for create in refused {
        assert_eq!(
            a.create(create).await.err(),
            Some(ntstatus::STATUS_ACCESS_DENIED),
            "{:#x} {}",
            create.access,
            create.disposition
        );
    }
    for disposition in [FILE_OPEN, FILE_OPEN_IF] {
        let s = a
            .open(
                Create::new("f.txt:s")
                    .access(READ, SHARE_ALL)
                    .disposition(disposition),
            )
            .await;
        assert_eq!(a.read(s, 0, 16).await.unwrap(), b"abc");
        a.close(s).await;
    }
    assert_eq!(files.stream_names("f.txt"), ["s"]);
}

#[tokio::test]
async fn an_overwrite_deletes_the_streams_and_waits_for_open_ones() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    for disposition in [FILE_OVERWRITE_IF, FILE_OVERWRITE] {
        make(&mut a, "f.txt", b"base-data").await;
        make(&mut a, "f.txt:s", b"stream-data").await;
        make(&mut a, "f.txt:t", b"x").await;
        // The open does not share write or delete; an overwrite goes ahead.
        let held = a
            .open(Create::new("f.txt:s").access(READ, SHARE_READ))
            .await;
        let f = b
            .create(Create::new("f.txt").disposition(disposition))
            .await
            .unwrap();
        assert_eq!(f.create_action, OVERWRITTEN);
        assert_eq!(files.contents("f.txt"), Some(Vec::new()));
        assert_eq!(files.stream_names("f.txt"), ["s"], "{disposition}");
        assert_eq!(
            b.create(Create::new("f.txt:s").access(READ, SHARE_ALL))
                .await
                .err(),
            Some(ntstatus::STATUS_DELETE_PENDING)
        );
        assert_eq!(
            b.streams(f.file_id).await,
            [entry("::$DATA", 0), entry(":s:$DATA", 11)]
        );
        assert_eq!(a.read(held, 0, 64).await.unwrap(), b"stream-data");
        a.close(held).await;
        assert!(files.stream_names("f.txt").is_empty());
        assert_eq!(
            b.create(Create::new("f.txt:s")).await.err(),
            Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
        );
        b.close(f.file_id).await;
    }
}

#[tokio::test]
async fn a_supersede_waits_for_stream_opens_that_share_delete() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"stream-data").await;

    let held = a
        .open(Create::new("f.txt:s").access(READ, SHARE_READ))
        .await;
    for access in [RW, RW | DELETE] {
        let create = Create::new("f.txt")
            .access(access, SHARE_ALL)
            .disposition(FILE_SUPERSEDE);
        assert_eq!(
            b.create(create).await.err(),
            Some(ntstatus::STATUS_SHARING_VIOLATION),
            "{access:#x}"
        );
    }
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));
    a.close(held).await;

    let held = a.open(Create::new("f.txt:s").access(READ, SHARE_ALL)).await;
    let f = b
        .create(
            Create::new("f.txt")
                .access(RW | DELETE, SHARE_ALL)
                .disposition(FILE_SUPERSEDE),
        )
        .await
        .unwrap();
    assert_eq!(f.create_action, SUPERSEDED);
    assert_eq!(
        b.create(Create::new("f.txt:s").access(READ, SHARE_ALL))
            .await
            .err(),
        Some(ntstatus::STATUS_DELETE_PENDING)
    );
    assert_eq!(a.read(held, 0, 64).await.unwrap(), b"stream-data");
    a.close(held).await;
    b.close(f.file_id).await;
    assert!(files.stream_names("f.txt").is_empty());
}

/// A FileRenameInformation buffer naming `to`.
fn rename_to(to: &str) -> Vec<u8> {
    let name = crate::utils::utf16le(to);
    let mut buffer = vec![0; 16];
    buffer.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&name);
    buffer
}

#[tokio::test]
async fn a_renamed_file_takes_its_open_streams_along() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"stream-data").await;
    make(&mut a, "d:ds", b"dir-stream").await;

    for (from, options, to) in [("f.txt", 0, "g.txt"), ("d", FILE_DIRECTORY_FILE, "e")] {
        let stream = if from == "d" { "d:ds" } else { "f.txt:s" };
        // A stream open that does not share delete keeps the file from
        // being opened for deletion, and so from being renamed.
        let unshared = a.open(Create::new(stream).access(READ, SHARE_READ)).await;
        let deleter = Create::new(from)
            .access(DELETE | READ, SHARE_ALL)
            .options(options);
        assert_eq!(
            b.create(deleter).await.err(),
            Some(ntstatus::STATUS_SHARING_VIOLATION),
            "{from}"
        );
        a.close(unshared).await;

        let held = a.open(Create::new(stream).access(READ, SHARE_ALL)).await;
        let renamer = b.open(deleter).await;
        assert_eq!(
            b.set_info(renamer, RENAME, rename_to(to)).await,
            0,
            "{from}"
        );
        b.close(renamer).await;
        let data = a.read(held, 0, 64).await.unwrap();
        let moved = stream.replacen(from, to, 1);
        let again = b.open(Create::new(&moved).access(READ, SHARE_ALL)).await;
        assert_eq!(b.read(again, 0, 64).await.unwrap(), data, "{moved}");
        b.close(again).await;
        a.close(held).await;
    }
    assert_eq!(files.stream_names("g.txt"), ["s"]);
    assert_eq!(files.stream_names("e"), ["ds"]);
}

#[tokio::test]
async fn stream_changes_are_not_reported_as_changes_of_the_file() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut watcher = Client::new(&state).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;
    let root = watcher
        .open(
            Create::new("")
                .access(READ, SHARE_ALL)
                .options(FILE_DIRECTORY_FILE),
        )
        .await;

    // Names, attributes, size, times and EAs.
    let watch = watcher.watch(root, 0xFF).await;
    let s = a.open(Create::new("f.txt:s")).await;
    assert_eq!(a.write(s, 0, b"abcdef").await, 0);
    assert_eq!(
        a.set_info(s, END_OF_FILE, 2u64.to_le_bytes().to_vec())
            .await,
        0
    );
    a.close(s).await;
    make(&mut a, "marker.txt", b"").await;
    assert_eq!(watcher.changes(watch).await, ["marker.txt"]);

    // A stream that comes with its file reports the file.
    let watch = watcher.watch(root, 0x1).await;
    let s = a
        .open(Create::new("new.txt:s").disposition(FILE_OPEN_IF))
        .await;
    a.close(s).await;
    assert_eq!(watcher.changes(watch).await, ["new.txt"]);
}

#[tokio::test]
async fn a_stream_that_fails_to_open_takes_its_new_file_back() {
    let files = MemFsBackend::new();
    let state = server_on(Share::new("home", Unfinished(files.clone())).public());
    let mut watcher = Client::new(&state).await;
    let mut a = Client::new(&state).await;
    let root = watcher
        .open(
            Create::new("")
                .access(READ, SHARE_ALL)
                .options(FILE_DIRECTORY_FILE),
        )
        .await;
    let watch = watcher.watch(root, 0x1).await;
    let create = Create::new("new.txt:s").disposition(FILE_OPEN_IF);
    assert_eq!(
        a.create(create).await.err(),
        Some(ntstatus::STATUS_ACCESS_DENIED)
    );
    assert_eq!(files.contents("new.txt"), None);
    make(&mut a, "marker.txt", b"").await;
    assert_eq!(watcher.changes(watch).await, ["marker.txt"]);
}

#[tokio::test]
async fn byte_range_locks_apply_per_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"0123456789").await;

    let base = a.open(Create::new("f.txt")).await;
    let stream = b.open(Create::new("f.txt:s")).await;
    assert_eq!(a.lock(base, 0, 10).await, 0);
    assert_eq!(b.lock(stream, 0, 10).await, 0);
    assert_eq!(b.write(stream, 0, b"ab").await, 0, "the stream's own lock");
    let other = a.open(Create::new("f.txt:s")).await;
    assert_eq!(
        a.lock(other, 0, 10).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    assert_eq!(
        a.read(other, 0, 4).await,
        Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
    );
    let base2 = b.open(Create::new("f.txt")).await;
    assert_eq!(
        b.read(base2, 0, 4).await,
        Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
    );
    a.close(base).await;
    assert_eq!(b.read(base2, 0, 4).await.unwrap(), b"data");
}

#[tokio::test]
async fn the_stream_list_names_every_stream_of_the_file() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;
    make(&mut a, "f.txt:Zone.Identifier", b"").await;
    make(&mut a, "d:ds", b"12345").await;

    let expected = [
        entry("::$DATA", 4),
        entry(":s:$DATA", 3),
        entry(":Zone.Identifier:$DATA", 0),
    ];
    let base = a.open(Create::new("f.txt")).await;
    assert_eq!(a.streams(base).await, expected);
    let s = a.open(Create::new("f.txt:zone.identifier")).await;
    assert_eq!(a.streams(s).await, expected, "from a stream open");
    let d = a
        .open(
            Create::new("d")
                .options(FILE_DIRECTORY_FILE)
                .access(READ, SHARE_ALL),
        )
        .await;
    assert_eq!(a.streams(d).await, [entry(":ds:$DATA", 5)]);
    let dir_stream = a.open(Create::new("d:ds")).await;
    assert_eq!(a.streams(dir_stream).await, [entry(":ds:$DATA", 5)]);
    let root = a
        .open(
            Create::new("")
                .options(FILE_DIRECTORY_FILE)
                .access(READ, SHARE_ALL),
        )
        .await;
    assert!(a.streams(root).await.is_empty(), "no streams, no default");

    // Whole entries only: 38 and 40 bytes, the first padded to 40.
    for (len, count) in [(37, 0), (38, 1), (79, 1), (80, 2)] {
        let (status, buffer) = a.query(base, 1, STREAMS, len).await;
        assert_eq!(status, ntstatus::STATUS_BUFFER_OVERFLOW, "{len}");
        assert_eq!(stream_entries(&buffer), expected[..count], "{len}");
    }
    let (status, buffer) = a.query(base, 1, STREAMS, 24).await;
    assert_eq!(
        (status, buffer.len()),
        (ntstatus::STATUS_BUFFER_OVERFLOW, 0)
    );
}

#[tokio::test]
async fn a_stream_open_reports_the_stream_s_size_and_the_file_s_times() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abcdef").await;
    let base = a.open(Create::new("f.txt")).await;
    let s = a
        .open(Create::new("f.txt:s").access(RW | DELETE, SHARE_ALL))
        .await;

    let standard = a.file_info(s, STANDARD).await;
    assert_eq!(u64_at(&standard, 8), 6, "EndOfFile");
    assert_eq!(u64_at(&a.file_info(base, STANDARD).await, 8), 4);
    assert_eq!(a.file_info(s, 0x22).await[40..48], 6u64.to_le_bytes());

    // Times set through the stream are the file's.
    let mut basic = vec![0; 40];
    basic[16..24].copy_from_slice(&0x01D0_0000_0000_0000u64.to_le_bytes());
    assert_eq!(a.set_info(s, BASIC, basic).await, 0);
    assert_eq!(
        u64_at(&a.file_info(base, BASIC).await, 16),
        0x01D0_0000_0000_0000
    );
    assert_eq!(a.file_info(s, BASIC).await, a.file_info(base, BASIC).await);

    // Sizes set through the stream are the stream's.
    assert_eq!(
        a.set_info(s, END_OF_FILE, 2u64.to_le_bytes().to_vec())
            .await,
        0
    );
    assert_eq!(a.read(s, 0, 16).await.unwrap(), b"ab");
    assert_eq!(
        a.set_info(s, ALLOCATION, 1u64.to_le_bytes().to_vec()).await,
        0
    );
    assert_eq!(a.read(s, 0, 16).await.unwrap(), b"a");
    assert_eq!(a.read(base, 0, 16).await.unwrap(), b"data");

    // A stream has no name of its own to rename or link.
    let mut rename = vec![0; 16];
    let to = crate::utils::utf16le("g.txt");
    rename.extend_from_slice(&(to.len() as u32).to_le_bytes());
    rename.extend_from_slice(&to);
    assert_eq!(
        a.set_info(s, RENAME, rename.clone()).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        a.set_info(s, LINK, rename).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(files.contents("g.txt"), None);
}

#[tokio::test]
async fn stream_opens_get_no_lease_and_break_none() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut holder = Client::from_client(&state, Uuid::from_u128(1)).await;
    let mut other = Client::from_client(&state, Uuid::from_u128(2)).await;

    let leased = holder
        .create(Create {
            lease: true,
            ..Create::new("f.txt")
        })
        .await
        .unwrap();
    assert_eq!(leased.oplock_level, 0xFF);
    let stream = other
        .create(Create {
            lease: true,
            ..Create::new("f.txt:s")
                .access(RW | DELETE, SHARE_ALL)
                .disposition(FILE_OPEN_IF)
        })
        .await
        .unwrap();
    assert_eq!(stream.oplock_level, 0);
    assert!(stream.create_contexts.is_empty());
    assert_eq!(other.write(stream.file_id, 0, b"abc").await, 0);
    assert_eq!(other.lock(stream.file_id, 0, 3).await, 0);
    assert_eq!(
        other
            .set_info(stream.file_id, END_OF_FILE, vec![0; 8])
            .await,
        0
    );
    assert_eq!(
        other.set_info(stream.file_id, DISPOSITION, vec![1]).await,
        0
    );
    other.close(stream.file_id).await;
    assert!(holder.peer.rx.try_recv().is_none(), "no lease break");
    holder.close(leased.file_id).await;

    // Opens and locks of named streams leave a lease on the file whole.
    let stream = other
        .open(Create::new("f.txt:s").disposition(FILE_OPEN_IF))
        .await;
    assert_eq!(other.lock(stream, 0, 1).await, 0);
    let leased = holder
        .create(Create {
            lease: true,
            ..Create::new("f.txt")
        })
        .await
        .unwrap();
    let contexts = CreateContext::parse_chain(&leased.create_contexts).unwrap();
    let lease = contexts
        .iter()
        .find(|c| c.name == CreateContext::NAME_RQLS)
        .expect("a lease");
    assert_eq!(LeaseContext::parse(&lease.data).unwrap().state, 0x7, "RWH");
}

#[tokio::test]
async fn extended_attributes_are_refused_on_a_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let create = Create {
        ea: true,
        ..Create::new("f.txt:s").disposition(FILE_OPEN_IF)
    };
    assert_eq!(
        a.create(create).await.err(),
        Some(ntstatus::STATUS_INVALID_PARAMETER)
    );
}

async fn fs_attributes(c: &mut Client) -> u32 {
    let root = c
        .open(
            Create::new("")
                .options(FILE_DIRECTORY_FILE)
                .access(READ, SHARE_ALL),
        )
        .await;
    let (status, buffer) = c.query(root, 2, FS_ATTRIBUTE, 1024).await;
    assert_eq!(status, 0);
    c.close(root).await;
    u32_at(&buffer, 0)
}

#[tokio::test]
async fn the_volume_reports_named_streams_only_when_the_share_serves_them() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut c = Client::new(&state).await;
    assert_eq!(
        fs_attributes(&mut c).await & FILE_NAMED_STREAMS,
        FILE_NAMED_STREAMS
    );

    for share in [
        Share::new(
            "home",
            MemFsBackend::new()
                .with_file("f.txt", b"data")
                .without_streams(),
        ),
        Share::new("home", MemFsBackend::new().with_file("f.txt", b"data")).named_streams(false),
    ] {
        let state = server_on(share.public());
        let mut c = Client::new(&state).await;
        assert_eq!(fs_attributes(&mut c).await, 0x6);
        for name in [
            "f.txt:s",
            "f.txt:s:$DATA",
            "new.txt:s",
            "f.txt:s:$INDEX_ALLOCATION",
        ] {
            let create = Create::new(name).disposition(FILE_OPEN_IF);
            assert_eq!(
                c.create(create).await.err(),
                Some(ntstatus::STATUS_OBJECT_NAME_INVALID),
                "{name}"
            );
        }
        let f = c.open(Create::new("f.txt::$DATA")).await;
        assert_eq!(c.streams(f).await, [entry("::$DATA", 4)]);
        c.close(f).await;
    }
}

/// A backend that claims named streams and leaves every stream method at
/// its default.
struct Unfinished(MemFsBackend);

#[async_trait]
impl ShareBackend for Unfinished {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.0.open(path, opts).await
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.0.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        self.0.rename(from, to, replace).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.0.capabilities()
    }
}

#[tokio::test]
async fn stream_requests_never_answer_not_supported() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;
    let s = a
        .open(Create::new("f.txt:s").access(RW | 0x100, SHARE_ALL))
        .await;
    let mut hidden = vec![0; 40];
    hidden[32] = 0x2;
    assert_eq!(
        a.set_info(s, BASIC, hidden.clone()).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    let base = a
        .open(Create::new("f.txt").access(RW | 0x100, SHARE_ALL))
        .await;
    assert_eq!(
        a.set_info(base, BASIC, hidden).await,
        ntstatus::STATUS_NOT_SUPPORTED,
        "an open of the file answers STATUS_NOT_SUPPORTED"
    );
    const POSITION: u8 = 0x0E;
    const NAME: u8 = 0x09;
    assert_eq!(
        a.set_info(s, POSITION, vec![0; 8]).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        a.query(s, 1, NAME, 1024).await.0,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        a.query(base, 1, NAME, 1024).await.0,
        ntstatus::STATUS_NOT_SUPPORTED
    );
    const SECURITY: u8 = 3;
    const QUOTA: u8 = 4;
    const FSCTL_SRV_REQUEST_RESUME_KEY: u32 = 0x0014_0078;
    assert_eq!(
        a.query(s, QUOTA, 0, 1024).await.0,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        a.query(s, SECURITY, 0, 1024).await.0,
        ntstatus::STATUS_INVALID_DEVICE_REQUEST
    );
    let mut quota = SetInfoRequest {
        structure_size: 33,
        info_type: QUOTA,
        file_information_class: 0,
        buffer_length: 8,
        buffer_offset: 0x60,
        reserved: 0,
        additional_information: 0,
        file_id: s,
        buffer: vec![0; 8],
    };
    let mut body = Vec::new();
    quota.write_to(&mut body).unwrap();
    assert_eq!(
        a.send(Command::SetInfo, &body).await.0,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    quota.file_id = base;
    let mut body = Vec::new();
    quota.write_to(&mut body).unwrap();
    assert_eq!(
        a.send(Command::SetInfo, &body).await.0,
        ntstatus::STATUS_NOT_SUPPORTED
    );
    assert_eq!(
        a.fsctl(s, FSCTL_SRV_REQUEST_RESUME_KEY).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        a.fsctl(base, FSCTL_SRV_REQUEST_RESUME_KEY).await,
        ntstatus::STATUS_NOT_SUPPORTED
    );
    let by_id = Create::new("f.txt:s").options(0x2000);
    assert_eq!(
        a.create(by_id).await.err(),
        Some(ntstatus::STATUS_INVALID_PARAMETER)
    );

    let state = server_on(
        Share::new(
            "home",
            Unfinished(MemFsBackend::new().with_file("f.txt", b"")),
        )
        .public(),
    );
    let mut a = Client::new(&state).await;
    for disposition in [FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE_IF] {
        let create = Create::new("f.txt:s").disposition(disposition);
        assert_eq!(
            a.create(create).await.err(),
            Some(ntstatus::STATUS_ACCESS_DENIED),
            "{disposition}"
        );
    }
}
