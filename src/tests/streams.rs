//! Named streams over the dispatcher, on a memory backend that stores
//! them: CREATE dispositions, share modes and locks per stream, deletion,
//! renames, the stream list, and shares that serve none.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::backend::{BackendCapabilities, Handle, OpenAction, OpenOptions, ShareBackend};
use crate::error::SmbResult;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CloseResponse, CreateContext,
    CreateRequest, CreateResponse, FileId, IoctlRequest, LeaseBreakNotification, LeaseContext,
    LockElement, LockRequest, QueryInfoRequest, QueryInfoResponse, ReadRequest, ReadResponse,
    SetInfoRequest, WriteRequest,
};
use crate::server::ServerState;
use crate::stream::StreamName;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{Peer, header, status};
use crate::{Share, SmbServer};

const READ: u32 = 0x0012_0089;
const WRITE: u32 = 0x0012_0116;
const RW: u32 = READ | WRITE;
const DELETE: u32 = 0x0001_0000;
const SHARE_READ: u32 = 0x1;
const SHARE_WRITE: u32 = 0x2;
const SHARE_DELETE: u32 = 0x4;
const SHARE_ALL: u32 = 0x7;

const COLLISION: u32 = ntstatus::STATUS_OBJECT_NAME_COLLISION;
const INVALID: u32 = ntstatus::STATUS_INVALID_PARAMETER;
const MISMATCH: u32 = ntstatus::STATUS_OBJECT_TYPE_MISMATCH;

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
const ALL: u8 = 0x12;
const NETWORK_OPEN: u8 = 0x22;
const RENAME: u8 = 0x0A;
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

    /// Closes `file_id`, asking for the attributes of the file, and
    /// returns them.
    async fn close_with_attributes(&mut self, file_id: FileId) -> u32 {
        let mut body = Vec::new();
        CloseRequest {
            structure_size: 24,
            flags: 1,
            reserved: 0,
            file_id,
        }
        .write_to(&mut body)
        .expect("close");
        let (status, body) = self.send(Command::Close, &body).await;
        assert_eq!(status, 0);
        CloseResponse::parse(&body)
            .expect("close response")
            .file_attributes
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

    /// Renames `file_id` to `to` with FileRenameInformation.
    async fn rename(&mut self, file_id: FileId, to: &str, replace: bool) -> u32 {
        let buffer = if replace {
            rename_over(to)
        } else {
            rename_to(to)
        };
        self.set_info(file_id, RENAME, buffer).await
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
        self.watch_with(dir, filter, 0).await
    }

    /// Sends a CHANGE_NOTIFY as [`Client::watch`] does, with `flags`.
    async fn watch_with(&mut self, dir: FileId, filter: u32, flags: u16) -> u64 {
        let mut body = Vec::new();
        ChangeNotifyRequest {
            structure_size: 32,
            flags,
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
        let events = self.events(async_id).await;
        events.into_iter().map(|(_, name)| name).collect()
    }

    /// The actions and names the final response to the CHANGE_NOTIFY
    /// `async_id` reports.
    async fn events(&mut self, async_id: u64) -> Vec<(u32, String)> {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), self.peer.next())
            .await
            .expect("a final response in time");
        assert_eq!(header(&frame).async_id(), Some(async_id));
        assert_eq!(status(&frame), 0);
        let buf = ChangeNotifyResponse::parse(&frame[SMB2_HEADER_LEN..])
            .expect("notify response")
            .buffer;
        let mut events = Vec::new();
        let mut at = 0;
        loop {
            let next = u32_at(&buf, at) as usize;
            let len = u32_at(&buf, at + 8) as usize;
            let units: Vec<u16> = buf[at + 12..at + 12 + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            events.push((u32_at(&buf, at + 4), String::from_utf16(&units).unwrap()));
            if next == 0 {
                return events;
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
async fn a_stream_open_with_write_data_alone_grows_the_stream() {
    const FILE_WRITE_DATA: u32 = 0x2;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut c = Client::new(&state).await;

    // How macOS sets an extended attribute.
    let id = c
        .open(
            Create::new("f.txt:org.example.k")
                .access(
                    FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
                    SHARE_READ | SHARE_DELETE,
                )
                .disposition(FILE_OVERWRITE_IF),
        )
        .await;
    assert_eq!(c.write(id, 0, b"value").await, 0);
    assert_eq!(c.write(id, 5, b"!").await, 0);
    c.close(id).await;
    let id = c.open(Create::new("f.txt:org.example.k")).await;
    assert_eq!(c.read(id, 0, 16).await.unwrap(), b"value!");
    c.close(id).await;
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
async fn a_stream_of_a_directory_reports_no_directory_attribute() {
    const DIRECTORY: u32 = 0x10;
    const NORMAL: u32 = 0x80;
    let state = server(&MemFsBackend::new()).await;
    let mut c = Client::new(&state).await;
    make(&mut c, "d:ds", b"dir").await;
    make(&mut c, "f.txt:s", b"file").await;

    let d = c
        .open(
            Create::new("d")
                .access(READ, SHARE_ALL)
                .options(FILE_DIRECTORY_FILE),
        )
        .await;
    assert_eq!(u32_at(&c.file_info(d, BASIC).await, 32), DIRECTORY);
    assert_eq!(c.file_info(d, STANDARD).await[21], 1);
    c.close(d).await;

    for (name, size) in [("d:ds", 3), ("f.txt:s", 4)] {
        let created = c.create(Create::new(name)).await.unwrap();
        assert_eq!(created.file_attributes, NORMAL, "{name}");
        assert_eq!(created.end_of_file, size, "{name}");
        let id = created.file_id;
        assert_eq!(u32_at(&c.file_info(id, BASIC).await, 32), NORMAL, "{name}");
        let standard = c.file_info(id, STANDARD).await;
        assert_eq!(u64_at(&standard, 8), size, "{name}");
        assert_eq!(standard[21], 0, "{name}");
        let all = c.file_info(id, ALL).await;
        assert_eq!(u32_at(&all, 32), NORMAL, "{name}");
        assert_eq!(all[40 + 21], 0, "{name}");
        let network_open = c.file_info(id, NETWORK_OPEN).await;
        assert_eq!(u64_at(&network_open, 40), size, "{name}");
        assert_eq!(u32_at(&network_open, 48), NORMAL, "{name}");
        assert_eq!(c.write(id, size, b"!").await, 0, "{name}");
        assert_eq!(c.close_with_attributes(id).await, NORMAL, "{name}");
    }
    let ds = c.open(Create::new("d:ds")).await;
    assert_eq!(c.read(ds, 0, 16).await.unwrap(), b"dir!");
    c.close(ds).await;
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

    // A stream of the file is renamed all the same.
    let s = a
        .open(Create::new("f.txt:s").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(a.rename(s, ":t", false).await, 0);
    a.close(s).await;
    assert_eq!(files.stream_names("f.txt"), ["t"]);
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

/// A FileRenameInformation buffer naming `to`, with ReplaceIfExists set.
fn rename_over(to: &str) -> Vec<u8> {
    let mut buffer = rename_to(to);
    buffer[0] = 1;
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
async fn a_stream_is_renamed_with_every_open_on_it() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"sdata").await;

    let s = a
        .open(Create::new("f.txt:s").access(RW | DELETE, SHARE_READ | SHARE_DELETE))
        .await;
    let reader = b.open(Create::new("f.txt:S").access(READ, SHARE_ALL)).await;
    assert_eq!(b.lock(reader, 100, 10).await, 0);
    for to in [":t", ":u:$DATA", ":v:$data"] {
        assert_eq!(a.rename(s, to, false).await, 0, "{to}");
    }
    // Its own name, in any case, leaves the stream as it is.
    assert_eq!(a.rename(s, ":V", false).await, 0);
    assert_eq!(files.stream_names("f.txt"), ["v"]);
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));
    assert_eq!(a.read(s, 0, 64).await.unwrap(), b"sdata");
    assert_eq!(b.read(reader, 0, 64).await.unwrap(), b"sdata");

    // The opens, their share modes and their locks are the new name's.
    assert_eq!(
        b.create(Create::new("f.txt:s")).await.err(),
        Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(
        b.create(Create::new("f.txt:V").access(RW, SHARE_ALL))
            .await
            .err(),
        Some(ntstatus::STATUS_SHARING_VIOLATION)
    );
    let other = b.open(Create::new("f.txt:v").access(READ, SHARE_ALL)).await;
    assert_eq!(
        b.lock(other, 100, 1).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    let fresh = b
        .open(
            Create::new("f.txt:s")
                .access(RW, 0)
                .disposition(FILE_CREATE),
        )
        .await;
    assert_eq!(b.lock(fresh, 100, 10).await, 0);
    for id in [other, fresh, reader] {
        b.close(id).await;
    }
    a.close(s).await;
    assert_eq!(files.stream_names("f.txt"), ["v", "s"]);
}

#[tokio::test]
async fn stream_renames_refuse_taken_mistyped_and_malformed_targets() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"sdata").await;
    make(&mut a, "f.txt:full", b"x").await;
    make(&mut a, "f.txt:empty", b"").await;
    make(&mut a, "f.txt:busy", b"").await;
    let busy = b
        .open(Create::new("f.txt:busy").access(READ, SHARE_ALL))
        .await;
    let s = a
        .open(Create::new("f.txt:s").access(RW | DELETE, SHARE_ALL))
        .await;

    let cases = [
        (":full", false, COLLISION),
        (":FULL", true, INVALID),
        (":busy", false, COLLISION),
        (":busy", true, INVALID),
        (":empty", false, COLLISION),
        ("::$DATA", false, COLLISION),
        ("::$DATA", true, INVALID),
        (":x:$INDEX_ALLOCATION", false, MISMATCH),
        (":x:$FOO", false, MISMATCH),
        (":x:", false, INVALID),
        (":a:b:c", false, INVALID),
        (":a\\b", false, INVALID),
        (":", false, INVALID),
        ("g.txt", false, INVALID),
        ("f.txt:x", false, INVALID),
        ("\\g.txt", false, INVALID),
    ];
    for (to, replace, expected) in cases {
        assert_eq!(a.rename(s, to, replace).await, expected, "{to} {replace}");
    }
    assert_eq!(files.stream_names("f.txt"), ["s", "full", "empty", "busy"]);
    assert_eq!(files.contents("g.txt"), None);

    // An empty stream no open is on is replaced.
    assert_eq!(a.rename(s, ":EMPTY", true).await, 0);
    assert_eq!(files.stream_names("f.txt"), ["EMPTY", "full", "busy"]);
    assert_eq!(a.read(s, 0, 64).await.unwrap(), b"sdata");
    b.close(busy).await;

    // A rename needs DELETE access.
    let reader = a
        .open(Create::new("f.txt:full").access(RW, SHARE_ALL))
        .await;
    assert_eq!(
        a.rename(reader, ":y", false).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
}

#[tokio::test]
async fn a_directory_renames_only_its_named_streams() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "d:ds", b"dir").await;

    let d = a
        .open(
            Create::new("d")
                .access(READ | DELETE, SHARE_ALL)
                .options(FILE_DIRECTORY_FILE),
        )
        .await;
    let f = a
        .open(Create::new("f.txt").access(RW | DELETE, SHARE_ALL))
        .await;
    let cases = [
        (d, ":x", false, INVALID),
        (d, ":x:$DATA", false, MISMATCH),
        (d, ":x:$INDEX_ALLOCATION", false, INVALID),
        (d, "::$DATA", false, MISMATCH),
        (d, "::$INDEX_ALLOCATION", false, INVALID),
        (f, ":x:$INDEX_ALLOCATION", false, MISMATCH),
    ];
    for (id, to, replace, expected) in cases {
        assert_eq!(a.rename(id, to, replace).await, expected, "{to} {replace}");
    }
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));
    assert!(files.stream_names("f.txt").is_empty());
    a.close(d).await;
    a.close(f).await;

    // A directory's named stream has no default stream to go to.
    let ds = a
        .open(Create::new("d:ds").access(RW | DELETE, SHARE_ALL))
        .await;
    assert_eq!(a.rename(ds, "::$DATA", false).await, INVALID);
    assert_eq!(a.rename(ds, ":de", false).await, 0);
    a.close(ds).await;
    assert_eq!(files.stream_names("d"), ["de"]);
}

#[tokio::test]
async fn the_default_stream_moves_into_a_named_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:full", b"x").await;
    make(&mut a, "f.txt:empty", b"").await;

    let f = a
        .open(Create::new("f.txt").access(RW | DELETE, SHARE_READ | SHARE_DELETE))
        .await;
    let cases = [
        (":full", false, COLLISION),
        (":full", true, INVALID),
        (":empty", false, COLLISION),
        ("::$DATA", false, COLLISION),
        ("::$DATA", true, 0),
    ];
    for (to, replace, expected) in cases {
        assert_eq!(a.rename(f, to, replace).await, expected, "{to} {replace}");
    }
    // Refused while the default stream has other opens.
    let other = b.open(Create::new("f.txt").access(0x80, SHARE_ALL)).await;
    assert_eq!(a.rename(f, ":x", false).await, INVALID);
    b.close(other).await;
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));

    assert_eq!(a.lock(f, 100, 10).await, 0);
    assert_eq!(a.rename(f, ":EMPTY", true).await, 0);
    assert_eq!(files.contents("f.txt"), Some(Vec::new()));
    assert_eq!(files.stream_names("f.txt"), ["full", "EMPTY"]);
    assert_eq!(a.read(f, 0, 64).await.unwrap(), b"data");
    assert_eq!(a.write(f, 0, b"ZZ").await, 0);
    assert_eq!(u64_at(&a.file_info(f, STANDARD).await, 8), 4, "EndOfFile");

    // The open, its share mode and its lock are the stream's now.
    let base = b.open(Create::new("f.txt").access(RW, SHARE_ALL)).await;
    assert_eq!(b.read(base, 0, 64).await, Err(ntstatus::STATUS_END_OF_FILE));
    assert_eq!(b.lock(base, 100, 10).await, 0);
    assert_eq!(
        b.create(Create::new("f.txt:empty").access(RW, SHARE_ALL))
            .await
            .err(),
        Some(ntstatus::STATUS_SHARING_VIOLATION)
    );
    let stream = b
        .open(Create::new("f.txt:empty").access(READ, SHARE_ALL))
        .await;
    assert_eq!(b.read(stream, 0, 64).await.unwrap(), b"ZZta");
    assert_eq!(
        b.lock(stream, 100, 1).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    for id in [base, stream] {
        b.close(id).await;
    }

    // Back again, moving the data into the empty default stream.
    assert_eq!(a.rename(f, "::$DATA", true).await, 0);
    a.close(f).await;
    assert_eq!(files.contents("f.txt"), Some(b"ZZta".to_vec()));
    assert_eq!(files.stream_names("f.txt"), ["full"]);
}

/// What a [`Picky`] backend refuses.
const ACCEPT: u8 = 0;
const REFUSE_WRITES: u8 = 1;
const REFUSE_OPENS: u8 = 2;
const REFUSE_OPENS_AND_MOVES_BACK: u8 = 3;
const FAIL_A_STREAM_OPEN_AFTER_A_MOVE: u8 = 4;
const FAILING_NEXT_STREAM_OPEN: u8 = 5;

/// A memory backend that, as `mode` says, refuses opens for writing, every
/// open, or every open and every rename into the default stream, with
/// STATUS_ACCESS_DENIED; or fails the first stream open after a rename
/// out of the default stream with STATUS_DISK_FULL.
struct Picky {
    inner: MemFsBackend,
    mode: Arc<std::sync::atomic::AtomicU8>,
}

impl Picky {
    fn check(&self, opts: &OpenOptions) -> SmbResult<()> {
        match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
            REFUSE_WRITES if opts.write => Err(crate::SmbError::AccessDenied),
            REFUSE_OPENS | REFUSE_OPENS_AND_MOVES_BACK => Err(crate::SmbError::AccessDenied),
            _ => Ok(()),
        }
    }
}

#[async_trait]
impl ShareBackend for Picky {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.check(&opts)?;
        self.inner.open(path, opts).await
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

    async fn open_stream(
        &self,
        file: Box<dyn Handle>,
        path: &SmbPath,
        stream: &StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let failing = self.mode.compare_exchange(
            FAILING_NEXT_STREAM_OPEN,
            ACCEPT,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        );
        let checked = match failing {
            Ok(_) => Err(crate::SmbError::DiskFull),
            Err(_) => self.check(&opts),
        };
        if let Err(e) = checked {
            let _ = file.close().await;
            return Err(e);
        }
        self.inner.open_stream(file, path, stream, opts).await
    }

    async fn rename_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        from: Option<&StreamName>,
        to: Option<&StreamName>,
        replace: bool,
    ) -> SmbResult<()> {
        let mode = self.mode.load(std::sync::atomic::Ordering::SeqCst);
        if mode == REFUSE_OPENS_AND_MOVES_BACK && to.is_none() {
            return Err(crate::SmbError::AccessDenied);
        }
        self.inner
            .rename_stream(path, file_index, from, to, replace)
            .await?;
        if mode == FAIL_A_STREAM_OPEN_AFTER_A_MOVE && from.is_none() {
            self.mode.store(
                FAILING_NEXT_STREAM_OPEN,
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        Ok(())
    }
}

#[tokio::test]
async fn a_moved_stream_gets_a_new_handle_or_moves_back() {
    let files = MemFsBackend::new().with_file("f.txt", b"data");
    let mode = Arc::new(std::sync::atomic::AtomicU8::new(ACCEPT));
    let picky = Picky {
        inner: files.clone(),
        mode: Arc::clone(&mode),
    };
    let state = server_on(Share::new("home", picky).public());
    let mut a = Client::new(&state).await;
    let set = |m| mode.store(m, std::sync::atomic::Ordering::SeqCst);
    make(&mut a, "f.txt:e", b"").await;

    // A file made read-only after the open: the new handle reads only.
    let f = a
        .open(Create::new("f.txt").access(RW | DELETE, SHARE_ALL))
        .await;
    let mut basic = vec![0; 40];
    basic[32] = 0x1;
    assert_eq!(a.set_info(f, BASIC, basic).await, 0);
    set(REFUSE_WRITES);
    assert_eq!(a.rename(f, ":x", false).await, 0);
    assert_eq!(files.contents("f.txt"), Some(Vec::new()));
    assert_eq!(files.stream_names("f.txt"), ["e", "x"]);
    assert_eq!(a.read(f, 0, 64).await.unwrap(), b"data");
    assert_eq!(a.rename(f, "::$DATA", true).await, 0);
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));
    assert_eq!(a.read(f, 0, 64).await.unwrap(), b"data");

    // No new handle: the data moves back, and the open keeps its handle.
    set(REFUSE_OPENS);
    assert_eq!(
        a.rename(f, ":y", false).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));
    assert_eq!(files.stream_names("f.txt"), ["e"]);
    assert_eq!(a.read(f, 0, 64).await.unwrap(), b"data");

    // An empty stream to replace that cannot be opened stays.
    assert_eq!(
        a.rename(f, ":e", true).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert_eq!(files.stream_names("f.txt"), ["e"]);

    // One the move replaced comes back with the data, and an error other
    // than STATUS_ACCESS_DENIED gets no second try.
    set(FAIL_A_STREAM_OPEN_AFTER_A_MOVE);
    assert_eq!(a.rename(f, ":e", true).await, ntstatus::STATUS_DISK_FULL);
    assert_eq!(files.contents("f.txt"), Some(b"data".to_vec()));
    assert_eq!(files.stream_names("f.txt"), ["e"]);
    assert_eq!(a.read(f, 0, 64).await.unwrap(), b"data");
    set(ACCEPT);
    let e = a.open(Create::new("f.txt:e").access(READ, SHARE_ALL)).await;
    assert_eq!(a.read(e, 0, 64).await, Err(ntstatus::STATUS_END_OF_FILE));
    a.close(e).await;

    // Nor a way back: the rename stands, and the open has no handle.
    set(REFUSE_OPENS_AND_MOVES_BACK);
    assert_eq!(a.rename(f, ":z", false).await, 0);
    assert_eq!(files.stream_names("f.txt"), ["e", "z"]);
    assert_eq!(a.read(f, 0, 64).await, Err(ntstatus::STATUS_FILE_CLOSED));
    a.close(f).await;
    set(ACCEPT);
    let z = a.open(Create::new("f.txt:z").access(READ, 0)).await;
    assert_eq!(a.read(z, 0, 64).await.unwrap(), b"data");
    a.close(z).await;
    assert_eq!(files.open_handles(), 0);
}

#[tokio::test]
async fn a_stream_moved_onto_the_default_stream_moves_back_without_a_handle() {
    let files = MemFsBackend::new().with_file("f.txt", b"");
    let mode = Arc::new(std::sync::atomic::AtomicU8::new(ACCEPT));
    let picky = Picky {
        inner: files.clone(),
        mode: Arc::clone(&mode),
    };
    let state = server_on(Share::new("home", picky).public());
    let mut a = Client::new(&state).await;
    let set = |m| mode.store(m, std::sync::atomic::Ordering::SeqCst);
    make(&mut a, "f.txt:s", b"sdata").await;
    let s = a
        .open(Create::new("f.txt:s").access(RW | DELETE, SHARE_ALL))
        .await;

    // The default stream cannot be opened once the data is in it, so the
    // data goes back to the stream, which the open stays on.
    set(REFUSE_OPENS);
    assert_eq!(
        a.rename(s, "::$DATA", true).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert_eq!(files.contents("f.txt"), Some(Vec::new()));
    assert_eq!(files.stream_names("f.txt"), ["s"]);
    assert_eq!(a.read(s, 0, 64).await.unwrap(), b"sdata");

    set(ACCEPT);
    assert_eq!(a.rename(s, "::$DATA", true).await, 0);
    assert_eq!(files.contents("f.txt"), Some(b"sdata".to_vec()));
    assert!(files.stream_names("f.txt").is_empty());
    assert_eq!(a.read(s, 0, 64).await.unwrap(), b"sdata");
    a.close(s).await;
    assert_eq!(files.open_handles(), 0);
}

#[tokio::test]
async fn a_stream_moved_onto_the_default_stream_shares_as_the_file_requires() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"sdata").await;
    make(&mut a, "f.txt:t", b"x").await;
    let base = a.open(Create::new("f.txt").access(RW, SHARE_ALL)).await;
    assert_eq!(a.set_info(base, END_OF_FILE, vec![0; 8]).await, 0);
    a.close(base).await;

    // On the default stream an open holding DELETE excludes opens of
    // other streams that do not share delete access.
    let s = a
        .open(Create::new("f.txt:s").access(RW | DELETE, SHARE_ALL))
        .await;
    let t = b
        .open(Create::new("f.txt:t").access(READ, SHARE_READ))
        .await;
    assert_eq!(
        a.rename(s, "::$DATA", true).await,
        ntstatus::STATUS_SHARING_VIOLATION
    );
    assert_eq!(files.stream_names("f.txt"), ["s", "t"]);
    assert_eq!(a.read(s, 0, 64).await.unwrap(), b"sdata");
    b.close(t).await;
    assert_eq!(a.rename(s, "::$DATA", true).await, 0);
    assert_eq!(files.contents("f.txt"), Some(b"sdata".to_vec()));
    a.close(s).await;
}

#[tokio::test]
async fn a_named_stream_moves_into_an_empty_default_stream() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"sdata").await;

    let s = a
        .open(Create::new("f.txt:s").access(RW | DELETE, SHARE_READ | SHARE_DELETE))
        .await;
    assert_eq!(a.rename(s, "::$DATA", true).await, INVALID, "data");
    let base = b.open(Create::new("f.txt").access(RW, SHARE_ALL)).await;
    assert_eq!(b.set_info(base, END_OF_FILE, vec![0; 8]).await, 0);
    b.close(base).await;
    let other = b.open(Create::new("f.txt").access(0x80, SHARE_ALL)).await;
    assert_eq!(a.rename(s, "::$DATA", true).await, INVALID, "open");
    b.close(other).await;
    let other = b.open(Create::new("f.txt:s").access(READ, SHARE_ALL)).await;
    assert_eq!(a.rename(s, "::$DATA", true).await, INVALID, "stream open");
    b.close(other).await;
    assert_eq!(a.rename(s, "::$DATA", false).await, COLLISION);

    // A mark for deletion stays behind with the stream's name.
    assert_eq!(a.set_info(s, DISPOSITION, vec![1]).await, 0);
    assert_eq!(a.rename(s, "::$DATA", true).await, 0);
    assert_eq!(files.contents("f.txt"), Some(b"sdata".to_vec()));
    assert!(files.stream_names("f.txt").is_empty());
    assert_eq!(a.read(s, 0, 64).await.unwrap(), b"sdata");
    assert_eq!(a.file_info(s, STANDARD).await[20], 0, "DeletePending");
    assert_eq!(
        b.create(Create::new("f.txt").access(RW, SHARE_ALL))
            .await
            .err(),
        Some(ntstatus::STATUS_SHARING_VIOLATION)
    );
    assert_eq!(
        b.create(Create::new("f.txt:s").access(READ, SHARE_ALL))
            .await
            .err(),
        Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
    );
    a.close(s).await;
    assert_eq!(files.contents("f.txt"), Some(b"sdata".to_vec()));
}

#[tokio::test]
async fn a_lease_on_the_default_stream_breaks_when_its_data_moves() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::from_client(&state, Uuid::from_u128(1)).await;
    let leased = a
        .create(Create {
            lease: true,
            ..Create::new("f.txt").access(RW | DELETE, SHARE_ALL)
        })
        .await
        .unwrap();
    assert_eq!(leased.oplock_level, 0xFF);
    assert_eq!(a.rename(leased.file_id, ":x", false).await, 0);
    let notice = tokio::time::timeout(std::time::Duration::from_secs(5), a.peer.next())
        .await
        .expect("a lease break");
    assert_eq!(header(&notice).command, Command::OplockBreak);
    let n = LeaseBreakNotification::parse(&notice[SMB2_HEADER_LEN..]).expect("break");
    assert_eq!((n.current_lease_state, n.new_lease_state), (0x7, 0));
    assert_eq!(a.read(leased.file_id, 0, 64).await.unwrap(), b"data");
    a.close(leased.file_id).await;
    assert_eq!(files.stream_names("f.txt"), ["x"]);
}

#[tokio::test]
async fn a_stream_keeps_its_mark_for_deletion_through_a_rename() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"sdata").await;
    make(&mut a, "f.txt:t", b"").await;

    let s = a
        .open(Create::new("f.txt:s").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(a.set_info(s, DISPOSITION, vec![1]).await, 0);
    assert_eq!(a.rename(s, ":gone", false).await, 0);
    assert_eq!(
        b.create(Create::new("f.txt:gone")).await.err(),
        Some(ntstatus::STATUS_DELETE_PENDING)
    );
    let again = b
        .open(Create::new("f.txt:s").disposition(FILE_CREATE))
        .await;
    b.close(again).await;
    a.close(s).await;
    assert_eq!(files.stream_names("f.txt"), ["t", "s"]);

    // A target marked for deletion is still there while it is open.
    let t = b
        .open(Create::new("f.txt:t").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(b.set_info(t, DISPOSITION, vec![1]).await, 0);
    let s = a
        .open(Create::new("f.txt:s").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(a.rename(s, ":t", false).await, COLLISION);
    assert_eq!(a.rename(s, ":t", true).await, INVALID);
    b.close(t).await;
    assert_eq!(a.rename(s, ":t", false).await, 0);
    a.close(s).await;
    assert_eq!(files.stream_names("f.txt"), ["t"]);
}

#[tokio::test]
async fn a_file_keeps_its_streams_pending_removal_through_a_rename() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"sdata").await;
    make(&mut a, "f.txt:t", b"x").await;

    let s = a
        .open(Create::new("f.txt:s").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(a.set_info(s, DISPOSITION, vec![1]).await, 0);
    let renamer = b
        .open(Create::new("f.txt").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(b.rename(renamer, "g.txt", false).await, 0);
    b.close(renamer).await;
    a.close(s).await;
    assert_eq!(files.stream_names("g.txt"), ["t"]);

    // A file deleted while a stream of it is open goes with its streams
    // once that closes, under the name a rename gave it.
    let t = a.open(Create::new("g.txt:t").access(READ, SHARE_ALL)).await;
    let deleter = b
        .open(Create::new("g.txt").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(b.set_info(deleter, DISPOSITION, vec![1]).await, 0);
    b.close(deleter).await;
    assert_eq!(
        a.create(Create::new("g.txt:t")).await.err(),
        Some(ntstatus::STATUS_DELETE_PENDING)
    );
    a.close(t).await;
    assert_eq!(files.contents("g.txt"), None);
    assert!(files.stream_names("g.txt").is_empty());
}

#[tokio::test]
async fn a_file_with_a_stream_open_is_not_replaced() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"mine").await;
    make(&mut a, "h.txt:old", b"theirs").await;

    let held = b
        .open(Create::new("h.txt:old").access(READ, SHARE_ALL))
        .await;
    let renamer = a
        .open(Create::new("f.txt").access(READ | DELETE, SHARE_ALL))
        .await;
    assert_eq!(
        a.rename(renamer, "h.txt", true).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    b.close(held).await;
    assert_eq!(a.rename(renamer, "h.txt", true).await, 0);
    a.close(renamer).await;
    assert_eq!(files.stream_names("h.txt"), ["s"]);
    assert_eq!(files.contents("f.txt"), None);
}

const ADDED: u32 = 1;
const REMOVED: u32 = 2;
const MODIFIED: u32 = 3;
const ADDED_STREAM: u32 = 6;
const REMOVED_STREAM: u32 = 7;
const MODIFIED_STREAM: u32 = 8;

/// (action, name) for each of `events`.
fn heard(events: &[(u32, &str)]) -> Vec<(u32, String)> {
    events.iter().map(|&(a, n)| (a, n.to_string())).collect()
}

/// The directory `name` opened by `c` to watch.
async fn watched(c: &mut Client, name: &str) -> FileId {
    c.open(
        Create::new(name)
            .access(READ, SHARE_ALL)
            .options(FILE_DIRECTORY_FILE),
    )
    .await
}

#[tokio::test]
async fn stream_changes_name_the_stream_after_its_file() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut watcher = Client::new(&state).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "f.txt:s", b"abc").await;
    let root = watched(&mut watcher, "").await;

    // A new stream, then a write through an open of it, at close.
    let w = watcher.watch(root, 0xFFF).await;
    let t = a
        .open(Create::new("f.txt:t").disposition(FILE_CREATE))
        .await;
    a.close(t).await;
    assert_eq!(watcher.events(w).await, heard(&[(ADDED_STREAM, "f.txt:t")]));
    let w = watcher.watch(root, 0xFFF).await;
    let s = a.open(Create::new("f.txt:s")).await;
    assert_eq!(a.write(s, 0, b"abcdef").await, 0);
    a.close(s).await;
    let written = heard(&[(MODIFIED, "f.txt"), (MODIFIED_STREAM, "f.txt:s")]);
    assert_eq!(watcher.events(w).await, written);

    // An overwrite and a resize report as they happen and at close.
    for resize in [false, true] {
        let w = watcher.watch(root, 0xFFF).await;
        let s = if resize {
            let s = a.open(Create::new("f.txt:s")).await;
            assert_eq!(
                a.set_info(s, END_OF_FILE, vec![2, 0, 0, 0, 0, 0, 0, 0])
                    .await,
                0
            );
            s
        } else {
            a.open(Create::new("f.txt:s").disposition(FILE_OVERWRITE_IF))
                .await
        };
        assert_eq!(watcher.events(w).await, written, "resize {resize}");
        let w = watcher.watch(root, 0xFFF).await;
        a.close(s).await;
        let closed = heard(&[(MODIFIED_STREAM, "f.txt:s")]);
        assert_eq!(watcher.events(w).await, closed, "resize {resize}");
    }

    // A rename reports both names and the file.
    let w = watcher.watch(root, 0xFFF).await;
    let s = a
        .open(Create::new("f.txt:s").access(RW | DELETE, SHARE_ALL))
        .await;
    assert_eq!(a.rename(s, ":u", false).await, 0);
    let renamed = heard(&[
        (MODIFIED_STREAM, "f.txt:s"),
        (MODIFIED, "f.txt"),
        (MODIFIED_STREAM, "f.txt:u"),
    ]);
    assert_eq!(watcher.events(w).await, renamed);

    // A deletion is a change of the stream: as it is marked, or at the
    // close that deletes it.
    let w = watcher.watch(root, 0xFFF).await;
    assert_eq!(a.set_info(s, DISPOSITION, vec![1]).await, 0);
    assert_eq!(
        watcher.events(w).await,
        heard(&[(MODIFIED_STREAM, "f.txt:u")])
    );
    let w = watcher.watch(root, 0xFFF).await;
    assert_eq!(a.set_info(s, DISPOSITION, vec![1]).await, 0, "marked again");
    let marker = a.open(Create::new("m.txt").disposition(FILE_CREATE)).await;
    a.close(marker).await;
    assert_eq!(watcher.events(w).await, heard(&[(ADDED, "m.txt")]));
    let w = watcher.watch(root, 0xFFF).await;
    a.close(s).await;
    let t = a
        .open(
            Create::new("f.txt:t")
                .access(READ | DELETE, SHARE_ALL)
                .options(FILE_DELETE_ON_CLOSE),
        )
        .await;
    a.close(t).await;
    assert_eq!(
        watcher.events(w).await,
        heard(&[(MODIFIED_STREAM, "f.txt:t")])
    );
    assert!(files.stream_names("f.txt").is_empty());

    // A stream that comes with its file, and one of a directory.
    let w = watcher.watch(root, 0xFFF).await;
    let n = a
        .open(Create::new("n.txt:s").disposition(FILE_OPEN_IF))
        .await;
    let added = heard(&[(ADDED, "n.txt"), (ADDED_STREAM, "n.txt:s")]);
    assert_eq!(watcher.events(w).await, added);
    let w = watcher.watch(root, 0xFFF).await;
    assert_eq!(a.write(n, 0, b"x").await, 0);
    a.close(n).await;
    let written = heard(&[(MODIFIED, "n.txt"), (MODIFIED_STREAM, "n.txt:s")]);
    assert_eq!(watcher.events(w).await, written);
    let w = watcher.watch(root, 0xFFF).await;
    let ds = a.open(Create::new("d:ds").disposition(FILE_CREATE)).await;
    a.close(ds).await;
    let first = heard(&[(MODIFIED, "d"), (ADDED_STREAM, "d:ds")]);
    assert_eq!(watcher.events(w).await, first);
    let w = watcher.watch(root, 0xFFF).await;
    let ds = a.open(Create::new("d:ds2").disposition(FILE_CREATE)).await;
    a.close(ds).await;
    assert_eq!(watcher.events(w).await, heard(&[(ADDED_STREAM, "d:ds2")]));

    // An overwrite of the file removes its streams; a deletion of the file
    // reports the file alone. A new watch leaves out the changes made to
    // set them up.
    make(&mut a, "n.txt:t", b"y").await;
    let root = watched(&mut watcher, "").await;
    let w = watcher.watch(root, 0xFFF).await;
    let n = a
        .open(Create::new("n.txt").disposition(FILE_OVERWRITE_IF))
        .await;
    let overwritten = heard(&[
        (REMOVED_STREAM, "n.txt:s"),
        (REMOVED_STREAM, "n.txt:t"),
        (MODIFIED, "n.txt"),
    ]);
    assert_eq!(watcher.events(w).await, overwritten);
    a.close(n).await;
    make(&mut a, "n.txt:s", b"z").await;
    let root = watched(&mut watcher, "").await;
    let w = watcher.watch(root, 0xFFF).await;
    let n = a
        .open(
            Create::new("n.txt")
                .access(READ | DELETE, SHARE_ALL)
                .options(FILE_DELETE_ON_CLOSE),
        )
        .await;
    a.close(n).await;
    assert_eq!(watcher.events(w).await, heard(&[(REMOVED, "n.txt")]));
}

#[tokio::test]
async fn stream_resizes_drops_and_overwrites_report_once() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut watcher = Client::new(&state).await;
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    make(&mut a, "d\\g.txt", b"").await;
    make(&mut a, "f.txt:s", b"abcdef").await;

    // A resize with no watch on the share yet reports the stream at close.
    let s = a.open(Create::new("f.txt:s")).await;
    assert_eq!(
        a.set_info(s, END_OF_FILE, vec![4, 0, 0, 0, 0, 0, 0, 0])
            .await,
        0
    );
    let root = watched(&mut watcher, "").await;
    let w = watcher.watch(root, 0xFFF).await;
    a.close(s).await;
    assert_eq!(
        watcher.events(w).await,
        heard(&[(MODIFIED_STREAM, "f.txt:s")])
    );

    // An allocation below the size resizes the stream.
    let s = a.open(Create::new("f.txt:s")).await;
    let w = watcher.watch(root, 0xFFF).await;
    assert_eq!(
        a.set_info(s, ALLOCATION, vec![2, 0, 0, 0, 0, 0, 0, 0])
            .await,
        0
    );
    let resized = heard(&[(MODIFIED, "f.txt"), (MODIFIED_STREAM, "f.txt:s")]);
    assert_eq!(watcher.events(w).await, resized);
    let w = watcher.watch(root, 0xFFF).await;
    a.close(s).await;
    assert_eq!(
        watcher.events(w).await,
        heard(&[(MODIFIED_STREAM, "f.txt:s")])
    );

    // The close of an open whose connection ends reports its write.
    let mut c = Client::new(&state).await;
    let s = c.open(Create::new("f.txt:s")).await;
    assert_eq!(c.write(s, 0, b"x").await, 0);
    let w = watcher.watch(root, 0xFFF).await;
    c.peer.drop_connection(&state).await;
    assert_eq!(watcher.events(w).await, resized);

    // A watch of the tree names the stream under its directory.
    let tree = watched(&mut watcher, "").await;
    let w = watcher
        .watch_with(tree, 0xFFF, ChangeNotifyRequest::FLAG_WATCH_TREE)
        .await;
    let g = a
        .open(Create::new("d\\g.txt:s").disposition(FILE_CREATE))
        .await;
    a.close(g).await;
    assert_eq!(
        watcher.events(w).await,
        heard(&[(ADDED_STREAM, "d\\g.txt:s")])
    );

    // An overwrite of a file whose stream is open elsewhere removes it
    // too, and a later overwrite does not report it again.
    make(&mut a, "n.txt:s", b"1").await;
    make(&mut a, "n.txt:t", b"2").await;
    let held = b.open(Create::new("n.txt:s").access(READ, SHARE_ALL)).await;
    let root = watched(&mut watcher, "").await;
    let w = watcher.watch(root, 0xFFF).await;
    let n = a
        .open(Create::new("n.txt").disposition(FILE_OVERWRITE_IF))
        .await;
    let overwritten = heard(&[
        (REMOVED_STREAM, "n.txt:s"),
        (REMOVED_STREAM, "n.txt:t"),
        (MODIFIED, "n.txt"),
    ]);
    assert_eq!(watcher.events(w).await, overwritten);
    a.close(n).await;
    make(&mut a, "n.txt:u", b"3").await;
    let root = watched(&mut watcher, "").await;
    let w = watcher.watch(root, 0xFFF).await;
    let n = a
        .open(Create::new("n.txt").disposition(FILE_OVERWRITE_IF))
        .await;
    let again = heard(&[(REMOVED_STREAM, "n.txt:u"), (MODIFIED, "n.txt")]);
    assert_eq!(watcher.events(w).await, again);
    a.close(n).await;
    b.close(held).await;
    assert!(files.stream_names("n.txt").is_empty());
}

#[tokio::test]
async fn stream_changes_match_the_stream_filters() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "d\\f.txt", b"").await;
    let cases = [
        (0x200, ADDED_STREAM, true),
        (0x400, MODIFIED_STREAM, true),
        (0x800, MODIFIED_STREAM, true),
        (0x10, MODIFIED, false),
    ];
    for (n, (filter, action, on_stream)) in cases.into_iter().enumerate() {
        let mut watcher = Client::new(&state).await;
        let d = watched(&mut watcher, "d").await;
        let w = watcher.watch(d, filter).await;
        let stream = format!("f.txt:s{n}");
        let s = a
            .open(Create::new(&format!("d\\{stream}")).disposition(FILE_CREATE))
            .await;
        assert_eq!(a.write(s, 0, b"x").await, 0);
        a.close(s).await;
        let name = if on_stream {
            stream
        } else {
            "f.txt".to_string()
        };
        assert_eq!(watcher.events(w).await, [(action, name)], "{filter:#x}");
    }
}

#[tokio::test]
async fn stream_changes_report_their_file_or_directory_under_both_times() {
    const LAST_WRITE: u32 = 0x10;
    const LAST_ACCESS: u32 = 0x20;
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut a = Client::new(&state).await;
    make(&mut a, "d\\f.txt", b"").await;
    let sub = a
        .open(
            Create::new("d\\sub")
                .access(READ, SHARE_ALL)
                .disposition(FILE_CREATE)
                .options(FILE_DIRECTORY_FILE),
        )
        .await;
    a.close(sub).await;
    for base in ["f.txt", "sub"] {
        let stream = format!("d\\{base}:s");
        let modified = heard(&[(MODIFIED, base)]);
        for filter in [LAST_WRITE, LAST_ACCESS] {
            make(&mut a, &stream, b"x").await;
            let mut watcher = Client::new(&state).await;
            let d = watched(&mut watcher, "d").await;

            // stream_changes_match_the_stream_filters covers a write to a
            // file's stream under LAST_WRITE.
            if base != "f.txt" || filter != LAST_WRITE {
                let w = watcher.watch(d, filter).await;
                let s = a.open(Create::new(&stream)).await;
                assert_eq!(a.write(s, 0, b"data").await, 0);
                a.close(s).await;
                let heard = watcher.events(w).await;
                assert_eq!(heard, modified, "write {base} {filter:#x}");
            }

            if filter == LAST_ACCESS {
                let w = watcher.watch(d, filter).await;
                let s = a.open(Create::new(&stream)).await;
                let size = 2u64.to_le_bytes().to_vec();
                assert_eq!(a.set_info(s, END_OF_FILE, size).await, 0);
                let heard = watcher.events(w).await;
                assert_eq!(heard, modified, "resize {base} {filter:#x}");
                a.close(s).await;
            }

            let w = watcher.watch(d, filter).await;
            let s = a
                .open(Create::new(&stream).disposition(FILE_OVERWRITE_IF))
                .await;
            let heard = watcher.events(w).await;
            assert_eq!(heard, modified, "overwrite {base} {filter:#x}");
            a.close(s).await;

            let w = watcher.watch(d, filter).await;
            let s = a
                .open(Create::new(&stream).access(RW | DELETE, SHARE_ALL))
                .await;
            assert_eq!(a.rename(s, ":t", true).await, 0);
            let heard = watcher.events(w).await;
            assert_eq!(heard, modified, "rename {base} {filter:#x}");
            a.close(s).await;
            let t = a
                .open(
                    Create::new(&format!("d\\{base}:t"))
                        .access(DELETE, SHARE_ALL)
                        .options(FILE_DELETE_ON_CLOSE),
                )
                .await;
            a.close(t).await;
        }
    }
}

#[tokio::test]
async fn changes_to_streams_named_with_a_quote_go_unreported() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut watcher = Client::new(&state).await;
    let mut a = Client::new(&state).await;
    let root = watched(&mut watcher, "").await;
    let w = watcher.watch(root, 0xFFF).await;
    let q = a
        .open(Create::new("f.txt:q\"x").disposition(FILE_CREATE))
        .await;
    assert_eq!(a.write(q, 0, b"x").await, 0);
    a.close(q).await;
    assert_eq!(watcher.events(w).await, heard(&[(MODIFIED, "f.txt")]));
}

#[tokio::test]
async fn data_moved_between_streams_reports_where_it_went() {
    let files = MemFsBackend::new();
    let state = server(&files).await;
    let mut watcher = Client::new(&state).await;
    let mut a = Client::new(&state).await;
    let root = watched(&mut watcher, "").await;

    // Written to the file, then moved into a stream: both at close.
    let f = a
        .open(Create::new("f.txt").access(RW | DELETE, SHARE_ALL))
        .await;
    assert_eq!(a.write(f, 0, b"BASE").await, 0);
    let w = watcher.watch(root, 0xFFF).await;
    assert_eq!(a.rename(f, ":m", false).await, 0);
    a.close(f).await;
    let moved = heard(&[(MODIFIED, "f.txt"), (MODIFIED_STREAM, "f.txt:m")]);
    assert_eq!(watcher.events(w).await, moved);

    // Moved back: the stream as it moves, the file at close.
    let m = a
        .open(Create::new("f.txt:m").access(RW | DELETE, SHARE_ALL))
        .await;
    let w = watcher.watch(root, 0xFFF).await;
    assert_eq!(a.rename(m, "::$DATA", true).await, 0);
    assert_eq!(
        watcher.events(w).await,
        heard(&[(MODIFIED_STREAM, "f.txt:m")])
    );
    let w = watcher.watch(root, 0xFFF).await;
    a.close(m).await;
    assert_eq!(watcher.events(w).await, heard(&[(MODIFIED, "f.txt")]));
    assert_eq!(files.contents("f.txt"), Some(b"BASE".to_vec()));
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
        // FILE_SUPPORTS_EXTENDED_ATTRIBUTES aside.
        assert_eq!(fs_attributes(&mut c).await & !0x0080_0000, 0x6);
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

/// A backend that stores named streams and leaves their rename at its
/// default.
struct Unrenamed(MemFsBackend);

#[async_trait]
impl ShareBackend for Unrenamed {
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

    async fn open_stream(
        &self,
        file: Box<dyn Handle>,
        path: &SmbPath,
        stream: &StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.0.open_stream(file, path, stream, opts).await
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

    let files = MemFsBackend::new().with_file("f.txt", b"");
    let state = server_on(Share::new("home", Unrenamed(files.clone())).public());
    let mut a = Client::new(&state).await;
    let s = a
        .open(
            Create::new("f.txt:s")
                .access(RW | DELETE, SHARE_ALL)
                .disposition(FILE_OPEN_IF),
        )
        .await;
    assert_eq!(
        a.rename(s, ":t", false).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert_eq!(files.stream_names("f.txt"), ["s"]);
}
