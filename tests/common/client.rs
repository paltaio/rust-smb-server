//! SMB2 client and backends for the file and query tests.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use smb_server::ntstatus::{STATUS_PENDING, STATUS_SUCCESS};
use smb_server::wire::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_RELATED_OPERATIONS,
};
use smb_server::wire::messages::{
    CloseRequest, CloseResponse, CreateRequest, CreateResponse, FileId, FileInfoClass,
    FlushRequest, InfoType, LockElement, LockRequest, LogoffRequest, QueryDirectoryRequest,
    QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse, ReadRequest, ReadResponse,
    SetInfoRequest, TreeDisconnectRequest, WriteRequest, WriteResponse,
};
use smb_server::{
    BackendCapabilities, Bytes, ConfigHandle, DirEntry, FileInfo, FileTimes, Handle,
    LocalFsBackend, OpenAction, OpenOptions, Share, ShareBackend, SmbPath, SmbResult, SmbServer,
    SmbServerBuilder,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::lease::is_break;
use super::transport::compound;
use super::{
    CLIENT_GUID, anonymous_session_setup, build_header, id_both_entries, message,
    negotiate_dialects_from, parse_response_header, read_frame, tree_connect, utf16le, write_frame,
};

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
pub const RW: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

pub const SHARE_READ: u32 = 0x1;
pub const SHARE_WRITE: u32 = 0x2;
pub const SHARE_DELETE: u32 = 0x4;
pub const SHARE_ALL: u32 = 0x7;

pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
pub const FILE_OPEN_BY_FILE_ID: u32 = 0x0000_2000;
pub const FILE_RESERVE_OPFILTER: u32 = 0x0010_0000;

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

pub const FILE_BASIC_INFORMATION: u8 = 0x04;
pub const FILE_STANDARD_INFORMATION: u8 = 0x05;
pub const FILE_INTERNAL_INFORMATION: u8 = 0x06;
pub const FILE_ACCESS_INFORMATION: u8 = 0x08;
pub const FILE_NAME_INFORMATION: u8 = 0x09;
pub const FILE_RENAME_INFORMATION: u8 = 0x0A;
pub const FILE_LINK_INFORMATION: u8 = 0x0B;
pub const FILE_DISPOSITION_INFORMATION: u8 = 0x0D;
pub const FILE_ALL_INFORMATION: u8 = 0x12;
pub const FILE_ALLOCATION_INFORMATION: u8 = 0x13;
pub const FILE_END_OF_FILE_INFORMATION: u8 = 0x14;
pub const FILE_ALTERNATE_NAME_INFORMATION: u8 = 0x15;
pub const FILE_STREAM_INFORMATION: u8 = 0x16;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 0x23;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 =
    FileInfoClass::FileIdBothDirectoryInformation as u8;
pub const FILE_SHORT_NAME_INFORMATION: u8 = 0x28;

pub const FS_VOLUME_INFORMATION: u8 = 0x01;
pub const FS_SIZE_INFORMATION: u8 = 0x03;
pub const FS_ATTRIBUTE_INFORMATION: u8 = 0x05;
pub const FS_CONTROL_INFORMATION: u8 = 0x06;
pub const FS_FULL_SIZE_INFORMATION: u8 = 0x07;
pub const FS_SECTOR_SIZE_INFORMATION: u8 = 0x0B;

pub const INFO_FILE: u8 = InfoType::File as u8;
pub const INFO_FILESYSTEM: u8 = InfoType::FileSystem as u8;
pub const INFO_SECURITY: u8 = InfoType::Security as u8;

pub const LOCK_SHARED: u32 = LockElement::FLAG_SHARED_LOCK;
pub const LOCK_EXCLUSIVE: u32 = LockElement::FLAG_EXCLUSIVE_LOCK;
pub const LOCK_UNLOCK: u32 = LockElement::FLAG_UNLOCK;
pub const LOCK_FAIL_IMMEDIATELY: u32 = LockElement::FLAG_FAIL_IMMEDIATELY;

/// A server on a loopback port with its configuration handle.
pub struct Server {
    pub addr: SocketAddr,
    pub config: ConfigHandle,
    task: JoinHandle<()>,
}

impl Server {
    pub async fn start(builder: SmbServerBuilder) -> Self {
        let (addr, config, _, task) = super::spawn_server(builder).await;
        Self { addr, config, task }
    }

    /// A server with one public share `share` on `backend`.
    pub async fn public(backend: impl ShareBackend) -> Self {
        Self::start(SmbServer::builder().share(Share::new("share", backend).public())).await
    }

    /// An anonymous client on `share`, negotiated at SMB 2.1.
    pub async fn client(&self) -> Client {
        Client::connect(self.addr, None).await
    }

    /// An anonymous client on `share`, negotiated at `dialect`.
    pub async fn client_at(&self, dialect: u16) -> Client {
        Client::connect(self.addr, Some(dialect)).await
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Status and body of a response.
pub type Reply = (u32, Vec<u8>);

/// Header and body of each response in a compound frame.
pub fn split_compound(frame: &[u8]) -> Vec<(smb_server::wire::header::Smb2Header, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = frame;
    loop {
        let (hdr, _) = parse_response_header(rest);
        let len = match hdr.next_command as usize {
            0 => rest.len(),
            next => next,
        };
        out.push((hdr, rest[64..len].to_vec()));
        if len == rest.len() {
            return out;
        }
        rest = &rest[len..];
    }
}

/// MessageId of the first response in `frame`.
fn first_mid(frame: &[u8]) -> u64 {
    parse_response_header(frame).0.message_id
}

/// MessageId and AsyncId of an interim response (MS-SMB2 3.3.4.2).
pub fn interim(frame: &[u8]) -> Option<(u64, u64)> {
    let (hdr, _) = parse_response_header(frame);
    (hdr.channel_sequence_status == STATUS_PENDING && hdr.next_command == 0)
        .then(|| Some((hdr.message_id, hdr.async_id()?)))
        .flatten()
}

/// A connected client with one session and one tree.
pub struct Client {
    pub s: TcpStream,
    pub session_id: u64,
    pub tree_id: u32,
    /// Lease break notifications that arrived while waiting for a response.
    pub breaks: VecDeque<Vec<u8>>,
    /// Response frames that arrived while waiting for another response.
    pub frames: VecDeque<Vec<u8>>,
    /// AsyncId of each request answered with an interim response, by
    /// MessageId.
    pub interims: HashMap<u64, u64>,
    next_mid: u64,
}

/// Fields of a CREATE request; `Default` opens an existing file for reading
/// and writing, sharing everything.
#[derive(Clone)]
pub struct Create<'a> {
    pub name: &'a str,
    pub oplock: u8,
    pub access: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    pub attributes: u32,
    pub contexts: Vec<u8>,
}

impl Default for Create<'_> {
    fn default() -> Self {
        Self {
            name: "",
            oplock: 0,
            access: RW,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: 0,
            attributes: 0,
            contexts: Vec::new(),
        }
    }
}

impl Create<'_> {
    /// The request body, with the name padded to 8 bytes and the contexts
    /// after it.
    pub fn body(&self) -> Vec<u8> {
        let mut name = utf16le(self.name);
        let name_length = name.len() as u16;
        name.resize(name.len().next_multiple_of(8), 0);
        let contexts_offset = if self.contexts.is_empty() {
            0
        } else {
            0x78 + name.len() as u32
        };
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: self.oplock,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: self.access,
            file_attributes: self.attributes,
            share_access: self.share,
            create_disposition: self.disposition,
            create_options: self.options,
            name_offset: 0x78,
            name_length,
            create_contexts_offset: contexts_offset,
            create_contexts_length: self.contexts.len() as u32,
            name,
            create_contexts: self.contexts.clone(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        body
    }
}

impl Client {
    pub async fn connect(addr: SocketAddr, dialect: Option<u16>) -> Self {
        Self::connect_with(addr, dialect, CLIENT_GUID, "share").await
    }

    /// An anonymous client `client_guid` on `share`, negotiated at
    /// `dialect`, or at SMB 2.1 offering 2.0.2 and 2.1.
    pub async fn connect_with(
        addr: SocketAddr,
        dialect: Option<u16>,
        client_guid: [u8; 16],
        share: &str,
    ) -> Self {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        let dialects = dialect.map_or(vec![0x0202, 0x0210], |d| vec![d]);
        negotiate_dialects_from(&mut s, &dialects, client_guid).await;
        let session_id = anonymous_session_setup(&mut s).await;
        let path = format!("\\\\127.0.0.1\\{share}");
        let tree_id = tree_connect(&mut s, &path, session_id, 3).await;
        Self::from_parts(s, session_id, tree_id)
    }

    /// A client on a connection that already has a session and a tree.
    pub fn from_parts(s: TcpStream, session_id: u64, tree_id: u32) -> Self {
        Self {
            s,
            session_id,
            tree_id,
            breaks: VecDeque::new(),
            frames: VecDeque::new(),
            interims: HashMap::new(),
            next_mid: 4,
        }
    }

    /// Sends a request on this client's session and tree. Lease breaks
    /// that arrive first are kept in [`Client::breaks`], other responses
    /// for later, and an interim response is skipped.
    pub async fn send(&mut self, command: Command, body: &[u8]) -> Reply {
        let mid = self.send_no_wait(command, body).await;
        self.recv(mid, command).await
    }

    /// Takes the next MessageId, for a request built by hand.
    pub fn take_mid(&mut self) -> u64 {
        self.next_mid += 1;
        self.next_mid - 1
    }

    /// Sends a request without reading its response; returns its
    /// MessageId.
    pub async fn send_no_wait(&mut self, command: Command, body: &[u8]) -> u64 {
        let mid = self.next_mid;
        let hdr = build_header(command, mid, self.session_id, self.tree_id);
        self.next_mid += 1;
        write_frame(&mut self.s, &hdr, body).await;
        mid
    }

    /// Sends a CANCEL for the request `mid`, naming it by `async_id` when
    /// given.
    pub async fn cancel(&mut self, mid: u64, async_id: Option<u64>) {
        let mut hdr = build_header(Command::Cancel, mid, self.session_id, self.tree_id);
        if let Some(async_id) = async_id {
            hdr.flags |= SMB2_FLAGS_ASYNC_COMMAND;
            hdr.tail = HeaderTail::async_(async_id);
        }
        write_frame(&mut self.s, &hdr, &[4, 0, 0, 0]).await;
    }

    /// Reads the next frame that is not a lease break, keeping breaks in
    /// [`Client::breaks`].
    pub async fn next_frame(&mut self) -> Vec<u8> {
        loop {
            let frame = read_frame(&mut self.s).await;
            if !is_break(&frame) {
                return frame;
            }
            self.breaks.push_back(frame);
        }
    }

    /// Reads frames until the final response to the request `mid` arrives
    /// and returns it. Interim responses are noted in
    /// [`Client::interims`]; other responses are kept for later.
    pub async fn recv_frame(&mut self, mid: u64) -> Vec<u8> {
        if let Some(at) = self.frames.iter().position(|f| first_mid(f) == mid) {
            return self.frames.remove(at).expect("position is in range");
        }
        loop {
            let frame = self.next_frame().await;
            if let Some((frame_mid, async_id)) = interim(&frame) {
                self.interims.insert(frame_mid, async_id);
                continue;
            }
            if first_mid(&frame) == mid {
                return frame;
            }
            self.frames.push_back(frame);
        }
    }

    /// Reads frames until a lease break arrives and returns it, keeping
    /// the responses read meanwhile.
    pub async fn read_break(&mut self) -> Vec<u8> {
        if let Some(frame) = self.breaks.pop_front() {
            return frame;
        }
        loop {
            let frame = read_frame(&mut self.s).await;
            if is_break(&frame) {
                return frame;
            }
            match interim(&frame) {
                Some((mid, async_id)) => {
                    self.interims.insert(mid, async_id);
                }
                None => self.frames.push_back(frame),
            }
        }
    }

    /// Reads frames until the request `mid` has an interim response and
    /// returns its AsyncId.
    pub async fn recv_interim(&mut self, mid: u64) -> u64 {
        loop {
            if let Some(async_id) = self.interims.get(&mid) {
                return *async_id;
            }
            let frame = self.next_frame().await;
            match interim(&frame) {
                Some((frame_mid, async_id)) => {
                    self.interims.insert(frame_mid, async_id);
                }
                None => self.frames.push_back(frame),
            }
        }
    }

    /// Reads the final response to the `command` request `mid`.
    pub async fn recv(&mut self, mid: u64, command: Command) -> Reply {
        let resp = self.recv_frame(mid).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, command);
        (rh.channel_sequence_status, rb.to_vec())
    }

    /// Sends `requests` as one compound frame, each marked related when
    /// its flag is set, and returns the status and body of each response.
    pub async fn send_compound(&mut self, requests: &[(Command, Vec<u8>, bool)]) -> Vec<Reply> {
        let first = self.send_compound_no_wait(requests).await;
        let frame = self.recv_frame(first).await;
        split_compound(&frame)
            .into_iter()
            .zip(requests)
            .map(|((hdr, body), (command, _, _))| {
                assert_eq!(hdr.command, *command);
                (hdr.channel_sequence_status, body)
            })
            .collect()
    }

    /// Sends `requests` as one compound frame without reading the response;
    /// returns the MessageId of the first.
    pub async fn send_compound_no_wait(&mut self, requests: &[(Command, Vec<u8>, bool)]) -> u64 {
        let first = self.next_mid;
        let messages: Vec<Vec<u8>> = requests
            .iter()
            .map(|(command, body, related)| {
                let mut hdr = build_header(*command, self.next_mid, self.session_id, self.tree_id);
                self.next_mid += 1;
                if *related {
                    hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
                }
                message(&hdr, body)
            })
            .collect();
        self.s.write_all(&compound(&messages)).await.expect("write");
        first
    }

    /// CREATE; returns the status and the raw response body.
    pub async fn create_raw(&mut self, c: Create<'_>) -> Reply {
        self.send(Command::Create, &c.body()).await
    }

    pub async fn create(&mut self, c: Create<'_>) -> Result<CreateResponse, u32> {
        let (status, rb) = self.create_raw(c).await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(CreateResponse::parse(&rb).expect("parse create"))
    }

    /// Opens an existing file with `access` and `share`; returns its FileId.
    pub async fn open(&mut self, name: &str, access: u32, share: u32) -> Result<FileId, u32> {
        self.create(Create {
            name,
            access,
            share,
            ..Create::default()
        })
        .await
        .map(|r| r.file_id)
    }

    /// Opens an existing file or directory with `access` and `options`,
    /// sharing everything; returns its FileId.
    pub async fn open_with_options(
        &mut self,
        name: &str,
        access: u32,
        options: u32,
    ) -> Result<FileId, u32> {
        self.create(Create {
            name,
            access,
            options,
            ..Create::default()
        })
        .await
        .map(|r| r.file_id)
    }

    /// Opens a directory for listing.
    pub async fn open_dir(&mut self, name: &str) -> FileId {
        self.open_with_options(name, FILE_GENERIC_READ, FILE_DIRECTORY_FILE)
            .await
            .expect("open directory")
    }

    pub async fn close_with(
        &mut self,
        file_id: FileId,
        flags: u16,
    ) -> (u32, Option<CloseResponse>) {
        let req = CloseRequest {
            structure_size: 24,
            flags,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::Close, &body).await;
        let resp = (status == STATUS_SUCCESS).then(|| CloseResponse::parse(&rb).expect("parse"));
        (status, resp)
    }

    pub async fn close(&mut self, file_id: FileId) {
        assert_eq!(self.close_with(file_id, 0).await.0, STATUS_SUCCESS);
    }

    pub async fn read_full(
        &mut self,
        file_id: FileId,
        offset: u64,
        length: u32,
        minimum_count: u32,
        channel: u32,
    ) -> Result<Vec<u8>, u32> {
        let req = ReadRequest {
            structure_size: 49,
            padding: ReadResponse::STANDARD_DATA_OFFSET,
            flags: 0,
            length,
            offset,
            file_id,
            minimum_count,
            channel,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            buffer: vec![0],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::Read, &body).await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(ReadResponse::parse(&rb).expect("parse read").data)
    }

    pub async fn read(
        &mut self,
        file_id: FileId,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, u32> {
        self.read_full(file_id, offset, length, 0, 0).await
    }

    /// WRITE with every field given. `data` follows the fixed part as is, so
    /// it holds any padding a `data_offset` above 0x70 needs.
    pub async fn write_raw(&mut self, req: WriteRequest) -> Result<u32, u32> {
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::Write, &body).await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(WriteResponse::parse(&rb).expect("parse write").count)
    }

    pub async fn write(&mut self, file_id: FileId, offset: u64, data: &[u8]) -> Result<u32, u32> {
        self.write_raw(write_request(file_id, offset, data)).await
    }

    pub async fn lock(&mut self, file_id: FileId, locks: &[(u64, u64, u32)]) -> u32 {
        let req = LockRequest {
            structure_size: 48,
            lock_count: locks.len() as u16,
            lock_sequence: 0,
            file_id,
            locks: locks
                .iter()
                .map(|&(offset, length, flags)| LockElement {
                    offset,
                    length,
                    flags,
                    reserved: 0,
                })
                .collect(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::Lock, &body).await.0
    }

    pub async fn set_info_raw(
        &mut self,
        file_id: FileId,
        info_type: u8,
        class: u8,
        buffer: Vec<u8>,
    ) -> u32 {
        let req = SetInfoRequest {
            structure_size: 33,
            info_type,
            file_information_class: class,
            buffer_length: buffer.len() as u32,
            buffer_offset: 0x60,
            reserved: 0,
            additional_information: 0,
            file_id,
            buffer,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::SetInfo, &body).await.0
    }

    pub async fn set_info(&mut self, file_id: FileId, class: u8, buffer: Vec<u8>) -> u32 {
        self.set_info_raw(file_id, 1, class, buffer).await
    }

    pub async fn set_delete(&mut self, file_id: FileId, delete: bool) -> u32 {
        self.set_info(file_id, FILE_DISPOSITION_INFORMATION, vec![delete.into()])
            .await
    }

    pub async fn flush(&mut self, file_id: FileId) -> u32 {
        let req = FlushRequest::new(file_id.persistent, file_id.volatile);
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::Flush, &body).await.0
    }

    pub async fn tree_disconnect(&mut self) -> u32 {
        let mut body = Vec::new();
        TreeDisconnectRequest::default()
            .write_to(&mut body)
            .expect("write");
        self.send(Command::TreeDisconnect, &body).await.0
    }

    pub async fn logoff(&mut self) -> u32 {
        let mut body = Vec::new();
        LogoffRequest::default().write_to(&mut body).expect("write");
        self.send(Command::Logoff, &body).await.0
    }

    /// SMB2_0_INFO_FILE QUERY_INFO for `class`; returns the output buffer.
    pub async fn query_file_info(&mut self, file_id: FileId, class: u8) -> Result<Vec<u8>, u32> {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type: 1,
            file_information_class: class,
            output_buffer_length: 4096,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        match self.send(Command::QueryInfo, &body).await {
            (0, rb) => Ok(QueryInfoResponse::parse(&rb).expect("parse").buffer),
            (status, _) => Err(status),
        }
    }

    /// QUERY_DIRECTORY; returns the status and the output buffer, empty
    /// for an error.
    pub async fn query_directory(
        &mut self,
        dir: FileId,
        class: u8,
        flags: u8,
        pattern: &str,
        output_buffer_length: u32,
    ) -> Reply {
        let pattern = utf16le(pattern);
        let req = QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: class,
            flags,
            file_index: 0,
            file_id: dir,
            file_name_offset: 64 + 32,
            file_name_length: pattern.len() as u16,
            output_buffer_length,
            file_name: pattern,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::QueryDirectory, &body).await;
        if status & 0xC000_0000 == 0xC000_0000 {
            return (status, Vec::new());
        }
        let resp = QueryDirectoryResponse::parse(&rb).expect("parse");
        (status, resp.buffer)
    }

    /// Sorted names QUERY_DIRECTORY returns for `pattern` in
    /// FileIdBothDirectoryInformation, or the status.
    pub async fn list(
        &mut self,
        dir: FileId,
        flags: u8,
        pattern: &str,
    ) -> Result<Vec<String>, u32> {
        let (status, buf) = self
            .query_directory(
                dir,
                FILE_ID_BOTH_DIRECTORY_INFORMATION,
                flags,
                pattern,
                65536,
            )
            .await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        let mut names: Vec<String> = id_both_entries(&buf).into_iter().map(|e| e.0).collect();
        names.sort();
        Ok(names)
    }

    /// QUERY_INFO; returns the status and the response body after the
    /// header.
    pub async fn query_info_raw(
        &mut self,
        file_id: FileId,
        info_type: u8,
        class: u8,
        output_buffer_length: u32,
    ) -> Reply {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type,
            file_information_class: class,
            output_buffer_length,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0x7,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::QueryInfo, &body).await
    }

    /// QUERY_INFO; returns the status and the output buffer, empty for an
    /// error.
    pub async fn query_info(
        &mut self,
        file_id: FileId,
        info_type: u8,
        class: u8,
        output_buffer_length: u32,
    ) -> Reply {
        let (status, rb) = self
            .query_info_raw(file_id, info_type, class, output_buffer_length)
            .await;
        if status & 0xC000_0000 == 0xC000_0000 {
            return (status, Vec::new());
        }
        (status, QueryInfoResponse::parse(&rb).expect("parse").buffer)
    }
}

pub fn u32_at(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

pub fn u64_at(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

/// A WRITE of `data` at `offset` with the data right after the fixed part.
pub fn write_request(file_id: FileId, offset: u64, data: &[u8]) -> WriteRequest {
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
}

/// Waits up to two seconds for `done` to hold.
pub async fn eventually(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    done()
}

pub fn local(root: &Path) -> LocalFsBackend {
    LocalFsBackend::new(root).expect("open root")
}

// ---------------------------------------------------------------------------
// Instrumented backend
// ---------------------------------------------------------------------------

/// Counters and gates shared by a [`Probe`] backend and the test.
#[derive(Default)]
pub struct Counters {
    pub opens: AtomicUsize,
    pub closes: AtomicUsize,
    pub flushes: AtomicUsize,
    pub stats: AtomicUsize,
    /// Stats after this many fail; 0 for never.
    pub fail_stats_after: AtomicUsize,
    /// When set, every open waits for a permit.
    pub open_gate: Option<Semaphore>,
    /// When set, every read waits for a permit.
    pub read_gate: Option<Semaphore>,
    /// Writes that have reached the backend.
    pub writes: AtomicUsize,
    /// When set, every write waits for a permit.
    pub write_gate: Option<Semaphore>,
}

impl Counters {
    pub fn get(n: &AtomicUsize) -> usize {
        n.load(Ordering::SeqCst)
    }
}

/// `LocalFsBackend` that counts handle calls and can hold opens and reads.
pub struct Probe {
    pub inner: LocalFsBackend,
    pub counters: Arc<Counters>,
}

impl Probe {
    pub fn new(root: &Path, counters: Counters) -> (Self, Arc<Counters>) {
        let counters = Arc::new(counters);
        let probe = Self {
            inner: local(root),
            counters: Arc::clone(&counters),
        };
        (probe, counters)
    }
}

#[async_trait::async_trait]
impl ShareBackend for Probe {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        if let Some(gate) = &self.counters.open_gate {
            gate.acquire().await.expect("gate").forget();
        }
        let (inner, action) = self.inner.open(path, opts).await?;
        self.counters.opens.fetch_add(1, Ordering::SeqCst);
        let handle = ProbeHandle {
            inner,
            counters: Arc::clone(&self.counters),
        };
        Ok((Box::new(handle), action))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.inner.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.inner.rename(from, to, replace_if_exists).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }
}

struct ProbeHandle {
    inner: Box<dyn Handle>,
    counters: Arc<Counters>,
}

#[async_trait::async_trait]
impl Handle for ProbeHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        if let Some(gate) = &self.counters.read_gate {
            gate.acquire().await.expect("gate").forget();
        }
        self.inner.read(offset, len).await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.counters.writes.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.counters.write_gate {
            gate.acquire().await.expect("gate").forget();
        }
        self.inner.write(offset, data).await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.counters.flushes.fetch_add(1, Ordering::SeqCst);
        self.inner.flush().await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let n = self.counters.stats.fetch_add(1, Ordering::SeqCst) + 1;
        let limit = self.counters.fail_stats_after.load(Ordering::SeqCst);
        if limit != 0 && n > limit {
            return Err(smb_server::SmbError::NotSupported);
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
        self.counters.closes.fetch_add(1, Ordering::SeqCst);
        self.inner.close().await
    }
}
