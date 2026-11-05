//! Extended attributes over the dispatcher, on a memory backend that
//! stores them: FileFullEaInformation queries and sets, the sizes other
//! classes and listings report, the `ExtA` create context, FILE_NEED_EA,
//! change notifications and shares that serve none.

use std::sync::Arc;
use std::time::Duration;

use crate::ea::Ea;
use crate::ntstatus;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CreateContext, CreateRequest,
    CreateResponse, Dialect, FileId, LeaseContext, QueryDirectoryRequest, QueryDirectoryResponse,
    QueryInfoRequest, QueryInfoResponse, SetInfoRequest,
};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{Peer, header, status};
use crate::{Share, SmbServer};

const READ: u32 = 0x0012_0089;
const WRITE: u32 = 0x0012_0116;
const READ_DATA: u32 = 0x0000_0001;
const READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const SHARE_ALL: u32 = 0x7;

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_NO_EA_KNOWLEDGE: u32 = 0x200;

const EA_INFORMATION: u8 = 0x07;
const FULL_EA: u8 = 0x0F;
const ALL: u8 = 0x12;
const FULL_DIRECTORY: u8 = 0x02;
const BOTH_DIRECTORY: u8 = 0x03;
const ID_FULL_DIRECTORY: u8 = 0x26;
const ID_BOTH_DIRECTORY: u8 = 0x25;
const FS_ATTRIBUTE: u8 = 0x05;

const RESTART_SCAN: u32 = 0x1;
const SINGLE: u32 = 0x2;
const INDEX: u32 = 0x4;

const FILE_SUPPORTS_EXTENDED_ATTRIBUTES: u32 = 0x0080_0000;
const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x4;
const FILE_NOTIFY_CHANGE_EA: u32 = 0x80;
const FILE_ACTION_ADDED: u32 = 1;
const FILE_ACTION_REMOVED: u32 = 2;
const FILE_ACTION_MODIFIED: u32 = 3;

/// One FILE_FULL_EA_INFORMATION entry, unpadded, NextEntryOffset `next`.
fn full_entry(next: u32, flags: u8, name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = next.to_le_bytes().to_vec();
    out.push(flags);
    out.push(name.len() as u8);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.extend_from_slice(value);
    out
}

/// A FILE_FULL_EA_INFORMATION list of `(name, value)`, entries padded to 4
/// bytes but the last.
fn full_list(eas: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (at, (name, value)) in eas.iter().enumerate() {
        let len = 8 + name.len() + 1 + value.len();
        let next = if at + 1 == eas.len() {
            0
        } else {
            len.next_multiple_of(4) as u32
        };
        let start = out.len();
        out.extend_from_slice(&full_entry(next, 0, name, value));
        if next != 0 {
            out.resize(start + next as usize, 0);
        }
    }
    out
}

/// A FILE_GET_EA_INFORMATION list of `names`.
fn get_list(names: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for (at, name) in names.iter().enumerate() {
        let len = 5 + name.len() + 1;
        let next = if at + 1 == names.len() {
            0
        } else {
            len.next_multiple_of(4) as u32
        };
        let start = out.len();
        out.extend_from_slice(&next.to_le_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        if next != 0 {
            out.resize(start + next as usize, 0);
        }
    }
    out
}

/// The names, flags and values of a FILE_FULL_EA_INFORMATION list,
/// checking that each entry but the last is padded to 4 bytes.
fn parse_list(buf: &[u8]) -> Vec<(String, u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let next = u32_at(buf, at) as usize;
        let name_len = buf[at + 5] as usize;
        let value_len = u16::from_le_bytes([buf[at + 6], buf[at + 7]]) as usize;
        let name = &buf[at + 8..at + 8 + name_len];
        assert_eq!(buf[at + 8 + name_len], 0, "a NUL after the name");
        let value = &buf[at + 9 + name_len..at + 9 + name_len + value_len];
        out.push((
            String::from_utf8(name.to_vec()).unwrap(),
            buf[at + 4],
            value.to_vec(),
        ));
        let len = 9 + name_len + value_len;
        if next == 0 {
            assert_eq!(at + len, buf.len(), "the last entry is not padded");
            return out;
        }
        assert_eq!(next, len.next_multiple_of(4));
        at += next;
    }
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

fn names(listed: &[(String, u8, Vec<u8>)]) -> Vec<&str> {
    listed.iter().map(|(name, _, _)| name.as_str()).collect()
}

/// A CREATE request.
#[derive(Clone)]
struct Create<'a> {
    name: &'a str,
    access: u32,
    disposition: u32,
    options: u32,
    exta: Option<Vec<u8>>,
    /// The key of a read, write and handle caching lease to ask for.
    lease: Option<[u8; 16]>,
}

impl<'a> Create<'a> {
    fn new(name: &'a str) -> Self {
        Self {
            name,
            access: READ | WRITE,
            disposition: FILE_OPEN,
            options: 0,
            exta: None,
            lease: None,
        }
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

    fn exta(self, data: Vec<u8>) -> Self {
        Self {
            exta: Some(data),
            ..self
        }
    }

    fn body(&self) -> Vec<u8> {
        let name = crate::utils::utf16le(self.name);
        let mut padded = name.clone();
        padded.resize(padded.len().next_multiple_of(8), 0);
        let mut list = Vec::new();
        if let Some(data) = &self.exta {
            list.push(CreateContext {
                name: CreateContext::NAME_EXTA.to_vec(),
                data: data.clone(),
            });
        }
        if let Some(key) = self.lease {
            list.push(CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data: LeaseContext {
                    key,
                    state: 0x7,
                    ..LeaseContext::default()
                }
                .encode(),
            });
        }
        let mut contexts = Vec::new();
        if !list.is_empty() {
            CreateContext::encode_chain(&list, &mut contexts).expect("contexts");
        }
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
            share_access: SHARE_ALL,
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

/// A FileFullEaInformation query.
struct Query<'a> {
    names: &'a [&'a str],
    flags: u32,
    index: u32,
    len: u32,
}

impl Default for Query<'_> {
    fn default() -> Self {
        Self {
            names: &[],
            flags: 0,
            index: 0,
            len: 4096,
        }
    }
}

/// One connection to the share `home` of `state`.
struct Client {
    peer: Peer,
    state: Arc<ServerState>,
}

impl Client {
    async fn new(state: &Arc<ServerState>) -> Self {
        Self {
            peer: Peer::new(state, false).await,
            state: Arc::clone(state),
        }
    }

    async fn send(&mut self, command: Command, body: &[u8]) -> (u32, Vec<u8>) {
        let (_, reply) = self.peer.request(&self.state, command, body).await;
        (status(&reply), reply[SMB2_HEADER_LEN..].to_vec())
    }

    async fn create(&mut self, create: Create<'_>) -> Result<FileId, u32> {
        match self.send(Command::Create, &create.body()).await {
            (0, body) => Ok(CreateResponse::parse(&body).expect("response").file_id),
            (status, _) => Err(status),
        }
    }

    async fn open(&mut self, create: Create<'_>) -> FileId {
        let name = create.name;
        match self.create(create).await {
            Ok(id) => id,
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

    async fn set_eas(&mut self, file_id: FileId, buffer: Vec<u8>) -> u32 {
        let mut body = Vec::new();
        SetInfoRequest {
            structure_size: 33,
            info_type: 1,
            file_information_class: FULL_EA,
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

    async fn query_info(
        &mut self,
        file_id: FileId,
        info_type: u8,
        class: u8,
        query: Query<'_>,
    ) -> (u32, Vec<u8>) {
        let input = if query.names.is_empty() {
            Vec::new()
        } else {
            get_list(query.names)
        };
        let mut body = Vec::new();
        QueryInfoRequest {
            structure_size: 41,
            info_type,
            file_information_class: class,
            output_buffer_length: query.len,
            input_buffer_offset: if input.is_empty() { 0 } else { 0x68 },
            reserved: 0,
            input_buffer_length: input.len() as u32,
            additional_information: query.index,
            flags: query.flags,
            file_id,
            input_buffer: input,
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

    async fn query(&mut self, file_id: FileId, query: Query<'_>) -> (u32, Vec<u8>) {
        self.query_info(file_id, 1, FULL_EA, query).await
    }

    /// A FileFullEaInformation query's status and response body.
    async fn query_raw(&mut self, file_id: FileId, query: Query<'_>) -> (u32, Vec<u8>) {
        let mut body = Vec::new();
        QueryInfoRequest {
            structure_size: 41,
            info_type: 1,
            file_information_class: FULL_EA,
            output_buffer_length: query.len,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: query.index,
            flags: query.flags,
            file_id,
            input_buffer: Vec::new(),
        }
        .write_to(&mut body)
        .expect("query info");
        self.send(Command::QueryInfo, &body).await
    }

    /// Every extended attribute of `file_id`, from the first.
    async fn all(&mut self, file_id: FileId) -> Vec<(String, u8, Vec<u8>)> {
        let restart = Query {
            flags: RESTART_SCAN,
            len: 65536,
            ..Query::default()
        };
        match self.query(file_id, restart).await {
            (0, buf) => parse_list(&buf),
            (ntstatus::STATUS_NO_EAS_ON_FILE, _) => Vec::new(),
            (status, _) => panic!("query: {status:#x}"),
        }
    }

    async fn info(&mut self, file_id: FileId, info_type: u8, class: u8) -> Vec<u8> {
        let (status, buf) = self
            .query_info(file_id, info_type, class, Query::default())
            .await;
        assert_eq!(status, 0, "class {class}");
        buf
    }

    /// The EaSize of each entry of a listing of `dir` in `class`.
    async fn listed_ea_sizes(&mut self, dir: FileId, class: u8) -> Vec<(String, u32)> {
        let mut body = Vec::new();
        QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: class,
            flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
            file_index: 0,
            file_id: dir,
            file_name_offset: 0x60,
            file_name_length: 2,
            output_buffer_length: 65536,
            file_name: crate::utils::utf16le("*"),
        }
        .write_to(&mut body)
        .expect("query directory");
        let (status, body) = self.send(Command::QueryDirectory, &body).await;
        assert_eq!(status, 0);
        let buf = QueryDirectoryResponse::parse(&body)
            .expect("response")
            .buffer;
        let (ea_at, name_at) = match class {
            FULL_DIRECTORY => (64, 68),
            BOTH_DIRECTORY => (64, 94),
            ID_FULL_DIRECTORY => (64, 80),
            _ => (64, 104),
        };
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let len = u32_at(&buf, at + 60) as usize;
            let units: Vec<u16> = buf[at + name_at..at + name_at + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push((
                String::from_utf16(&units).unwrap(),
                u32_at(&buf, at + ea_at),
            ));
            let next = u32_at(&buf, at) as usize;
            if next == 0 {
                return out;
            }
            at += next;
        }
    }

    /// Sends a CHANGE_NOTIFY on `dir` for `filter`, which has to wait.
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

    /// The actions and names the CHANGE_NOTIFY `async_id` reports.
    async fn changes(&mut self, async_id: u64) -> Vec<(u32, String)> {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.peer.next())
            .await
            .expect("a final response in time");
        assert_eq!(header(&frame).async_id(), Some(async_id));
        assert_eq!(status(&frame), 0);
        let buf = ChangeNotifyResponse::parse(&frame[SMB2_HEADER_LEN..])
            .expect("notify response")
            .buffer;
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let len = u32_at(&buf, at + 8) as usize;
            let units: Vec<u16> = buf[at + 12..at + 12 + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push((u32_at(&buf, at + 4), String::from_utf16(&units).unwrap()));
            match u32_at(&buf, at) as usize {
                0 => return out,
                next => at += next,
            }
        }
    }

    /// Asserts that nothing arrives on the connection for a while.
    async fn quiet(&mut self) {
        let early = tokio::time::timeout(Duration::from_millis(200), self.peer.next()).await;
        assert!(early.is_err(), "unexpected {:?}", early.map(|f| header(&f)));
    }
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
fn server(files: &MemFsBackend) -> Arc<ServerState> {
    let files = files.clone().with_file("f.txt", b"data").with_dir("d");
    server_on(Share::new("home", files).public())
}

#[tokio::test]
async fn set_attributes_list_back_with_their_sizes_everywhere() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    assert_eq!(c.all(f).await, []);
    assert_eq!(
        c.query(f, Query::default()).await.0,
        ntstatus::STATUS_NO_EAS_ON_FILE
    );
    assert_eq!(c.info(f, 1, EA_INFORMATION).await, 0u32.to_le_bytes());

    let set = full_list(&[("test", b"hello"), ("Big", &[7; 301])]);
    assert_eq!(c.set_eas(f, set.clone()).await, 0);
    let (status, listed) = c.query(f, Query::default()).await;
    assert_eq!(status, 0);
    assert_eq!(listed, set);
    // Each entry padded, the last too: 18 to 20, 313 to 316.
    let size: u32 = 20 + 316;
    assert_eq!(c.info(f, 1, EA_INFORMATION).await, size.to_le_bytes());
    let all = c.info(f, 1, ALL).await;
    assert_eq!(u32_at(&all, 72), size, "FileAllInformation EaSize");
    // An open of a named stream reports the file's.
    let s = c
        .open(Create::new("f.txt:s").disposition(FILE_OPEN_IF))
        .await;
    assert_eq!(c.info(s, 1, EA_INFORMATION).await, size.to_le_bytes());

    let root = c
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    for class in [
        FULL_DIRECTORY,
        BOTH_DIRECTORY,
        ID_BOTH_DIRECTORY,
        ID_FULL_DIRECTORY,
    ] {
        let listed = c.listed_ea_sizes(root, class).await;
        assert!(listed.contains(&("f.txt".to_string(), size)), "{listed:?}");
        assert!(listed.contains(&("d".to_string(), 0)), "{listed:?}");
    }
    let attributes = u32_at(&c.info(root, 2, FS_ATTRIBUTE).await, 0);
    assert_eq!(
        attributes & FILE_SUPPORTS_EXTENDED_ATTRIBUTES,
        FILE_SUPPORTS_EXTENDED_ATTRIBUTES
    );
}

#[tokio::test]
async fn names_compare_without_case_and_keep_the_stored_spelling() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    let set = full_list(&[("Alpha", b"1"), ("beta", b"22"), ("Gamma", b"333")]);
    assert_eq!(c.set_eas(f, set).await, 0);
    assert_eq!(c.set_eas(f, full_list(&[("ALPHA", b"one")])).await, 0);
    let listed = c.all(f).await;
    assert_eq!(names(&listed), ["Alpha", "beta", "Gamma"]);
    assert_eq!(listed[0].2, b"one");

    // Names that the file does not have come back with empty values.
    let (status, buf) = c
        .query(
            f,
            Query {
                names: &["GAMMA", "missing", "Beta"],
                ..Query::default()
            },
        )
        .await;
    assert_eq!(status, 0);
    let asked = parse_list(&buf);
    assert_eq!(names(&asked), ["Gamma", "missing", "beta"]);
    assert_eq!(asked[1].2, b"");
    assert_eq!(asked[2].2, b"22");

    // An empty value removes the attribute, under any spelling; removing
    // a name the file does not have changes nothing.
    assert_eq!(
        c.set_eas(f, full_list(&[("BETA", b""), ("nope", b"")]))
            .await,
        0
    );
    assert_eq!(names(&c.all(f).await), ["Alpha", "Gamma"]);
    assert_eq!(
        c.set_eas(f, full_list(&[("alpha", b""), ("gamma", b"")]))
            .await,
        0
    );
    assert_eq!(
        c.query(f, Query::default()).await.0,
        ntstatus::STATUS_NO_EAS_ON_FILE
    );
    assert!(files.eas("f.txt").is_empty());
}

#[tokio::test]
async fn queries_step_through_the_attributes_from_the_open_index() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    let set = full_list(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);
    assert_eq!(c.set_eas(f, set).await, 0);

    let single = |flags| Query {
        flags,
        ..Query::default()
    };
    let one = |buf: &[u8]| names(&parse_list(buf)).concat();
    let (status, buf) = c.query(f, single(RESTART_SCAN | SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "a".to_string()));
    let (status, buf) = c.query(f, single(SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "b".to_string()));
    // Without SL_RETURN_SINGLE_ENTRY, the rest.
    let (status, buf) = c.query(f, single(0)).await;
    assert_eq!((status, one(&buf)), (0, "c".to_string()));
    assert_eq!(c.query(f, single(0)).await.0, ntstatus::STATUS_NO_MORE_EAS);
    assert_eq!(
        c.query(f, single(SINGLE)).await.0,
        ntstatus::STATUS_NO_MORE_EAS
    );

    // An index picks the entry and moves the open's place past it.
    let at = |index| Query {
        flags: INDEX | RESTART_SCAN | SINGLE,
        index,
        ..Query::default()
    };
    let (status, buf) = c.query(f, at(2)).await;
    assert_eq!((status, one(&buf)), (0, "b".to_string()));
    let (status, buf) = c.query(f, single(SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "c".to_string()));
    assert_eq!(c.query(f, at(4)).await.0, ntstatus::STATUS_NO_MORE_EAS);
    for index in [0, 5] {
        assert_eq!(
            c.query(f, at(index)).await.0,
            ntstatus::STATUS_NONEXISTENT_EA_ENTRY,
            "index {index}"
        );
    }
    // An index wins over a restart.
    let (status, buf) = c.query(f, at(3)).await;
    assert_eq!((status, one(&buf)), (0, "c".to_string()));

    // Each open has its own place.
    let g = c.open(Create::new("f.txt")).await;
    let (status, buf) = c.query(g, single(SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "a".to_string()));

    // A set through any open leaves every open that carries on from its
    // place with a corrupt list until it restarts.
    assert_eq!(c.set_eas(f, full_list(&[("d", b"4")])).await, 0);
    for id in [f, g] {
        assert_eq!(
            c.query(id, single(SINGLE)).await.0,
            ntstatus::STATUS_EA_CORRUPT_ERROR
        );
    }
    let (status, buf) = c.query(g, single(RESTART_SCAN | SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "a".to_string()));
    let (status, buf) = c.query(g, single(SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "b".to_string()));
    // A new open, and one that never queried, start at the first.
    let h = c.open(Create::new("f.txt")).await;
    assert_eq!(c.set_eas(f, full_list(&[("d", b"")])).await, 0);
    let (status, buf) = c.query(h, single(SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "a".to_string()));
    // A failed set changes nothing, and is not counted.
    assert_eq!(
        c.set_eas(f, full_list(&[("e", b"5"), ("f*", b"6")])).await,
        ntstatus::STATUS_INVALID_EA_NAME
    );
    let (status, buf) = c.query(h, single(SINGLE)).await;
    assert_eq!((status, one(&buf)), (0, "b".to_string()));
}

#[tokio::test]
async fn a_short_buffer_gets_the_whole_entries_that_fit() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    let set = full_list(&[("one", b"11111"), ("two", b"2")]);
    assert_eq!(c.set_eas(f, set.clone()).await, 0);
    let first = 8 + 4 + 5;

    let sized = |len| Query {
        flags: RESTART_SCAN,
        len,
        ..Query::default()
    };
    let (status, body) = c.query_raw(f, sized(first - 1)).await;
    assert_eq!(status, ntstatus::STATUS_BUFFER_TOO_SMALL);
    // ByteCount 4 and a required length of 0.
    assert_eq!(body, [9, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
    // Names that do not all fit give nothing.
    let listed = Query {
        names: &["one", "two"],
        len: set.len() as u32 - 1,
        ..Query::default()
    };
    assert_eq!(
        c.query(f, listed).await,
        (ntstatus::STATUS_BUFFER_OVERFLOW, Vec::new())
    );
    for len in [first, set.len() as u32 - 1] {
        let (status, buf) = c.query(f, sized(len)).await;
        assert_eq!(status, ntstatus::STATUS_BUFFER_OVERFLOW, "{len}");
        assert_eq!(buf, full_list(&[("one", b"11111")]));
    }
    // The open's place moved past what was returned.
    let (status, buf) = c.query(f, Query::default()).await;
    assert_eq!((status, buf), (0, full_list(&[("two", b"2")])));
    let (status, buf) = c.query(f, sized(set.len() as u32)).await;
    assert_eq!((status, buf), (0, set));
}

#[tokio::test]
async fn a_set_applies_whole_or_not_at_all() {
    let files = MemFsBackend::new().with_ea_room(400);
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    assert_eq!(c.set_eas(f, full_list(&[("keep", b"v")])).await, 0);

    let refused = [
        (
            full_list(&[("new", b"x"), ("a*b", b"y")]),
            ntstatus::STATUS_INVALID_EA_NAME,
        ),
        (
            full_entry(0, 0x01, "new", b"x"),
            ntstatus::STATUS_INVALID_EA_NAME,
        ),
        (
            full_entry(0, 0, "new", b"x")[..12].to_vec(),
            ntstatus::STATUS_EA_LIST_INCONSISTENT,
        ),
        (
            full_entry(28, 0, "new", b"x"),
            ntstatus::STATUS_EA_LIST_INCONSISTENT,
        ),
        // Past the room the backend has.
        (
            full_list(&[("keep", b""), ("new", &[1; 400])]),
            ntstatus::STATUS_EA_TOO_LARGE,
        ),
    ];
    for (buffer, expected) in refused {
        assert_eq!(c.set_eas(f, buffer).await, expected);
        assert_eq!(files.eas("f.txt"), [Ea::new("keep", b"v".to_vec())]);
    }
}

#[tokio::test]
async fn the_list_limit_counts_what_the_file_ends_up_with() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    // 5 + 1 + 65525 = 65531 bytes.
    assert_eq!(c.set_eas(f, full_list(&[("a", &[1; 65525])])).await, 0);
    assert_eq!(
        c.set_eas(f, full_list(&[("b", b"x")])).await,
        ntstatus::STATUS_EA_TOO_LARGE
    );
    assert_eq!(names(&c.all(f).await), ["a"]);
    // Replacing the large one frees its room in the same set.
    assert_eq!(
        c.set_eas(f, full_list(&[("A", b""), ("b", &[2; 1000])]))
            .await,
        0
    );
    assert_eq!(names(&c.all(f).await), ["b"]);
}

#[tokio::test]
async fn reading_and_writing_attributes_need_their_own_access() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    assert_eq!(c.set_eas(f, full_list(&[("n", b"v")])).await, 0);

    let no_read = c
        .open(Create::new("f.txt").access(READ_DATA | READ_ATTRIBUTES | FILE_WRITE_EA))
        .await;
    assert_eq!(
        c.query(no_read, Query::default()).await.0,
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert_eq!(c.set_eas(no_read, full_list(&[("m", b"w")])).await, 0);
    let no_write = c
        .open(Create::new("f.txt").access(READ_DATA | FILE_READ_EA))
        .await;
    assert_eq!(
        c.set_eas(no_write, full_list(&[("o", b"x")])).await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert_eq!(names(&c.all(no_write).await), ["n", "m"]);
}

#[tokio::test]
async fn an_open_of_a_named_stream_has_no_attributes_of_its_own() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let s = c
        .open(Create::new("f.txt:s").disposition(FILE_OPEN_IF))
        .await;
    assert_eq!(
        c.set_eas(s, full_list(&[("n", b"v")])).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        c.query(s, Query::default()).await.0,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert!(files.eas("f.txt").is_empty());
}

#[tokio::test]
async fn a_create_context_gives_a_new_file_its_attributes() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let exta = full_list(&[("Made", b"new"), ("gone", b""), ("made", b"last")]);
    let f = c
        .open(Create::new("new.txt").disposition(FILE_CREATE).exta(exta))
        .await;
    // A name listed twice takes the last value and spelling.
    assert_eq!(c.all(f).await, [("made".to_string(), 0, b"last".to_vec())]);
    c.close(f).await;

    // An open of an existing file ignores the context.
    let f = c
        .open(
            Create::new("new.txt")
                .disposition(FILE_OPEN_IF)
                .exta(full_list(&[("other", b"x")])),
        )
        .await;
    assert_eq!(names(&c.all(f).await), ["made"]);
    c.close(f).await;

    let d = c
        .open(
            Create::new("dir")
                .disposition(FILE_CREATE)
                .options(FILE_DIRECTORY_FILE)
                .access(READ)
                .exta(full_list(&[("onDir", b"1")])),
        )
        .await;
    assert_eq!(names(&c.all(d).await), ["onDir"]);
    let empty = c
        .open(
            Create::new("empty.txt")
                .disposition(FILE_CREATE)
                .exta(Vec::new()),
        )
        .await;
    assert_eq!(c.all(empty).await, []);

    for (create, expected) in [
        (
            Create::new("bad.txt").exta(full_list(&[("a?", b"x")])),
            ntstatus::STATUS_INVALID_EA_NAME,
        ),
        (
            Create::new("bad.txt").exta(full_entry(0, 0, "n", b"v")[..9].to_vec()),
            ntstatus::STATUS_EA_LIST_INCONSISTENT,
        ),
        (
            Create::new("bad.txt")
                .options(FILE_NO_EA_KNOWLEDGE)
                .exta(full_list(&[("n", b"v")])),
            ntstatus::STATUS_ACCESS_DENIED,
        ),
        (
            Create::new("bad.txt").exta(full_list(&[("n", &[0; 65526])])),
            ntstatus::STATUS_EA_TOO_LARGE,
        ),
    ] {
        let create = create.disposition(FILE_CREATE);
        assert_eq!(c.create(create).await.err(), Some(expected));
    }
    assert_eq!(files.contents("bad.txt"), None);
}

#[tokio::test]
async fn an_overwrite_replaces_the_attributes_of_the_file() {
    let files = MemFsBackend::new()
        .with_file("o.txt", b"data")
        .with_ea("o.txt", Ea::new("Old", b"1".to_vec()))
        .with_ea("o.txt", Ea::new("Kept", b"2".to_vec()));
    let state = server(&files);
    let mut c = Client::new(&state).await;
    for disposition in [FILE_OVERWRITE_IF, FILE_OVERWRITE, FILE_SUPERSEDE] {
        let f = c
            .open(
                Create::new("o.txt")
                    .disposition(disposition)
                    .exta(full_list(&[("kept", b"3"), ("New", b"4")])),
            )
            .await;
        let listed = c.all(f).await;
        assert_eq!(names(&listed), ["Kept", "New"], "{disposition}");
        assert_eq!(listed[0].2, b"3");
        c.close(f).await;
    }
    // Without the context, an overwrite leaves none.
    let f = c
        .open(Create::new("o.txt").disposition(FILE_OVERWRITE_IF))
        .await;
    assert_eq!(c.all(f).await, []);
}

#[tokio::test]
async fn a_create_context_on_a_named_stream_leaves_the_file_alone() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let exta = full_list(&[("n", b"v")]);
    for disposition in [FILE_CREATE, FILE_OPEN_IF] {
        let s = c
            .open(
                Create::new("f.txt:s")
                    .disposition(disposition)
                    .exta(exta.clone()),
            )
            .await;
        c.close(s).await;
    }
    assert_eq!(
        c.create(
            Create::new("f.txt:s")
                .disposition(FILE_OVERWRITE_IF)
                .exta(exta)
        )
        .await
        .err(),
        Some(ntstatus::STATUS_INVALID_PARAMETER)
    );
    assert!(files.eas("f.txt").is_empty());
}

#[tokio::test]
async fn files_that_need_attributes_refuse_opens_that_do_not_know_them() {
    let mut needed = Ea::new("Needed", b"x".to_vec());
    needed.needed = true;
    let files = MemFsBackend::new()
        .with_file("n.txt", b"data")
        .with_ea("n.txt", needed)
        .with_file("plain.txt", b"data")
        .with_ea("plain.txt", Ea::new("Plain", b"y".to_vec()));
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let blind = |name| Create::new(name).options(FILE_NO_EA_KNOWLEDGE);
    assert_eq!(
        c.create(blind("n.txt")).await.err(),
        Some(ntstatus::STATUS_ACCESS_DENIED)
    );
    // Overwriting it is refused before the file changes.
    assert_eq!(
        c.create(blind("n.txt").disposition(FILE_OVERWRITE_IF))
            .await
            .err(),
        Some(ntstatus::STATUS_ACCESS_DENIED)
    );
    assert_eq!(files.contents("n.txt").as_deref(), Some(&b"data"[..]));
    // A named stream of it is not the file.
    let s = c.open(blind("n.txt:s").disposition(FILE_OPEN_IF)).await;
    c.close(s).await;
    let plain = c.open(blind("plain.txt")).await;
    c.close(plain).await;

    let f = c.open(Create::new("n.txt")).await;
    assert_eq!(
        c.all(f).await,
        [("Needed".to_string(), 0x80, b"x".to_vec())]
    );
}

#[tokio::test]
async fn a_set_is_reported_when_the_open_that_set_it_closes() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let mut w = Client::new(&state).await;
    let root = w
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    for filter in [FILE_NOTIFY_CHANGE_EA, FILE_NOTIFY_CHANGE_ATTRIBUTES] {
        let watch = w.watch(root, filter).await;
        let f = c.open(Create::new("f.txt")).await;
        assert_eq!(c.set_eas(f, full_list(&[("n", b"v")])).await, 0);
        w.quiet().await;
        c.close(f).await;
        assert_eq!(
            w.changes(watch).await,
            [(FILE_ACTION_MODIFIED, "f.txt".to_string())]
        );
    }
}

#[tokio::test]
async fn a_share_without_extended_attributes_has_none() {
    let files = MemFsBackend::new()
        .with_file("f.txt", b"data")
        .with_ea("f.txt", Ea::new("Kept", b"v".to_vec()));
    let state = server_on(
        Share::new("home", files.clone())
            .public()
            .extended_attributes(false),
    );
    has_none(&state).await;
    assert_eq!(files.eas("f.txt"), [Ea::new("Kept", b"v".to_vec())]);
    let state = server_on(Share::new("home", files.clone().without_eas()).public());
    has_none(&state).await;
    // A stream name on a share with neither streams nor extended
    // attributes fails on the attributes.
    let neither = MemFsBackend::new()
        .with_file("f.txt", b"data")
        .without_streams()
        .without_eas();
    has_none(&server_on(Share::new("home", neither).public())).await;
}

/// Checks that the share `home` of `state`, whose `f.txt` the backend
/// gave an extended attribute, serves none.
async fn has_none(state: &Arc<ServerState>) {
    let mut c = Client::new(state).await;
    let f = c.open(Create::new("f.txt")).await;
    let refused = ntstatus::STATUS_INVALID_DEVICE_REQUEST;
    assert_eq!(c.query(f, Query::default()).await.0, refused);
    assert_eq!(c.info(f, 1, EA_INFORMATION).await, 0u32.to_le_bytes());
    assert_eq!(c.set_eas(f, full_list(&[("n", b"v")])).await, refused);
    assert_eq!(c.set_eas(f, full_list(&[("a*b", b"v")])).await, refused);
    // The list is read before.
    assert_eq!(
        c.set_eas(f, full_entry(0, 0, "n", b"v")[..9].to_vec())
            .await,
        ntstatus::STATUS_EA_LIST_INCONSISTENT
    );
    let root = c
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let listed = c.listed_ea_sizes(root, FULL_DIRECTORY).await;
    assert!(listed.contains(&("f.txt".to_string(), 0)), "{listed:?}");
    assert_eq!(
        u32_at(&c.info(root, 2, FS_ATTRIBUTE).await, 0) & FILE_SUPPORTS_EXTENDED_ATTRIBUTES,
        0
    );
    for create in [
        Create::new("new.txt").disposition(FILE_CREATE),
        Create::new("f.txt"),
        Create::new("f.txt:s").disposition(FILE_OPEN_IF),
    ] {
        let create = create.exta(full_list(&[("n", b"v")]));
        assert_eq!(
            c.create(create).await.err(),
            Some(ntstatus::STATUS_EAS_NOT_SUPPORTED)
        );
    }
    // An empty context carries none.
    let empty = Create::new("empty.txt")
        .disposition(FILE_OPEN_IF)
        .exta(Vec::new());
    let id = c.open(empty).await;
    c.close(id).await;
}

#[tokio::test]
async fn a_share_without_named_streams_keeps_extended_attributes() {
    let files = MemFsBackend::new().with_file("f.txt", b"data");
    let state = server_on(Share::new("home", files).public().named_streams(false));
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    assert_eq!(c.set_eas(f, full_list(&[("n", b"v")])).await, 0);
    assert_eq!(names(&c.all(f).await), ["n"]);
}

#[tokio::test]
async fn a_short_buffer_on_smb_311_carries_its_length_in_an_error_context() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    *c.peer.conn.dialect.write().await = Some(Dialect::Smb311);
    let f = c.open(Create::new("f.txt")).await;
    assert_eq!(c.set_eas(f, full_list(&[("n", b"value")])).await, 0);
    let small = Query {
        flags: RESTART_SCAN,
        len: 4,
        ..Query::default()
    };
    let (status, body) = c.query_raw(f, small).await;
    assert_eq!(status, ntstatus::STATUS_BUFFER_TOO_SMALL);
    // ErrorContextCount 1, ByteCount 12, then ErrorDataLength 4, ErrorId
    // 0 and a required length of 0.
    assert_eq!(
        body,
        [9, 0, 1, 0, 12, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[tokio::test]
async fn a_failed_set_is_not_reported() {
    let files = MemFsBackend::new().with_ea_room(64);
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let mut w = Client::new(&state).await;
    let root = w
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let watch = w.watch(root, FILE_NOTIFY_CHANGE_EA).await;
    let f = c.open(Create::new("f.txt")).await;
    for refused in [full_list(&[("a?", b"v")]), full_list(&[("big", &[0; 100])])] {
        assert_ne!(c.set_eas(f, refused).await, 0);
    }
    c.close(f).await;
    w.quiet().await;
    // A change that follows is the first the watch hears.
    let f = c.open(Create::new("f.txt")).await;
    assert_eq!(c.set_eas(f, full_list(&[("n", b"v")])).await, 0);
    c.close(f).await;
    assert_eq!(
        w.changes(watch).await,
        [(FILE_ACTION_MODIFIED, "f.txt".to_string())]
    );
}

#[tokio::test]
async fn an_overwrite_whose_attributes_do_not_fit_leaves_the_file_as_it_was() {
    let files = MemFsBackend::new()
        .with_file("o.txt", b"contents")
        .with_stream("o.txt", "s", b"stream")
        .with_ea("o.txt", Ea::new("Old", b"1".to_vec()))
        .with_ea_room(64);
    let state = server(&files);
    let mut c = Client::new(&state).await;
    for disposition in [FILE_OVERWRITE_IF, FILE_OVERWRITE, FILE_SUPERSEDE] {
        let create = Create::new("o.txt")
            .disposition(disposition)
            .exta(full_list(&[("new", &[0; 100])]));
        assert_eq!(
            c.create(create).await.err(),
            Some(ntstatus::STATUS_EA_TOO_LARGE),
            "{disposition}"
        );
        assert_eq!(files.contents("o.txt").as_deref(), Some(&b"contents"[..]));
        assert_eq!(files.stream_names("o.txt"), ["s"]);
        assert_eq!(files.eas("o.txt"), [Ea::new("Old", b"1".to_vec())]);
    }
}

#[tokio::test]
async fn an_overwrite_reports_the_attributes_it_removed_at_once() {
    let files = MemFsBackend::new()
        .with_file("o.txt", b"data")
        .with_ea("o.txt", Ea::new("Old", b"1".to_vec()))
        .with_file("plain.txt", b"data");
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let mut w = Client::new(&state).await;
    let root = w
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let watch = w.watch(root, FILE_NOTIFY_CHANGE_EA).await;
    // A file without attributes changes none.
    let plain = c
        .open(Create::new("plain.txt").disposition(FILE_OVERWRITE_IF))
        .await;
    c.close(plain).await;
    w.quiet().await;
    let o = c
        .open(Create::new("o.txt").disposition(FILE_OVERWRITE_IF))
        .await;
    assert_eq!(
        w.changes(watch).await,
        [(FILE_ACTION_MODIFIED, "o.txt".to_string())]
    );
    // Nothing more comes when the open closes.
    w.watch(root, FILE_NOTIFY_CHANGE_EA).await;
    c.close(o).await;
    w.quiet().await;
}

#[tokio::test]
async fn a_new_file_whose_attributes_fail_is_reported_gone() {
    let files = MemFsBackend::new().with_ea_room(16);
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let mut w = Client::new(&state).await;
    let root = w
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let watch = w.watch(root, 0x1).await;
    let create = Create::new("big.txt")
        .disposition(FILE_CREATE)
        .exta(full_list(&[("n", &[0; 100])]));
    assert_eq!(
        c.create(create).await.err(),
        Some(ntstatus::STATUS_EA_TOO_LARGE)
    );
    assert_eq!(files.contents("big.txt"), None);
    let mut events = w.changes(watch).await;
    if events.len() == 1 {
        let watch = w.watch(root, 0x1).await;
        events.extend(w.changes(watch).await);
    }
    assert_eq!(
        events,
        [
            (FILE_ACTION_ADDED, "big.txt".to_string()),
            (FILE_ACTION_REMOVED, "big.txt".to_string()),
        ]
    );
}

#[tokio::test]
async fn a_create_that_waits_for_a_lease_break_sets_its_attributes_once() {
    let files = MemFsBackend::new().with_file("x.txt", b"old");
    let state = server(&files);
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    let leased = b
        .open(Create {
            lease: Some([0xB0; 16]),
            ..Create::new("x.txt")
        })
        .await;
    // The file goes outside the server; the lease on its name stays.
    files.remove("x.txt");
    let create = Create {
        lease: Some([0xA0; 16]),
        ..Create::new("x.txt")
            .disposition(FILE_CREATE)
            .exta(full_list(&[("n", b"v")]))
    };
    let (_, interim) = a
        .peer
        .request(&a.state, Command::Create, &create.body())
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    let notice = tokio::time::timeout(Duration::from_secs(5), b.peer.next())
        .await
        .expect("a lease break");
    assert_eq!(header(&notice).command, Command::OplockBreak);
    b.close(leased).await;
    let done = tokio::time::timeout(Duration::from_secs(5), a.peer.next())
        .await
        .expect("the CREATE completes");
    assert_eq!(status(&done), 0);
    assert_eq!(files.ea_sets(), 1);
    assert_eq!(files.eas("x.txt"), [Ea::new("n", b"v".to_vec())]);
}

#[tokio::test]
async fn names_in_a_create_context_count_only_where_they_apply() {
    let files = MemFsBackend::new();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    let bad = full_list(&[("a*b", b"v")]);
    let malformed = full_entry(64, 0, "n", b"v");
    for (create, expected) in [
        (Create::new("f.txt"), Ok(())),
        (Create::new("f.txt").disposition(FILE_OPEN_IF), Ok(())),
        (
            Create::new("missing.txt"),
            Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND),
        ),
        (
            Create::new("f.txt").disposition(FILE_CREATE),
            Err(ntstatus::STATUS_OBJECT_NAME_COLLISION),
        ),
        (
            Create::new("new.txt").disposition(FILE_OPEN_IF),
            Err(ntstatus::STATUS_INVALID_EA_NAME),
        ),
        (
            Create::new("f.txt").disposition(FILE_OVERWRITE_IF),
            Err(ntstatus::STATUS_INVALID_EA_NAME),
        ),
        (Create::new("f.txt:s").disposition(FILE_OPEN_IF), Ok(())),
        (
            Create::new("gone.txt:s").disposition(FILE_OPEN_IF),
            Err(ntstatus::STATUS_ACCESS_DENIED),
        ),
    ] {
        let name = create.name;
        let result = c.create(create.exta(bad.clone())).await.map(|_| ());
        assert_eq!(result, expected, "{name}");
    }
    assert_eq!(files.contents("f.txt").as_deref(), Some(&b"data"[..]));
    for name in ["new.txt", "gone.txt"] {
        assert_eq!(files.contents(name), None, "{name}");
    }
    // A malformed list fails wherever it is.
    for create in [Create::new("f.txt"), Create::new("f.txt:s")] {
        assert_eq!(
            c.create(create.exta(malformed.clone())).await.err(),
            Some(ntstatus::STATUS_EA_LIST_INCONSISTENT)
        );
    }
}

#[tokio::test]
async fn an_overwrite_of_a_directory_leaves_its_attributes() {
    let files = MemFsBackend::new()
        .with_dir("d")
        .with_ea("d", Ea::new("Kept", b"v".to_vec()))
        .with_ea("", Ea::new("Root", b"r".to_vec()));
    let state = server(&files);
    let mut c = Client::new(&state).await;
    for name in ["d", ""] {
        for disposition in [FILE_OVERWRITE_IF, FILE_OVERWRITE, FILE_SUPERSEDE] {
            for exta in [None, Some(full_list(&[("new", b"1")]))] {
                let mut create = Create::new(name).disposition(disposition);
                create.exta = exta;
                assert_eq!(
                    c.create(create).await.err(),
                    Some(ntstatus::STATUS_FILE_IS_A_DIRECTORY),
                    "{name:?} {disposition}"
                );
            }
        }
    }
    assert_eq!(files.eas("d"), [Ea::new("Kept", b"v".to_vec())]);
    assert_eq!(files.eas(""), [Ea::new("Root", b"r".to_vec())]);
}

#[tokio::test]
async fn an_overwrite_the_backend_refuses_puts_the_attributes_back() {
    let files = MemFsBackend::new()
        .with_file("o.txt", b"data")
        .with_ea("o.txt", Ea::new("Old", b"1".to_vec()))
        .failing_overwrites();
    let state = server(&files);
    let mut c = Client::new(&state).await;
    for exta in [None, Some(full_list(&[("new", b"2"), ("old", b"3")]))] {
        let mut create = Create::new("o.txt").disposition(FILE_OVERWRITE_IF);
        create.exta = exta;
        assert_eq!(
            c.create(create).await.err(),
            Some(ntstatus::STATUS_ACCESS_DENIED)
        );
        assert_eq!(files.eas("o.txt"), [Ea::new("Old", b"1".to_vec())]);
        assert_eq!(files.contents("o.txt").as_deref(), Some(&b"data"[..]));
    }
}

#[tokio::test]
async fn a_cancelled_create_takes_back_the_file_it_made() {
    let files = MemFsBackend::new().with_file("x.txt", b"old");
    let state = server(&files);
    let mut a = Client::new(&state).await;
    let mut b = Client::new(&state).await;
    let leased = b
        .open(Create {
            lease: Some([0xB0; 16]),
            ..Create::new("x.txt")
        })
        .await;
    files.remove("x.txt");
    let create = Create {
        lease: Some([0xA0; 16]),
        ..Create::new("x.txt")
            .disposition(FILE_CREATE)
            .exta(full_list(&[("n", b"v")]))
    };
    let (mid, interim) = a
        .peer
        .request(&a.state, Command::Create, &create.body())
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert!(files.contents("x.txt").is_some(), "made before the wait");
    let cancel = a.peer.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    assert!(a.peer.dispatch(&a.state, &cancel).await.is_none());
    let done = tokio::time::timeout(Duration::from_secs(5), a.peer.next())
        .await
        .expect("the CREATE ends");
    assert_eq!(status(&done), ntstatus::STATUS_CANCELLED);
    // The file goes with the last open on it.
    b.close(leased).await;
    assert_eq!(files.contents("x.txt"), None);
    assert_eq!(files.ea_sets(), 0);
}

/// A symlink to a file lists with the extended attributes of its target,
/// as an open of its name sees them.
#[cfg(all(target_os = "linux", feature = "localfs"))]
#[tokio::test]
async fn a_symlink_lists_with_the_attributes_of_its_target() {
    use crate::ShareBackend as _;

    let exe = std::env::current_exe().unwrap();
    let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
    let backend = crate::fs::LocalFsBackend::new(td.path()).unwrap();
    if !backend.capabilities().extended_attributes {
        eprintln!(
            "skipping: no extended attributes on {}",
            td.path().display()
        );
        return;
    }
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    std::os::unix::fs::symlink("f.txt", td.path().join("link.txt")).unwrap();
    let state = server_on(Share::new("home", backend).public());
    let mut c = Client::new(&state).await;
    let f = c.open(Create::new("f.txt")).await;
    assert_eq!(c.set_eas(f, full_list(&[("test", b"hello")])).await, 0);
    let size = c.info(f, 1, EA_INFORMATION).await;
    c.close(f).await;
    let link = c.open(Create::new("link.txt").access(READ)).await;
    assert_eq!(c.info(link, 1, EA_INFORMATION).await, size);
    c.close(link).await;

    let size = u32_at(&size, 0);
    assert_ne!(size, 0);
    let root = c
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let listed = c.listed_ea_sizes(root, FULL_DIRECTORY).await;
    assert!(listed.contains(&("f.txt".to_string(), size)), "{listed:?}");
    assert!(
        listed.contains(&("link.txt".to_string(), size)),
        "{listed:?}"
    );
}
