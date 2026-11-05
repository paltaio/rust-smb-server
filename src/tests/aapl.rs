//! Apple's `AAPL` create context over the dispatcher: the reply to a
//! server query, its place among the other response contexts, volume caps
//! per share, malformed queries, reconnects, and a server that ignores the
//! context.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::Access;
use crate::backend::{BackendCapabilities, Handle, OpenAction, OpenOptions, ShareBackend};
use crate::conn::state::TreeConnect;
use crate::error::SmbResult;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    CreateContext, CreateRequest, CreateResponse, FileId, LeaseContext, QueryDirectoryRequest,
    QueryDirectoryResponse,
};
use crate::server::ServerState;
use crate::tests::memfs::{DIR_MODE, FILE_MODE, MemFsBackend};
use crate::tests::peer::{Peer, status};
use crate::{Share, SmbServer, SmbServerBuilder};

const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const SYNCHRONIZE: u32 = 0x0010_0000;
const READ_WRITE: u32 = 0x3;
const FILE_OPEN: u32 = 1;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const CLIENT: Uuid = Uuid::from_bytes([0xC1; 16]);

/// A server query for every part from a client with every extension.
const QUERY: [u8; 24] = [
    0x01, 0, 0, 0, 0, 0, 0, 0, //
    0x07, 0, 0, 0, 0, 0, 0, 0, //
    0x3F, 0, 0, 0, 0, 0, 0, 0,
];

/// READ_DIR_ATTR, which shares with named streams get, and UNIX_BASED on
/// Unix hosts.
const SERVER_CAPS: u64 = if cfg!(unix) { 0x05 } else { 0x01 };

/// Memory backend whose names are case-sensitive.
struct CaseSensitive(MemFsBackend);

#[async_trait]
impl ShareBackend for CaseSensitive {
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
        BackendCapabilities {
            case_sensitive: true,
            ..self.0.capabilities()
        }
    }
}

fn server_with(builder: SmbServerBuilder, backend: impl ShareBackend) -> Arc<ServerState> {
    builder
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("home", backend).public())
        .build()
        .expect("build")
        .state()
}

fn server() -> Arc<ServerState> {
    server_with(
        SmbServer::builder(),
        MemFsBackend::new().with_file("f.txt", b"data"),
    )
}

fn context(name: &[u8; 4], data: &[u8]) -> CreateContext {
    CreateContext {
        name: name.to_vec(),
        data: data.to_vec(),
    }
}

fn aapl(data: &[u8]) -> CreateContext {
    context(CreateContext::NAME_AAPL, data)
}

fn lease() -> CreateContext {
    let data = LeaseContext {
        key: [0xD1; 16],
        state: 0x7,
        ..LeaseContext::default()
    }
    .encode();
    context(CreateContext::NAME_RQLS, &data)
}

/// A CREATE that opens `name` with `access`, `options` and `contexts`,
/// asking for a lease when `contexts` holds a lease request.
fn create_body(name: &str, access: u32, options: u32, contexts: &[CreateContext]) -> Vec<u8> {
    let name = crate::utils::utf16le(name);
    let mut padded = name.clone();
    padded.resize(name.len().next_multiple_of(8), 0);
    let leased = contexts.iter().any(|c| c.name == CreateContext::NAME_RQLS);
    let mut chain = Vec::new();
    CreateContext::encode_chain(contexts, &mut chain).expect("contexts");
    let mut body = Vec::new();
    CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: if leased { 0xFF } else { 0 },
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: access,
        file_attributes: 0,
        share_access: 0x7,
        create_disposition: FILE_OPEN,
        create_options: options,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: if chain.is_empty() {
            0
        } else {
            0x78 + padded.len() as u32
        },
        create_contexts_length: chain.len() as u32,
        name: padded,
        create_contexts: chain,
    }
    .write_to(&mut body)
    .expect("create");
    body
}

/// The CREATE of the share root a client sends when it mounts the share,
/// with `query` as the data of the `AAPL` context, followed by `MxAc`.
fn mount_body(query: &[u8]) -> Vec<u8> {
    let contexts = [aapl(query), context(CreateContext::NAME_MXAC, &[])];
    create_body(
        "",
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_DIRECTORY_FILE,
        &contexts,
    )
}

/// The status of the CREATE answered by `reply`, its FileId and its
/// response contexts.
fn created(reply: &[u8]) -> (u32, FileId, Vec<CreateContext>) {
    let status = status(reply);
    if status != ntstatus::STATUS_SUCCESS {
        return (status, FileId::default(), Vec::new());
    }
    let created = CreateResponse::parse(&reply[SMB2_HEADER_LEN..]).expect("create response");
    let contexts = CreateContext::parse_chain(&created.create_contexts).expect("contexts");
    (status, created.file_id, contexts)
}

async fn send(state: &Arc<ServerState>, peer: &mut Peer, body: &[u8]) -> (u32, Vec<CreateContext>) {
    let (_, reply) = peer.request(state, Command::Create, body).await;
    let (status, _, contexts) = created(&reply);
    (status, contexts)
}

async fn mount(
    state: &Arc<ServerState>,
    peer: &mut Peer,
    query: &[u8],
) -> (u32, Vec<CreateContext>) {
    send(state, peer, &mount_body(query)).await
}

/// The reply a query for every part gets.
fn reply(server_caps: u64, volume_caps: u64, model: &str) -> Vec<u8> {
    let model = crate::utils::utf16le(model);
    [
        &[1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0][..],
        &server_caps.to_le_bytes(),
        &volume_caps.to_le_bytes(),
        &[0, 0, 0, 0],
        &(model.len() as u32).to_le_bytes(),
        &model,
    ]
    .concat()
}

fn aapl_reply(contexts: &[CreateContext]) -> Option<&[u8]> {
    contexts
        .iter()
        .find(|c| c.name == CreateContext::NAME_AAPL)
        .map(|c| c.data.as_slice())
}

fn names(contexts: &[CreateContext]) -> Vec<&[u8]> {
    contexts.iter().map(|c| c.name.as_slice()).collect()
}

#[tokio::test]
async fn a_mount_query_gets_the_server_caps_volume_caps_and_model() {
    let state = server();
    let mut peer = Peer::new(&state, false).await;
    let (status, contexts) = mount(&state, &mut peer, &QUERY).await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(
        names(&contexts),
        [&CreateContext::NAME_AAPL[..], &CreateContext::NAME_MXAC[..]]
    );
    assert_eq!(
        aapl_reply(&contexts),
        Some(&reply(SERVER_CAPS, 0, "smb-server")[..])
    );
}

#[tokio::test]
async fn the_reply_comes_first_among_the_response_contexts() {
    let state = server();
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let mut dh2q = 60_000u32.to_le_bytes().to_vec();
    dh2q.extend_from_slice(&[0; 12]);
    dh2q.extend_from_slice(&[0xE1; 16]);
    let contexts = [
        context(CreateContext::NAME_DH2Q, &dh2q),
        lease(),
        context(CreateContext::NAME_QFID, &[]),
        context(CreateContext::NAME_MXAC, &[]),
        aapl(&QUERY),
    ];
    let body = create_body("f.txt", READ_WRITE, 0, &contexts);
    let (status, contexts) = send(&state, &mut peer, &body).await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(
        names(&contexts),
        [
            &CreateContext::NAME_AAPL[..],
            &CreateContext::NAME_MXAC[..],
            &CreateContext::NAME_QFID[..],
            &CreateContext::NAME_RQLS[..],
            &CreateContext::NAME_DH2Q[..],
        ]
    );
}

#[tokio::test]
async fn each_share_on_a_connection_gets_its_own_volume_caps() {
    let state = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("home", MemFsBackend::new()).public())
        .share(Share::new("cs", CaseSensitive(MemFsBackend::new())).public())
        .build()
        .expect("build")
        .state();
    let mut peer = Peer::new(&state, false).await;
    let cs = state.find_share("cs").await.expect("share");
    let session = peer.conn.sessions.read().await[&1].clone();
    session.read().await.trees.write().await.insert(
        2,
        Arc::new(RwLock::new(TreeConnect::new(2, cs, Access::ReadWrite))),
    );
    for (tree, volume_caps) in [(2u32, 0x02), (1, 0), (2, 0x02)] {
        let (_, mut msg) = peer.message(Command::Create, &mount_body(&QUERY));
        msg[36..40].copy_from_slice(&tree.to_le_bytes());
        let response = peer.dispatch(&state, &msg).await.expect("a response");
        let (status, _, contexts) = created(&response);
        assert_eq!(status, ntstatus::STATUS_SUCCESS, "tree {tree}");
        assert_eq!(
            aapl_reply(&contexts),
            Some(&reply(SERVER_CAPS, volume_caps, "smb-server")[..]),
            "tree {tree}"
        );
    }
}

#[tokio::test]
async fn the_reply_carries_the_configured_model() {
    let builder = SmbServer::builder().apple_model("Example NAS");
    let state = server_with(builder, MemFsBackend::new());
    let mut peer = Peer::new(&state, false).await;
    let (_, contexts) = mount(&state, &mut peer, &QUERY).await;
    assert_eq!(
        aapl_reply(&contexts),
        Some(&reply(SERVER_CAPS, 0, "Example NAS")[..])
    );
}

#[tokio::test]
async fn a_reply_carries_only_the_parts_asked_for() {
    let state = server();
    let mut peer = Peer::new(&state, false).await;
    let mut query = QUERY;
    query[8] = 0x06;
    let (_, contexts) = mount(&state, &mut peer, &query).await;
    let mut expected = reply(0, 0, "smb-server");
    expected.drain(16..24);
    expected[8] = 0x06;
    assert_eq!(aapl_reply(&contexts), Some(&expected[..]));
}

#[tokio::test]
async fn a_malformed_query_fails_the_create() {
    let state = server();
    let mut peer = Peer::new(&state, false).await;
    let (status, _) = mount(&state, &mut peer, &QUERY[..23]).await;
    assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER);
}

#[tokio::test]
async fn a_reconnect_ignores_the_context() {
    let state = server();
    let durable = [lease(), context(CreateContext::NAME_DHNQ, &[0; 16])];
    let mut peer = Peer::from_client(&state, true, CLIENT).await;
    let (_, reply) = peer
        .request(
            &state,
            Command::Create,
            &create_body("f.txt", READ_WRITE, 0, &durable),
        )
        .await;
    let (status, mut file_id, contexts) = created(&reply);
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert!(names(&contexts).contains(&&CreateContext::NAME_DHNQ[..]));
    for query in [&QUERY[..], &QUERY[..23]] {
        peer.drop_connection(&state).await;
        peer = Peer::from_client(&state, true, CLIENT).await;
        let mut dhnc = file_id.persistent.to_le_bytes().to_vec();
        dhnc.extend_from_slice(&file_id.volatile.to_le_bytes());
        let contexts = [
            lease(),
            context(CreateContext::NAME_DHNC, &dhnc),
            aapl(query),
        ];
        let body = create_body("f.txt", READ_WRITE, 0, &contexts);
        let (_, reply) = peer.request(&state, Command::Create, &body).await;
        let (status, reconnected, contexts) = created(&reply);
        assert_eq!(status, ntstatus::STATUS_SUCCESS, "{query:02x?}");
        assert_eq!(reconnected.persistent, file_id.persistent);
        assert_eq!(aapl_reply(&contexts), None);
        file_id = reconnected;
    }
}

#[tokio::test]
async fn with_apple_extensions_off_the_context_is_ignored() {
    let builder = SmbServer::builder().apple_extensions(false);
    let state = server_with(builder, MemFsBackend::new());
    let mut peer = Peer::new(&state, false).await;
    for query in [&QUERY[..], &QUERY[..23]] {
        let (status, contexts) = mount(&state, &mut peer, query).await;
        assert_eq!(status, ntstatus::STATUS_SUCCESS);
        assert_eq!(names(&contexts), [&CreateContext::NAME_MXAC[..]]);
    }
}

const ID_BOTH: u8 = 0x25;
const BOTH: u8 = 0x03;
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const FILE_EXECUTE: u32 = 0x20;

/// An `AFP_AfpInfo` stream holding `finder`.
fn afp_info(finder: &[u8; 32]) -> Vec<u8> {
    let mut out = b"AFP\0\0\0\x01\0\0\0\0\0\x80\0\0\0".to_vec();
    out.extend_from_slice(finder);
    out.extend_from_slice(&[0; 12]);
    out
}

/// Finder info with type TEXT, creator ttxt, the red label and extended
/// flags 0x0001.
fn labelled() -> [u8; 32] {
    let mut finder = [0u8; 32];
    finder[..8].copy_from_slice(b"TEXTttxt");
    finder[8..10].copy_from_slice(&[0x00, 0x0C]);
    finder[24..26].copy_from_slice(&[0x00, 0x01]);
    finder
}

/// A share holding `f.txt` with Finder info and a 1000-byte resource fork,
/// `plain.txt` with neither, and the directory `d` with Finder flags.
fn files() -> MemFsBackend {
    let mut folder = [0u8; 32];
    folder[8..10].copy_from_slice(&[0x40, 0x00]);
    MemFsBackend::new()
        .with_file("f.txt", b"data")
        .with_stream("f.txt", "AFP_AfpInfo", &afp_info(&labelled()))
        .with_stream("f.txt", "AFP_Resource", &[7; 1000])
        .with_file("plain.txt", b"x")
        .with_dir("d")
        .with_stream("d", "afp_afpinfo", &afp_info(&folder))
}

/// One entry of a directory listing: name, EaSize, the 2 bytes after it,
/// the 24 bytes of ShortName, Reserved2 and FileId.
#[derive(Debug)]
struct Listed {
    name: String,
    ea_size: u32,
    short: [u8; 2],
    short_name: [u8; 24],
    reserved2: u16,
}

async fn list(state: &Arc<ServerState>, peer: &mut Peer, tree: u32, class: u8) -> Vec<Listed> {
    list_in(state, peer, tree, class, 65536).await
}

/// The first response to a listing of the share root with an output
/// buffer of `len` bytes.
async fn list_in(
    state: &Arc<ServerState>,
    peer: &mut Peer,
    tree: u32,
    class: u8,
    len: u32,
) -> Vec<Listed> {
    let dir = open_dir(state, peer, tree, "").await;
    let flags = QueryDirectoryRequest::FLAG_RESTART_SCANS;
    let (status, listed) = query(state, peer, tree, dir, class, flags, len).await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    listed
}

/// Opens the directory `path` on `tree`.
async fn open_dir(state: &Arc<ServerState>, peer: &mut Peer, tree: u32, path: &str) -> FileId {
    let open = create_body(
        path,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE | 0x1,
        FILE_DIRECTORY_FILE,
        &[],
    );
    let (_, mut msg) = peer.message(Command::Create, &open);
    msg[36..40].copy_from_slice(&tree.to_le_bytes());
    let reply = peer.dispatch(state, &msg).await.expect("a response");
    let (opened, dir, _) = created(&reply);
    assert_eq!(opened, ntstatus::STATUS_SUCCESS);
    dir
}

/// One QUERY_DIRECTORY for "*" on the directory open as `dir`: its status
/// and the entries of its response.
async fn query(
    state: &Arc<ServerState>,
    peer: &mut Peer,
    tree: u32,
    dir: FileId,
    class: u8,
    flags: u8,
    len: u32,
) -> (u32, Vec<Listed>) {
    let pattern = crate::utils::utf16le("*");
    let mut body = Vec::new();
    QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: class,
        flags,
        file_index: 0,
        file_id: dir,
        file_name_offset: 96,
        file_name_length: pattern.len() as u16,
        output_buffer_length: len,
        file_name: pattern,
    }
    .write_to(&mut body)
    .expect("query");
    let (_, mut msg) = peer.message(Command::QueryDirectory, &body);
    msg[36..40].copy_from_slice(&tree.to_le_bytes());
    let reply = peer.dispatch(state, &msg).await.expect("a response");
    let status = status(&reply);
    if status != ntstatus::STATUS_SUCCESS {
        return (status, Vec::new());
    }
    let buf = QueryDirectoryResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("listing")
        .buffer;
    let u32_at = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let (name_at, ea_at) = match class {
            ID_BOTH => (104, 64),
            _ => (94, 64),
        };
        let len = u32_at(at + 60) as usize;
        let units: Vec<u16> = buf[at + name_at..at + name_at + len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(Listed {
            name: String::from_utf16(&units).unwrap(),
            ea_size: u32_at(at + ea_at),
            short: [buf[at + 68], buf[at + 69]],
            short_name: buf[at + 70..at + 94].try_into().unwrap(),
            reserved2: if class == ID_BOTH {
                u16::from_le_bytes([buf[at + 94], buf[at + 95]])
            } else {
                0
            },
        });
        match u32_at(at) {
            0 => break,
            next => at += next as usize,
        }
    }
    (status, out)
}

fn entry<'a>(listed: &'a [Listed], name: &str) -> &'a Listed {
    listed.iter().find(|e| e.name == name).expect(name)
}

/// The 24 bytes of ShortName a listing with Finder data carries.
fn short_name(fork: u64, finder: [u8; 16]) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(&fork.to_le_bytes());
    out[8..].copy_from_slice(&finder);
    out
}

/// The 16 bytes of Finder info without an `AFP_AfpInfo` stream.
const NO_FINDER_INFO: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0];

#[tokio::test]
async fn listings_after_read_dir_attr_carry_finder_data() {
    let state = server_with(SmbServer::builder(), files());
    let mut peer = Peer::new(&state, false).await;
    let (_, contexts) = mount(&state, &mut peer, &QUERY).await;
    assert_eq!(
        aapl_reply(&contexts),
        Some(&reply(SERVER_CAPS, 0, "smb-server")[..])
    );
    let listed = list(&state, &mut peer, 1, ID_BOTH).await;
    let mut names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, [".", "..", "d", "f.txt", "plain.txt"]);
    for e in &listed {
        assert_eq!(e.short, [24, 0], "{e:?}");
    }

    let f = entry(&listed, "f.txt");
    assert_eq!(f.ea_size, FILE_ALL_ACCESS & !FILE_EXECUTE);
    let mut finder = [0u8; 16];
    finder[..8].copy_from_slice(b"TEXTttxt");
    finder[8..12].copy_from_slice(&[0x00, 0x0C, 0x00, 0x01]);
    // MemFsBackend files were created at 0x01D9_0000_0000_0000.
    finder[12..].copy_from_slice(&0x2B12_1F7Eu32.to_be_bytes());
    assert_eq!(f.short_name, short_name(1000, finder));
    assert_eq!(u32::from(f.reserved2), FILE_MODE & 0xFFFF);

    let plain = entry(&listed, "plain.txt");
    assert_eq!(plain.short_name, short_name(0, NO_FINDER_INFO));

    let d = entry(&listed, "d");
    assert_eq!(d.ea_size, FILE_ALL_ACCESS);
    let mut folder = [0u8; 16];
    folder[8..10].copy_from_slice(&[0x40, 0x00]);
    folder[12..].copy_from_slice(&0x2B12_1F7Eu32.to_be_bytes());
    assert_eq!(d.short_name, short_name(0, folder));
    assert_eq!(u32::from(d.reserved2), DIR_MODE & 0xFFFF);

    for dot in [".", ".."] {
        let e = entry(&listed, dot);
        assert_eq!(e.ea_size, FILE_ALL_ACCESS);
        assert_eq!(e.short_name, short_name(0, NO_FINDER_INFO));
        assert_eq!(u32::from(e.reserved2), DIR_MODE & 0xFFFF);
    }

    // Other classes keep their layout.
    for e in list(&state, &mut peer, 1, BOTH).await {
        assert_eq!((e.ea_size, e.short, e.short_name), (0, [0, 0], [0; 24]));
    }
}

/// [`files`] and six more files, so a listing with a 346-byte buffer
/// takes several responses.
fn more_files() -> MemFsBackend {
    (1..=6).fold(files(), |files, i| {
        files.with_file(&format!("e{i}.txt"), b"x")
    })
}

#[tokio::test]
async fn each_response_of_a_listing_peeks_at_the_entries_it_carries() {
    let files = more_files();
    let state = server_with(SmbServer::builder(), files.clone());
    let mut peer = Peer::new(&state, false).await;
    mount(&state, &mut peer, &QUERY).await;
    let dir = open_dir(&state, &mut peer, 1, "").await;
    let mut flags = QueryDirectoryRequest::FLAG_RESTART_SCANS;
    let mut carried = Vec::new();
    loop {
        let (status, listed) = query(&state, &mut peer, 1, dir, ID_BOTH, flags, 346).await;
        if status == ntstatus::STATUS_NO_MORE_FILES {
            break;
        }
        assert_eq!(status, ntstatus::STATUS_SUCCESS);
        let names: Vec<String> = listed
            .into_iter()
            .map(|e| e.name)
            .filter(|n| n != "." && n != "..")
            .collect();
        carried.push(names);
        flags = 0;
    }
    assert_eq!(carried.iter().map(Vec::len).sum::<usize>(), 9);
    assert!(carried.len() > 2, "{carried:?}");
    assert_eq!(files.peeks(), carried);
}

#[tokio::test]
async fn a_refused_peek_is_not_asked_again_until_the_listing_restarts() {
    let files = more_files().without_peeks();
    let state = server_with(SmbServer::builder(), files.clone());
    let mut peer = Peer::new(&state, false).await;
    mount(&state, &mut peer, &QUERY).await;
    let dir = open_dir(&state, &mut peer, 1, "").await;
    let mut query_all = async |flags: u8| {
        let mut flags = flags;
        let mut responses = 0;
        loop {
            let (status, _) = query(&state, &mut peer, 1, dir, ID_BOTH, flags, 346).await;
            if status != ntstatus::STATUS_SUCCESS {
                return responses;
            }
            responses += 1;
            flags = 0;
        }
    };
    assert!(query_all(QueryDirectoryRequest::FLAG_RESTART_SCANS).await > 2);
    assert_eq!(files.peeks().len(), 1);
    query_all(QueryDirectoryRequest::FLAG_RESTART_SCANS).await;
    assert_eq!(files.peeks().len(), 2);
    query_all(QueryDirectoryRequest::FLAG_REOPEN).await;
    assert_eq!(files.peeks().len(), 3);
}

#[tokio::test]
async fn listings_without_read_dir_attr_are_plain() {
    let state = server_with(SmbServer::builder(), files());
    let mut peer = Peer::new(&state, false).await;
    let plain = |listed: Vec<Listed>| {
        listed
            .iter()
            .all(|e| (e.ea_size, e.short, e.short_name, e.reserved2) == (0, [0, 0], [0; 24], 0))
    };
    assert!(plain(list(&state, &mut peer, 1, ID_BOTH).await));
    // A client without READ_DIR_ATTR gets none.
    let mut query = QUERY;
    query[16] = 0x3E;
    let (_, contexts) = mount(&state, &mut peer, &query).await;
    assert_eq!(
        aapl_reply(&contexts),
        Some(&reply(SERVER_CAPS & !1, 0, "smb-server")[..])
    );
    assert!(plain(list(&state, &mut peer, 1, ID_BOTH).await));
    // Nor does one whose query asks for no server caps.
    let mut query = QUERY;
    query[8] = 0x06;
    mount(&state, &mut peer, &query).await;
    assert!(plain(list(&state, &mut peer, 1, ID_BOTH).await));
}

#[tokio::test]
async fn read_dir_attr_once_granted_stays_for_every_share() {
    let state = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("home", files()).public())
        .share(Share::new("bare", files().without_streams()).public())
        .build()
        .expect("build")
        .state();
    let mut peer = Peer::new(&state, false).await;
    let bare = state.find_share("bare").await.expect("share");
    let session = peer.conn.sessions.read().await[&1].clone();
    session.read().await.trees.write().await.insert(
        2,
        Arc::new(RwLock::new(TreeConnect::new(2, bare, Access::Read))),
    );
    let mount_bare = async |peer: &mut Peer| {
        let (_, mut msg) = peer.message(Command::Create, &mount_body(&QUERY));
        msg[36..40].copy_from_slice(&2u32.to_le_bytes());
        let response = peer.dispatch(&state, &msg).await.expect("a response");
        let (_, _, contexts) = created(&response);
        contexts
    };
    // Before a grant, the share without streams gets none.
    let contexts = mount_bare(&mut peer).await;
    assert_eq!(
        aapl_reply(&contexts),
        Some(&reply(SERVER_CAPS & !1, 0, "smb-server")[..])
    );
    assert_eq!(
        entry(&list(&state, &mut peer, 2, ID_BOTH).await, "f.txt").short,
        [0, 0]
    );
    mount(&state, &mut peer, &QUERY).await;
    // After it, that share gets READ_DIR_ATTR too and lists Finder data
    // without its streams, with the read-only tree's access.
    let contexts = mount_bare(&mut peer).await;
    assert_eq!(
        aapl_reply(&contexts),
        Some(&reply(SERVER_CAPS, 0, "smb-server")[..])
    );
    let listed = list(&state, &mut peer, 2, ID_BOTH).await;
    let f = entry(&listed, "f.txt");
    assert_eq!(f.short, [24, 0]);
    assert_eq!(f.short_name, short_name(0, NO_FINDER_INFO));
    assert_eq!(f.ea_size, 0x0012_0089);
    let listed = list(&state, &mut peer, 1, ID_BOTH).await;
    assert_eq!(
        entry(&listed, "f.txt").short_name[..8],
        1000u64.to_le_bytes()
    );
    // So does a query that asks for no server caps.
    let mut query = QUERY;
    query[8] = 0x06;
    mount(&state, &mut peer, &query).await;
    let listed = list(&state, &mut peer, 1, ID_BOTH).await;
    assert_eq!(entry(&listed, "f.txt").short, [24, 0]);
}

#[tokio::test]
async fn a_backend_without_stream_peeks_lists_no_finder_info() {
    let state = server_with(SmbServer::builder(), files().without_peeks());
    let mut peer = Peer::new(&state, false).await;
    mount(&state, &mut peer, &QUERY).await;
    for e in list(&state, &mut peer, 1, ID_BOTH).await {
        assert_eq!(e.short, [24, 0], "{e:?}");
        assert_eq!(e.short_name, short_name(0, NO_FINDER_INFO), "{e:?}");
        assert_ne!(e.ea_size, 0, "{e:?}");
    }
}

/// Special files and a symlink out of the share in a listed directory on
/// a host filesystem: the listing finishes, and those entries carry no
/// Finder data while a regular file beside them does.
#[cfg(all(unix, feature = "localfs"))]
#[tokio::test]
async fn special_files_and_escaping_links_list_without_finder_data() {
    use crate::backend::OpenIntent;
    use crate::fs::LocalFsBackend;

    let exe = std::env::current_exe().unwrap();
    let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
    let (root, outside) = (td.path().join("share"), td.path().join("outside"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let with_info = async |dir: &std::path::Path, name: &str| {
        let backend = LocalFsBackend::new(dir).unwrap();
        let path: SmbPath = name.parse().unwrap();
        let opts = OpenOptions {
            read: true,
            write: true,
            write_attributes: false,
            intent: OpenIntent::OpenOrCreate,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        };
        let (file, _) = backend.open(&path, opts).await.unwrap();
        let stream = "AFP_AfpInfo".parse().unwrap();
        let (h, _) = backend
            .open_stream(file, &path, &stream, opts)
            .await
            .unwrap();
        h.write(0, &afp_info(&labelled())).await.unwrap();
        h.close().await.unwrap();
    };
    let backend = LocalFsBackend::new(&root).unwrap();
    if !backend.capabilities().named_streams {
        eprintln!("skipping: no named streams on {}", root.display());
        return;
    }
    with_info(&root, "f.txt").await;
    with_info(&outside, "f.txt").await;
    let fifo =
        std::ffi::CString::new(root.join("fifo").into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: `fifo` is a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
    let _socket = std::os::unix::net::UnixListener::bind(root.join("sock")).unwrap();
    std::os::unix::fs::symlink(outside.join("f.txt"), root.join("out.txt")).unwrap();

    let state = server_with(SmbServer::builder(), backend);
    let mut peer = Peer::new(&state, false).await;
    mount(&state, &mut peer, &QUERY).await;
    let listed = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        list(&state, &mut peer, 1, ID_BOTH),
    )
    .await
    .expect("the listing finishes");
    let finder = entry(&listed, "f.txt").short_name;
    assert_eq!(finder[8..16], *b"TEXTttxt");
    for name in ["fifo", "sock", "out.txt"] {
        let e = entry(&listed, name);
        assert_eq!(e.short_name, short_name(0, NO_FINDER_INFO), "{name}");
    }
}

/// A symlink in a subdirectory to a file beside that directory lists as
/// a link, without Finder data, and a peek from the subdirectory finds
/// none, while a file in it has its own.
#[cfg(all(unix, feature = "localfs"))]
#[tokio::test]
async fn a_link_out_of_a_listed_subdirectory_has_no_finder_data() {
    use crate::backend::OpenIntent;
    use crate::fs::LocalFsBackend;

    let exe = std::env::current_exe().unwrap();
    let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
    let root = td.path();
    std::fs::create_dir_all(root.join("other")).unwrap();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    let backend = LocalFsBackend::new(root).unwrap();
    if !backend.capabilities().named_streams {
        eprintln!("skipping: no named streams on {}", root.display());
        return;
    }
    let opts = OpenOptions {
        read: true,
        write: true,
        write_attributes: false,
        intent: OpenIntent::OpenOrCreate,
        directory: false,
        non_directory: false,
        delete_on_close: false,
    };
    let stream: crate::StreamName = "AFP_AfpInfo".parse().unwrap();
    for name in ["other\\f", "sub\\g.txt"] {
        let path: SmbPath = name.parse().unwrap();
        let (file, _) = backend.open(&path, opts).await.unwrap();
        let (h, _) = backend
            .open_stream(file, &path, &stream, opts)
            .await
            .unwrap();
        h.write(0, &afp_info(&labelled())).await.unwrap();
        h.close().await.unwrap();
    }
    std::os::unix::fs::symlink("../other/f", root.join("sub").join("link")).unwrap();

    let dir_opts = OpenOptions {
        write: false,
        directory: true,
        intent: OpenIntent::Open,
        ..opts
    };
    let (sub, _) = backend
        .open(&"sub".parse().unwrap(), dir_opts)
        .await
        .unwrap();
    let streams = [(stream, 60)];
    let peeked = sub
        .peek_streams(&[("link", &streams[..]), ("g.txt", &streams[..])])
        .await
        .unwrap();
    sub.close().await.unwrap();
    assert!(peeked[0][0].is_none());
    assert_eq!(peeked[1][0].as_ref().map(|(size, _)| *size), Some(60));

    let state = server_with(SmbServer::builder(), backend);
    let mut peer = Peer::new(&state, false).await;
    mount(&state, &mut peer, &QUERY).await;
    let dir = open_dir(&state, &mut peer, 1, "sub").await;
    let flags = QueryDirectoryRequest::FLAG_RESTART_SCANS;
    let (status, listed) = query(&state, &mut peer, 1, dir, ID_BOTH, flags, 65536).await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    let link = entry(&listed, "link");
    assert_eq!(link.short_name, short_name(0, NO_FINDER_INFO));
    assert_eq!(u32::from(link.reserved2) & 0o170_000, 0o120_000);
    assert_eq!(entry(&listed, "g.txt").short_name[8..16], *b"TEXTttxt");
}
