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
use crate::proto::messages::{CreateContext, CreateRequest, CreateResponse, FileId, LeaseContext};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
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

/// UNIX_BASED on Unix hosts.
const SERVER_CAPS: u64 = if cfg!(unix) { 0x04 } else { 0 };

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
