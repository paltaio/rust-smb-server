//! Named pipes on IPC$ driven through the dispatcher: READs that wait for
//! a reply, and pipe opens ending with their tree, session or connection.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::ntstatus;
use crate::proto::header::{Command, SMB2_FLAGS_ASYNC_COMMAND, SMB2_HEADER_LEN};
use crate::proto::messages::{
    CloseRequest, CreateRequest, CreateResponse, FileId, ReadRequest, ReadResponse, WriteRequest,
};
use crate::rpc::pdu::PTYPE_FAULT;
use crate::rpc::pdu::tests::{BIND_3CTX, unhex};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{Peer, header, status};
use crate::{Access, Share, SmbServer};

/// FILE_GENERIC_READ | FILE_GENERIC_WRITE.
const PIPE_ACCESS: u32 = 0x0012_019F;

fn smb_server() -> SmbServer {
    SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(Share::new("home", MemFsBackend::new()).user("alice", Access::ReadWrite))
        .build()
        .expect("build")
}

fn server() -> Arc<ServerState> {
    smb_server().state()
}

fn create_body(name: &str) -> Vec<u8> {
    let name = crate::utils::utf16le(name);
    let mut body = Vec::new();
    CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: PIPE_ACCESS,
        file_attributes: 0,
        share_access: 3,
        create_disposition: 1,
        create_options: 0x0040_0040,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: Vec::new(),
    }
    .write_to(&mut body)
    .expect("create");
    body
}

fn write_body(file_id: FileId, data: &[u8]) -> Vec<u8> {
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
    body
}

fn read_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    ReadRequest {
        structure_size: 49,
        padding: 0x50,
        flags: 0,
        length: 4280,
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

fn close_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    }
    .write_to(&mut body)
    .expect("close");
    body
}

/// A request on context 0 with `call_id`.
fn request_pdu(call_id: u32) -> Vec<u8> {
    let mut pdu = vec![5, 0, 0, 3, 0x10, 0, 0, 0, 24, 0, 0, 0];
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(&[0, 0, 0, 0, 0, 0, 15, 0]);
    pdu
}

/// The data of a READ response.
fn read_data(frame: &[u8]) -> Vec<u8> {
    ReadResponse::parse(&frame[SMB2_HEADER_LEN..])
        .expect("read response")
        .data
}

/// Opens srvsvc on `peer` and binds it; the bind_ack is read.
async fn bound_pipe(state: &Arc<ServerState>, peer: &mut Peer) -> FileId {
    let (_, reply) = peer
        .request(state, Command::Create, &create_body("srvsvc"))
        .await;
    assert_eq!(status(&reply), 0);
    let file_id = CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id;
    let (_, reply) = peer
        .request(
            state,
            Command::Write,
            &write_body(file_id, &unhex(BIND_3CTX)),
        )
        .await;
    assert_eq!(status(&reply), 0);
    let (_, reply) = peer
        .request(state, Command::Read, &read_body(file_id))
        .await;
    assert_eq!(status(&reply), 0);
    assert_eq!(read_data(&reply)[2], 12, "a bind_ack");
    file_id
}

/// A READ on the bound, empty pipe, which goes asynchronous. Returns its
/// MessageId and AsyncId.
async fn waiting_read(state: &Arc<ServerState>, peer: &mut Peer, file_id: FileId) -> (u64, u64) {
    let (mid, interim) = peer
        .request(state, Command::Read, &read_body(file_id))
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert_eq!(peer.conn.pending.len(), 1);
    (mid, header(&interim).async_id().expect("an AsyncId"))
}

fn open_count(peer: &Peer) -> usize {
    peer.conn.open_count.load(Ordering::Acquire)
}

#[tokio::test]
async fn a_write_completes_a_waiting_read() {
    let state = server();
    let mut peer = Peer::on_ipc(&state, false).await;
    let file_id = bound_pipe(&state, &mut peer).await;
    let (_, async_id) = waiting_read(&state, &mut peer, file_id).await;

    let (_, reply) = peer
        .request(
            &state,
            Command::Write,
            &write_body(file_id, &request_pdu(5)),
        )
        .await;
    assert_eq!(status(&reply), 0);
    let last = peer.next().await;
    let hdr = header(&last);
    assert_eq!(hdr.command, Command::Read);
    assert_ne!(hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
    assert_eq!(hdr.async_id(), Some(async_id));
    assert_eq!(status(&last), 0);
    let fault = read_data(&last);
    assert_eq!((fault[2], fault[12]), (PTYPE_FAULT, 5));
    assert_eq!(peer.conn.pending.len(), 0);
}

#[tokio::test]
async fn cancel_ends_a_waiting_read() {
    let state = server();
    let mut peer = Peer::on_ipc(&state, false).await;
    let file_id = bound_pipe(&state, &mut peer).await;
    let (mid, async_id) = waiting_read(&state, &mut peer, file_id).await;
    let cancel = peer.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    assert!(peer.dispatch(&state, &cancel).await.is_none());
    let last = peer.next().await;
    assert_eq!(header(&last).async_id(), Some(async_id));
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
    // The pipe still works.
    let (_, reply) = peer
        .request(
            &state,
            Command::Write,
            &write_body(file_id, &request_pdu(6)),
        )
        .await;
    assert_eq!(status(&reply), 0);
}

#[tokio::test]
async fn a_waiting_read_ends_with_its_pipe_tree_or_session() {
    let cases = [
        (Command::Close, ntstatus::STATUS_PIPE_BROKEN),
        (
            Command::TreeDisconnect,
            ntstatus::STATUS_NETWORK_NAME_DELETED,
        ),
        (Command::Logoff, ntstatus::STATUS_USER_SESSION_DELETED),
    ];
    for (command, expected) in cases {
        let state = server();
        let mut peer = Peer::on_ipc(&state, false).await;
        let file_id = bound_pipe(&state, &mut peer).await;
        let (_, async_id) = waiting_read(&state, &mut peer, file_id).await;
        let body = match command {
            Command::Close => close_body(file_id),
            _ => vec![4, 0, 0, 0],
        };
        let (_, reply) = peer.request(&state, command, &body).await;
        assert_eq!(status(&reply), 0, "{command:?}");
        let last = peer.next().await;
        assert_eq!(header(&last).async_id(), Some(async_id), "{command:?}");
        assert_eq!(status(&last), expected, "{command:?}");
        assert_eq!(peer.conn.pending.len(), 0, "{command:?}");
        assert_eq!(open_count(&peer), 0, "{command:?}");
    }
}

#[tokio::test]
async fn the_end_of_the_connection_ends_a_waiting_read_and_its_pipe() {
    let state = server();
    let mut peer = Peer::on_ipc(&state, false).await;
    let file_id = bound_pipe(&state, &mut peer).await;
    waiting_read(&state, &mut peer, file_id).await;
    assert_eq!(open_count(&peer), 1);
    peer.drop_connection(&state).await;
    assert_eq!(peer.conn.pending.len(), 0);
    assert_eq!(open_count(&peer), 0);
}

#[tokio::test]
async fn waiting_reads_are_answered_in_order_and_end_with_their_pipe() {
    let state = server();
    let mut peer = Peer::on_ipc(&state, false).await;
    let file_id = bound_pipe(&state, &mut peer).await;
    let (_, first) = waiting_read(&state, &mut peer, file_id).await;
    let (mid, interim) = peer
        .request(&state, Command::Read, &read_body(file_id))
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    let second = header(&interim).async_id().expect("an AsyncId");
    assert_ne!(mid, 0);

    peer.request(
        &state,
        Command::Write,
        &write_body(file_id, &request_pdu(5)),
    )
    .await;
    let last = peer.next().await;
    assert_eq!(header(&last).async_id(), Some(first));
    assert_eq!(read_data(&last)[12], 5);

    let (_, reply) = peer
        .request(&state, Command::Close, &close_body(file_id))
        .await;
    assert_eq!(status(&reply), 0);
    let last = peer.next().await;
    assert_eq!(header(&last).async_id(), Some(second));
    assert_eq!(status(&last), ntstatus::STATUS_PIPE_BROKEN);
}

#[tokio::test(start_paused = true)]
async fn a_read_whose_pipe_went_before_it_waited_ends() {
    // The pipe, tree or session goes away after the READ found the pipe
    // and before its wait began, as a concurrent configuration change can
    // do; the stop it sent reached no waiting request.
    for (gone, expected) in [
        ("pipe", ntstatus::STATUS_PIPE_BROKEN),
        ("tree", ntstatus::STATUS_NETWORK_NAME_DELETED),
        ("session", ntstatus::STATUS_USER_SESSION_DELETED),
    ] {
        let state = server();
        let mut peer = Peer::on_ipc(&state, false).await;
        let file_id = bound_pipe(&state, &mut peer).await;
        let (_, async_id) = waiting_read(&state, &mut peer, file_id).await;
        let session = peer.conn.sessions.read().await[&1].clone();
        match gone {
            "pipe" => {
                let session = session.read().await;
                let tree = session.trees.read().await[&1].clone();
                crate::handlers::pipes(&*tree.read().await).remove(&file_id);
            }
            "tree" => {
                session.read().await.trees.write().await.remove(&1);
            }
            _ => {
                peer.conn.sessions.write().await.remove(&1);
            }
        }
        let last = tokio::time::timeout(std::time::Duration::from_secs(60), peer.next())
            .await
            .expect("the READ ends");
        assert_eq!(header(&last).async_id(), Some(async_id), "{gone}");
        assert_eq!(status(&last), expected, "{gone}");
    }
}

#[tokio::test]
async fn pipe_opens_are_released_on_every_path() {
    let paths = [
        "close",
        "tree disconnect",
        "logoff",
        "close_all",
        "remove_user",
    ];
    for path in paths {
        let server = smb_server();
        let state = server.state();
        let mut peer = Peer::on_ipc(&state, true).await;
        state.active_connections.register(&peer.conn).await;
        let first = bound_pipe(&state, &mut peer).await;
        let second = bound_pipe(&state, &mut peer).await;
        // The connection's own end cancels waiting requests before
        // close_all runs; the other paths end them.
        let waits = path != "close_all";
        if waits {
            waiting_read(&state, &mut peer, second).await;
        }
        assert_eq!(open_count(&peer), 2, "{path}");
        match path {
            "close" => {
                for file_id in [first, second] {
                    let (_, reply) = peer
                        .request(&state, Command::Close, &close_body(file_id))
                        .await;
                    assert_eq!(status(&reply), 0);
                }
                let (_, reply) = peer
                    .request(&state, Command::Close, &close_body(first))
                    .await;
                assert_eq!(status(&reply), ntstatus::STATUS_FILE_CLOSED);
            }
            "tree disconnect" | "logoff" => {
                let command = if path == "logoff" {
                    Command::Logoff
                } else {
                    Command::TreeDisconnect
                };
                let (_, reply) = peer.request(&state, command, &[4, 0, 0, 0]).await;
                assert_eq!(status(&reply), 0);
            }
            "close_all" => peer.conn.close_all(None).await,
            _ => server
                .config_handle()
                .remove_user("alice")
                .await
                .expect("remove alice"),
        }
        // The waiting READ ends, and its pipe with it.
        if waits {
            assert_ne!(status(&peer.next().await), 0, "{path}");
        }
        assert_eq!(peer.conn.pending.len(), 0, "{path}");
        assert_eq!(open_count(&peer), 0, "{path}");
    }
}
