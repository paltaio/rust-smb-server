//! Change notification driven through the dispatcher: waiting requests,
//! their completion by other connections, and every way they end.

use std::sync::Arc;
use std::time::Duration;

use crate::files::MAX_WATCHES_PER_CONNECTION;
use crate::ntstatus;
use crate::proto::crypto::{SigningAlgo, verify};
use crate::proto::header::{
    Command, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_RELATED_OPERATIONS, SMB2_HEADER_LEN,
};
use crate::proto::messages::change_notify::{
    FILE_ACTION_ADDED, FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME,
    FILE_ACTION_RENAMED_OLD_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
};
use crate::proto::messages::{
    ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CreateContext, CreateRequest,
    CreateResponse, FileId, LeaseBreakAck, LeaseContext, QueryInfoRequest, SetInfoRequest,
    WriteRequest,
};
use crate::server::{ConfigHandle, ServerState};
use crate::tests::memfs::MemFsBackend;
use crate::tests::peer::{KEY, Peer, header, status};
use crate::{Share, SmbServer};

const LIST: u32 = 0x0012_0089;
const DELETE: u32 = 0x0001_0000;
const FILE_OPEN_IF: u32 = 3;
const FILE_CREATE: u32 = 2;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
const NAMES: u32 = 0x3;
const READ_WRITE: u32 = 0x3;
const LEASE_KEY: [u8; 16] = [0xB2; 16];

fn create_body(name: &str, access: u32, disposition: u32, options: u32) -> Vec<u8> {
    create_body_with(name, access, disposition, options, None)
}

/// A CREATE of `name`, asking for the lease state `lease` under
/// `LEASE_KEY` when given.
fn create_body_with(
    name: &str,
    access: u32,
    disposition: u32,
    options: u32,
    lease: Option<u32>,
) -> Vec<u8> {
    let name = crate::utils::utf16le(name);
    let mut padded = name.clone();
    padded.resize(padded.len().next_multiple_of(8), 0);
    let mut contexts = Vec::new();
    if let Some(state) = lease {
        let data = LeaseContext {
            key: LEASE_KEY,
            state,
            ..LeaseContext::default()
        }
        .encode();
        let context = CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data,
        };
        CreateContext::encode_chain(&[context], &mut contexts).expect("contexts");
    }
    let mut body = Vec::new();
    CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: if lease.is_some() { 0xFF } else { 0 },
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: access,
        file_attributes: 0,
        share_access: 0x7,
        create_disposition: disposition,
        create_options: options,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: if lease.is_some() {
            0x78 + padded.len() as u32
        } else {
            0
        },
        create_contexts_length: contexts.len() as u32,
        name: padded,
        create_contexts: contexts,
    }
    .write_to(&mut body)
    .expect("create");
    body
}

fn notify_body(file_id: FileId, len: u32, filter: u32) -> Vec<u8> {
    let mut body = Vec::new();
    ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: len,
        file_id,
        completion_filter: filter,
        reserved: 0,
    }
    .write_to(&mut body)
    .expect("change notify");
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

fn query_info_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    QueryInfoRequest {
        structure_size: 41,
        info_type: 1,
        file_information_class: 4,
        output_buffer_length: 0x100,
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
    body
}

/// A server with the public share `home`, and a handle to change it.
fn server() -> (Arc<ServerState>, ConfigHandle) {
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("home", MemFsBackend::new()).public())
        .build()
        .expect("build");
    (server.state(), server.config_handle())
}

async fn home(state: &Arc<ServerState>) -> Arc<crate::server::ShareBindings> {
    state.find_share("home").await.expect("share")
}

/// Opens the directory `name` for listing, creating it if needed.
async fn open_dir(peer: &mut Peer, state: &Arc<ServerState>, name: &str) -> FileId {
    let body = create_body(name, LIST, FILE_OPEN_IF, FILE_DIRECTORY_FILE);
    let (_, reply) = peer.request(state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0, "open {name}");
    CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id
}

async fn close(peer: &mut Peer, state: &Arc<ServerState>, file_id: FileId) {
    let (_, reply) = peer
        .request(state, Command::Close, &close_body(file_id))
        .await;
    assert_eq!(status(&reply), 0);
}

/// Creates the file `name` and closes it.
async fn create_file(peer: &mut Peer, state: &Arc<ServerState>, name: &str) {
    let body = create_body(name, 0x0012_0116, FILE_CREATE, 0);
    let (_, reply) = peer.request(state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0, "create {name}");
    let file_id = CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id;
    close(peer, state, file_id).await;
}

/// Deletes the file `name` through a delete-on-close open.
async fn delete_file(peer: &mut Peer, state: &Arc<ServerState>, name: &str) {
    let body = create_body(name, DELETE, 1, FILE_DELETE_ON_CLOSE);
    let (_, reply) = peer.request(state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0, "open {name} for deletion");
    let file_id = CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id;
    close(peer, state, file_id).await;
}

/// Sends a CHANGE_NOTIFY on `dir` that has to wait; returns its MessageId
/// and AsyncId.
async fn wait_notify(peer: &mut Peer, state: &Arc<ServerState>, dir: FileId) -> (u64, u64) {
    let (mid, interim) = peer
        .request(state, Command::ChangeNotify, &notify_body(dir, 4096, NAMES))
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    (mid, header(&interim).async_id().expect("an AsyncId"))
}

/// (action, name) of each entry of a CHANGE_NOTIFY response frame.
fn entries(frame: &[u8]) -> Vec<(u32, String)> {
    let resp = ChangeNotifyResponse::parse(&frame[SMB2_HEADER_LEN..]).expect("notify response");
    assert_eq!(resp.output_buffer_offset, 0x48);
    let buf = resp.buffer;
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let field = |o: usize| u32::from_le_bytes(buf[at + o..at + o + 4].try_into().unwrap());
        let len = field(8) as usize;
        let name: Vec<u16> = buf[at + 12..at + 12 + len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push((field(4), String::from_utf16(&name).unwrap()));
        match field(0) {
            0 => break,
            next => at += next as usize,
        }
    }
    out
}

fn added(name: &str) -> (u32, String) {
    (FILE_ACTION_ADDED, name.to_string())
}

/// The final response of the request `async_id`, the next message queued
/// for `peer`.
async fn final_of(peer: &mut Peer, async_id: u64) -> Vec<u8> {
    let last = tokio::time::timeout(Duration::from_secs(5), peer.next())
        .await
        .expect("a final response in time");
    let hdr = header(&last);
    assert_eq!(hdr.command, Command::ChangeNotify);
    assert_eq!(hdr.async_id(), Some(async_id));
    last
}

/// Lets the connection tasks run until none has anything left to do.
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

/// `messages` chained into one compound frame, each after the first
/// marked related when `related`.
fn compound(messages: &[Vec<u8>], related: bool) -> Vec<u8> {
    let mut frame = Vec::new();
    for (index, msg) in messages.iter().enumerate() {
        let mut msg = msg.clone();
        if related && index > 0 {
            msg[0x10] |= SMB2_FLAGS_RELATED_OPERATIONS as u8;
        }
        if index + 1 < messages.len() {
            msg.resize(msg.len().next_multiple_of(8), 0);
            let next = msg.len() as u32;
            msg[0x14..0x18].copy_from_slice(&next.to_le_bytes());
        }
        frame.extend_from_slice(&msg);
    }
    frame
}

/// The responses of a compound frame.
fn split(frame: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = frame;
    loop {
        let next = header(rest).next_command as usize;
        if next == 0 {
            out.push(rest);
            return out;
        }
        out.push(&rest[..next]);
        rest = &rest[next..];
    }
}

#[tokio::test]
async fn a_waiting_request_completes_when_another_connection_creates_a_file() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, true).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let (mid, async_id) = wait_notify(&mut watcher, &state, dir).await;

    let mut maker = Peer::new(&state, false).await;
    create_file(&mut maker, &state, "d\\x.txt").await;
    let last = final_of(&mut watcher, async_id).await;
    let hdr = header(&last);
    assert_eq!(status(&last), 0);
    assert_eq!(hdr.message_id, mid);
    assert_ne!(hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
    assert_eq!(hdr.credit_request_response, 0);
    assert!(verify(&last, &KEY, SigningAlgo::AesCmac).is_ok());
    assert_eq!(entries(&last), [added("x.txt")]);
    assert_eq!(watcher.conn.pending.len(), 0);

    // A watch for file names only does not see a directory being created.
    let other = open_dir(&mut watcher, &state, "e").await;
    let (_, interim) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(other, 4096, FILE_NOTIFY_CHANGE_FILE_NAME),
        )
        .await;
    let async_id = header(&interim).async_id().expect("waiting");
    open_dir(&mut maker, &state, "e\\sub").await;
    create_file(&mut maker, &state, "e\\f").await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [added("f")]
    );
}

#[tokio::test]
async fn changes_buffered_between_requests_come_back_at_once_in_order() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let (_, async_id) = wait_notify(&mut watcher, &state, dir).await;
    create_file(&mut maker, &state, "d\\a").await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [added("a")]
    );

    create_file(&mut maker, &state, "d\\b").await;
    open_dir(&mut maker, &state, "d\\c").await;
    delete_file(&mut maker, &state, "d\\a").await;
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(dir, 4096, NAMES),
        )
        .await;
    assert_eq!(status(&reply), 0);
    assert_eq!(header(&reply).flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
    assert_eq!(
        entries(&reply),
        [
            added("b"),
            added("c"),
            (FILE_ACTION_REMOVED, "a".to_string())
        ]
    );
}

#[tokio::test]
async fn waiting_requests_complete_one_per_change_oldest_first() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let (_, first) = wait_notify(&mut watcher, &state, dir).await;
    let (_, second) = wait_notify(&mut watcher, &state, dir).await;

    create_file(&mut maker, &state, "d\\a").await;
    assert_eq!(entries(&final_of(&mut watcher, first).await), [added("a")]);
    settle().await;
    assert!(watcher.rx.try_recv().is_none());
    create_file(&mut maker, &state, "d\\b").await;
    assert_eq!(entries(&final_of(&mut watcher, second).await), [added("b")]);
}

#[tokio::test]
async fn a_cancelled_request_leaves_later_changes_to_the_next() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let (mid, async_id) = wait_notify(&mut watcher, &state, dir).await;
    let cancel = watcher.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    assert!(watcher.dispatch(&state, &cancel).await.is_none());
    let last = final_of(&mut watcher, async_id).await;
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);

    create_file(&mut maker, &state, "d\\a").await;
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(dir, 4096, NAMES),
        )
        .await;
    assert_eq!(entries(&reply), [added("a")]);
}

#[tokio::test]
async fn a_change_and_a_cancel_get_exactly_one_response_whichever_comes_first() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;

    // The change wins: the CANCEL that follows finds nothing to cancel.
    let (mid, async_id) = wait_notify(&mut watcher, &state, dir).await;
    create_file(&mut maker, &state, "d\\a").await;
    let last = final_of(&mut watcher, async_id).await;
    assert_eq!(status(&last), 0);
    assert_eq!(entries(&last), [added("a")]);
    let cancel = watcher.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    assert!(watcher.dispatch(&state, &cancel).await.is_none());
    settle().await;
    assert!(watcher.rx.try_recv().is_none(), "one response only");

    // The CANCEL wins over a change made before the request runs again,
    // and the change stays for the next request.
    let (mid, async_id) = wait_notify(&mut watcher, &state, dir).await;
    let cancel = watcher.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    assert!(watcher.dispatch(&state, &cancel).await.is_none());
    create_file(&mut maker, &state, "d\\b").await;
    let last = final_of(&mut watcher, async_id).await;
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
    settle().await;
    assert!(watcher.rx.try_recv().is_none(), "one response only");
    assert_eq!(watcher.conn.pending.len(), 0);
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(dir, 4096, NAMES),
        )
        .await;
    assert_eq!(entries(&reply), [added("b")]);
}

/// A watcher on `d` whose CHANGE_NOTIFY waits; returns the watcher, the
/// directory's FileId and the request's AsyncId.
async fn waiting(state: &Arc<ServerState>, signed: bool) -> (Peer, FileId, u64) {
    let mut watcher = Peer::new(state, signed).await;
    let dir = open_dir(&mut watcher, state, "d").await;
    let (_, async_id) = wait_notify(&mut watcher, state, dir).await;
    (watcher, dir, async_id)
}

/// Checks that `last` ends a waiting CHANGE_NOTIFY with
/// STATUS_NOTIFY_CLEANUP in a CHANGE_NOTIFY body, and that the watch is
/// gone.
async fn assert_cleanup(state: &Arc<ServerState>, watcher: &Peer, last: &[u8]) {
    assert_eq!(status(last), ntstatus::STATUS_NOTIFY_CLEANUP);
    assert_eq!(
        last[SMB2_HEADER_LEN..],
        [9, 0, 0x48, 0, 0, 0, 0, 0],
        "an empty CHANGE_NOTIFY body"
    );
    settle().await;
    assert_eq!(home(state).await.watches.len(), 0);
    assert_eq!(watcher.conn.notify_budget.watches(), 0);
}

#[tokio::test]
async fn closing_the_directory_ends_waiting_requests_with_cleanup() {
    let (state, _) = server();
    let (mut watcher, dir, async_id) = waiting(&state, false).await;
    close(&mut watcher, &state, dir).await;
    let last = final_of(&mut watcher, async_id).await;
    assert_cleanup(&state, &watcher, &last).await;
}

#[tokio::test]
async fn tree_disconnect_ends_waiting_requests_with_cleanup() {
    let (state, _) = server();
    let (mut watcher, _, async_id) = waiting(&state, false).await;
    let (_, reply) = watcher
        .request(&state, Command::TreeDisconnect, &[4, 0, 0, 0])
        .await;
    assert_eq!(status(&reply), 0);
    let last = final_of(&mut watcher, async_id).await;
    assert_cleanup(&state, &watcher, &last).await;
}

#[tokio::test]
async fn logoff_ends_waiting_requests_with_cleanup_signed_by_the_old_session() {
    let (state, _) = server();
    let (mut watcher, _, async_id) = waiting(&state, true).await;
    let (_, reply) = watcher
        .request(&state, Command::Logoff, &[4, 0, 0, 0])
        .await;
    assert_eq!(status(&reply), 0);
    let last = final_of(&mut watcher, async_id).await;
    assert!(verify(&last, &KEY, SigningAlgo::AesCmac).is_ok());
    assert_cleanup(&state, &watcher, &last).await;
}

#[tokio::test]
async fn removing_the_share_ends_waiting_requests_with_cleanup() {
    let (state, config) = server();
    let (mut watcher, _, async_id) = waiting(&state, false).await;
    state.active_connections.register(&watcher.conn).await;
    let share = home(&state).await;
    config.remove_share("home").await.expect("removed");
    let last = final_of(&mut watcher, async_id).await;
    assert_eq!(status(&last), ntstatus::STATUS_NOTIFY_CLEANUP);
    settle().await;
    assert_eq!(share.watches.len(), 0);
}

#[tokio::test]
async fn connection_teardown_cancels_waiting_requests_and_drops_the_watch() {
    let (state, _) = server();
    let (mut watcher, _, async_id) = waiting(&state, false).await;
    watcher.drop_connection(&state).await;
    let last = final_of(&mut watcher, async_id).await;
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
    assert_eq!(watcher.conn.pending.len(), 0);
    assert_eq!(home(&state).await.watches.len(), 0);
    assert_eq!(watcher.conn.notify_budget.watches(), 0);
}

#[tokio::test]
async fn handles_buffer_on_their_own_and_start_empty() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let first = open_dir(&mut watcher, &state, "d").await;
    let second = open_dir(&mut watcher, &state, "d").await;
    let (_, async_id) = wait_notify(&mut watcher, &state, first).await;
    create_file(&mut maker, &state, "d\\a").await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [added("a")]
    );

    // The second handle saw nothing before its first request.
    let (_, async_id) = wait_notify(&mut watcher, &state, second).await;
    create_file(&mut maker, &state, "d\\b").await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [added("b")]
    );
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(first, 4096, NAMES),
        )
        .await;
    assert_eq!(entries(&reply), [added("b")]);
}

#[tokio::test]
async fn a_waiting_notify_in_the_middle_of_a_compound_fails() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let (_, create) = watcher.message(
        Command::Create,
        &create_body("d", LIST, FILE_OPEN_IF, FILE_DIRECTORY_FILE),
    );
    let (_, notify) = watcher.message(
        Command::ChangeNotify,
        &notify_body(FileId::any(), 4096, NAMES),
    );
    let (_, query) = watcher.message(Command::QueryInfo, &query_info_body(FileId::any()));
    let frame = watcher
        .dispatch(&state, &compound(&[create, notify, query], true))
        .await
        .expect("a response");
    let statuses: Vec<_> = split(&frame).into_iter().map(status).collect();
    assert_eq!(
        statuses,
        [0, ntstatus::STATUS_INTERNAL_ERROR, 0],
        "CREATE, CHANGE_NOTIFY, QUERY_INFO"
    );
    assert_eq!(watcher.conn.pending.len(), 0);
    // The refused request armed the watch.
    assert_eq!(home(&state).await.watches.len(), 1);
}

#[tokio::test]
async fn a_notify_last_in_a_compound_waits() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let (_, create) = watcher.message(
        Command::Create,
        &create_body("d", LIST, FILE_OPEN_IF, FILE_DIRECTORY_FILE),
    );
    let (notify_mid, notify) = watcher.message(
        Command::ChangeNotify,
        &notify_body(FileId::any(), 4096, NAMES),
    );
    let frame = watcher
        .dispatch(&state, &compound(&[create, notify], true))
        .await
        .expect("a response");
    let responses = split(&frame);
    assert_eq!(responses.len(), 2);
    assert_eq!(status(responses[0]), 0);
    let interim = header(responses[1]);
    assert_eq!(interim.channel_sequence_status, ntstatus::STATUS_PENDING);
    assert_eq!(interim.message_id, notify_mid);
    let async_id = interim.async_id().expect("an AsyncId");
    create_file(&mut maker, &state, "d\\a").await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [added("a")]
    );
}

#[tokio::test]
async fn a_notify_with_buffered_changes_works_anywhere_in_a_compound() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let (_, async_id) = wait_notify(&mut watcher, &state, dir).await;
    create_file(&mut maker, &state, "d\\a").await;
    final_of(&mut watcher, async_id).await;
    create_file(&mut maker, &state, "d\\b").await;

    let (_, notify) = watcher.message(Command::ChangeNotify, &notify_body(dir, 4096, NAMES));
    let (_, echo) = watcher.message(Command::Echo, &[4, 0, 0, 0]);
    let frame = watcher
        .dispatch(&state, &compound(&[notify, echo], false))
        .await
        .expect("a response");
    let responses = split(&frame);
    assert_eq!(status(responses[0]), 0);
    assert_eq!(entries(responses[0]), [added("b")]);
    assert_eq!(status(responses[1]), 0);
}

#[tokio::test]
async fn past_the_waiting_limit_a_notify_is_refused_and_its_watch_buffers() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let busy = open_dir(&mut watcher, &state, "d").await;
    let other = open_dir(&mut watcher, &state, "d").await;
    let mut queued = Vec::new();
    for _ in 0..crate::conn::pending::MAX_PENDING_REQUESTS {
        queued.push(wait_notify(&mut watcher, &state, busy).await.1);
    }
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(other, 4096, NAMES),
        )
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_INSUFFICIENT_RESOURCES);

    create_file(&mut maker, &state, "d\\a").await;
    assert_eq!(
        entries(&final_of(&mut watcher, queued[0]).await),
        [added("a")]
    );
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(other, 4096, NAMES),
        )
        .await;
    assert_eq!(entries(&reply), [added("a")]);
}

#[tokio::test]
async fn past_the_watch_limit_a_notify_is_refused() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    for _ in 0..MAX_WATCHES_PER_CONNECTION {
        let dir = open_dir(&mut watcher, &state, "d").await;
        let (mid, async_id) = wait_notify(&mut watcher, &state, dir).await;
        let cancel = watcher.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
        watcher.dispatch(&state, &cancel).await;
        let last = final_of(&mut watcher, async_id).await;
        assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
    }
    let dir = open_dir(&mut watcher, &state, "d").await;
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(dir, 4096, NAMES),
        )
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    assert_eq!(
        watcher.conn.notify_budget.watches(),
        MAX_WATCHES_PER_CONNECTION
    );
}

/// Memory backend whose opens that may create a file say they created it,
/// as when the file appeared between the backend creating it and the open
/// entering the file table.
struct ClaimsCreated(MemFsBackend);

#[async_trait::async_trait]
impl crate::ShareBackend for ClaimsCreated {
    async fn open(
        &self,
        path: &crate::SmbPath,
        opts: crate::OpenOptions,
    ) -> crate::SmbResult<(Box<dyn crate::Handle>, crate::OpenAction)> {
        let claims = !opts.directory && opts.intent == crate::OpenIntent::OpenOrCreate;
        let (handle, action) = self.0.open(path, opts).await?;
        Ok((
            handle,
            if claims {
                crate::OpenAction::Created
            } else {
                action
            },
        ))
    }

    async fn unlink(&self, path: &crate::SmbPath) -> crate::SmbResult<()> {
        self.0.unlink(path).await
    }

    async fn rename(
        &self,
        from: &crate::SmbPath,
        to: &crate::SmbPath,
        replace: bool,
    ) -> crate::SmbResult<()> {
        self.0.rename(from, to, replace).await
    }

    fn capabilities(&self) -> crate::BackendCapabilities {
        self.0.capabilities()
    }
}

#[tokio::test]
async fn a_create_that_waits_for_a_lease_break_reports_its_file_once() {
    let files = MemFsBackend::new().with_file("d\\f.txt", b"data");
    let state = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("home", ClaimsCreated(files)).public())
        .build()
        .expect("build")
        .state();
    let mut watcher = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let (_, async_id) = wait_notify(&mut watcher, &state, dir).await;

    let mut holder = Peer::new(&state, false).await;
    let body = create_body_with("d\\f.txt", READ_WRITE, 1, 0, Some(0x7));
    let (_, reply) = holder.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0);
    let mut waiter = Peer::new(&state, false).await;
    let body = create_body("d\\f.txt", READ_WRITE, FILE_OPEN_IF, 0);
    let (_, interim) = waiter.request(&state, Command::Create, &body).await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [added("f.txt")]
    );

    let (_, async_id) = wait_notify(&mut watcher, &state, dir).await;
    let mut ack = Vec::new();
    LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: LEASE_KEY,
        lease_state: 0x3,
        lease_duration: 0,
    }
    .write_to(&mut ack)
    .expect("ack");
    let (_, reply) = holder.request(&state, Command::OplockBreak, &ack).await;
    assert_eq!(status(&reply), 0);
    let created = tokio::time::timeout(Duration::from_secs(5), waiter.next())
        .await
        .expect("the CREATE completes in time");
    assert_eq!(status(&created), 0);

    let mut maker = Peer::new(&state, false).await;
    create_file(&mut maker, &state, "d\\z").await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [added("z")]
    );
}

/// Renames `name`, opened with `options`, to `to`, replacing an existing
/// target when `replace`.
async fn rename(
    peer: &mut Peer,
    state: &Arc<ServerState>,
    name: &str,
    to: &str,
    replace: bool,
    options: u32,
) {
    let status = rename_status(peer, state, name, to, replace, options).await;
    assert_eq!(status, 0, "rename {name} to {to}");
}

/// [`rename`], returning the status of the SET_INFO.
async fn rename_status(
    peer: &mut Peer,
    state: &Arc<ServerState>,
    name: &str,
    to: &str,
    replace: bool,
    options: u32,
) -> u32 {
    let body = create_body(name, DELETE | 0x80, 1, options);
    let (_, reply) = peer.request(state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0, "open {name} for renaming");
    let file_id = CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id;
    let target = crate::utils::utf16le(to);
    let mut buffer = vec![u8::from(replace)];
    buffer.extend_from_slice(&[0; 15]);
    buffer.extend_from_slice(&(target.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&target);
    let mut body = Vec::new();
    SetInfoRequest {
        structure_size: 33,
        info_type: 1,
        file_information_class: 10,
        buffer_length: buffer.len() as u32,
        buffer_offset: 0x60,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    }
    .write_to(&mut body)
    .expect("set info");
    let (_, reply) = peer.request(state, Command::SetInfo, &body).await;
    close(peer, state, file_id).await;
    status(&reply)
}

/// Arms a watch on `dir` and cancels the request, so later changes are
/// buffered with no request waiting.
async fn arm_idle(peer: &mut Peer, state: &Arc<ServerState>, dir: FileId, tree: bool) {
    arm_idle_with(peer, state, dir, NAMES, tree).await;
}

/// [`arm_idle`] with the filter `filter`.
async fn arm_idle_with(
    peer: &mut Peer,
    state: &Arc<ServerState>,
    dir: FileId,
    filter: u32,
    tree: bool,
) {
    let mut body = notify_body(dir, 4096, filter);
    body[2] = u8::from(tree);
    let (mid, interim) = peer.request(state, Command::ChangeNotify, &body).await;
    let async_id = header(&interim).async_id().expect("waiting");
    let cancel = peer.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    peer.dispatch(state, &cancel).await;
    let last = final_of(peer, async_id).await;
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
}

#[tokio::test]
async fn a_replaced_target_spelled_differently_is_removed_under_its_stored_name() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    create_file(&mut maker, &state, "d\\a").await;
    create_file(&mut maker, &state, "d\\t.txt").await;
    let (_, async_id) = wait_notify(&mut watcher, &state, dir).await;
    rename(&mut maker, &state, "d\\a", "d\\T.TXT", true, 0).await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [
            (FILE_ACTION_REMOVED, "t.txt".to_string()),
            (FILE_ACTION_RENAMED_OLD_NAME, "a".to_string()),
            (FILE_ACTION_RENAMED_NEW_NAME, "T.TXT".to_string()),
        ]
    );
}

#[tokio::test]
async fn a_change_of_case_removes_the_stored_name_first() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    create_file(&mut maker, &state, "d\\x.txt").await;
    let (_, async_id) = wait_notify(&mut watcher, &state, dir).await;
    rename(&mut maker, &state, "d\\x.txt", "d\\X.TXT", false, 0).await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [
            (FILE_ACTION_REMOVED, "x.txt".to_string()),
            (FILE_ACTION_RENAMED_OLD_NAME, "x.txt".to_string()),
            (FILE_ACTION_RENAMED_NEW_NAME, "X.TXT".to_string()),
        ]
    );
}

/// A point a backend call stops at until the test lets it go.
struct Gate {
    reached: tokio::sync::Semaphore,
    go: tokio::sync::Semaphore,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            reached: tokio::sync::Semaphore::new(0),
            go: tokio::sync::Semaphore::new(0),
        }
    }
}

impl Gate {
    async fn pass(&self) {
        self.reached.add_permits(1);
        self.go.acquire().await.expect("gate").forget();
    }

    /// Waits until a call stops here.
    async fn reached(&self) {
        let reached = self.reached.acquire();
        tokio::time::timeout(Duration::from_secs(5), reached)
            .await
            .expect("the gate is reached in time")
            .expect("gate")
            .forget();
    }

    fn open(&self) {
        self.go.add_permits(1);
    }
}

/// Memory backend whose creates of a file named `x`, and stats of handles
/// opened on such a file, stop at the gates given, and which counts the
/// renames that reach it. With `blind`, opening an existing directory
/// fails.
#[derive(Clone, Default)]
struct Gated {
    inner: MemFsBackend,
    create: Option<Arc<Gate>>,
    stat: Option<Arc<Gate>>,
    blind: bool,
    /// Handles take no creation time.
    drop_creation: bool,
    renames: Arc<std::sync::atomic::AtomicUsize>,
}

impl Gated {
    fn renames(&self) -> usize {
        self.renames.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn state(&self) -> Arc<ServerState> {
        SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("home", self.clone()).public())
            .build()
            .expect("build")
            .state()
    }
}

#[async_trait::async_trait]
impl crate::ShareBackend for Gated {
    async fn open(
        &self,
        path: &crate::SmbPath,
        opts: crate::OpenOptions,
    ) -> crate::SmbResult<(Box<dyn crate::Handle>, crate::OpenAction)> {
        if self.blind && opts.directory && opts.intent == crate::OpenIntent::Open {
            return Err(crate::SmbError::AccessDenied);
        }
        let gated = path.file_name() == Some("x");
        if gated
            && opts.intent == crate::OpenIntent::Create
            && let Some(gate) = &self.create
        {
            gate.pass().await;
        }
        let (handle, action) = self.inner.open(path, opts).await?;
        let stat = self.stat.as_ref().filter(|_| gated).map(Arc::clone);
        if stat.is_none() && !self.drop_creation {
            return Ok((handle, action));
        }
        let handle = GatedHandle {
            inner: handle,
            stat,
            drop_creation: self.drop_creation,
        };
        Ok((Box::new(handle), action))
    }

    async fn unlink(&self, path: &crate::SmbPath) -> crate::SmbResult<()> {
        self.inner.unlink(path).await
    }

    async fn rename(
        &self,
        from: &crate::SmbPath,
        to: &crate::SmbPath,
        replace: bool,
    ) -> crate::SmbResult<()> {
        self.renames
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.rename(from, to, replace).await
    }

    fn capabilities(&self) -> crate::BackendCapabilities {
        self.inner.capabilities()
    }
}

/// A handle whose `stat` stops at a gate, and which may drop creation
/// times.
struct GatedHandle {
    inner: Box<dyn crate::Handle>,
    stat: Option<Arc<Gate>>,
    drop_creation: bool,
}

#[async_trait::async_trait]
impl crate::Handle for GatedHandle {
    async fn read(&self, offset: u64, len: u32) -> crate::SmbResult<bytes::Bytes> {
        self.inner.read(offset, len).await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> crate::SmbResult<u32> {
        self.inner.write(offset, data).await
    }

    async fn flush(&self) -> crate::SmbResult<()> {
        self.inner.flush().await
    }

    async fn stat(&self) -> crate::SmbResult<crate::FileInfo> {
        if let Some(gate) = &self.stat {
            gate.pass().await;
        }
        self.inner.stat().await
    }

    async fn set_times(&self, mut times: crate::FileTimes) -> crate::SmbResult<()> {
        if self.drop_creation {
            times.creation_time = None;
        }
        self.inner.set_times(times).await
    }

    async fn set_attributes(&self, attributes: u32) -> crate::SmbResult<()> {
        self.inner.set_attributes(attributes).await
    }

    async fn truncate(&self, len: u64) -> crate::SmbResult<()> {
        self.inner.truncate(len).await
    }

    async fn list_dir(&self, pattern: Option<&str>) -> crate::SmbResult<Vec<crate::DirEntry>> {
        self.inner.list_dir(pattern).await
    }

    async fn close(self: Box<Self>) -> crate::SmbResult<()> {
        self.inner.close().await
    }
}

/// Opens `name` for reading and writing, creating it when `create`, and
/// keeps it open.
async fn hold_open(peer: &mut Peer, state: &Arc<ServerState>, name: &str, options: u32) -> FileId {
    let body = create_body(name, 0x0012_0116 | DELETE, FILE_OPEN_IF, options);
    let (_, reply) = peer.request(state, Command::Create, &body).await;
    assert_eq!(status(&reply), 0, "open {name}");
    CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id
}

#[tokio::test]
async fn a_directory_rename_waits_for_a_create_below_it_and_is_refused() {
    let gate = Arc::new(Gate::default());
    let backend = Gated {
        create: Some(Arc::clone(&gate)),
        ..Gated::default()
    };
    let state = backend.state();
    let mut watcher = Peer::new(&state, false).await;
    let top = open_dir(&mut watcher, &state, "d").await;
    let sub = open_dir(&mut watcher, &state, "d\\sub").await;
    arm_idle(&mut watcher, &state, top, true).await;
    arm_idle(&mut watcher, &state, sub, false).await;

    let mut maker = Peer::new(&state, false).await;
    let creating = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            let body = create_body("d\\sub\\x", 0x0012_0116, FILE_CREATE, 0);
            let (_, reply) = maker.request(&state, Command::Create, &body).await;
            assert_eq!(status(&reply), 0);
            let file_id = CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
                .expect("create response")
                .file_id;
            (maker, file_id)
        }
    });
    gate.reached().await;
    let mut renamer = Peer::new(&state, false).await;
    let renaming = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            let status = rename_status(
                &mut renamer,
                &state,
                "d\\sub",
                "d\\moved",
                false,
                FILE_DIRECTORY_FILE,
            )
            .await;
            (renamer, status)
        }
    });
    settle().await;
    assert_eq!(backend.renames(), 0, "the rename waits for the create");
    gate.open();
    let (mut maker, x) = creating.await.expect("create");
    let (mut renamer, refused) = renaming.await.expect("rename");
    // The new file is open below the directory.
    assert_eq!(refused, ntstatus::STATUS_ACCESS_DENIED);
    assert_eq!(backend.renames(), 0);

    close(&mut maker, &state, x).await;
    rename(
        &mut renamer,
        &state,
        "d\\sub",
        "d\\moved",
        false,
        FILE_DIRECTORY_FILE,
    )
    .await;
    create_file(&mut maker, &state, "d\\moved\\y").await;
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(sub, 4096, NAMES),
        )
        .await;
    assert_eq!(entries(&reply), [added("x"), added("y")]);
    let mut body = notify_body(top, 4096, NAMES);
    body[2] = 1;
    let (_, reply) = watcher.request(&state, Command::ChangeNotify, &body).await;
    assert_eq!(
        entries(&reply),
        [
            added("sub\\x"),
            (FILE_ACTION_RENAMED_OLD_NAME, "sub".to_string()),
            (FILE_ACTION_RENAMED_NEW_NAME, "moved".to_string()),
            added("moved\\y"),
        ]
    );
}

#[tokio::test]
async fn a_created_file_enters_the_file_table_before_a_rename_runs() {
    let gate = Arc::new(Gate::default());
    let backend = Gated {
        stat: Some(Arc::clone(&gate)),
        ..Gated::default()
    };
    let state = backend.state();
    let mut maker = Peer::new(&state, false).await;
    open_dir(&mut maker, &state, "d").await;
    let creating = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            let body = create_body("d\\x", 0x0012_0116, FILE_CREATE, 0);
            let (_, reply) = maker.request(&state, Command::Create, &body).await;
            (maker, status(&reply))
        }
    });
    gate.reached().await;
    let mut renamer = Peer::new(&state, false).await;
    let renaming = tokio::spawn({
        let state = Arc::clone(&state);
        async move { rename_status(&mut renamer, &state, "d", "e", false, FILE_DIRECTORY_FILE).await }
    });
    settle().await;
    assert_eq!(backend.renames(), 0, "the rename waits for the create");
    gate.open();
    let (_maker, created) = creating.await.expect("create");
    assert_eq!(created, 0);
    assert_eq!(
        renaming.await.expect("rename"),
        ntstatus::STATUS_ACCESS_DENIED
    );
    let share = home(&state).await;
    assert!(share.files.path_is_open(&"d\\x".parse().unwrap(), false));
}

#[tokio::test]
async fn a_delete_that_waited_for_a_rename_removes_the_file_by_its_new_name() {
    let gate = Arc::new(Gate::default());
    let backend = Gated {
        create: Some(Arc::clone(&gate)),
        ..Gated::default()
    };
    let state = backend.state();
    let share = home(&state).await;
    let mut watcher = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    open_dir(&mut watcher, &state, "o").await;
    let mut deleter = Peer::new(&state, false).await;
    let doomed = hold_open(&mut deleter, &state, "d\\f", FILE_DELETE_ON_CLOSE).await;
    arm_idle(&mut watcher, &state, dir, false).await;

    // A create elsewhere holds renames off while the rename queues, and
    // the delete then queues behind the rename.
    let mut maker = Peer::new(&state, false).await;
    let creating = tokio::spawn({
        let state = Arc::clone(&state);
        async move { create_file(&mut maker, &state, "o\\x").await }
    });
    gate.reached().await;
    let mut renamer = Peer::new(&state, false).await;
    let renaming = tokio::spawn({
        let state = Arc::clone(&state);
        async move { rename(&mut renamer, &state, "d", "e", false, FILE_DIRECTORY_FILE).await }
    });
    settle().await;
    let closing = tokio::spawn({
        let state = Arc::clone(&state);
        async move { close(&mut deleter, &state, doomed).await }
    });
    let pending = "d\\f".parse().unwrap();
    for _ in 0..100 {
        if share.files.delete_pending_at(&pending, false) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(share.files.delete_pending_at(&pending, false));
    settle().await;
    assert_eq!(backend.renames(), 0);
    {
        use crate::ShareBackend as _;
        let opts = crate::OpenOptions::default();
        let f = backend.inner.open(&pending, opts).await;
        assert!(f.is_ok(), "the delete waits behind the rename");
        f.unwrap().0.close().await.unwrap();
    }
    gate.open();
    creating.await.expect("create");
    renaming.await.expect("rename");
    closing.await.expect("close");

    use crate::ShareBackend as _;
    let opts = crate::OpenOptions::default();
    for gone in ["d\\f", "e\\f"] {
        let path: crate::SmbPath = gone.parse().unwrap();
        assert!(backend.inner.open(&path, opts).await.is_err(), "{gone}");
    }
    let (_, reply) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(dir, 4096, NAMES),
        )
        .await;
    assert_eq!(entries(&reply), [(FILE_ACTION_REMOVED, "f".to_string())]);
}

#[tokio::test]
async fn names_below_a_renamed_directory_compare_without_case() {
    let (state, _) = server();
    let mut holder = Peer::new(&state, false).await;
    open_dir(&mut holder, &state, "D").await;
    open_dir(&mut holder, &state, "D\\SUB").await;
    hold_open(&mut holder, &state, "D\\SUB\\x", 0).await;
    let mut renamer = Peer::new(&state, false).await;
    open_dir(&mut renamer, &state, "d").await;
    let status = rename_status(&mut renamer, &state, "d", "e", false, FILE_DIRECTORY_FILE).await;
    assert_eq!(status, ntstatus::STATUS_ACCESS_DENIED);
}

#[tokio::test]
async fn a_rename_whose_stored_name_cannot_be_looked_up_is_reported_as_a_rename() {
    let backend = Gated {
        blind: true,
        ..Gated::default()
    };
    let state = backend.state();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    create_file(&mut maker, &state, "d\\a").await;
    create_file(&mut maker, &state, "d\\t").await;
    let (_, async_id) = wait_notify(&mut watcher, &state, dir).await;
    rename(&mut maker, &state, "d\\a", "d\\t", true, 0).await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [
            (FILE_ACTION_RENAMED_OLD_NAME, "a".to_string()),
            (FILE_ACTION_RENAMED_NEW_NAME, "t".to_string()),
        ]
    );
}

/// What a request on the armed watch `dir` gets at once, or `None` when it
/// would wait; such a request is cancelled.
async fn now(peer: &mut Peer, state: &Arc<ServerState>, dir: FileId) -> Option<Vec<(u32, String)>> {
    let (mid, reply) = peer
        .request(state, Command::ChangeNotify, &notify_body(dir, 4096, NAMES))
        .await;
    if status(&reply) != ntstatus::STATUS_PENDING {
        return Some(entries(&reply));
    }
    let async_id = header(&reply).async_id().expect("waiting");
    let cancel = peer.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    peer.dispatch(state, &cancel).await;
    let last = final_of(peer, async_id).await;
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
    None
}

fn modified(name: &str) -> (u32, String) {
    (
        crate::proto::messages::change_notify::FILE_ACTION_MODIFIED,
        name.to_string(),
    )
}

async fn set_info(
    peer: &mut Peer,
    state: &Arc<ServerState>,
    file_id: FileId,
    class: u8,
    buffer: Vec<u8>,
) -> u32 {
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
    status(&peer.request(state, Command::SetInfo, &body).await.1)
}

async fn write(peer: &mut Peer, state: &Arc<ServerState>, file_id: FileId, data: &[u8]) {
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
    assert_eq!(
        status(&peer.request(state, Command::Write, &body).await.1),
        0
    );
}

const CREATION: u32 = 0x40;
const LAST_ACCESS: u32 = 0x20;
const LAST_WRITE: u32 = 0x10;
const SIZE: u32 = 0x8;
const ATTRIBUTES: u32 = 0x4;
/// The filter macOS clients use.
const MACOS: u32 = 0xD47;

#[tokio::test]
async fn times_set_through_basic_info_are_reported_under_their_bits() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let filters = [CREATION, LAST_ACCESS, LAST_WRITE, ATTRIBUTES];
    let mut watches = Vec::new();
    for filter in filters {
        let dir = open_dir(&mut watcher, &state, "d").await;
        arm_idle_with(&mut watcher, &state, dir, filter, false).await;
        watches.push(dir);
    }
    // f0 gets a creation time, f1 an access time, f2 a write time, f3 a
    // change time; the change time alone reports nothing.
    let mut files = Vec::new();
    for at in 0..4 {
        let name = format!("d\\f{at}");
        let file = hold_open(&mut maker, &state, &name, 0).await;
        let mut buffer = vec![0u8; 40];
        buffer[at * 8..at * 8 + 8].copy_from_slice(&0x01D0_0000_0000_0000u64.to_le_bytes());
        assert_eq!(set_info(&mut maker, &state, file, 4, buffer).await, 0);
        files.push(file);
    }
    // Reported while the files are still open.
    for (at, dir) in watches.into_iter().enumerate() {
        let expected = (at < 3).then(|| vec![modified(&format!("f{at}"))]);
        assert_eq!(
            now(&mut watcher, &state, dir).await,
            expected,
            "filter {:#x}",
            filters[at]
        );
    }
    for file in files {
        close(&mut maker, &state, file).await;
    }
}

#[tokio::test]
async fn a_write_is_reported_once_when_its_open_closes() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut writer = Peer::new(&state, false).await;
    let times = open_dir(&mut watcher, &state, "d").await;
    let macos = open_dir(&mut watcher, &state, "d").await;
    let names = open_dir(&mut watcher, &state, "d").await;
    let file = hold_open(&mut writer, &state, "d\\f", 0).await;
    arm_idle_with(&mut watcher, &state, macos, MACOS, false).await;
    arm_idle_with(&mut watcher, &state, names, NAMES, false).await;
    let (_, interim) = watcher
        .request(
            &state,
            Command::ChangeNotify,
            &notify_body(times, 4096, LAST_WRITE),
        )
        .await;
    let async_id = header(&interim).async_id().expect("waiting");

    write(&mut writer, &state, file, b"one").await;
    write(&mut writer, &state, file, b"two").await;
    settle().await;
    assert!(watcher.rx.try_recv().is_none(), "nothing before the close");
    close(&mut writer, &state, file).await;
    assert_eq!(
        entries(&final_of(&mut watcher, async_id).await),
        [modified("f")]
    );
    // ATTRIBUTES goes with every content change.
    assert_eq!(
        now(&mut watcher, &state, macos).await,
        Some(vec![modified("f")])
    );
    assert_eq!(now(&mut watcher, &state, names).await, None);
    assert_eq!(now(&mut watcher, &state, times).await, None);

    // A close that deletes the written file reports the removal only.
    let file = hold_open(&mut writer, &state, "d\\g", FILE_DELETE_ON_CLOSE).await;
    assert_eq!(
        now(&mut watcher, &state, names).await,
        Some(vec![added("g")])
    );
    write(&mut writer, &state, file, b"gone").await;
    close(&mut writer, &state, file).await;
    assert_eq!(
        now(&mut watcher, &state, macos).await,
        Some(vec![added("g"), (FILE_ACTION_REMOVED, "g".to_string())])
    );
}

#[tokio::test]
async fn size_changes_are_reported_once_and_an_unchanged_size_not_at_all() {
    let (state, _) = server();
    let share = home(&state).await;
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let file = hold_open(&mut maker, &state, "d\\f", 0).await;
    write(&mut maker, &state, file, b"0123456789").await;
    arm_idle_with(&mut watcher, &state, dir, SIZE, false).await;
    let size = |n: u64| n.to_le_bytes().to_vec();

    // FileEndOfFileInformation: one report for one change.
    let pushes = share.watches.pushes();
    assert_eq!(set_info(&mut maker, &state, file, 20, size(4)).await, 0);
    assert_eq!(share.watches.pushes() - pushes, 1);
    assert_eq!(
        now(&mut watcher, &state, dir).await,
        Some(vec![modified("f")])
    );
    assert_eq!(set_info(&mut maker, &state, file, 20, size(4)).await, 0);
    assert_eq!(now(&mut watcher, &state, dir).await, None, "the same size");
    assert_eq!(set_info(&mut maker, &state, file, 20, size(8)).await, 0);
    assert_eq!(
        now(&mut watcher, &state, dir).await,
        Some(vec![modified("f")])
    );
    // FileAllocationInformation past the end changes nothing; below it,
    // it truncates.
    assert_eq!(set_info(&mut maker, &state, file, 19, size(4096)).await, 0);
    assert_eq!(now(&mut watcher, &state, dir).await, None);
    assert_eq!(set_info(&mut maker, &state, file, 19, size(2)).await, 0);
    assert_eq!(
        now(&mut watcher, &state, dir).await,
        Some(vec![modified("f")])
    );

    // A directory has no size to set.
    let sub = create_body(
        "d\\sub",
        0x2 | 0x0012_0089,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE,
    );
    let (_, reply) = maker.request(&state, Command::Create, &sub).await;
    let sub = CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id;
    assert_eq!(
        set_info(&mut maker, &state, sub, 20, size(0)).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(now(&mut watcher, &state, dir).await, None);
}

#[tokio::test]
async fn cleanup_waits_until_the_close_response_is_queued() {
    let (state, _) = server();
    let (mut watcher, dir, async_id) = waiting(&state, false).await;
    let (_, close) = watcher.message(Command::Close, &close_body(dir));
    let out = crate::dispatch::dispatch_frame(&state, &watcher.conn, &close)
        .await
        .expect("a response");
    assert_eq!(status(&out.bytes), 0);
    settle().await;
    assert!(
        watcher.rx.try_recv().is_none(),
        "nothing before the CLOSE response"
    );
    drop(out.after_send);
    let last = final_of(&mut watcher, async_id).await;
    assert_cleanup(&state, &watcher, &last).await;
}

#[tokio::test]
async fn a_basic_info_that_changes_nothing_reports_nothing() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let file = hold_open(&mut maker, &state, "d\\f", 0).await;
    arm_idle_with(&mut watcher, &state, dir, 0xFFF, false).await;
    let basic = |time: i64, attributes: u32| {
        let mut buffer = Vec::with_capacity(40);
        for _ in 0..4 {
            buffer.extend_from_slice(&time.to_le_bytes());
        }
        buffer.extend_from_slice(&attributes.to_le_bytes());
        buffer.extend_from_slice(&[0; 4]);
        buffer
    };
    // Times left alone, kept as they are or released, the attributes the
    // file has, ARCHIVE the backend does not keep, the times it has.
    for (time, attributes) in [
        (0, 0),
        (-1, 0),
        (-2, 0),
        (0, 0x80),
        (0, 0x20),
        (0x01D9_0000_0000_0000, 0),
    ] {
        let status = set_info(&mut maker, &state, file, 4, basic(time, attributes)).await;
        assert_eq!(status, 0, "{time:#x} {attributes:#x}");
    }
    assert_eq!(now(&mut watcher, &state, dir).await, None);
}

#[tokio::test]
async fn a_time_the_backend_drops_is_not_reported() {
    let backend = Gated {
        drop_creation: true,
        ..Gated::default()
    };
    let state = backend.state();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let creation = open_dir(&mut watcher, &state, "d").await;
    let write_time = open_dir(&mut watcher, &state, "d").await;
    let file = hold_open(&mut maker, &state, "d\\f", 0).await;
    arm_idle_with(&mut watcher, &state, creation, CREATION, false).await;
    arm_idle_with(&mut watcher, &state, write_time, LAST_WRITE, false).await;
    let mut buffer = vec![0u8; 40];
    buffer[0..8].copy_from_slice(&0x01D0_0000_0000_0000u64.to_le_bytes());
    buffer[16..24].copy_from_slice(&0x01D0_0000_0000_0000u64.to_le_bytes());
    assert_eq!(set_info(&mut maker, &state, file, 4, buffer).await, 0);
    assert_eq!(now(&mut watcher, &state, creation).await, None);
    assert_eq!(
        now(&mut watcher, &state, write_time).await,
        Some(vec![modified("f")])
    );
}

#[tokio::test]
async fn a_directory_s_attributes_are_reported_to_its_parent_s_watchers() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut maker = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let body = create_body("d\\sub", 0x100 | 0x80, FILE_OPEN_IF, FILE_DIRECTORY_FILE);
    let (_, reply) = maker.request(&state, Command::Create, &body).await;
    let sub = CreateResponse::parse(&reply[SMB2_HEADER_LEN..])
        .expect("create response")
        .file_id;
    arm_idle_with(&mut watcher, &state, dir, ATTRIBUTES, false).await;
    let mut buffer = vec![0u8; 40];
    buffer[32..36].copy_from_slice(&0x1u32.to_le_bytes());
    assert_eq!(set_info(&mut maker, &state, sub, 4, buffer).await, 0);
    assert_eq!(
        now(&mut watcher, &state, dir).await,
        Some(vec![modified("sub")])
    );
}

#[tokio::test]
async fn a_written_open_ended_with_its_tree_session_or_connection_reports_the_write() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    arm_idle_with(&mut watcher, &state, dir, LAST_WRITE, false).await;
    for (at, end) in [Command::TreeDisconnect, Command::Logoff, Command::Echo]
        .into_iter()
        .enumerate()
    {
        let mut writer = Peer::new(&state, false).await;
        let name = format!("d\\f{at}");
        let file = hold_open(&mut writer, &state, &name, 0).await;
        write(&mut writer, &state, file, b"data").await;
        assert_eq!(now(&mut watcher, &state, dir).await, None, "{end:?}");
        if end == Command::Echo {
            writer.drop_connection(&state).await;
        } else {
            let (_, reply) = writer.request(&state, end, &[4, 0, 0, 0]).await;
            assert_eq!(status(&reply), 0);
        }
        assert_eq!(
            now(&mut watcher, &state, dir).await,
            Some(vec![modified(&format!("f{at}"))]),
            "{end:?}"
        );
    }
}

#[tokio::test]
async fn a_write_is_reported_under_the_name_the_file_has_at_close() {
    let (state, _) = server();
    let mut watcher = Peer::new(&state, false).await;
    let mut writer = Peer::new(&state, false).await;
    let dir = open_dir(&mut watcher, &state, "d").await;
    let file = hold_open(&mut writer, &state, "d\\f", 0).await;
    arm_idle_with(&mut watcher, &state, dir, LAST_WRITE, false).await;
    write(&mut writer, &state, file, b"data").await;
    let mut renamer = Peer::new(&state, false).await;
    rename(&mut renamer, &state, "d\\f", "d\\g", false, 0).await;
    close(&mut writer, &state, file).await;
    assert_eq!(
        now(&mut watcher, &state, dir).await,
        Some(vec![modified("g")])
    );
}
