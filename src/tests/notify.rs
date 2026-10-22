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
    FILE_ACTION_ADDED, FILE_ACTION_REMOVED, FILE_NOTIFY_CHANGE_FILE_NAME,
};
use crate::proto::messages::{
    ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CreateContext, CreateRequest,
    CreateResponse, FileId, LeaseBreakAck, LeaseContext, QueryInfoRequest,
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
        [9, 0, 0x48, 0, 0, 0, 0, 0, 0],
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
