//! Handle caching: breaks that need an acknowledgment, requests answered
//! asynchronously while a break completes, cancellation, and compounds.

#![cfg(feature = "localfs")]

mod common;

use std::time::Duration;

use common::auth::status;
use common::client::*;
use common::crypto::{Cipher, EncryptedSession, is_transform};
use common::lease::*;
use common::{message, start_server};
use smb_server::ntstatus;
use smb_server::wire::header::{Command, SMB2_FLAGS_ASYNC_COMMAND, Smb2Header};
use smb_server::wire::messages::{
    CloseRequest, CreateResponse, FileId, LeaseBreakAck, LeaseBreakNotification, LeaseContext,
    QueryInfoRequest, SetInfoRequest,
};
use smb_server::{Share, SmbServer};
use tempfile::{TempDir, tempdir};
use tokio::io::AsyncWriteExt;

const RH: u32 = LEASE_READ_CACHING | LEASE_HANDLE_CACHING;
const R: u32 = LEASE_READ_CACHING;
const KEY_A: [u8; 16] = [0xA1; 16];
const KEY_B: [u8; 16] = [0xB2; 16];
const WAIT: Duration = Duration::from_secs(5);
const RELATED: FileId = FileId::new(u64::MAX, u64::MAX);

/// A server with public share `share` holding `f.txt`, `g.txt` and
/// `d\f.txt`.
async fn server() -> (Server, TempDir) {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"contents").unwrap();
    std::fs::write(td.path().join("g.txt"), b"other").unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    std::fs::write(td.path().join("d").join("f.txt"), b"inner").unwrap();
    (Server::public(local(td.path())).await, td)
}

/// Opens `name` sharing `share`, asking for RWH under `key`; checks that RH
/// is granted.
async fn hold_rh(c: &mut Client, name: &str, key: [u8; 16], share: u32) -> FileId {
    let resp = c
        .create(Create {
            share,
            ..leased(name, rqls_v1(key, RWH))
        })
        .await
        .expect("create");
    let lease = lease_reply(&resp).expect("lease context");
    assert_eq!((lease.key, lease.state), (key, RH));
    resp.file_id
}

/// A CREATE of `name` asking for DELETE, which a holder that does not share
/// delete access refuses.
fn deleting(name: &str) -> Create<'_> {
    Create {
        name,
        access: DELETE | FILE_READ_ATTRIBUTES,
        ..Create::default()
    }
}

fn assert_break(n: &LeaseBreakNotification, key: [u8; 16], from: u32, to: u32) {
    assert_eq!(n.lease_key, key);
    assert_eq!(
        n.flags,
        LeaseBreakNotification::FLAG_ACK_REQUIRED,
        "a lease caching handles needs an acknowledgment"
    );
    assert_eq!((n.current_lease_state, n.new_lease_state), (from, to));
}

/// Acknowledges a break of `key` with `state`; returns the status and the
/// state the response reports.
async fn ack(c: &mut Client, key: [u8; 16], state: u32) -> (u32, Option<u32>) {
    let (status, body) = c
        .send(Command::OplockBreak, &lease_ack_body(key, state))
        .await;
    let reported = (status == 0).then(|| LeaseBreakAck::parse(&body).unwrap().lease_state);
    (status, reported)
}

/// Checks the final response of an asynchronous request: ASYNC with the
/// AsyncId its interim response gave, and no credits.
fn assert_final(frame: &[u8], async_id: u64) -> Smb2Header {
    let (hdr, _) = Smb2Header::parse(frame).unwrap();
    assert_ne!(hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
    assert_eq!(hdr.async_id(), Some(async_id));
    assert_eq!(hdr.credit_request_response, 0);
    hdr
}

fn rename_body(file_id: FileId, to: &str, replace: bool) -> Vec<u8> {
    let name = common::utf16le(to);
    let mut buffer = vec![u8::from(replace)];
    buffer.extend_from_slice(&[0; 15]);
    buffer.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&name);
    let mut body = Vec::new();
    SetInfoRequest {
        structure_size: 33,
        info_type: 1,
        file_information_class: FILE_RENAME_INFORMATION,
        buffer_length: buffer.len() as u32,
        buffer_offset: 0x60,
        reserved: 0,
        additional_information: 0,
        file_id,
        buffer,
    }
    .write_to(&mut body)
    .unwrap();
    body
}

#[tokio::test]
async fn clients_with_different_keys_both_cache_handles() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = Client::connect_with(server.addr, None, [0x11; 16], "share").await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_ALL).await;
    hold_rh(&mut b, "f.txt", KEY_B, SHARE_ALL).await;
    assert!(a.drain_breaks().await.is_empty());
}

#[tokio::test]
async fn a_sharing_violation_waits_while_the_holder_closes_its_cached_handle() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let fa = hold_rh(&mut a, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;

    let mid = b
        .send_no_wait(Command::Create, &deleting("f.txt").body())
        .await;
    let async_id = b.recv_interim(mid).await;
    assert_ne!(async_id, 0);
    let n = a.next_break(WAIT).await.expect("handle break");
    assert_break(&n, KEY_A, RH, R);

    a.close(fa).await;
    let frame = b.recv_frame(mid).await;
    let hdr = assert_final(&frame, async_id);
    assert_eq!(hdr.channel_sequence_status, 0, "CREATE succeeds");
    // The lease ended with its last open.
    assert_eq!(
        ack(&mut a, KEY_A, R).await.0,
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_handle_kept_after_the_break_fails_the_waiting_open() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;
    let mid = b
        .send_no_wait(Command::Create, &deleting("f.txt").body())
        .await;
    b.recv_interim(mid).await;
    a.next_break(WAIT).await.expect("handle break");
    assert_eq!(ack(&mut a, KEY_A, R).await, (0, Some(R)));
    let (status, _) = b.recv(mid, Command::Create).await;
    assert_eq!(status, ntstatus::STATUS_SHARING_VIOLATION);
}

#[tokio::test]
async fn one_connection_waits_for_its_own_handle_break() {
    let (server, _td) = server().await;
    for second_key in [Some(KEY_B), None] {
        let mut c = server.client().await;
        let first = hold_rh(&mut c, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;
        let contexts = second_key.map(|key| rqls_v1(key, RWH)).unwrap_or_default();
        let create = Create {
            oplock: if second_key.is_some() {
                OPLOCK_LEVEL_LEASE
            } else {
                0
            },
            contexts,
            ..deleting("f.txt")
        };
        let mid = c.send_no_wait(Command::Create, &create.body()).await;
        c.recv_interim(mid).await;
        let n = c
            .next_break(WAIT)
            .await
            .expect("break on the same connection");
        assert_break(&n, KEY_A, RH, R);
        // The connection keeps answering while the CREATE waits.
        c.close(first).await;
        let (status, body) = c.recv(mid, Command::Create).await;
        assert_eq!(status, 0, "{second_key:?}");
        let resp = CreateResponse::parse(&body).unwrap();
        match second_key {
            Some(key) => {
                let lease = lease_reply(&resp).expect("lease");
                assert_eq!((lease.key, lease.state), (key, RH));
            }
            None => assert_eq!(lease_data(&resp), None),
        }
        c.close(resp.file_id).await;
    }
}

#[tokio::test]
async fn acknowledgments_are_checked_against_the_break() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_ALL).await;
    let fb = b.open("f.txt", RW, SHARE_ALL).await.unwrap();
    // The write completes without waiting for the acknowledgment.
    b.write(fb, 0, b"x").await.unwrap();
    let n = a.next_break(WAIT).await.expect("break");
    assert_break(&n, KEY_A, RH, 0);

    assert_eq!(
        ack(&mut a, KEY_A, R).await.0,
        ntstatus::STATUS_REQUEST_NOT_ACCEPTED
    );
    // Another open with the key during the break promotes nothing.
    let again = a
        .create(leased("f.txt", rqls_v1(KEY_A, RWH)))
        .await
        .unwrap();
    let lease = lease_reply(&again).unwrap();
    assert_eq!(lease.state, RH);
    assert_eq!(lease.flags, LeaseContext::FLAG_BREAK_IN_PROGRESS);

    assert_eq!(ack(&mut a, KEY_A, 0).await, (0, Some(0)));
    assert_eq!(ack(&mut a, KEY_A, 0).await.0, ntstatus::STATUS_UNSUCCESSFUL);
    assert_eq!(
        ack(&mut a, KEY_B, 0).await.0,
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_rename_over_a_cached_target_waits_for_the_handle_break() {
    let (server, td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let fa = hold_rh(&mut a, "f.txt", KEY_A, SHARE_ALL).await;
    let src = b
        .open("g.txt", DELETE | FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    let mid = b
        .send_no_wait(Command::SetInfo, &rename_body(src, "f.txt", true))
        .await;
    let async_id = b.recv_interim(mid).await;
    let n = a.next_break(WAIT).await.expect("handle break");
    assert_break(&n, KEY_A, RH, R);
    a.close(fa).await;
    let frame = b.recv_frame(mid).await;
    assert_eq!(assert_final(&frame, async_id).channel_sequence_status, 0);
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"other");
}

#[tokio::test]
async fn a_rename_over_a_target_kept_open_is_refused() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_ALL).await;
    let src = b
        .open("g.txt", DELETE | FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    let mid = b
        .send_no_wait(Command::SetInfo, &rename_body(src, "f.txt", true))
        .await;
    b.recv_interim(mid).await;
    a.next_break(WAIT).await.expect("handle break");
    assert_eq!(ack(&mut a, KEY_A, R).await, (0, Some(R)));
    let (status, _) = b.recv(mid, Command::SetInfo).await;
    assert_eq!(status, ntstatus::STATUS_ACCESS_DENIED);
}

#[tokio::test]
async fn closing_the_renamed_open_ends_a_waiting_rename() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_ALL).await;
    let src = b
        .open("g.txt", DELETE | FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    let mid = b
        .send_no_wait(Command::SetInfo, &rename_body(src, "f.txt", true))
        .await;
    b.recv_interim(mid).await;
    b.close(src).await;
    let (status, _) = b.recv(mid, Command::SetInfo).await;
    assert_eq!(status, ntstatus::STATUS_FILE_CLOSED);
}

#[tokio::test]
async fn renames_and_deletes_break_handle_caching_without_waiting() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    // A file open below a renamed directory.
    hold_rh(&mut a, "d\\f.txt", KEY_A, SHARE_ALL).await;
    let dir = b
        .open_with_options("d", DELETE | FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    let (status, _) = b
        .send(Command::SetInfo, &rename_body(dir, "e", false))
        .await;
    assert_eq!(status, 0);
    let n = a.next_break(WAIT).await.expect("break below the directory");
    assert_break(&n, KEY_A, RH, R);

    // The renamed file itself.
    hold_rh(&mut a, "g.txt", KEY_B, SHARE_ALL).await;
    let g = b
        .open("g.txt", DELETE | FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    let (status, _) = b
        .send(Command::SetInfo, &rename_body(g, "h.txt", false))
        .await;
    assert_eq!(status, 0);
    let n = a.next_break(WAIT).await.expect("break of the renamed file");
    assert_break(&n, KEY_B, RH, R);

    // A file marked delete-pending.
    let key = [0xC3; 16];
    hold_rh(&mut a, "f.txt", key, SHARE_ALL).await;
    let f = b
        .open("f.txt", DELETE | FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    assert_eq!(b.set_delete(f, true).await, 0);
    let n = a.next_break(WAIT).await.expect("break of the deleted file");
    assert_break(&n, key, RH, R);
}

#[tokio::test]
async fn a_cancelled_create_ends_with_status_cancelled() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;

    let by_async_id = b
        .send_no_wait(Command::Create, &deleting("f.txt").body())
        .await;
    let async_id = b.recv_interim(by_async_id).await;
    let by_message_id = b
        .send_no_wait(Command::Create, &deleting("f.txt").body())
        .await;
    b.recv_interim(by_message_id).await;
    a.next_break(WAIT).await.expect("one break for both");

    b.cancel(by_async_id, Some(async_id)).await;
    let (status, _) = b.recv(by_async_id, Command::Create).await;
    assert_eq!(status, ntstatus::STATUS_CANCELLED);
    b.cancel(by_message_id, None).await;
    let (status, _) = b.recv(by_message_id, Command::Create).await;
    assert_eq!(status, ntstatus::STATUS_CANCELLED);

    // The holder's acknowledgment still completes the break.
    assert_eq!(ack(&mut a, KEY_A, R).await, (0, Some(R)));
    // A CANCEL for a finished request does nothing.
    b.cancel(by_async_id, Some(async_id)).await;
    assert!(b.drain_breaks().await.is_empty());
    assert!(b.frames.is_empty(), "no response follows the late CANCEL");
}

#[tokio::test]
async fn a_compound_waits_at_its_create_and_finishes_in_a_second_frame() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let fa = hold_rh(&mut a, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;

    let mut query = Vec::new();
    QueryInfoRequest {
        structure_size: 41,
        info_type: 1,
        file_information_class: FILE_STANDARD_INFORMATION,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: RELATED,
        input_buffer: vec![],
    }
    .write_to(&mut query)
    .unwrap();
    let mut close = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: RELATED,
    }
    .write_to(&mut close)
    .unwrap();
    let first = b
        .send_compound_no_wait(&[
            (Command::Create, deleting("f.txt").body(), false),
            (Command::QueryInfo, query, true),
            (Command::Close, close, true),
        ])
        .await;

    let frame = b.next_frame().await;
    let responses = split_compound(&frame);
    assert_eq!(responses.len(), 1, "the first frame is the interim alone");
    let (hdr, _) = &responses[0];
    assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_PENDING);
    assert_eq!(hdr.message_id, first);
    let async_id = hdr.async_id().expect("an AsyncId");
    assert_ne!(hdr.credit_request_response, 0);

    a.next_break(WAIT).await.expect("handle break");
    a.close(fa).await;
    let frame = b.next_frame().await;
    let responses = split_compound(&frame);
    let summary: Vec<_> = responses
        .iter()
        .map(|(h, _)| (h.command, h.channel_sequence_status))
        .collect();
    assert_eq!(
        summary,
        [
            (Command::Create, 0),
            (Command::QueryInfo, 0),
            (Command::Close, 0)
        ]
    );
    assert_eq!(responses[0].0.async_id(), Some(async_id));
    assert_eq!(responses[0].0.credit_request_response, 0);
    assert_eq!(responses[1].0.tree_id(), Some(b.tree_id));
}

#[tokio::test]
async fn an_acknowledgment_breaks_on_when_a_later_trigger_needs_less() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let mut c = server.client().await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;
    let mid = b
        .send_no_wait(Command::Create, &deleting("f.txt").body())
        .await;
    b.recv_interim(mid).await;
    let n = a.next_break(WAIT).await.expect("handle break");
    assert_break(&n, KEY_A, RH, R);

    // A write during the break needs no read caching either.
    let fc = c.open("f.txt", RW, SHARE_READ | SHARE_WRITE).await.unwrap();
    c.write(fc, 0, b"x").await.unwrap();
    assert!(
        a.drain_breaks().await.is_empty(),
        "no second notification yet"
    );

    assert_eq!(ack(&mut a, KEY_A, R).await, (0, Some(R)));
    assert!(
        a.breaks.is_empty(),
        "the further break follows the response"
    );
    let n = a.next_break(WAIT).await.expect("break on to NONE");
    assert_eq!(n.flags, 0, "a read lease needs no acknowledgment");
    assert_eq!((n.current_lease_state, n.new_lease_state), (R, 0));
    let (status, _) = b.recv(mid, Command::Create).await;
    assert_eq!(status, ntstatus::STATUS_SHARING_VIOLATION);
}

#[tokio::test]
async fn an_interim_response_is_encrypted_like_the_request() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"contents").unwrap();
    let (addr, task) = start_server(
        SmbServer::builder().user("alice", "password").share(
            Share::new("secret", local(td.path()))
                .public()
                .encrypt_data(),
        ),
    )
    .await;
    let mut holder =
        EncryptedSession::smb311(addr, &[Cipher::Aes128Gcm], "alice", "password").await;
    let mut other = EncryptedSession::smb311(addr, &[Cipher::Aes128Gcm], "alice", "password").await;
    for sess in [&mut holder, &mut other] {
        assert_eq!(status(&sess.tree_connect(r"\\srv\secret").await), 0);
    }
    let create = Create {
        share: SHARE_READ | SHARE_WRITE,
        ..leased("f.txt", rqls_v2(KEY_A, RWH, None, 0))
    };
    let resp = holder.send_encrypted(Command::Create, &create.body()).await;
    let held = CreateResponse::parse(&resp[64..]).unwrap();
    assert_eq!(lease_reply(&held).unwrap().state, RH);

    let hdr = other.header(Command::Create);
    let sealed = other.seal(&message(&hdr, &deleting("f.txt").body()));
    let frame = other.exchange(&sealed).await;
    assert!(is_transform(&frame), "the interim response is encrypted");
    let interim_frame = other.open(&frame).expect("interim decrypts");
    assert_eq!(status(&interim_frame), ntstatus::STATUS_PENDING);
    let async_id = Smb2Header::parse(&interim_frame)
        .unwrap()
        .0
        .async_id()
        .expect("an AsyncId");

    let frame = tokio::time::timeout(WAIT, common::read_frame(&mut holder.stream))
        .await
        .expect("break in time");
    let (_, n) = parse_break(&frame);
    assert_break(&n, KEY_A, RH, R);
    let mut close = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: held.file_id,
    }
    .write_to(&mut close)
    .unwrap();
    assert_eq!(
        status(&holder.send_encrypted(Command::Close, &close).await),
        0
    );

    let frame = tokio::time::timeout(WAIT, common::read_frame(&mut other.stream))
        .await
        .expect("final response in time");
    assert!(is_transform(&frame), "the final response is encrypted");
    let last = other.open(&frame).expect("final decrypts");
    assert_eq!(status(&last), 0);
    assert_final(&last, async_id);
    task.abort();
}

#[tokio::test]
async fn a_compound_with_two_waiting_creates_answers_in_three_frames() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let fa = hold_rh(&mut a, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;
    let ga = hold_rh(&mut a, "g.txt", KEY_B, SHARE_READ | SHARE_WRITE).await;
    b.send_compound_no_wait(&[
        (Command::Create, deleting("f.txt").body(), false),
        (Command::Create, deleting("g.txt").body(), false),
    ])
    .await;

    let frame = b.next_frame().await;
    let responses = split_compound(&frame);
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0].0.channel_sequence_status,
        ntstatus::STATUS_PENDING
    );
    let first = responses[0].0.async_id().expect("an AsyncId");
    let n = a.next_break(WAIT).await.expect("break of f.txt");
    assert_eq!(n.lease_key, KEY_A);
    a.close(fa).await;

    let frame = b.next_frame().await;
    let responses = split_compound(&frame);
    let summary: Vec<_> = responses
        .iter()
        .map(|(h, _)| h.channel_sequence_status)
        .collect();
    assert_eq!(summary, [0, ntstatus::STATUS_PENDING]);
    assert_eq!(responses[0].0.async_id(), Some(first));
    let second = responses[1].0.async_id().expect("an AsyncId");
    assert_ne!(second, first);
    let n = a.next_break(WAIT).await.expect("break of g.txt");
    assert_eq!(n.lease_key, KEY_B);
    a.close(ga).await;

    let frame = b.next_frame().await;
    let responses = split_compound(&frame);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].0.channel_sequence_status, 0);
    assert_eq!(responses[0].0.async_id(), Some(second));
}

#[tokio::test]
async fn a_cancel_compounded_after_its_create_cancels_it() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    hold_rh(&mut a, "f.txt", KEY_A, SHARE_READ | SHARE_WRITE).await;
    let mid = b.take_mid();
    let create = message(
        &common::build_header(Command::Create, mid, b.session_id, b.tree_id),
        &deleting("f.txt").body(),
    );
    let cancel = message(
        &common::build_header(Command::Cancel, mid, b.session_id, b.tree_id),
        &[4, 0, 0, 0],
    );
    b.s.write_all(&common::transport::compound(&[create, cancel]))
        .await
        .unwrap();
    b.recv_interim(mid).await;
    let (status, _) = b.recv(mid, Command::Create).await;
    assert_eq!(status, ntstatus::STATUS_CANCELLED);
}
