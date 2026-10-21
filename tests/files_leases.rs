//! Leases: the LEASING capability, lease create contexts, sharing a lease
//! between opens, and what breaks a read lease.

#![cfg(feature = "localfs")]

mod common;

use std::time::Duration;

use common::auth::{negotiate_311_body, preauth_context, request, status};
use common::client::*;
use common::crypto::{Cipher, EncryptedSession};
use common::lease::*;
use common::{negotiate_body, start_server};
use smb_server::ntstatus;
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CloseRequest, CreateResponse, FileId, LeaseBreakNotification, LeaseContext, NegotiateResponse,
};
use smb_server::{Share, SmbServer};
use tempfile::{TempDir, tempdir};
use tokio::net::TcpStream;

const CAP_LEASING: u32 = 0x0000_0002;
const KEY_A: [u8; 16] = [0xA1; 16];
const KEY_B: [u8; 16] = [0xB2; 16];
const WAIT: Duration = Duration::from_secs(5);

/// A server with public share `share` on a directory holding `f.txt`.
async fn server() -> (Server, TempDir) {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"contents").unwrap();
    std::fs::write(td.path().join("g.txt"), b"other").unwrap();
    std::fs::create_dir(td.path().join("dir")).unwrap();
    (Server::public(local(td.path())).await, td)
}

/// Opens `name` asking for `contexts`; returns the response.
async fn open_leased(c: &mut Client, name: &str, contexts: Vec<u8>) -> CreateResponse {
    c.create(leased(name, contexts)).await.expect("create")
}

/// Opens `f.txt` asking for R under `key` with a version 1 context, and
/// checks that R is granted.
async fn hold_read_lease(c: &mut Client, key: [u8; 16]) -> FileId {
    let resp = open_leased(c, "f.txt", rqls_v1(key, LEASE_READ_CACHING)).await;
    assert_eq!(resp.oplock_level, OPLOCK_LEVEL_LEASE);
    let lease = lease_reply(&resp).expect("lease context");
    assert_eq!((lease.key, lease.state), (key, LEASE_READ_CACHING));
    resp.file_id
}

fn assert_broken_to_none(n: &LeaseBreakNotification, key: [u8; 16]) {
    assert_eq!(n.structure_size, 44);
    assert_eq!(n.lease_key, key);
    assert_eq!(n.flags, 0, "a read lease needs no acknowledgment");
    assert_eq!(n.current_lease_state, LEASE_READ_CACHING);
    assert_eq!(n.new_lease_state, 0);
}

async fn negotiate_capabilities(body: &[u8]) -> u32 {
    let (addr, task) = start_server(SmbServer::builder()).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let frame = request(&mut s, Command::Negotiate, 0, 0, 0, body).await;
    assert_eq!(status(&frame), 0);
    task.abort();
    NegotiateResponse::parse(&frame[64..]).unwrap().capabilities
}

#[tokio::test]
async fn leasing_is_advertised_from_smb_2_1_on() {
    for dialect in [0x0210, 0x0300, 0x0302] {
        let caps = negotiate_capabilities(&negotiate_body(&[dialect], 1, 0)).await;
        assert_ne!(caps & CAP_LEASING, 0, "{dialect:#x}");
    }
    let smb311 = negotiate_311_body(&[0x0311], &[preauth_context(&[0x0001])]);
    assert_ne!(negotiate_capabilities(&smb311).await & CAP_LEASING, 0);
    let caps = negotiate_capabilities(&negotiate_body(&[0x0202], 1, 0)).await;
    assert_eq!(caps & CAP_LEASING, 0);
}

#[tokio::test]
async fn opens_get_read_and_handle_caching_in_the_version_they_asked_for() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    let resp = open_leased(&mut c, "f.txt", rqls_v1(KEY_A, RWH)).await;
    assert_eq!(resp.oplock_level, OPLOCK_LEVEL_LEASE);
    let data = lease_data(&resp).expect("lease context");
    assert_eq!(data.len(), 32);
    let lease = LeaseContext::parse(&data).unwrap();
    assert_eq!(
        (lease.key, lease.state, lease.flags),
        (KEY_A, LEASE_READ_CACHING | LEASE_HANDLE_CACHING, 0)
    );

    let mut c = server.client_at(0x0302).await;
    let parent = [0x99; 16];
    let resp = open_leased(&mut c, "f.txt", rqls_v2(KEY_B, RWH, Some(parent), 4)).await;
    assert_eq!(resp.oplock_level, OPLOCK_LEVEL_LEASE);
    let data = lease_data(&resp).expect("lease context");
    assert_eq!(data.len(), 52);
    let lease = LeaseContext::parse(&data).unwrap();
    assert_eq!(lease.state, LEASE_READ_CACHING | LEASE_HANDLE_CACHING);
    assert_eq!(lease.epoch, 5);
    assert_eq!(lease.flags, LeaseContext::FLAG_PARENT_LEASE_KEY_SET);
    assert_eq!(lease.parent_key, parent);

    // A version 1 context on SMB 3.x gets a version 1 reply.
    let resp = open_leased(&mut c, "g.txt", rqls_v1([0xC3; 16], RWH)).await;
    assert_eq!(lease_data(&resp).map(|d| d.len()), Some(32));
}

#[tokio::test]
async fn lease_contexts_that_ask_for_nothing_get_nothing() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    let (status, _) = c.create_raw(leased("f.txt", rqls(vec![0; 40]))).await;
    assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER);

    let no_lease = |resp: &CreateResponse| {
        assert_eq!(resp.oplock_level, 0);
        assert_eq!(lease_data(resp), None);
    };
    // Version 2 on SMB 2.1, an all-zero key, and a state without R.
    no_lease(&open_leased(&mut c, "f.txt", rqls_v2(KEY_A, RWH, None, 0)).await);
    no_lease(&open_leased(&mut c, "f.txt", rqls_v1([0; 16], RWH)).await);
    let resp = open_leased(&mut c, "f.txt", rqls_v1(KEY_A, LEASE_WRITE_CACHING)).await;
    assert_eq!(resp.oplock_level, OPLOCK_LEVEL_LEASE);
    assert_eq!(lease_reply(&resp).unwrap().state, 0);
    // A context without the lease oplock level is ignored, even malformed.
    for contexts in [rqls_v1(KEY_B, RWH), rqls(vec![0; 40])] {
        let resp = c
            .create(Create {
                name: "f.txt",
                oplock: 0x09,
                contexts,
                ..Create::default()
            })
            .await
            .unwrap();
        no_lease(&resp);
    }
    // Directories get no lease.
    let resp = c
        .create(Create {
            options: FILE_DIRECTORY_FILE,
            access: FILE_GENERIC_READ,
            ..leased("dir", rqls_v1(KEY_B, RWH))
        })
        .await
        .unwrap();
    no_lease(&resp);
    let resp = c
        .create(Create {
            access: FILE_GENERIC_READ,
            ..leased("dir", rqls_v1(KEY_B, RWH))
        })
        .await
        .unwrap();
    no_lease(&resp);

    // SMB 2.0.2 has no leases.
    let mut old = server.client_at(0x0202).await;
    no_lease(&open_leased(&mut old, "f.txt", rqls_v1(KEY_A, RWH)).await);
}

#[tokio::test]
async fn opens_with_one_key_share_the_lease() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    let first = hold_read_lease(&mut c, KEY_A).await;
    let second = hold_read_lease(&mut c, KEY_A).await;
    // Writes through either open break nothing of their own lease.
    c.write(first, 0, b"x").await.unwrap();
    c.write(second, 0, b"y").await.unwrap();
    assert!(c.drain_breaks().await.is_empty());
    // Closing one leaves the lease to the other.
    c.close(first).await;
    assert_eq!(c.ack(KEY_A, 0).await, ntstatus::STATUS_UNSUCCESSFUL);
    c.close(second).await;
    assert_eq!(
        c.ack(KEY_A, 0).await,
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_held_key_fails_on_another_file_or_share() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"contents").unwrap();
    std::fs::write(td.path().join("g.txt"), b"other").unwrap();
    let server = Server::start(
        SmbServer::builder()
            .share(Share::new("share", local(td.path())).public())
            .share(Share::new("other", local(td.path())).public()),
    )
    .await;
    let mut a = server.client().await;
    hold_read_lease(&mut a, KEY_A).await;
    let (status, _) = a.create_raw(leased("g.txt", rqls_v1(KEY_A, RWH))).await;
    assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER);

    let mut other = Client::connect_with(server.addr, None, common::CLIENT_GUID, "other").await;
    let (status, _) = other.create_raw(leased("f.txt", rqls_v1(KEY_A, RWH))).await;
    assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER);

    // The same key from another client is another lease.
    let mut b = Client::connect_with(server.addr, None, [0x11; 16], "share").await;
    let fb = hold_read_lease(&mut b, KEY_A).await;
    b.write(fb, 0, b"z").await.unwrap();
    let n = a.next_break(WAIT).await.expect("break");
    assert_broken_to_none(&n, KEY_A);
    assert!(b.drain_breaks().await.is_empty());
}

#[tokio::test]
async fn a_lease_ends_with_its_last_open() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    let f = hold_read_lease(&mut c, KEY_A).await;
    assert_eq!(c.ack(KEY_A, 0).await, ntstatus::STATUS_UNSUCCESSFUL);
    c.close(f).await;
    assert_eq!(
        c.ack(KEY_A, 0).await,
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
    // A dropped connection ends its leases too.
    hold_read_lease(&mut c, KEY_B).await;
    let mut other = server.client().await;
    drop(c);
    assert!(
        eventually_async(
            async || other.ack(KEY_B, 0).await == ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
        )
        .await
    );
}

/// Retries `check` for up to two seconds.
async fn eventually_async(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[derive(Debug, Clone, Copy)]
enum Change {
    Write,
    EndOfFile,
    Allocation,
    AllocationKeepsSize,
    Lock,
}

/// Makes `change` to the file through `f`.
async fn make(c: &mut Client, f: FileId, change: Change) {
    match change {
        Change::Write => {
            c.write(f, 0, b"new").await.unwrap();
        }
        Change::EndOfFile => {
            let eof = 3u64.to_le_bytes().to_vec();
            assert_eq!(c.set_info(f, FILE_END_OF_FILE_INFORMATION, eof).await, 0);
        }
        Change::Allocation => {
            let size = 1u64.to_le_bytes().to_vec();
            assert_eq!(c.set_info(f, FILE_ALLOCATION_INFORMATION, size).await, 0);
        }
        Change::AllocationKeepsSize => {
            let size = (1u64 << 20).to_le_bytes().to_vec();
            assert_eq!(c.set_info(f, FILE_ALLOCATION_INFORMATION, size).await, 0);
        }
        Change::Lock => {
            assert_eq!(c.lock(f, &[(100, 1, LOCK_EXCLUSIVE)]).await, 0);
            assert_eq!(c.lock(f, &[(100, 1, LOCK_UNLOCK)]).await, 0);
        }
    }
}

#[tokio::test]
async fn writes_size_changes_and_locks_through_other_opens_break_read_leases() {
    let (server, _td) = server().await;
    let mut holder = server.client().await;
    let mut other = server.client().await;
    let fo = other.open("f.txt", RW, SHARE_ALL).await.unwrap();

    for change in [
        Change::Write,
        Change::EndOfFile,
        Change::Allocation,
        Change::AllocationKeepsSize,
        Change::Lock,
    ] {
        let fh = hold_read_lease(&mut holder, KEY_A).await;
        make(&mut other, fo, change).await;
        let n = holder
            .next_break(WAIT)
            .await
            .unwrap_or_else(|| panic!("{change:?}"));
        assert_broken_to_none(&n, KEY_A);
        assert_eq!(n.new_epoch, 0, "version 1");
        // The break needed no acknowledgment, so none is accepted.
        assert_eq!(holder.ack(KEY_A, 0).await, ntstatus::STATUS_UNSUCCESSFUL);
        // NONE breaks no further.
        make(&mut other, fo, change).await;
        assert!(holder.drain_breaks().await.is_empty(), "{change:?}");
        holder.close(fh).await;
    }
}

#[tokio::test]
async fn opens_break_read_leases_only_when_they_overwrite() {
    let (server, _td) = server().await;
    let mut holder = server.client().await;
    let mut other = server.client().await;
    hold_read_lease(&mut holder, KEY_A).await;

    let f = other.open("f.txt", RW, SHARE_ALL).await.unwrap();
    other.close(f).await;
    let f = other
        .open("f.txt", FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    other.close(f).await;
    assert!(holder.drain_breaks().await.is_empty());

    for disposition in [FILE_OVERWRITE_IF, FILE_OVERWRITE, FILE_SUPERSEDE] {
        let resp = holder
            .create(leased("f.txt", rqls_v1(KEY_B, LEASE_READ_CACHING)))
            .await
            .unwrap();
        assert_eq!(lease_reply(&resp).unwrap().state, LEASE_READ_CACHING);
        let f = other
            .create(Create {
                name: "f.txt",
                disposition,
                ..Create::default()
            })
            .await
            .unwrap()
            .file_id;
        // KEY_A broke on the first overwrite already.
        let breaks = holder.drain_breaks().await;
        let keys: Vec<_> = breaks.iter().map(|n| n.lease_key).collect();
        let expected: &[[u8; 16]] = if disposition == FILE_OVERWRITE_IF {
            &[KEY_A, KEY_B]
        } else {
            &[KEY_B]
        };
        assert_eq!(keys, expected, "{disposition}");
        for n in &breaks {
            assert_broken_to_none(n, n.lease_key);
        }
        other.close(f).await;
        holder.close(resp.file_id).await;
    }
}

#[tokio::test]
async fn a_break_on_the_triggering_connection_comes_first() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    hold_read_lease(&mut c, KEY_A).await;
    // An open without a lease on the same connection still breaks it.
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    assert!(c.breaks.is_empty());
    c.write(f, 0, b"x").await.unwrap();
    assert_eq!(c.breaks.len(), 1, "break before the WRITE response");
    let n = c.next_break(WAIT).await.unwrap();
    assert_broken_to_none(&n, KEY_A);
}

#[tokio::test]
async fn version_2_epochs_count_grants_and_breaks() {
    let (server, _td) = server().await;
    let mut holder = server.client_at(0x0300).await;
    let mut other = server.client_at(0x0300).await;
    let resp = open_leased(
        &mut holder,
        "f.txt",
        rqls_v2(KEY_A, LEASE_READ_CACHING, None, 0),
    )
    .await;
    assert_eq!(lease_reply(&resp).unwrap().epoch, 1);
    let fo = other.open("f.txt", RW, SHARE_ALL).await.unwrap();
    other.write(fo, 0, b"x").await.unwrap();
    let n = holder.next_break(WAIT).await.expect("break");
    assert_broken_to_none(&n, KEY_A);
    assert_eq!(n.new_epoch, 2);
    // Another open with the key promotes the lease from NONE back to R.
    let again = open_leased(
        &mut holder,
        "f.txt",
        rqls_v2(KEY_A, LEASE_READ_CACHING, None, 0),
    )
    .await;
    let lease = lease_reply(&again).unwrap();
    assert_eq!((lease.state, lease.epoch), (LEASE_READ_CACHING, 3));
    // A byte-range lock on the file keeps new leases from being granted.
    assert_eq!(other.lock(fo, &[(0, 1, LOCK_EXCLUSIVE)]).await, 0);
    let n = holder.next_break(WAIT).await.expect("break");
    assert_eq!(n.new_epoch, 4);
    let locked = open_leased(
        &mut holder,
        "f.txt",
        rqls_v2(KEY_B, LEASE_READ_CACHING, None, 7),
    )
    .await;
    let lease = lease_reply(&locked).unwrap();
    assert_eq!((lease.state, lease.epoch), (0, 7));
}

#[tokio::test]
async fn breaks_on_an_encrypted_session_are_plain_frames() {
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
    let mut writer =
        EncryptedSession::smb311(addr, &[Cipher::Aes128Gcm], "alice", "password").await;
    for sess in [&mut holder, &mut writer] {
        assert_eq!(status(&sess.tree_connect(r"\\srv\secret").await), 0);
    }

    let resp = holder
        .send_encrypted(
            Command::Create,
            &leased("f.txt", rqls_v2(KEY_A, LEASE_READ_CACHING, None, 0)).body(),
        )
        .await;
    assert_eq!(status(&resp), 0);
    let created = CreateResponse::parse(&resp[64..]).unwrap();
    assert_eq!(lease_reply(&created).unwrap().state, LEASE_READ_CACHING);

    let resp = writer
        .send_encrypted(
            Command::Create,
            &Create {
                name: "f.txt",
                ..Create::default()
            }
            .body(),
        )
        .await;
    let file_id = CreateResponse::parse(&resp[64..]).unwrap().file_id;
    let mut body = Vec::new();
    write_request(file_id, 0, b"x").write_to(&mut body).unwrap();
    assert_eq!(
        status(&writer.send_encrypted(Command::Write, &body).await),
        0
    );

    let frame = tokio::time::timeout(WAIT, common::read_frame(&mut holder.stream))
        .await
        .expect("break in time");
    let (hdr, n) = parse_break(&frame);
    assert_eq!(hdr.session_id, 0);
    assert_broken_to_none(&n, KEY_A);
    assert_eq!(n.new_epoch, 2);
    task.abort();
}

#[tokio::test]
async fn a_share_with_leases_off_grants_none_and_breaks_none() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"contents").unwrap();
    let server = Server::start(
        SmbServer::builder().share(Share::new("share", local(td.path())).public().leases(false)),
    )
    .await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let resp = open_leased(&mut a, "f.txt", rqls_v1(KEY_A, RWH)).await;
    assert_eq!(resp.oplock_level, 0);
    assert_eq!(lease_data(&resp), None);
    let fb = b.open("f.txt", RW, SHARE_ALL).await.unwrap();
    b.write(fb, 0, b"x").await.unwrap();
    assert!(a.drain_breaks().await.is_empty());
    assert_eq!(
        a.ack(KEY_A, 0).await,
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
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
    .unwrap();
    body
}

fn write_body(file_id: FileId, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    write_request(file_id, 0, data).write_to(&mut body).unwrap();
    body
}

#[tokio::test]
async fn a_lease_ended_and_granted_again_in_one_compound_still_breaks() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    // Keeps the file in the table between the two leases.
    let plain = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let create = leased("f.txt", rqls_v1(KEY_A, LEASE_READ_CACHING)).body();
    let replies = c
        .send_compound(&[
            (Command::Create, create.clone(), false),
            (Command::Close, close_body(FileId::any()), true),
            (Command::Create, create, false),
        ])
        .await;
    let statuses: Vec<u32> = replies.iter().map(|r| r.0).collect();
    assert_eq!(statuses, [0, 0, 0]);
    let second = CreateResponse::parse(&replies[2].1).unwrap();
    assert_eq!(lease_reply(&second).unwrap().state, LEASE_READ_CACHING);
    assert!(c.breaks.is_empty());

    c.write(plain, 0, b"x").await.unwrap();
    let n = c.next_break(WAIT).await.expect("break of the second lease");
    assert_broken_to_none(&n, KEY_A);
    c.close(second.file_id).await;
    c.close(plain).await;
}

#[tokio::test]
async fn a_lease_broken_later_in_its_compound_breaks_after_the_response() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    let plain = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let replies = c
        .send_compound(&[
            (
                Command::Create,
                leased("f.txt", rqls_v1(KEY_A, LEASE_READ_CACHING)).body(),
                false,
            ),
            (Command::Write, write_body(plain, b"x"), false),
        ])
        .await;
    assert_eq!((replies[0].0, replies[1].0), (0, 0));
    let created = CreateResponse::parse(&replies[0].1).unwrap();
    assert_eq!(lease_reply(&created).unwrap().state, LEASE_READ_CACHING);
    assert!(c.breaks.is_empty(), "no break before the compound response");
    let n = c.next_break(WAIT).await.expect("break after the response");
    assert_broken_to_none(&n, KEY_A);
}

#[tokio::test]
async fn a_held_back_break_follows_the_grant_on_its_connection() {
    let (server, _td) = server().await;
    let mut first = server.client().await;
    let mut second = server.client().await;
    hold_read_lease(&mut first, KEY_A).await;
    let plain = second.open("f.txt", RW, SHARE_ALL).await.unwrap();
    // The second connection of the same client opens with the same lease,
    // and its write in the same compound breaks it.
    let replies = second
        .send_compound(&[
            (
                Command::Create,
                leased("f.txt", rqls_v1(KEY_A, LEASE_READ_CACHING)).body(),
                false,
            ),
            (Command::Write, write_body(plain, b"x"), false),
        ])
        .await;
    assert_eq!((replies[0].0, replies[1].0), (0, 0));
    assert!(second.breaks.is_empty());
    let n = second.next_break(WAIT).await.expect("break");
    assert_broken_to_none(&n, KEY_A);
    assert!(first.drain_breaks().await.is_empty());
}

#[tokio::test]
async fn a_lease_granted_during_a_write_breaks_once_the_write_lands() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"contents").unwrap();
    let (probe, counters) = Probe::new(
        td.path(),
        Counters {
            write_gate: Some(tokio::sync::Semaphore::new(0)),
            ..Counters::default()
        },
    );
    let server = Server::public(probe).await;
    let mut writer = server.client().await;
    let mut reader = server.client().await;
    let fw = writer.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let mid = writer
        .send_no_wait(Command::Write, &write_body(fw, b"new"))
        .await;
    assert!(eventually(|| Counters::get(&counters.writes) == 1).await);

    // The write has broken what there was to break and waits in the
    // backend; a lease granted now would cache the old contents.
    hold_read_lease(&mut reader, KEY_A).await;
    counters.write_gate.as_ref().unwrap().add_permits(1);
    assert_eq!(writer.recv(mid, Command::Write).await.0, 0);
    let n = reader
        .next_break(WAIT)
        .await
        .expect("break after the write");
    assert_broken_to_none(&n, KEY_A);
}
