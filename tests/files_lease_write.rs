//! Write caching: who gets it, what breaks it, and the opens that wait for
//! the holder to write back first.

#![cfg(feature = "localfs")]

mod common;

use std::time::Duration;

use common::client::*;
use common::lease::*;
use smb_server::ntstatus;
use smb_server::wire::header::Command;
use smb_server::wire::messages::{CreateResponse, LeaseBreakAck, LeaseBreakNotification};
use tempfile::{TempDir, tempdir};

const R: u32 = LEASE_READ_CACHING;
const RH: u32 = LEASE_READ_CACHING | LEASE_HANDLE_CACHING;
const RW: u32 = LEASE_READ_CACHING | LEASE_WRITE_CACHING;
const KEY_A: [u8; 16] = [0xA1; 16];
const KEY_B: [u8; 16] = [0xB2; 16];
const WAIT: Duration = Duration::from_secs(5);

async fn server() -> (Server, TempDir) {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"contents").unwrap();
    (Server::public(local(td.path())).await, td)
}

/// Opens f.txt asking for `state` under `key`; returns the response.
async fn open_with(c: &mut Client, key: [u8; 16], state: u32) -> CreateResponse {
    c.create(leased("f.txt", rqls_v1(key, state)))
        .await
        .expect("create")
}

/// A CREATE of `name` without a lease, for reading and writing.
fn plain(name: &str) -> Create<'_> {
    Create {
        name,
        ..Create::default()
    }
}

fn granted(resp: &CreateResponse) -> u32 {
    lease_reply(resp).expect("lease context").state
}

fn assert_break(n: &LeaseBreakNotification, key: [u8; 16], from: u32, to: u32) {
    assert_eq!(n.lease_key, key);
    assert_eq!(n.flags, LeaseBreakNotification::FLAG_ACK_REQUIRED);
    assert_eq!((n.current_lease_state, n.new_lease_state), (from, to));
}

async fn ack(c: &mut Client, key: [u8; 16], state: u32) -> (u32, Option<u32>) {
    let (status, body) = c
        .send(Command::OplockBreak, &lease_ack_body(key, state))
        .await;
    let reported = (status == 0).then(|| LeaseBreakAck::parse(&body).unwrap().lease_state);
    (status, reported)
}

#[tokio::test]
async fn a_sole_opener_gets_write_caching_and_another_open_waits_for_it() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = Client::connect_with(server.addr, None, [0x11; 16], "share").await;
    let held = open_with(&mut a, KEY_A, RWH).await;
    assert_eq!(granted(&held), RWH);

    let create = leased("f.txt", rqls_v1(KEY_B, RWH));
    let mid = b.send_no_wait(Command::Create, &create.body()).await;
    b.recv_interim(mid).await;
    let n = a.next_break(WAIT).await.expect("write break");
    assert_break(&n, KEY_A, RWH, RH);
    assert_eq!(ack(&mut a, KEY_A, RH).await, (0, Some(RH)));

    let (status, body) = b.recv(mid, Command::Create).await;
    assert_eq!(status, 0);
    let resp = CreateResponse::parse(&body).unwrap();
    // The holder's open stays, so the second client gets no write caching.
    assert_eq!(granted(&resp), RH);
}

#[tokio::test]
async fn data_written_back_before_the_acknowledgment_is_seen_by_the_waiting_open() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let held = open_with(&mut a, KEY_A, RWH).await;

    let mid = b
        .send_no_wait(
            Command::Create,
            &Create {
                name: "f.txt",
                access: FILE_GENERIC_READ,
                ..Create::default()
            }
            .body(),
        )
        .await;
    b.recv_interim(mid).await;
    a.next_break(WAIT).await.expect("write break");
    // The holder writes back what it cached, then acknowledges.
    a.write(held.file_id, 0, b"fresh!!!").await.unwrap();
    assert_eq!(ack(&mut a, KEY_A, RH).await.0, 0);

    let (status, body) = b.recv(mid, Command::Create).await;
    assert_eq!(status, 0);
    let fb = CreateResponse::parse(&body).unwrap().file_id;
    assert_eq!(b.read(fb, 0, 64).await.unwrap(), b"fresh!!!");
}

#[tokio::test]
async fn one_connection_waits_for_its_own_write_break() {
    let (server, _td) = server().await;
    for second_key in [Some(KEY_B), None] {
        let mut c = server.client().await;
        let first = open_with(&mut c, KEY_A, RWH).await;
        assert_eq!(granted(&first), RWH);
        let create = match second_key {
            Some(key) => leased("f.txt", rqls_v1(key, RWH)),
            None => plain("f.txt"),
        };
        let mid = c.send_no_wait(Command::Create, &create.body()).await;
        c.recv_interim(mid).await;
        let n = c
            .next_break(WAIT)
            .await
            .expect("break on the same connection");
        assert_break(&n, KEY_A, RWH, RH);
        assert_eq!(ack(&mut c, KEY_A, RH).await, (0, Some(RH)));
        let (status, body) = c.recv(mid, Command::Create).await;
        assert_eq!(status, 0, "{second_key:?}");
        let resp = CreateResponse::parse(&body).unwrap();
        match second_key {
            Some(_) => assert_eq!(granted(&resp), RH),
            None => assert_eq!(lease_data(&resp), None),
        }
        c.close(resp.file_id).await;
        c.close(first.file_id).await;
    }
}

#[tokio::test]
async fn an_overwrite_waits_and_truncates_after_the_write_back() {
    let (server, td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let held = open_with(&mut a, KEY_A, RWH).await;

    let mid = b
        .send_no_wait(
            Command::Create,
            &Create {
                name: "f.txt",
                disposition: FILE_OVERWRITE_IF,
                ..Create::default()
            }
            .body(),
        )
        .await;
    b.recv_interim(mid).await;
    let n = a.next_break(WAIT).await.expect("break to none");
    assert_break(&n, KEY_A, RWH, 0);
    // Nothing is truncated while the holder still writes back.
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"contents");
    a.write(held.file_id, 0, b"written back").await.unwrap();
    assert_eq!(ack(&mut a, KEY_A, 0).await, (0, Some(0)));

    let (status, _) = b.recv(mid, Command::Create).await;
    assert_eq!(status, 0);
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"");
}

#[tokio::test]
async fn a_lock_waits_for_the_writes_another_client_caches() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let held = open_with(&mut a, KEY_A, RW).await;
    assert_eq!(granted(&held), RW);

    let attrs = b
        .open("f.txt", FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    assert!(
        a.drain_breaks().await.is_empty(),
        "attribute-only opens break nothing"
    );
    // A lock through that open breaks to NONE and is refused while the
    // holder may still write back.
    assert_eq!(
        b.lock(attrs, &[(0, 1, LOCK_EXCLUSIVE)]).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    let n = a.next_break(WAIT).await.expect("break to none");
    assert_break(&n, KEY_A, RW, 0);
    assert_eq!(
        b.lock(attrs, &[(0, 1, LOCK_EXCLUSIVE)]).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED,
        "still refused during the break"
    );
    a.write(held.file_id, 0, b"written back").await.unwrap();
    assert_eq!(ack(&mut a, KEY_A, 0).await, (0, Some(0)));
    assert_eq!(b.lock(attrs, &[(0, 1, LOCK_EXCLUSIVE)]).await, 0);
}

#[tokio::test]
async fn a_lease_is_promoted_by_later_opens_with_its_key() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    for (first, second, expected) in [
        (R, RW, RW),
        (R, RWH, RWH),
        (RH, RWH, RWH),
        (RW, RWH, RWH),
        // Not a superset of what is held: nothing changes.
        (RH, RW, RH),
    ] {
        let one = open_with(&mut c, KEY_A, first).await;
        assert_eq!(granted(&one), first);
        let two = open_with(&mut c, KEY_A, second).await;
        assert_eq!(granted(&two), expected, "{first} then {second}");
        assert!(c.drain_breaks().await.is_empty());
        c.close(two.file_id).await;
        c.close(one.file_id).await;
    }
}

#[tokio::test]
async fn write_caching_is_refused_beside_another_open() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    // A promotion drops write caching, then keeps handle caching.
    let one = open_with(&mut a, KEY_A, R).await;
    let other = b.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let two = open_with(&mut a, KEY_A, RWH).await;
    assert_eq!(granted(&two), RH);
    // A new lease too.
    let three = open_with(&mut b, KEY_B, RWH).await;
    assert_eq!(granted(&three), RH);
    b.close(three.file_id).await;
    b.close(other).await;
    a.close(two.file_id).await;
    a.close(one.file_id).await;
}

#[tokio::test]
async fn directories_get_no_write_caching() {
    let (server, _td) = server().await;
    let mut c = server.client_at(0x0302).await;
    let resp = c
        .create(Create {
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            ..leased("f.txt", rqls_v2(KEY_A, RWH, None, 0))
        })
        .await
        .unwrap();
    assert_eq!(granted(&resp), RH);
}

#[tokio::test]
async fn a_byte_range_lock_refuses_read_caching_but_not_a_sole_writer() {
    let (server, _td) = server().await;
    let mut c = server.client().await;
    let one = open_with(&mut c, KEY_A, R).await;
    assert_eq!(c.lock(one.file_id, &[(0, 1, LOCK_EXCLUSIVE)]).await, 0);
    // The same key, alone on the file, still gets write caching.
    let two = open_with(&mut c, KEY_A, RWH).await;
    assert_eq!(granted(&two), RWH);
    // Another key asks for read and handle caching, through an open that
    // breaks nothing.
    let mut other = server.client().await;
    let three = other
        .create(Create {
            access: FILE_READ_ATTRIBUTES,
            ..leased("f.txt", rqls_v1([0xC3; 16], RH))
        })
        .await
        .unwrap();
    assert_eq!(granted(&three), 0);
}

#[tokio::test]
async fn version_2_epochs_count_write_caching_grants_and_breaks() {
    let (server, _td) = server().await;
    let mut a = server.client_at(0x0300).await;
    let mut b = server.client_at(0x0300).await;
    let held = a
        .create(leased("f.txt", rqls_v2(KEY_A, RWH, None, 0)))
        .await
        .unwrap();
    let lease = lease_reply(&held).unwrap();
    assert_eq!((lease.state, lease.epoch), (RWH, 1));

    let mid = b
        .send_no_wait(Command::Create, &plain("f.txt").body())
        .await;
    b.recv_interim(mid).await;
    let n = a.next_break(WAIT).await.expect("write break");
    assert_eq!(
        (n.current_lease_state, n.new_lease_state, n.new_epoch),
        (RWH, RH, 2)
    );
    assert_eq!(ack(&mut a, KEY_A, RH).await, (0, Some(RH)));
    let (status, body) = b.recv(mid, Command::Create).await;
    assert_eq!(status, 0);
    let fb = CreateResponse::parse(&body).unwrap().file_id;

    b.write(fb, 0, b"x").await.unwrap();
    let n = a.next_break(WAIT).await.expect("break to none");
    assert_eq!(
        (n.current_lease_state, n.new_lease_state, n.new_epoch),
        (RH, 0, 3)
    );
    // The acknowledgment leaves the epoch alone.
    assert_eq!(ack(&mut a, KEY_A, 0).await, (0, Some(0)));
    let again = a
        .create(leased("f.txt", rqls_v2(KEY_A, RWH, None, 0)))
        .await
        .unwrap();
    let lease = lease_reply(&again).unwrap();
    assert_eq!((lease.state, lease.epoch), (RH, 4));
}

#[tokio::test]
async fn an_acknowledgment_that_keeps_too_much_breaks_on() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let mut c = server.client().await;
    let held = a
        .create(Create {
            share: SHARE_READ | SHARE_WRITE,
            ..leased("f.txt", rqls_v1(KEY_A, RWH))
        })
        .await
        .unwrap();
    assert_eq!(granted(&held), RWH);
    // An open for reading needs write caching gone.
    let reader = b
        .send_no_wait(
            Command::Create,
            &Create {
                name: "f.txt",
                access: FILE_GENERIC_READ,
                ..Create::default()
            }
            .body(),
        )
        .await;
    b.recv_interim(reader).await;
    let n = a.next_break(WAIT).await.expect("write break");
    assert_break(&n, KEY_A, RWH, RH);

    // An open the holder's sharing refuses needs handle caching gone too.
    let deleter = c
        .send_no_wait(
            Command::Create,
            &Create {
                name: "f.txt",
                access: DELETE | FILE_READ_ATTRIBUTES,
                ..Create::default()
            }
            .body(),
        )
        .await;
    c.recv_interim(deleter).await;
    assert!(a.drain_breaks().await.is_empty(), "one break at a time");

    assert_eq!(ack(&mut a, KEY_A, RH).await, (0, Some(RH)));
    let n = a.next_break(WAIT).await.expect("break on to R");
    assert_break(&n, KEY_A, RH, R);
    assert_eq!(b.recv(reader, Command::Create).await.0, 0);

    a.close(held.file_id).await;
    assert_eq!(c.recv(deleter, Command::Create).await.0, 0);
    assert_eq!(
        ack(&mut a, KEY_A, R).await.0,
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_waiting_open_does_not_block_the_holders_opens() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let held = a
        .create(Create {
            access: FILE_GENERIC_READ,
            ..leased("f.txt", rqls_v1(KEY_A, RWH))
        })
        .await
        .unwrap();
    assert_eq!(granted(&held), RWH);
    // Admitted beside the holder, but it shares reading only.
    let mid = b
        .send_no_wait(
            Command::Create,
            &Create {
                name: "f.txt",
                share: SHARE_READ,
                ..Create::default()
            }
            .body(),
        )
        .await;
    b.recv_interim(mid).await;
    a.next_break(WAIT).await.expect("write break");
    // The holder opens for writing while the other open waits.
    let writer = a
        .create(leased("f.txt", rqls_v1(KEY_A, RWH)))
        .await
        .expect("not blocked by the waiting open");
    assert_eq!(ack(&mut a, KEY_A, RH).await.0, 0);
    // Once the wait ends, the waiting open runs its sharing check.
    assert_eq!(
        b.recv(mid, Command::Create).await.0,
        ntstatus::STATUS_SHARING_VIOLATION
    );
    a.close(writer.file_id).await;
}

#[tokio::test]
async fn a_file_deleted_while_an_open_waits_fails_it() {
    let (server, _td) = server().await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let held = a
        .create(Create {
            access: RW | DELETE,
            ..leased("f.txt", rqls_v1(KEY_A, RWH))
        })
        .await
        .unwrap();
    let mid = b
        .send_no_wait(Command::Create, &plain("f.txt").body())
        .await;
    b.recv_interim(mid).await;
    a.next_break(WAIT).await.expect("write break");
    assert_eq!(a.set_delete(held.file_id, true).await, 0);
    assert_eq!(ack(&mut a, KEY_A, RH).await.0, 0);
    assert_eq!(
        b.recv(mid, Command::Create).await.0,
        ntstatus::STATUS_DELETE_PENDING
    );
}
