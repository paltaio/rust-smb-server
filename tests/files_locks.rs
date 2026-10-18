//! Byte-range locks across opens and connections.

mod common;

use common::client::*;
use smb_server::ntstatus;
use smb_server::wire::messages::FileId;
use tempfile::tempdir;

const EX_NOW: u32 = LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY;
const SH_NOW: u32 = LOCK_SHARED | LOCK_FAIL_IMMEDIATELY;

async fn two_opens(td: &std::path::Path) -> (Server, Client, FileId, Client, FileId) {
    std::fs::write(td.join("f.txt"), vec![b'x'; 200]).unwrap();
    let server = Server::public(local(td)).await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let fa = a.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let fb = b.open("f.txt", RW, SHARE_ALL).await.unwrap();
    (server, a, fa, b, fb)
}

#[tokio::test]
async fn conflicting_locks_and_io_are_refused() {
    let td = tempdir().unwrap();
    let (_server, mut a, fa, mut b, fb) = two_opens(td.path()).await;

    assert_eq!(a.lock(fa, &[(0, 50, LOCK_EXCLUSIVE)]).await, 0);
    assert_eq!(
        b.lock(fb, &[(10, 10, EX_NOW)]).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    assert_eq!(
        b.lock(fb, &[(10, 10, SH_NOW)]).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    // A request that would wait fails at once.
    assert_eq!(
        b.lock(fb, &[(10, 10, LOCK_EXCLUSIVE)]).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    assert_eq!(
        b.read(fb, 5, 10).await,
        Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
    );
    assert_eq!(
        b.write(fb, 49, b"zz").await,
        Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
    );
    assert_eq!(b.read(fb, 50, 10).await.unwrap().len(), 10);
    // The owner keeps reading and writing its range.
    assert_eq!(a.write(fa, 0, b"own").await, Ok(3));
    assert_eq!(a.read(fa, 0, 3).await.unwrap(), b"own");

    // Shared locks admit readers and refuse every writer.
    assert_eq!(b.lock(fb, &[(100, 10, SH_NOW)]).await, 0);
    assert_eq!(a.lock(fa, &[(105, 10, SH_NOW)]).await, 0);
    assert_eq!(a.read(fa, 100, 5).await.unwrap().len(), 5);
    assert_eq!(
        b.write(fb, 100, b"w").await,
        Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
    );

    assert_eq!(a.lock(fa, &[(0, 50, LOCK_UNLOCK)]).await, 0);
    assert_eq!(b.read(fb, 5, 10).await.unwrap().len(), 10);
}

#[tokio::test]
async fn failed_lock_request_releases_its_earlier_ranges() {
    let td = tempdir().unwrap();
    let (_server, mut a, fa, mut b, fb) = two_opens(td.path()).await;

    assert_eq!(a.lock(fa, &[(100, 10, EX_NOW)]).await, 0);
    assert_eq!(
        b.lock(fb, &[(0, 10, EX_NOW), (100, 10, EX_NOW)]).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    assert_eq!(a.lock(fa, &[(0, 10, EX_NOW)]).await, 0);
}

#[tokio::test]
async fn invalid_lock_requests_are_rejected() {
    let td = tempdir().unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    let (_server, mut a, fa, _b, _fb) = two_opens(td.path()).await;

    assert_eq!(
        a.lock(fa, &[(0, 10, LOCK_UNLOCK)]).await,
        ntstatus::STATUS_RANGE_NOT_LOCKED
    );
    for flags in [
        0,
        0x08,
        LOCK_SHARED | LOCK_EXCLUSIVE,
        LOCK_UNLOCK | LOCK_SHARED,
    ] {
        assert_eq!(
            a.lock(fa, &[(0, 10, flags)]).await,
            ntstatus::STATUS_INVALID_PARAMETER,
            "flags {flags:#x}"
        );
    }
    assert_eq!(
        a.lock(fa, &[(0, 10, EX_NOW), (20, 10, LOCK_UNLOCK)]).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    // Several elements each need FAIL_IMMEDIATELY.
    assert_eq!(
        a.lock(fa, &[(0, 10, LOCK_EXCLUSIVE), (20, 10, LOCK_EXCLUSIVE)])
            .await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(a.lock(fa, &[]).await, ntstatus::STATUS_INVALID_PARAMETER);
    assert_eq!(
        a.lock(fa, &[(u64::MAX, 2, EX_NOW)]).await,
        ntstatus::STATUS_INVALID_LOCK_RANGE
    );
    assert_eq!(
        a.lock(FileId::new(0xDEAD, 0xDEAD), &[(0, 1, EX_NOW)]).await,
        ntstatus::STATUS_FILE_CLOSED
    );
    let dir = a.open("d", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    assert_eq!(
        a.lock(dir, &[(0, 1, EX_NOW)]).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
}

#[tokio::test]
async fn locks_past_the_limit_are_refused() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), vec![b'x'; 200]).unwrap();
    let server = Server::start(
        smb_server::SmbServer::builder()
            .max_locks_per_open(2)
            .share(smb_server::Share::new("share", local(td.path())).public()),
    )
    .await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let fa = a.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let fb = b.open("f.txt", RW, SHARE_ALL).await.unwrap();

    assert_eq!(a.lock(fa, &[(0, 10, EX_NOW), (20, 10, EX_NOW)]).await, 0);
    assert_eq!(
        a.lock(fa, &[(40, 10, EX_NOW)]).await,
        ntstatus::STATUS_INSUFFICIENT_RESOURCES
    );
    // A request that crosses the limit takes none of its ranges.
    assert_eq!(a.lock(fa, &[(0, 10, LOCK_UNLOCK)]).await, 0);
    assert_eq!(
        a.lock(fa, &[(40, 10, EX_NOW), (60, 10, EX_NOW)]).await,
        ntstatus::STATUS_INSUFFICIENT_RESOURCES
    );
    assert_eq!(b.lock(fb, &[(40, 10, EX_NOW)]).await, 0);
    assert_eq!(a.lock(fa, &[(80, 10, EX_NOW)]).await, 0);
}

#[tokio::test]
async fn locks_go_away_with_their_open() {
    let td = tempdir().unwrap();
    let (_server, mut a, fa, mut b, fb) = two_opens(td.path()).await;

    assert_eq!(a.lock(fa, &[(0, 10, EX_NOW)]).await, 0);
    assert_eq!(
        b.lock(fb, &[(0, 10, EX_NOW)]).await,
        ntstatus::STATUS_LOCK_NOT_GRANTED
    );
    a.close(fa).await;
    assert_eq!(b.lock(fb, &[(0, 10, EX_NOW)]).await, 0);
}
