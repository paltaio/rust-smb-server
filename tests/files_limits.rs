//! The per-connection open limit.

#[path = "support_files.rs"]
mod support;

use smb_server::ntstatus;
use support::*;
use tempfile::tempdir;

#[tokio::test]
async fn opens_past_the_limit_are_refused() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    server.config.set_max_opens_per_connection(2);
    let mut a = server.client().await;
    let mut b = server.client().await;

    let first = a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    let _second = a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(
        a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_INSUFFICIENT_RESOURCES)
    );
    // A refused CREATE makes nothing.
    assert_eq!(
        a.create(Create {
            name: "new.txt",
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap_err(),
        ntstatus::STATUS_INSUFFICIENT_RESOURCES
    );
    assert!(!td.path().join("new.txt").exists());
    // The limit is per connection.
    assert!(b.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.is_ok());

    a.close(first).await;
    assert!(a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.is_ok());
    // A failed CREATE gives its slot back.
    assert_eq!(a.tree_disconnect().await, 0);
}

#[tokio::test]
async fn failed_creates_release_their_slot() {
    let td = tempdir().unwrap();
    let server = Server::public(local(td.path())).await;
    server.config.set_max_opens_per_connection(1);
    let mut a = server.client().await;
    for _ in 0..3 {
        assert_eq!(
            a.open("missing.txt", FILE_READ_DATA, SHARE_ALL).await,
            Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    assert!(a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.is_ok());
}

#[tokio::test]
async fn the_builder_sets_the_open_limit() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::start(
        smb_server::SmbServer::builder()
            .max_opens_per_connection(1)
            .share(smb_server::Share::new("share", local(td.path())).public()),
    )
    .await;
    let mut c = server.client().await;
    let first = c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_INSUFFICIENT_RESOURCES)
    );
    c.close(first).await;
}
