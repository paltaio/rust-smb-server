//! ShareAccess between opens of one file, on one or several connections.

#[path = "support_files.rs"]
mod support;

use smb_server::ntstatus;
use support::*;
use tempfile::tempdir;

#[tokio::test]
async fn exclusive_open_refuses_other_opens() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;

    let fa = a.open("f.txt", RW, 0).await.unwrap();
    for access in [FILE_READ_DATA, FILE_WRITE_DATA, DELETE] {
        assert_eq!(
            b.open("f.txt", access, SHARE_ALL).await,
            Err(ntstatus::STATUS_SHARING_VIOLATION),
            "access {access:#x}"
        );
    }
    // The same connection is refused as well.
    assert_eq!(
        a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_SHARING_VIOLATION)
    );
    // Attribute access does not take part.
    let attrs = b
        .open("f.txt", FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0)
        .await
        .unwrap();
    b.close(attrs).await;

    a.close(fa).await;
    let fb = b.open("f.txt", FILE_READ_DATA, SHARE_READ).await.unwrap();
    assert!(a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.is_ok());
    assert_eq!(
        a.open("f.txt", FILE_WRITE_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_SHARING_VIOLATION)
    );
    // A new open must share what the existing opens hold.
    assert_eq!(
        a.open("f.txt", FILE_READ_DATA, SHARE_WRITE).await,
        Err(ntstatus::STATUS_SHARING_VIOLATION)
    );
    b.close(fb).await;
}

#[tokio::test]
async fn refused_overwrite_leaves_the_file_alone() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"precious").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;

    let fa = a.open("f.txt", FILE_READ_DATA, SHARE_READ).await.unwrap();
    for disposition in [FILE_OVERWRITE, FILE_OVERWRITE_IF] {
        let status = b
            .create(Create {
                name: "f.txt",
                disposition,
                ..Create::default()
            })
            .await
            .unwrap_err();
        assert_eq!(status, ntstatus::STATUS_SHARING_VIOLATION);
    }
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"precious");
    a.close(fa).await;
}

#[tokio::test]
async fn delete_access_needs_share_delete() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;

    let fa = a
        .open("f.txt", FILE_READ_DATA, SHARE_READ | SHARE_WRITE)
        .await
        .unwrap();
    assert_eq!(
        b.open("f.txt", DELETE, SHARE_ALL).await,
        Err(ntstatus::STATUS_SHARING_VIOLATION)
    );
    a.close(fa).await;
    let fb = b.open("f.txt", DELETE, SHARE_ALL).await.unwrap();
    // An open without FILE_SHARE_DELETE cannot join an open holding DELETE.
    assert_eq!(
        a.open("f.txt", FILE_READ_DATA, SHARE_READ | SHARE_WRITE)
            .await,
        Err(ntstatus::STATUS_SHARING_VIOLATION)
    );
    b.close(fb).await;
}
