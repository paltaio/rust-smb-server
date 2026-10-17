//! Delete-pending belongs to the file: it holds until the last open closes.

#[path = "support_files.rs"]
mod support;

use smb_server::ntstatus;
use support::*;
use tempfile::tempdir;

const ACCESS: u32 = RW | DELETE;

#[tokio::test]
async fn file_stays_until_the_last_open_closes() {
    let td = tempdir().unwrap();
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;

    let fa = a.open("f.txt", ACCESS, SHARE_ALL).await.unwrap();
    let fb = b.open("f.txt", ACCESS, SHARE_ALL).await.unwrap();
    assert_eq!(a.set_delete(fa, true).await, 0);
    assert_eq!(
        b.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_DELETE_PENDING)
    );
    assert_eq!(
        b.create(Create {
            name: "f.txt",
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap_err(),
        ntstatus::STATUS_DELETE_PENDING
    );

    a.close(fa).await;
    assert!(path.exists(), "removed while another open remains");
    assert_eq!(b.read(fb, 0, 4).await.unwrap(), b"data");
    assert_eq!(
        a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_DELETE_PENDING)
    );
    b.close(fb).await;
    assert!(!path.exists());
    assert_eq!(
        a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
    );
}

#[tokio::test]
async fn clearing_the_disposition_through_another_open_keeps_the_file() {
    let td = tempdir().unwrap();
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;

    let fa = a.open("f.txt", ACCESS, SHARE_ALL).await.unwrap();
    let fb = b.open("f.txt", ACCESS, SHARE_ALL).await.unwrap();
    assert_eq!(a.set_delete(fa, true).await, 0);
    assert_eq!(b.set_delete(fb, false).await, 0);
    a.close(fa).await;
    b.close(fb).await;
    assert!(path.exists());
}

#[tokio::test]
async fn delete_on_close_waits_for_the_other_opens() {
    let td = tempdir().unwrap();
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;

    let fb = b.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    let fa = a
        .create(Create {
            name: "f.txt",
            access: ACCESS,
            options: FILE_DELETE_ON_CLOSE,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    // Until the flagged open closes the file is not delete-pending.
    let other = b.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    b.close(other).await;

    a.close(fa).await;
    assert!(path.exists());
    assert_eq!(
        a.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_DELETE_PENDING)
    );
    b.close(fb).await;
    assert!(!path.exists());
}

#[tokio::test]
async fn delete_on_close_of_a_read_only_file_leaves_it_whole() {
    let td = tempdir().unwrap();
    let path = td.path().join("ro.txt");
    std::fs::write(&path, b"keep").unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let status = c
        .create(Create {
            name: "ro.txt",
            access: RW | DELETE,
            disposition: FILE_OVERWRITE_IF,
            options: FILE_DELETE_ON_CLOSE,
            ..Create::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status, ntstatus::STATUS_CANNOT_DELETE);
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
}
