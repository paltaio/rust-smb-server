//! Delete-pending belongs to the file: it holds until the last open closes.

mod common;

use common::client::*;
use smb_server::ntstatus;
use smb_server::wire::messages::FileId;
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

/// DeletePending as FileStandardInformation and FileAllInformation report it.
async fn reported_delete_pending(c: &mut Client, file_id: FileId) -> (bool, bool) {
    let standard = c
        .query_file_info(file_id, FILE_STANDARD_INFORMATION)
        .await
        .unwrap();
    let all = c
        .query_file_info(file_id, FILE_ALL_INFORMATION)
        .await
        .unwrap();
    (standard[20] != 0, all[40 + 20] != 0)
}

#[tokio::test]
async fn query_info_reports_delete_pending_on_every_open() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;

    let fa = a.open("f.txt", ACCESS, SHARE_ALL).await.unwrap();
    let fb = b.open("f.txt", ACCESS, SHARE_ALL).await.unwrap();
    assert_eq!(reported_delete_pending(&mut b, fb).await, (false, false));
    assert_eq!(a.set_delete(fa, true).await, 0);
    assert_eq!(reported_delete_pending(&mut a, fa).await, (true, true));
    assert_eq!(reported_delete_pending(&mut b, fb).await, (true, true));
    assert_eq!(a.set_delete(fa, false).await, 0);
    assert_eq!(reported_delete_pending(&mut b, fb).await, (false, false));
    a.close(fa).await;
    b.close(fb).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn delete_on_close_keeps_a_directory_with_hidden_entries() {
    let td = tempdir().unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    std::fs::write(td.path().join("d").join("a:b"), b"x").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut a = server.client().await;
    let mut b = server.client().await;
    let dir = |options| Create {
        name: "d",
        access: RW | DELETE,
        options: FILE_DIRECTORY_FILE | options,
        ..Create::default()
    };

    let fa = a.create(dir(FILE_DELETE_ON_CLOSE)).await.unwrap().file_id;
    let fb = b.create(dir(0)).await.unwrap().file_id;
    a.close(fa).await;
    // The directory is not empty, so closing the delete-on-close open
    // leaves it as it was.
    let again = a.create(dir(0)).await.unwrap().file_id;
    a.close(again).await;
    b.close(fb).await;
    assert!(td.path().join("d").join("a:b").exists());
}
