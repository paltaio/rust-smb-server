//! SET_INFO request validation.

#[path = "support_files.rs"]
mod support;

use smb_server::ntstatus;
use smb_server::wire::messages::FileId;
use support::*;
use tempfile::tempdir;

const FILE_STANDARD_INFORMATION: u8 = 5;
const FILE_LINK_INFORMATION: u8 = 11;
const SECURITY: u8 = 3;

#[tokio::test]
async fn set_info_checks_the_open_first_then_the_request() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", RW | DELETE, SHARE_ALL).await.unwrap();
    let bogus = FileId::new(0xBAD, 0xBAD);

    assert_eq!(
        c.set_info_raw(bogus, SECURITY, 0, vec![0; 20]).await,
        ntstatus::STATUS_FILE_CLOSED
    );
    assert_eq!(
        c.set_info(bogus, 0x7F, vec![0; 8]).await,
        ntstatus::STATUS_FILE_CLOSED
    );
    assert_eq!(
        c.set_info(f, FILE_END_OF_FILE_INFORMATION, vec![]).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        c.set_info(f, FILE_STANDARD_INFORMATION, vec![0; 24]).await,
        ntstatus::STATUS_INVALID_INFO_CLASS
    );
    assert_eq!(
        c.set_info(f, 0x7F, vec![0; 8]).await,
        ntstatus::STATUS_INVALID_INFO_CLASS
    );
    assert_eq!(
        c.set_info(f, FILE_LINK_INFORMATION, vec![0; 24]).await,
        ntstatus::STATUS_NOT_SUPPORTED
    );
}

#[tokio::test]
async fn rename_with_a_root_directory_is_refused() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", RW | DELETE, SHARE_ALL).await.unwrap();

    let name = support::common::utf16le("g.txt");
    let mut buf = vec![0u8; 20];
    buf[8] = 5; // RootDirectory
    buf[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(&name);
    assert_eq!(
        c.set_info(f, FILE_RENAME_INFORMATION, buf.clone()).await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    // A FileNameLength past the buffer.
    buf[8] = 0;
    buf[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        c.set_info(f, FILE_RENAME_INFORMATION, buf).await,
        ntstatus::STATUS_INFO_LENGTH_MISMATCH
    );
    assert!(td.path().join("f.txt").exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn disposition_counts_names_the_listing_hides() {
    let td = tempdir().unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    std::fs::write(td.path().join("d").join("a:b"), b"x").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let dir = c
        .create(Create {
            name: "d",
            access: RW | DELETE,
            options: FILE_DIRECTORY_FILE,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    assert_eq!(
        c.set_delete(dir, true).await,
        ntstatus::STATUS_DIRECTORY_NOT_EMPTY
    );
    c.close(dir).await;
    assert!(td.path().join("d").join("a:b").exists());
}
