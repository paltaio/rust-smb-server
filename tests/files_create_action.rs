//! CREATE reports what the open did, and a missing directory on the way to
//! the name is reported as such.

mod common;

use common::client::*;
use smb_server::{LocalFsBackend, OpenAction, OpenIntent, OpenOptions, ShareBackend, ntstatus};
use tempfile::tempdir;

const SUPERSEDED: u32 = 0;
const OPENED: u32 = 1;
const CREATED: u32 = 2;
const OVERWRITTEN: u32 = 3;

#[tokio::test]
async fn create_action_follows_what_the_backend_did() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("old.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    let cases = [
        ("new-open-if.txt", FILE_OPEN_IF, CREATED),
        ("old.txt", FILE_OPEN_IF, OPENED),
        ("new-overwrite-if.txt", FILE_OVERWRITE_IF, CREATED),
        ("old.txt", FILE_OVERWRITE_IF, OVERWRITTEN),
        ("old.txt", FILE_OVERWRITE, OVERWRITTEN),
        ("old.txt", FILE_SUPERSEDE, SUPERSEDED),
        ("new-supersede.txt", FILE_SUPERSEDE, CREATED),
        ("new-create.txt", FILE_CREATE, CREATED),
        ("old.txt", FILE_OPEN, OPENED),
    ];
    for (name, disposition, action) in cases {
        let resp = c
            .create(Create {
                name,
                disposition,
                ..Create::default()
            })
            .await
            .unwrap_or_else(|s| panic!("{name} {disposition}: {s:#x}"));
        assert_eq!(
            resp.create_action, action,
            "{name} disposition {disposition}"
        );
        c.close(resp.file_id).await;
    }

    let dir = c
        .create(Create {
            name: "d",
            access: FILE_GENERIC_READ,
            disposition: FILE_OPEN_IF,
            options: FILE_DIRECTORY_FILE,
            ..Create::default()
        })
        .await
        .unwrap();
    assert_eq!(dir.create_action, CREATED);
    c.close(dir.file_id).await;
    let dir = c
        .create(Create {
            name: "d",
            access: FILE_GENERIC_READ,
            disposition: FILE_OPEN_IF,
            options: FILE_DIRECTORY_FILE,
            ..Create::default()
        })
        .await
        .unwrap();
    assert_eq!(dir.create_action, OPENED);
}

#[tokio::test]
async fn missing_parent_is_path_not_found() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("file"), b"").unwrap();
    std::fs::create_dir(td.path().join("dir")).unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    for (name, disposition) in [
        ("nodir\\f.txt", FILE_OPEN),
        ("nodir\\f.txt", FILE_CREATE),
        ("nodir\\deeper\\f.txt", FILE_OPEN_IF),
        ("file\\f.txt", FILE_OPEN),
    ] {
        let status = c
            .create(Create {
                name,
                disposition,
                ..Create::default()
            })
            .await
            .unwrap_err();
        assert_eq!(status, ntstatus::STATUS_OBJECT_PATH_NOT_FOUND, "{name}");
    }
    let status = c
        .create(Create {
            name: "dir\\missing.txt",
            ..Create::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status, ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    // A file opened as a directory is still not a directory.
    let status = c
        .create(Create {
            name: "file",
            access: FILE_GENERIC_READ,
            options: FILE_DIRECTORY_FILE,
            ..Create::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status, ntstatus::STATUS_NOT_A_DIRECTORY);
}

#[tokio::test]
async fn open_if_opens_an_existing_file_with_the_access_asked_for() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("ro.txt"), b"keep").unwrap();
    let backend = LocalFsBackend::new(td.path()).unwrap();
    let path = "ro.txt".parse().unwrap();
    let opts = OpenOptions {
        read: true,
        write: false,
        write_attributes: false,
        intent: OpenIntent::OpenOrCreate,
        directory: false,
        non_directory: false,
        delete_on_close: false,
    };
    let (h, action) = backend.open(&path, opts).await.unwrap();
    assert_eq!(action, OpenAction::Opened);
    // The host descriptor is read-only, so even a privileged process cannot
    // write through it.
    assert!(h.write(0, b"X").await.is_err());
    h.close().await.unwrap();
    assert_eq!(std::fs::read(td.path().join("ro.txt")).unwrap(), b"keep");

    let (h, action) = backend
        .open(&"new.txt".parse().unwrap(), opts)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Created);
    h.close().await.unwrap();
}
