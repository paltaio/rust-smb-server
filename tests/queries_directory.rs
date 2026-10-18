//! QUERY_DIRECTORY against `LocalFsBackend` over TCP loopback.
#![cfg(feature = "localfs")]

mod common;

use common::client::*;
use common::id_both_entries;
use smb_server::wire::messages::QueryDirectoryRequest;
use smb_server::{LocalFsBackend, ntstatus};
use tempfile::tempdir;

const RESTART: u8 = QueryDirectoryRequest::FLAG_RESTART_SCANS;
const REOPEN: u8 = QueryDirectoryRequest::FLAG_REOPEN;

async fn client(root: &std::path::Path) -> (Server, Client) {
    let server = Server::public(LocalFsBackend::new(root).expect("open root")).await;
    let c = server.client().await;
    (server, c)
}

#[tokio::test]
async fn first_query_with_no_match_returns_no_such_file() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a.txt"), b"x").expect("write");
    std::fs::create_dir(td.path().join("empty")).expect("mkdir");
    let (_server, mut c) = client(td.path()).await;

    let root = c.open_dir("").await;
    assert_eq!(
        c.list(root, 0, "nomatch*").await,
        Err(ntstatus::STATUS_NO_SUCH_FILE)
    );
    assert_eq!(
        c.list(root, 0, "nomatch*").await,
        Err(ntstatus::STATUS_NO_MORE_FILES)
    );
    // A reopen is a first query again.
    assert_eq!(
        c.list(root, REOPEN, "nomatch*").await,
        Err(ntstatus::STATUS_NO_SUCH_FILE)
    );
    c.close(root).await;

    let empty = c.open_dir("empty").await;
    assert_eq!(
        c.list(empty, 0, "*.txt").await,
        Err(ntstatus::STATUS_NO_SUCH_FILE)
    );
    c.close(empty).await;
}

#[tokio::test]
async fn dot_entries_lead_listings_below_the_root() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("d")).expect("mkdir");
    std::fs::write(td.path().join("d").join("f.txt"), b"x").expect("write");
    let (_server, mut c) = client(td.path()).await;

    let root = c.open_dir("").await;
    assert_eq!(c.list(root, 0, "*").await.unwrap(), ["d"]);
    let dir = c.open_dir("d").await;
    assert_eq!(
        c.list(dir, RESTART, "*").await.unwrap(),
        [".", "..", "f.txt"]
    );
    assert_eq!(c.list(dir, RESTART, "*.txt").await.unwrap(), ["f.txt"]);
    assert_eq!(c.list(dir, RESTART, ".").await.unwrap(), ["."]);

    // "." carries the directory's id and ".." its parent's.
    let (status, buf) = c
        .query_directory(dir, FILE_ID_BOTH_DIRECTORY_INFORMATION, RESTART, "*", 65536)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    let entries = id_both_entries(&buf);
    let (_, dir_id) = c
        .query_info(dir, INFO_FILE, FILE_INTERNAL_INFORMATION, 8)
        .await;
    let (_, root_id) = c
        .query_info(root, INFO_FILE, FILE_INTERNAL_INFORMATION, 8)
        .await;
    assert_eq!(entries[0].0, ".");
    assert_eq!(entries[0].1, u64_at(&dir_id, 0));
    assert_eq!(entries[1].0, "..");
    assert_eq!(entries[1].1, u64_at(&root_id, 0));

    c.close(dir).await;
    c.close(root).await;
}

#[tokio::test]
async fn an_entry_larger_than_the_buffer_returns_a_partial_name() {
    let td = tempdir().expect("tempdir");
    let name = "n".repeat(40);
    std::fs::write(td.path().join(&name), b"x").expect("write");
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;

    // FileIdBothDirectoryInformation has 104 fixed bytes.
    let (status, _) = c
        .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, RESTART, "*", 103)
        .await;
    assert_eq!(status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);

    let (status, buf) = c
        .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, RESTART, "*", 114)
        .await;
    assert_eq!(status, ntstatus::STATUS_BUFFER_OVERFLOW);
    assert_eq!(buf.len(), 114);
    let entries = id_both_entries(&buf);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "n".repeat(5));
    assert_eq!(entries[0].2, 80);

    // The same entry comes back whole with room for it.
    let (status, buf) = c
        .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, 0, "*", 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(id_both_entries(&buf)[0].0, name);
    // The last entry is not padded.
    assert_eq!(buf.len(), 104 + 80);

    c.close(root).await;
}

#[tokio::test]
async fn entries_that_do_not_fit_wait_for_the_next_query() {
    let td = tempdir().expect("tempdir");
    for name in ["a", "b", "c"] {
        std::fs::write(td.path().join(name), b"x").expect("write");
    }
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;

    // Room for one 106-byte entry, then 112 bytes to the next one.
    let mut seen = Vec::new();
    let mut flags = RESTART;
    loop {
        let (status, buf) = c
            .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, flags, "*", 200)
            .await;
        flags = 0;
        if status == ntstatus::STATUS_NO_MORE_FILES {
            break;
        }
        assert_eq!(status, ntstatus::STATUS_SUCCESS);
        let entries = id_both_entries(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(buf.len(), 106);
        seen.push(entries[0].0.clone());
    }
    seen.sort();
    assert_eq!(seen, ["a", "b", "c"]);

    c.close(root).await;
}

#[tokio::test]
async fn listing_requires_list_directory_access() {
    let td = tempdir().expect("tempdir");
    let (_server, mut c) = client(td.path()).await;
    let dir = c
        .open_with_options("", FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    assert_eq!(
        c.list(dir, RESTART, "*").await,
        Err(ntstatus::STATUS_ACCESS_DENIED)
    );
    c.close(dir).await;
}

#[tokio::test]
async fn information_classes_get_the_spec_statuses() {
    let td = tempdir().expect("tempdir");
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;
    // FileIdExtdDirectoryInformation and FileIdAllExtdBothDirectoryInformation.
    for class in [0x3C, 0x51] {
        let (status, _) = c.query_directory(root, class, RESTART, "*", 4096).await;
        assert_eq!(status, ntstatus::STATUS_NOT_SUPPORTED, "class {class:#x}");
    }
    // FileBasicInformation is not a directory class; 0x7F is no class.
    for class in [0x04, 0x7F] {
        let (status, _) = c.query_directory(root, class, RESTART, "*", 4096).await;
        assert_eq!(
            status,
            ntstatus::STATUS_INVALID_INFO_CLASS,
            "class {class:#x}"
        );
    }
    c.close(root).await;
}

#[tokio::test]
async fn patterns_are_validated_and_kept_across_restarts() {
    let td = tempdir().expect("tempdir");
    for name in ["a1", "a2", "b1"] {
        std::fs::write(td.path().join(name), b"x").expect("write");
    }
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;

    assert_eq!(
        c.list(root, RESTART, "bad|name").await,
        Err(ntstatus::STATUS_OBJECT_NAME_INVALID)
    );
    assert_eq!(
        c.list(root, RESTART, &"<".repeat(256)).await,
        Err(ntstatus::STATUS_OBJECT_NAME_INVALID)
    );
    assert_eq!(c.list(root, RESTART, "a*").await.unwrap(), ["a1", "a2"]);
    // A restart with no pattern keeps the earlier one.
    assert_eq!(c.list(root, RESTART, "").await.unwrap(), ["a1", "a2"]);
    // A restart with a pattern replaces it.
    assert_eq!(c.list(root, RESTART, "b*").await.unwrap(), ["b1"]);

    c.close(root).await;
}

#[tokio::test]
async fn output_buffer_is_capped_at_max_transact_size() {
    let td = tempdir().expect("tempdir");
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;
    let (status, _) = c
        .query_directory(
            root,
            FILE_ID_BOTH_DIRECTORY_INFORMATION,
            RESTART,
            "*",
            0x7FFF_FFFF,
        )
        .await;
    assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER);
    c.close(root).await;
}

/// Every listed name opens, and names that cannot be opened are not listed.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn listing_and_open_agree_on_names() {
    use smb_server::ShareBackend as _;

    let td = tempdir().expect("tempdir");
    for name in ["aux.c", "a:b", "q?", "lower.txt"] {
        std::fs::write(td.path().join(name), b"x").expect("write");
    }
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    assert!(backend.capabilities().case_sensitive);
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let root = c.open_dir("").await;

    let names = c.list(root, RESTART, "*").await.unwrap();
    assert_eq!(names, ["aux.c", "lower.txt"]);
    for name in &names {
        let id = c.open(name, FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
        c.close(id).await;
    }
    // Lookups are case-sensitive here, and so is matching.
    assert!(
        c.open("LOWER.TXT", FILE_GENERIC_READ, SHARE_ALL)
            .await
            .is_err()
    );
    assert_eq!(
        c.list(root, RESTART, "LOWER.TXT").await,
        Err(ntstatus::STATUS_NO_MORE_FILES)
    );
    assert_eq!(
        c.list(root, RESTART, "lower.*").await.unwrap(),
        ["lower.txt"]
    );

    c.close(root).await;
}
