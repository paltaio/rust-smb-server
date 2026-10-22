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
const SINGLE: u8 = QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY;

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
async fn dot_entries_lead_listings() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("d")).expect("mkdir");
    std::fs::write(td.path().join("d").join("f.txt"), b"x").expect("write");
    let (_server, mut c) = client(td.path()).await;

    let root = c.open_dir("").await;
    assert_eq!(c.list(root, 0, "*").await.unwrap(), [".", "..", "d"]);
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

/// Names in a FileIdBothDirectoryInformation buffer, in the order returned.
fn names(buf: &[u8]) -> Vec<String> {
    id_both_entries(buf).into_iter().map(|e| e.0).collect()
}

/// Name and bytes of each entry in a QUERY_DIRECTORY buffer of `class`.
fn dir_entries(class: u8, mut buf: &[u8]) -> Vec<(String, &[u8])> {
    let (name_length_at, name_at) = match class {
        0x01 => (60, 64),
        0x02 => (60, 68),
        0x03 => (60, 94),
        0x0C => (8, 12),
        0x25 => (60, 104),
        0x26 => (60, 80),
        _ => panic!("class {class:#x}"),
    };
    let mut out = Vec::new();
    loop {
        let next = u32_at(buf, 0) as usize;
        let end = name_at + u32_at(buf, name_length_at) as usize;
        let units: Vec<u16> = buf[name_at..end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        out.push((String::from_utf16(&units).expect("utf16"), &buf[..end]));
        if next == 0 {
            return out;
        }
        buf = &buf[next..];
    }
}

#[tokio::test]
async fn dot_entries_at_an_empty_root_page_and_restart() {
    let td = tempdir().expect("tempdir");
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;

    // One entry per query, when asked for one or when only one fits: "."
    // takes 106 bytes and ".." starts 112 bytes in. The second round
    // restarts a listing that ran out.
    for (flags, len) in [(SINGLE, 65536), (0, 110)] {
        for (i, name) in [".", ".."].into_iter().enumerate() {
            let flags = if i == 0 { flags | RESTART } else { flags };
            let (status, buf) = c
                .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, flags, "*", len)
                .await;
            assert_eq!(status, ntstatus::STATUS_SUCCESS);
            assert_eq!(names(&buf), [name]);
        }
        assert_eq!(
            c.list(root, flags, "*").await,
            Err(ntstatus::STATUS_NO_MORE_FILES)
        );
    }

    // A reopen lists them again.
    assert_eq!(c.list(root, REOPEN, "*").await.unwrap(), [".", ".."]);
    assert_eq!(
        c.list(root, 0, "*").await,
        Err(ntstatus::STATUS_NO_MORE_FILES)
    );

    c.close(root).await;
}

#[tokio::test]
async fn patterns_at_the_root_apply_to_dot_entries() {
    let td = tempdir().expect("tempdir");
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;

    assert_eq!(
        c.list(root, 0, "*.txt").await,
        Err(ntstatus::STATUS_NO_SUCH_FILE)
    );
    std::fs::write(td.path().join("a.txt"), b"x").expect("write");
    assert_eq!(c.list(root, RESTART, "*.txt").await.unwrap(), ["a.txt"]);
    assert_eq!(c.list(root, RESTART, "a*").await.unwrap(), ["a.txt"]);
    assert_eq!(
        c.list(root, RESTART, "*").await.unwrap(),
        [".", "..", "a.txt"]
    );
    assert_eq!(c.list(root, RESTART, ".").await.unwrap(), ["."]);
    assert_eq!(c.list(root, RESTART, "..").await.unwrap(), [".."]);
    assert_eq!(c.list(root, RESTART, ".*").await.unwrap(), [".", ".."]);
    assert_eq!(c.list(root, RESTART, "?").await.unwrap(), ["."]);
    assert_eq!(c.list(root, RESTART, "??").await.unwrap(), [".."]);
    // DOS_QM matches nothing at a dot or at the end, DOS_DOT matches a dot
    // or nothing at the end, and DOS_STAR stops before the last dot.
    assert_eq!(c.list(root, RESTART, ".>").await.unwrap(), ["."]);
    assert_eq!(c.list(root, RESTART, "\"\"").await.unwrap(), [".", ".."]);
    assert_eq!(c.list(root, RESTART, "<.").await.unwrap(), [".", ".."]);
    assert_eq!(
        c.list(root, RESTART, "<").await,
        Err(ntstatus::STATUS_NO_MORE_FILES)
    );

    // The dot entries come first, in this order.
    let (status, buf) = c
        .query_directory(
            root,
            FILE_ID_BOTH_DIRECTORY_INFORMATION,
            RESTART,
            "*",
            65536,
        )
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(names(&buf), [".", "..", "a.txt"]);

    c.close(root).await;
}

#[tokio::test]
async fn dot_entries_at_the_root_describe_the_root() {
    let td = tempdir().expect("tempdir");
    let (_server, mut c) = client(td.path()).await;
    let root = c.open_dir("").await;
    let (_, internal) = c
        .query_info(root, INFO_FILE, FILE_INTERNAL_INFORMATION, 8)
        .await;
    let root_id = u64_at(&internal, 0);
    assert_ne!(root_id, 0);
    let (_, basic) = c
        .query_info(root, INFO_FILE, FILE_BASIC_INFORMATION, 40)
        .await;

    // FileDirectoryInformation, FileFullDirectoryInformation,
    // FileBothDirectoryInformation, FileNamesInformation,
    // FileIdBothDirectoryInformation and FileIdFullDirectoryInformation.
    for class in [0x01, 0x02, 0x03, 0x0C, 0x25, 0x26] {
        let (status, buf) = c.query_directory(root, class, RESTART, "*", 4096).await;
        assert_eq!(status, ntstatus::STATUS_SUCCESS, "class {class:#x}");
        let entries = dir_entries(class, &buf);
        let listed: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(listed, [".", ".."], "class {class:#x}");
        let (dot, dotdot) = (entries[0].1, entries[1].1);
        // ".." has FileIndex 0.
        assert_eq!(u32_at(dotdot, 4), 0, "class {class:#x}");
        if class == 0x0C {
            continue;
        }
        // Times, sizes and attributes: both are the root directory.
        assert_eq!(dot[8..60], dotdot[8..60], "class {class:#x}");
        assert_eq!(u64_at(dot, 24), u64_at(&basic, 16), "class {class:#x}");
        assert_eq!(u32_at(dot, 56), u32_at(&basic, 32), "class {class:#x}");
        assert_ne!(u32_at(dot, 56) & FILE_ATTRIBUTE_DIRECTORY, 0);
        // "." carries the root's id and ".." none.
        let id_at = match class {
            0x25 => 96,
            0x26 => 72,
            _ => continue,
        };
        assert_eq!(u64_at(dot, id_at), root_id, "class {class:#x}");
        assert_eq!(u64_at(dotdot, id_at), 0, "class {class:#x}");
    }

    c.close(root).await;
}

/// The requests `smbclient -c ls` makes on a share: a CREATE of the root
/// for listing and reading attributes, then FileIdBothDirectoryInformation
/// queries for "*" with no flags until STATUS_NO_MORE_FILES.
#[tokio::test]
async fn smbclient_ls_lists_an_empty_share() {
    let td = tempdir().expect("tempdir");
    let (_server, mut c) = client(td.path()).await;
    let root = c
        .create(Create {
            access: FILE_READ_DATA | FILE_READ_ATTRIBUTES,
            share: SHARE_READ | SHARE_WRITE,
            options: FILE_DIRECTORY_FILE,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            ..Create::default()
        })
        .await
        .expect("open root")
        .file_id;

    let mut listed = Vec::new();
    loop {
        let (status, buf) = c
            .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, 0, "*", 65536)
            .await;
        if status == ntstatus::STATUS_NO_MORE_FILES {
            break;
        }
        assert_eq!(status, ntstatus::STATUS_SUCCESS);
        listed.extend(names(&buf));
    }
    assert_eq!(listed, [".", ".."]);

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
        .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, RESTART, "n*", 103)
        .await;
    assert_eq!(status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);

    let (status, buf) = c
        .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, RESTART, "n*", 114)
        .await;
    assert_eq!(status, ntstatus::STATUS_BUFFER_OVERFLOW);
    assert_eq!(buf.len(), 114);
    let entries = id_both_entries(&buf);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "n".repeat(5));
    assert_eq!(entries[0].2, 80);

    // The same entry comes back whole with room for it.
    let (status, buf) = c
        .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION, 0, "n*", 4096)
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

    // Room for one entry of 106 or 108 bytes, then 112 bytes to the next
    // one.
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
        assert_eq!(buf.len(), 104 + 2 * entries[0].0.len());
        seen.push(entries[0].0.clone());
    }
    seen.sort();
    assert_eq!(seen, [".", "..", "a", "b", "c"]);

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

/// Every listed name but "." and ".." opens, and names that cannot be
/// opened are not listed.
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
    assert_eq!(names, [".", "..", "aux.c", "lower.txt"]);
    for name in &names[2..] {
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
