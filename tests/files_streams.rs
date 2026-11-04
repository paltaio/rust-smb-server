//! Named streams on a `LocalFsBackend` share on Linux, over the wire: what
//! lands on disk, and what watchers hear of it.

#![cfg(all(feature = "localfs", target_os = "linux"))]

mod common;

use std::path::Path;
use std::time::Duration;

use common::client::*;
use common::notify::*;
use smb_server::ntstatus::STATUS_SUCCESS;
use smb_server::{LocalFsBackend, Share};
use tempfile::TempDir;

const ATTRIBUTES: u32 = 0x4;
const LAST_WRITE: u32 = 0x10;
const STREAM_NAME: u32 = 0x200;
const STREAM_SIZE: u32 = 0x400;
const STREAM_WRITE: u32 = 0x800;
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
const FILE_ACTION_MODIFIED_STREAM: u32 = 8;

/// A new directory under the build's temporary directory holding `f.txt`,
/// or `None` where that filesystem has no user extended attributes.
fn root() -> Option<TempDir> {
    let td = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    match rustix::fs::getxattr_query(td.path(), "user.DosStream.") {
        Err(rustix::io::Errno::NODATA) => Some(td),
        probe => {
            eprintln!(
                "skipping: no user extended attributes on {} ({probe:?})",
                td.path().display()
            );
            None
        }
    }
}

/// The value of the extended attribute `attr` of `path`.
fn xattr(path: &Path, attr: &str) -> Option<Vec<u8>> {
    let len = rustix::fs::getxattr_query(path, attr).ok()?;
    let mut buf = vec![0; len];
    let len = rustix::fs::getxattr(path, attr, &mut buf[..]).unwrap();
    buf.truncate(len);
    Some(buf)
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

/// Name and size of each FILE_STREAM_INFORMATION entry in `buf`.
fn stream_entries(buf: &[u8]) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let next = u32_at(buf, at) as usize;
        let len = u32_at(buf, at + 4) as usize;
        let units: Vec<u16> = buf[at + 24..at + 24 + len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let size = u64::from_le_bytes(buf[at + 8..at + 16].try_into().unwrap());
        entries.push((String::from_utf16(&units).unwrap(), size));
        if next == 0 {
            break;
        }
        at += next;
    }
    entries
}

/// Creates or overwrites the stream `name`, writes `data` to it and closes
/// it, as a macOS client sets an extended attribute.
async fn set_stream(c: &mut Client, name: &str, data: &[u8]) -> Result<(), u32> {
    let created = c
        .create(Create {
            name,
            access: FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_READ | SHARE_DELETE,
            disposition: FILE_OVERWRITE_IF,
            ..Create::default()
        })
        .await?;
    let written = c.write(created.file_id, 0, data).await;
    c.close(created.file_id).await;
    written.map(|_| ())
}

/// Removes the stream `name` as a macOS client removes an extended
/// attribute: an open for DELETE, a disposition, a close.
async fn remove_stream(c: &mut Client, name: &str) {
    let created = c
        .create(Create {
            name,
            access: DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            share: 0,
            ..Create::default()
        })
        .await
        .expect("open for deletion");
    assert_eq!(c.set_delete(created.file_id, true).await, STATUS_SUCCESS);
    c.close(created.file_id).await;
}

async fn read_stream(c: &mut Client, name: &str) -> Result<Vec<u8>, u32> {
    let created = c
        .create(Create {
            name,
            access: FILE_GENERIC_READ,
            ..Create::default()
        })
        .await?;
    let data = c.read(created.file_id, 0, 65536).await;
    c.close(created.file_id).await;
    data
}

#[tokio::test]
async fn streams_land_in_extended_attributes() {
    let Some(td) = root() else {
        return;
    };
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    let f = td.path().join("f.txt");

    let share = c.open_dir("").await;
    let (status, attributes) = c
        .query_info(share, INFO_FILESYSTEM, FS_ATTRIBUTE_INFORMATION, 1024)
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        u32_at(&attributes, 0) & FILE_NAMED_STREAMS,
        FILE_NAMED_STREAMS
    );
    c.close(share).await;

    let tags = "com.apple.metadata\u{F022}_kMDItemUserTags";
    set_stream(&mut c, &format!("f.txt:{tags}"), b"bplist")
        .await
        .unwrap();
    set_stream(&mut c, "f.txt:Zone.Identifier", b"[ZoneTransfer]")
        .await
        .unwrap();
    assert_eq!(
        xattr(&f, &format!("user.DosStream.{tags}:$DATA")).unwrap(),
        b"bplist\0"
    );
    assert_eq!(
        xattr(&f, "user.DosStream.Zone.Identifier:$DATA").unwrap(),
        b"[ZoneTransfer]\0"
    );
    assert_eq!(std::fs::read(&f).unwrap(), b"data");
    assert_eq!(
        read_stream(&mut c, "f.txt:zone.identifier:$DATA")
            .await
            .unwrap(),
        b"[ZoneTransfer]"
    );

    let file = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let info = c
        .query_file_info(file, FILE_STREAM_INFORMATION)
        .await
        .unwrap();
    c.close(file).await;
    let mut listed = stream_entries(&info);
    listed[1..].sort();
    assert_eq!(
        listed,
        [
            ("::$DATA".to_string(), 4),
            (":Zone.Identifier:$DATA".to_string(), 14),
            (format!(":{tags}:$DATA"), 6)
        ]
    );

    remove_stream(&mut c, &format!("f.txt:{tags}")).await;
    assert!(xattr(&f, &format!("user.DosStream.{tags}:$DATA")).is_none());

    // An overwrite of the file takes its streams with it.
    let overwritten = c
        .create(Create {
            name: "f.txt",
            disposition: FILE_OVERWRITE_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(overwritten.file_id).await;
    assert!(xattr(&f, "user.DosStream.Zone.Identifier:$DATA").is_none());
}

#[tokio::test]
async fn a_stream_on_a_missing_file_creates_the_file() {
    let Some(td) = root() else {
        return;
    };
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    set_stream(&mut c, "new.txt:s", b"x").await.unwrap();
    let new = td.path().join("new.txt");
    assert_eq!(std::fs::read(&new).unwrap(), b"");
    assert_eq!(xattr(&new, "user.DosStream.s:$DATA").unwrap(), b"x\0");
}

#[tokio::test]
async fn a_stream_past_what_an_attribute_holds_is_served_from_the_store() {
    let Some(td) = root() else {
        return;
    };
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut watcher = server.client().await;
    let mut c = server.client().await;
    let share = watcher.open_dir("").await;
    let mid = arm(&mut watcher, share, 4096, NAMES, false).await;

    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let created = c
        .create(Create {
            name: "f.txt:big",
            disposition: FILE_OVERWRITE_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    for (at, chunk) in data.chunks(65536).enumerate() {
        let offset = (at * 65536) as u64;
        assert_eq!(
            c.write(created.file_id, offset, chunk).await,
            Ok(chunk.len() as u32)
        );
    }
    c.close(created.file_id).await;
    assert!(xattr(&td.path().join("f.txt"), "user.DosStream.big:$DATA").is_none());

    let opened = c
        .open("f.txt:big", FILE_GENERIC_READ, SHARE_ALL)
        .await
        .unwrap();
    let mut read = Vec::new();
    while read.len() < data.len() {
        read.extend(c.read(opened, read.len() as u64, 65536).await.unwrap());
    }
    c.close(opened).await;
    assert_eq!(read, data);
    let file = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let info = c
        .query_file_info(file, FILE_STREAM_INFORMATION)
        .await
        .unwrap();
    c.close(file).await;
    assert_eq!(
        stream_entries(&info),
        [
            ("::$DATA".to_string(), 4),
            (":big:$DATA".to_string(), 200_000)
        ]
    );

    // The store made in the share root is not a change clients hear of.
    tokio::time::sleep(Duration::from_millis(600)).await;
    create_file(&mut c, "marker").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("marker")])
    );
}

async fn create_file(c: &mut Client, name: &str) {
    let created = c
        .create(Create {
            name,
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(created.file_id).await;
}

/// The changes a watcher of the share root with every attribute, write and
/// stream filter hears while a client sets, rewrites and removes a stream
/// of `f.txt` on a share over `backend`.
async fn heard_of_stream_changes(td: &TempDir, backend: LocalFsBackend) -> Vec<(u32, String)> {
    let filter = ATTRIBUTES | LAST_WRITE | STREAM_NAME | STREAM_SIZE | STREAM_WRITE;
    let server = Server::start(
        smb_server::SmbServer::builder().share(Share::new("share", backend).public()),
    )
    .await;
    let mut watcher = server.client().await;
    let mut c = server.client().await;
    let root = watcher.open_dir("").await;
    arm_idle(&mut watcher, root, filter, false).await;
    set_stream(&mut c, "f.txt:s", b"one").await.unwrap();
    set_stream(&mut c, "f.txt:s", b"two").await.unwrap();
    remove_stream(&mut c, "f.txt:s").await;
    assert!(xattr(&td.path().join("f.txt"), "user.DosStream.s:$DATA").is_none());
    // Longer than the server waits for its own report of a change the
    // kernel saw.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let heard = now(&mut watcher, root, false).await.unwrap_or_default();
    watcher.close(root).await;
    heard
}

#[tokio::test]
async fn stream_changes_through_the_server_are_heard_once() {
    let Some(td) = root() else {
        return;
    };
    let quiet = heard_of_stream_changes(
        &td,
        LocalFsBackend::new(td.path())
            .unwrap()
            .watch_host_changes(false),
    )
    .await;
    assert!(!quiet.is_empty());
    let watched = heard_of_stream_changes(&td, LocalFsBackend::new(td.path()).unwrap()).await;
    assert_eq!(watched, quiet);

    // The kernel's reports do reach the watcher: an attribute set on the
    // host is a change of the file's attributes.
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut watcher = server.client().await;
    let root = watcher.open_dir("").await;
    let mid = arm(&mut watcher, root, 4096, ATTRIBUTES, false).await;
    rustix::fs::setxattr(
        td.path().join("f.txt"),
        "user.DosStream.host:$DATA",
        b"\0",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![modified("f.txt")])
    );
}

#[tokio::test]
async fn writes_through_a_long_lived_stream_open_are_not_heard_from_the_host() {
    let Some(td) = root() else {
        return;
    };
    let filter = ATTRIBUTES | LAST_WRITE | STREAM_NAME | STREAM_SIZE | STREAM_WRITE;
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut watcher = server.client().await;
    let mut c = server.client().await;
    let root = watcher.open_dir("").await;
    let created = c
        .create(Create {
            name: "f.txt:s",
            access: FILE_WRITE_DATA | SYNCHRONIZE,
            disposition: FILE_OVERWRITE_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    arm_idle(&mut watcher, root, filter, false).await;
    // Longer than the server's record of a change it made hides the
    // kernel's report of it.
    for (round, wait) in [(0u8, 5600), (1, 600)] {
        assert_eq!(c.write(created.file_id, 0, &[round; 8]).await, Ok(8));
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
    assert_eq!(now(&mut watcher, root, false).await, None);
    c.close(created.file_id).await;
    assert_eq!(
        now(&mut watcher, root, false).await,
        Some(vec![
            modified("f.txt"),
            (FILE_ACTION_MODIFIED_STREAM, "f.txt:s".to_string())
        ])
    );
}
