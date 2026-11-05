//! Named streams on a `LocalFsBackend` share on Windows, over the wire:
//! the NTFS streams that requests leave on the host.

#![cfg(all(feature = "localfs", windows))]

mod common;

use std::io::Read as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;

use common::client::*;
use smb_server::LocalFsBackend;
use smb_server::ntstatus::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS};
use smb_server::wire::messages::FileId;
use tempfile::TempDir;

const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

/// A new directory under the build's temporary directory holding `f.txt`
/// and the directory `dir`.
fn root() -> TempDir {
    let td = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    std::fs::create_dir(td.path().join("dir")).unwrap();
    td
}

/// The stream `stream` of `path`, read on the host.
fn host_stream(path: &Path, stream: &str) -> Option<Vec<u8>> {
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let mut name = path.as_os_str().to_owned();
    name.push(format!(":{stream}"));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(name)
        .ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    Some(data)
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

/// Opens the stream `name` with `disposition`, writes `data` to it in
/// 64 KiB pieces and closes it.
async fn write_stream(
    c: &mut Client,
    name: &str,
    disposition: u32,
    data: &[u8],
) -> Result<(), u32> {
    let created = c
        .create(Create {
            name,
            access: FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_READ | SHARE_DELETE,
            disposition,
            ..Create::default()
        })
        .await?;
    let mut written = Ok(());
    for (at, chunk) in data.chunks(65536).enumerate() {
        if let Err(e) = c.write(created.file_id, (at * 65536) as u64, chunk).await {
            written = Err(e);
            break;
        }
    }
    c.close(created.file_id).await;
    written
}

async fn read_stream(c: &mut Client, name: &str) -> Result<Vec<u8>, u32> {
    let opened = c.open(name, FILE_GENERIC_READ, SHARE_ALL).await?;
    let mut data = Vec::new();
    loop {
        match c.read(opened, data.len() as u64, 65536).await {
            Ok(chunk) if !chunk.is_empty() => data.extend(chunk),
            _ => break,
        }
    }
    c.close(opened).await;
    Ok(data)
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

#[tokio::test]
async fn streams_land_in_ntfs_streams() {
    let td = root();
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
    write_stream(
        &mut c,
        &format!("f.txt:{tags}"),
        FILE_OVERWRITE_IF,
        b"bplist00",
    )
    .await
    .unwrap();
    let fork: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    write_stream(&mut c, "f.txt:AFP_Resource", FILE_OPEN_IF, &fork)
        .await
        .unwrap();
    write_stream(&mut c, "dir:ds", FILE_OVERWRITE_IF, b"dir stream")
        .await
        .unwrap();
    assert_eq!(host_stream(&f, tags).unwrap(), b"bplist00");
    assert_eq!(host_stream(&f, "AFP_Resource").unwrap(), fork);
    assert_eq!(
        host_stream(&td.path().join("dir"), "ds").unwrap(),
        b"dir stream"
    );
    assert_eq!(
        read_stream(&mut c, "f.txt:afp_resource").await.unwrap(),
        fork
    );
    assert_eq!(std::fs::read(&f).unwrap(), b"data");

    let file = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let listed = c
        .query_file_info(file, FILE_STREAM_INFORMATION)
        .await
        .unwrap();
    c.close(file).await;
    let mut listed = stream_entries(&listed);
    listed[1..].sort();
    assert_eq!(
        listed,
        [
            ("::$DATA".to_string(), 4),
            (":AFP_Resource:$DATA".to_string(), 300_000),
            (format!(":{tags}:$DATA"), 8),
        ]
    );

    remove_stream(&mut c, &format!("f.txt:{tags}")).await;
    assert!(host_stream(&f, tags).is_none());
    assert_eq!(
        read_stream(&mut c, &format!("f.txt:{tags}")).await,
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );

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
    assert!(host_stream(&f, "AFP_Resource").is_none());
}

/// Renames the open `file` to `to`, a stream name such as `:s` or
/// `::$DATA`.
async fn rename(c: &mut Client, file: FileId, to: &str, replace: bool) -> u32 {
    let name = common::utf16le(to);
    let mut buf = vec![0u8; 16];
    buf[0] = u8::from(replace);
    buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(&name);
    c.set_info(file, FILE_RENAME_INFORMATION, buf).await
}

#[tokio::test]
async fn streams_rename_both_ways_through_the_default_stream() {
    let td = root();
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    let f = td.path().join("f.txt");
    write_stream(&mut c, "f.txt:s", FILE_OVERWRITE_IF, b"sdata")
        .await
        .unwrap();

    // A named stream to another name.
    let s = c.open("f.txt:s", RW | DELETE, SHARE_ALL).await.unwrap();
    assert_eq!(rename(&mut c, s, ":t", false).await, STATUS_SUCCESS);
    assert!(host_stream(&f, "s").is_none());
    assert_eq!(host_stream(&f, "t").unwrap(), b"sdata");
    c.close(s).await;

    // The default stream into a named one, through the client's own open
    // of the default stream, which then reads the stream.
    let default = c.open("f.txt", RW | DELETE, SHARE_ALL).await.unwrap();
    assert_eq!(
        rename(&mut c, default, ":moved", false).await,
        STATUS_SUCCESS
    );
    assert_eq!(std::fs::read(&f).unwrap(), b"");
    assert_eq!(host_stream(&f, "moved").unwrap(), b"data");
    assert_eq!(c.read(default, 0, 64).await.unwrap(), b"data");
    c.close(default).await;

    // A named stream onto the empty default stream, which the open then
    // reads.
    let t = c.open("f.txt:t", RW | DELETE, SHARE_ALL).await.unwrap();
    assert_eq!(rename(&mut c, t, "::$DATA", true).await, STATUS_SUCCESS);
    assert_eq!(std::fs::read(&f).unwrap(), b"sdata");
    assert!(host_stream(&f, "t").is_none());
    assert_eq!(c.read(t, 0, 64).await.unwrap(), b"sdata");
    assert_eq!(c.write(t, 5, b"!").await, Ok(1));
    c.close(t).await;
    assert_eq!(std::fs::read(&f).unwrap(), b"sdata!");
}
