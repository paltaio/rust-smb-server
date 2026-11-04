//! Named streams on a `LocalFsBackend` share on macOS, over the wire: the
//! extended attributes a macOS client's requests leave on the host.

#![cfg(all(feature = "localfs", target_os = "macos"))]

mod common;

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use common::client::*;
use smb_server::LocalFsBackend;
use smb_server::ntstatus::{
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use tempfile::TempDir;

const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

/// A new directory under the build's temporary directory holding `f.txt`.
fn root() -> TempDir {
    let td = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    td
}

/// The value of the extended attribute `attr` of `path`.
fn xattr(path: &Path, attr: &str) -> Option<Vec<u8>> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let attr = CString::new(attr).unwrap();
    let mut buf = vec![0u8; 32 << 20];
    // SAFETY: `path` and `attr` are NUL-terminated and `buf` is valid for
    // writes of `buf.len()` bytes; all outlive the call.
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            attr.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            0,
        )
    };
    let len = usize::try_from(len).ok()?;
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
async fn finder_data_lands_in_the_attributes_the_host_finder_reads() {
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

    // Tags.
    let tags = "com.apple.metadata\u{F022}_kMDItemUserTags";
    write_stream(
        &mut c,
        &format!("f.txt:{tags}"),
        FILE_OVERWRITE_IF,
        b"bplist00",
    )
    .await
    .unwrap();
    assert_eq!(
        xattr(&f, "com.apple.metadata:_kMDItemUserTags").unwrap(),
        b"bplist00"
    );

    // Finder info: read the AfpInfo, then write it back with a label.
    assert_eq!(
        read_stream(&mut c, "f.txt:AFP_AfpInfo").await,
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    let info = c
        .create(Create {
            name: "f.txt:AFP_AfpInfo",
            disposition: FILE_OPEN_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    let mut afp_info = c.read(info.file_id, 0, 60).await.unwrap();
    assert_eq!(&afp_info[..16], b"AFP\0\0\0\x01\0\0\0\0\0\x80\0\0\0");
    afp_info[16..24].copy_from_slice(b"TEXTttxt");
    afp_info[25] = 0x0c;
    assert_eq!(c.write(info.file_id, 0, &afp_info).await, Ok(60));
    assert_eq!(
        c.write(info.file_id, 0, b"not AfpInfo").await,
        Err(STATUS_INVALID_PARAMETER)
    );
    c.close(info.file_id).await;
    assert_eq!(
        xattr(&f, "com.apple.FinderInfo").unwrap(),
        &afp_info[16..48]
    );

    // A resource fork larger than one write.
    let fork: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    write_stream(&mut c, "f.txt:AFP_Resource", FILE_OPEN_IF, &fork)
        .await
        .unwrap();
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), fork);
    assert_eq!(
        read_stream(&mut c, "f.txt:afp_resource").await.unwrap(),
        fork
    );

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
            (":AFP_AfpInfo:$DATA".to_string(), 60),
            (":AFP_Resource:$DATA".to_string(), 300_000),
            (format!(":{tags}:$DATA"), 8),
        ]
    );

    remove_stream(&mut c, &format!("f.txt:{tags}")).await;
    assert!(xattr(&f, "com.apple.metadata:_kMDItemUserTags").is_none());

    // An overwrite of the file takes its Finder info and fork with it.
    let overwritten = c
        .create(Create {
            name: "f.txt",
            disposition: FILE_OVERWRITE_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(overwritten.file_id).await;
    assert!(xattr(&f, "com.apple.FinderInfo").is_none());
    assert!(xattr(&f, "com.apple.ResourceFork").is_none());
}
