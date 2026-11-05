//! Named streams on a `LocalFsBackend` share on every host, over the wire:
//! the streams a macOS client keeps extended attributes and Finder info in.

#![cfg(feature = "localfs")]

mod common;

use std::path::Path;

use common::client::*;
use smb_server::LocalFsBackend;
use smb_server::ntstatus::STATUS_SUCCESS;

const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

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

/// Opens the stream `name` with `disposition`, writes `data` and closes it.
async fn write_stream(c: &mut Client, name: &str, disposition: u32, data: &[u8]) {
    let created = c
        .create(Create {
            name,
            access: FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_READ | SHARE_DELETE,
            disposition,
            ..Create::default()
        })
        .await
        .unwrap_or_else(|s| panic!("create {name}: {s:#x}"));
    assert_eq!(
        c.write(created.file_id, 0, data).await,
        Ok(data.len() as u32)
    );
    c.close(created.file_id).await;
}

async fn read_stream(c: &mut Client, name: &str) -> Vec<u8> {
    let opened = c.open(name, FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let data = c.read(opened, 0, 65536).await.unwrap();
    c.close(opened).await;
    data
}

/// Every entry under `dir` whose name starts with `._`.
fn apple_double_files(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("._") {
            found.push(entry.path().display().to_string());
        }
        if entry.file_type().unwrap().is_dir() {
            found.extend(apple_double_files(&entry.path()));
        }
    }
    found
}

#[cfg(target_os = "macos")]
fn xattr(path: &Path, attr: &str) -> Option<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let attr = CString::new(attr).unwrap();
    let mut buf = vec![0u8; 65536];
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
    buf.truncate(usize::try_from(len).ok()?);
    Some(buf)
}

#[tokio::test]
async fn macos_attributes_round_trip_as_named_streams() {
    let td = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;

    let share = c.open_dir("").await;
    let (status, attributes) = c
        .query_info(share, INFO_FILESYSTEM, FS_ATTRIBUTE_INFORMATION, 1024)
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    c.close(share).await;
    let named_streams = u32_at(&attributes, 0) & FILE_NAMED_STREAMS != 0;
    #[cfg(not(any(target_os = "macos", windows)))]
    if !named_streams {
        eprintln!("skipping: no named streams on {}", td.path().display());
        return;
    }
    assert!(named_streams, "no named streams on {}", td.path().display());

    let attrs: [(&str, &[u8]); 2] = [
        (
            "com.apple.LaunchServices.OpenWith",
            b"bplist00\xd3\x01\x02\x03\x04\x05\x06Wversion",
        ),
        (
            "com.apple.quarantine",
            b"0083;6aecf0c6;Safari;0CFA7772-7BB0-4054-A3CD-7357DFFF72C8",
        ),
    ];
    for (name, value) in attrs {
        write_stream(&mut c, &format!("f.txt:{name}"), FILE_OVERWRITE_IF, value).await;
    }
    // Finder info with a red label, in the AfpInfo layout macOS writes.
    let mut afp_info = [0u8; 60];
    afp_info[..16].copy_from_slice(b"AFP\0\0\0\x01\0\0\0\0\0\0\0\0\x80");
    afp_info[16..24].copy_from_slice(b"TEXTttxt");
    afp_info[25] = 0x0c;
    write_stream(&mut c, "f.txt:AFP_AfpInfo", FILE_OPEN_IF, &afp_info).await;

    for (name, value) in attrs {
        assert_eq!(read_stream(&mut c, &format!("f.txt:{name}")).await, value);
    }
    // A macOS host keeps the Finder info alone and rebuilds the header.
    let read = read_stream(&mut c, "f.txt:AFP_AfpInfo").await;
    assert_eq!(read.len(), 60);
    assert_eq!(&read[..4], b"AFP\0");
    assert_eq!(read[16..], afp_info[16..]);

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
            (":com.apple.LaunchServices.OpenWith:$DATA".to_string(), 23),
            (":com.apple.quarantine:$DATA".to_string(), 57),
        ]
    );

    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
    assert_eq!(apple_double_files(td.path()), Vec::<String>::new());

    #[cfg(target_os = "macos")]
    {
        let f = td.path().join("f.txt");
        for (name, value) in attrs {
            assert_eq!(xattr(&f, name).as_deref(), Some(value), "{name}");
        }
        assert_eq!(
            xattr(&f, "com.apple.FinderInfo").as_deref(),
            Some(&afp_info[16..48])
        );
    }
}
