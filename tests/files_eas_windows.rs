//! Extended attributes on a `LocalFsBackend` share on Windows, over the
//! wire: the NTFS extended attributes requests leave on the host.

#![cfg(all(feature = "localfs", windows))]

mod common;

use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

use common::client::*;
use smb_server::ntstatus::{STATUS_ACCESS_DENIED, STATUS_NO_EAS_ON_FILE, STATUS_SUCCESS};
use smb_server::{LocalFsBackend, ShareBackend as _};
use tempfile::TempDir;
use windows_sys::Wdk::Storage::FileSystem::{NtQueryEaFile, NtSetEaFile};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const FULL_EA: u8 = 0x0F;
const EA_INFORMATION: u8 = 0x07;
const FILE_READ_EA: u32 = 0x08;
const FILE_WRITE_EA: u32 = 0x10;
const FILE_NO_EA_KNOWLEDGE: u32 = 0x200;
const FILE_NEED_EA: u8 = 0x80;

/// A new directory under the build's temporary directory holding `f.txt`,
/// or `None` where its volume has no extended attributes.
fn root() -> Option<TempDir> {
    let td = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    if !LocalFsBackend::new(td.path())
        .unwrap()
        .capabilities()
        .extended_attributes
    {
        eprintln!(
            "skipping: no extended attributes on {}",
            td.path().display()
        );
        return None;
    }
    Some(td)
}

/// A FILE_FULL_EA_INFORMATION list of `(flags, name, value)`, each entry
/// but the last padded.
fn ea_list(eas: &[(u8, &str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (at, (flags, name, value)) in eas.iter().enumerate() {
        let start = out.len();
        let len = 8 + name.len() + 1 + value.len();
        let next = if at + 1 == eas.len() {
            0
        } else {
            len.next_multiple_of(4)
        };
        out.extend_from_slice(&(next as u32).to_le_bytes());
        out.push(*flags);
        out.push(name.len() as u8);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(value);
        out.resize(start + len.max(next), 0);
    }
    out
}

/// Flags, names and values of a FILE_FULL_EA_INFORMATION list.
fn parse(buf: &[u8]) -> Vec<(u8, String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let name_len = buf[at + 5] as usize;
        let value_len = u16::from_le_bytes([buf[at + 6], buf[at + 7]]) as usize;
        let name = String::from_utf8(buf[at + 8..at + 8 + name_len].to_vec()).unwrap();
        let value = buf[at + 9 + name_len..at + 9 + name_len + value_len].to_vec();
        out.push((buf[at + 4], name, value));
        match u32_at(buf, at) as usize {
            0 => return out,
            next => at += next,
        }
    }
}

/// `path` opened on the host with `access`.
fn host_open(path: &Path, access: u32) -> std::fs::File {
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .access_mode(access)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap()
}

/// The extended attributes NTFS has for `path`.
fn host_eas(path: &Path) -> Vec<(u8, String, Vec<u8>)> {
    let file = host_open(path, FILE_READ_EA);
    let mut buf = vec![0u8; 65536];
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buf` and `status_block` are live locals of the sizes passed.
    let status = unsafe {
        NtQueryEaFile(
            file.as_raw_handle() as _,
            &mut status_block,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            false,
            std::ptr::null(),
            0,
            std::ptr::null(),
            true,
        )
    };
    if status as u32 == STATUS_NO_EAS_ON_FILE {
        return Vec::new();
    }
    assert_eq!(status, 0, "NtQueryEaFile {:#x}", status as u32);
    parse(&buf[..status_block.Information])
}

/// Sets `list`, a FILE_FULL_EA_INFORMATION list, on `path` on the host.
fn host_set(path: &Path, list: &[u8]) {
    let file = host_open(path, FILE_WRITE_EA);
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `list` and `status_block` are live locals of the sizes passed.
    let status = unsafe {
        NtSetEaFile(
            file.as_raw_handle() as _,
            &mut status_block,
            list.as_ptr().cast(),
            list.len() as u32,
        )
    };
    assert_eq!(status, 0, "NtSetEaFile {:#x}", status as u32);
}

async fn query(c: &mut Client, name: &str) -> Vec<(u8, String, Vec<u8>)> {
    let f = c.open(name, FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let (status, buf) = c.query_info(f, INFO_FILE, FULL_EA, 65536).await;
    c.close(f).await;
    match status {
        STATUS_SUCCESS => parse(&buf),
        STATUS_NO_EAS_ON_FILE => Vec::new(),
        status => panic!("query {name}: {status:#x}"),
    }
}

#[tokio::test]
async fn extended_attributes_are_the_ntfs_ones() {
    let Some(td) = root() else {
        return;
    };
    let f = td.path().join("f.txt");
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    let id = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let list = ea_list(&[(0, "Test", b"hello"), (0, "b", b"xy")]);
    assert_eq!(c.set_info(id, FULL_EA, list).await, STATUS_SUCCESS);
    c.close(id).await;

    // NTFS keeps the names in uppercase.
    let expected = vec![
        (0, "TEST".to_string(), b"hello".to_vec()),
        (0, "B".to_string(), b"xy".to_vec()),
    ];
    assert_eq!(host_eas(&f), expected);
    assert_eq!(query(&mut c, "f.txt").await, expected);

    // 18 bytes padded to 20, and 12.
    let size = 32;
    let id = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let (status, info) = c.query_info(id, INFO_FILE, EA_INFORMATION, 4).await;
    assert_eq!((status, u32_at(&info, 0)), (STATUS_SUCCESS, size));
    c.close(id).await;
    let s = c
        .create(Create {
            name: "f.txt:s",
            disposition: FILE_OPEN_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    let (status, info) = c.query_info(s.file_id, INFO_FILE, EA_INFORMATION, 4).await;
    assert_eq!((status, u32_at(&info, 0)), (STATUS_SUCCESS, size));
    c.close(s.file_id).await;
    let dir = c.open_dir("").await;
    let (status, listing) = c
        .query_directory(dir, FILE_ID_BOTH_DIRECTORY_INFORMATION, 1, "f.txt", 4096)
        .await;
    assert_eq!((status, u32_at(&listing, 64)), (STATUS_SUCCESS, size));

    let id = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let remove = ea_list(&[(0, "test", b""), (0, "B", b"")]);
    assert_eq!(c.set_info(id, FULL_EA, remove).await, STATUS_SUCCESS);
    c.close(id).await;
    assert_eq!(host_eas(&f), []);
}

#[tokio::test]
async fn a_file_that_needs_its_attributes_refuses_opens_that_do_not_know_them() {
    let Some(td) = root() else {
        return;
    };
    let f = td.path().join("f.txt");
    host_set(&f, &ea_list(&[(FILE_NEED_EA, "needed", b"1")]));
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    assert_eq!(
        query(&mut c, "f.txt").await,
        [(FILE_NEED_EA, "NEEDED".to_string(), b"1".to_vec())]
    );
    let blind = |name| Create {
        name,
        access: FILE_GENERIC_READ,
        options: FILE_NO_EA_KNOWLEDGE,
        ..Create::default()
    };
    assert_eq!(
        c.create(blind("f.txt")).await.err(),
        Some(STATUS_ACCESS_DENIED)
    );
    // A named stream of it is not the file.
    let s = c
        .create(Create {
            name: "f.txt:s",
            disposition: FILE_OPEN_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(s.file_id).await;
    let s = c.create(blind("f.txt:s")).await.unwrap();
    c.close(s.file_id).await;
}

#[tokio::test]
async fn a_read_only_file_takes_extended_attributes() {
    let Some(td) = root() else {
        return;
    };
    let f = td.path().join("f.txt");
    let mut permissions = std::fs::metadata(&f).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&f, permissions).unwrap();
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    let id = c
        .open("f.txt", FILE_READ_ATTRIBUTES | FILE_WRITE_EA, SHARE_ALL)
        .await
        .unwrap();
    let list = ea_list(&[(0, "n", b"v")]);
    assert_eq!(c.set_info(id, FULL_EA, list).await, STATUS_SUCCESS);
    c.close(id).await;
    assert_eq!(host_eas(&f), [(0, "N".to_string(), b"v".to_vec())]);
    assert!(std::fs::metadata(&f).unwrap().permissions().readonly());
}

#[tokio::test]
async fn listings_report_reparse_points_as_their_opens_do() {
    let Some(td) = root() else {
        return;
    };
    let sub = td.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    host_set(&sub, &ea_list(&[(0, "onSub", b"1")]));
    host_set(&td.path().join("f.txt"), &ea_list(&[(0, "onFile", b"1")]));
    let junction = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(td.path().join("j"))
        .arg(&sub)
        .output()
        .unwrap();
    assert!(junction.status.success(), "{junction:?}");
    let mut names = vec!["f.txt", "sub", "j"];
    // A file symlink needs a privilege the runner may not have.
    if std::os::windows::fs::symlink_file(td.path().join("f.txt"), td.path().join("l.txt")).is_ok()
    {
        names.push("l.txt");
    }
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    let dir = c.open_dir("").await;
    for name in names {
        let (status, listing) = c
            .query_directory(dir, FILE_ID_BOTH_DIRECTORY_INFORMATION, 1, name, 4096)
            .await;
        assert_eq!(status, STATUS_SUCCESS, "{name}");
        let listed = u32_at(&listing, 64);
        let opened = match c.open(name, FILE_READ_ATTRIBUTES, SHARE_ALL).await {
            Ok(id) => {
                let (status, info) = c.query_info(id, INFO_FILE, EA_INFORMATION, 4).await;
                c.close(id).await;
                assert_eq!(status, STATUS_SUCCESS, "{name}");
                u32_at(&info, 0)
            }
            Err(_) => 0,
        };
        assert_eq!(listed, opened, "{name}");
        assert_eq!(listed & 0x8000_0000, 0, "{name}: a reparse tag");
    }
}
