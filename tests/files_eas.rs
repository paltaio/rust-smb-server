//! Extended attributes on a `LocalFsBackend` share on Linux, over the
//! wire: the `user.` extended attributes requests leave on the host, and
//! the ones they leave alone.

#![cfg(all(feature = "localfs", target_os = "linux"))]

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use common::client::*;
use smb_server::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_EA_TOO_LARGE, STATUS_NO_EAS_ON_FILE, STATUS_SUCCESS,
};
use smb_server::wire::messages::CreateContext;
use smb_server::{LocalFsBackend, Share};
use tempfile::TempDir;

const FULL_EA: u8 = 0x0F;
const EA_INFORMATION: u8 = 0x07;

/// A new directory under the build's temporary directory holding `f.txt`,
/// or `None` where that filesystem has no user extended attributes.
fn root() -> Option<TempDir> {
    let td = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    match rustix::fs::getxattr_query(td.path(), "user.probe") {
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

fn xattr(path: &Path, attr: &str) -> Option<Vec<u8>> {
    let len = rustix::fs::getxattr_query(path, attr).ok()?;
    let mut buf = vec![0; len];
    let len = rustix::fs::getxattr(path, attr, &mut buf[..]).unwrap();
    buf.truncate(len);
    Some(buf)
}

fn set_xattr(path: &Path, attr: &str, value: &[u8]) {
    rustix::fs::setxattr(path, attr, value, rustix::fs::XattrFlags::empty()).unwrap();
}

/// The `user.` extended attributes of `path`, sorted.
fn user_xattrs(path: &Path) -> Vec<String> {
    let len = rustix::fs::listxattr_query(path).unwrap();
    let mut buf = vec![0; len];
    let len = rustix::fs::listxattr(path, &mut buf[..]).unwrap();
    let mut names: Vec<String> = buf[..len]
        .split(|&b| b == 0)
        .filter_map(|n| std::str::from_utf8(n).ok())
        .filter(|n| n.starts_with("user."))
        .map(str::to_string)
        .collect();
    names.sort();
    names
}

/// A FILE_FULL_EA_INFORMATION list, each entry but the last padded.
fn ea_list(eas: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (at, (name, value)) in eas.iter().enumerate() {
        let start = out.len();
        let len = 8 + name.len() + 1 + value.len();
        let next = if at + 1 == eas.len() {
            0
        } else {
            len.next_multiple_of(4)
        };
        out.extend_from_slice(&(next as u32).to_le_bytes());
        out.push(0);
        out.push(name.len() as u8);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(value);
        out.resize(start + len.max(next), 0);
    }
    out
}

/// Names and values of a FILE_FULL_EA_INFORMATION list.
fn parse(buf: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let name_len = buf[at + 5] as usize;
        let value_len = u16::from_le_bytes([buf[at + 6], buf[at + 7]]) as usize;
        let name = String::from_utf8(buf[at + 8..at + 8 + name_len].to_vec()).unwrap();
        let value = buf[at + 9 + name_len..at + 9 + name_len + value_len].to_vec();
        out.push((name, value));
        match u32_at(buf, at) as usize {
            0 => return out,
            next => at += next,
        }
    }
}

/// Every extended attribute of `name` the server lists.
async fn eas(c: &mut Client, name: &str) -> Vec<(String, Vec<u8>)> {
    let f = c.open(name, FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let (status, buf) = c.query_info(f, INFO_FILE, FULL_EA, 65536).await;
    c.close(f).await;
    match status {
        STATUS_SUCCESS => parse(&buf),
        STATUS_NO_EAS_ON_FILE => Vec::new(),
        status => panic!("query {name}: {status:#x}"),
    }
}

async fn set(c: &mut Client, name: &str, eas: &[(&str, &[u8])]) -> u32 {
    let f = c.open(name, RW, SHARE_ALL).await.unwrap();
    let status = c.set_info(f, FULL_EA, ea_list(eas)).await;
    c.close(f).await;
    status
}

fn pairs(list: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    list.iter()
        .map(|(n, v)| (n.to_string(), v.to_vec()))
        .collect()
}

#[tokio::test]
async fn extended_attributes_are_user_attributes_beside_the_streams() {
    let Some(td) = root() else {
        return;
    };
    let f = td.path().join("f.txt");
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    assert_eq!(eas(&mut c, "f.txt").await, []);

    // A named stream, Samba's DOS attributes and the server's own record
    // are attributes on the host too.
    let s = c
        .create(Create {
            name: "f.txt:s",
            disposition: FILE_OPEN_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(s.file_id).await;
    set_xattr(&f, "user.DOSATTRIB", b"0x20");
    set_xattr(&f, "user.smb-server.other", b"x");
    set_xattr(&f, "user.xdg.origin.url", b"https://example.com");

    assert_eq!(
        set(&mut c, "f.txt", &[("Test", b"hello"), ("b", b"xy")]).await,
        STATUS_SUCCESS
    );
    assert_eq!(xattr(&f, "user.Test").unwrap(), b"hello");
    assert_eq!(xattr(&f, "user.b").unwrap(), b"xy");
    let mut listed = eas(&mut c, "f.txt").await;
    listed.sort();
    assert_eq!(
        listed,
        pairs(&[
            ("Test", b"hello"),
            ("b", b"xy"),
            ("xdg.origin.url", b"https://example.com"),
        ])
    );
    // Each entry padded: 8 + 14 + 1 + 19 = 42 to 44, 18 to 20, 12.
    let size = 44 + 20 + 12;
    let id = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let (status, info) = c.query_info(id, INFO_FILE, EA_INFORMATION, 4).await;
    assert_eq!((status, u32_at(&info, 0)), (STATUS_SUCCESS, size));
    c.close(id).await;
    let dir = c.open_dir("").await;
    let (status, listing) = c
        .query_directory(dir, FILE_ID_BOTH_DIRECTORY_INFORMATION, 1, "f.txt", 4096)
        .await;
    assert_eq!((status, u32_at(&listing, 64)), (STATUS_SUCCESS, size));

    // Removing every attribute leaves the host's own.
    assert_eq!(
        set(
            &mut c,
            "f.txt",
            &[("TEST", b""), ("B", b""), ("xdg.origin.url", b"")]
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(eas(&mut c, "f.txt").await, []);
    assert_eq!(
        user_xattrs(&f),
        [
            "user.DOSATTRIB",
            "user.DosStream.s:$DATA",
            "user.smb-server.other"
        ]
    );
}

#[tokio::test]
async fn names_keep_the_spelling_the_host_stores() {
    let Some(td) = root() else {
        return;
    };
    let f = td.path().join("f.txt");
    set_xattr(&f, "user.MiXed", b"old");
    set_xattr(&f, "user.dup", b"lower");
    set_xattr(&f, "user.DUP", b"upper");
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    // Of the names that differ in case, the one that sorts first counts.
    let mut listed = eas(&mut c, "f.txt").await;
    listed.sort();
    assert_eq!(listed, pairs(&[("DUP", b"upper"), ("MiXed", b"old")]));
    assert_eq!(
        set(&mut c, "f.txt", &[("mixed", b"new"), ("Dup", b"one")]).await,
        STATUS_SUCCESS
    );
    assert_eq!(user_xattrs(&f), ["user.DUP", "user.MiXed"]);
    assert_eq!(xattr(&f, "user.MiXed").unwrap(), b"new");
    assert_eq!(xattr(&f, "user.DUP").unwrap(), b"one");
    assert_eq!(
        set(&mut c, "f.txt", &[("MIXED", b""), ("new", b"n")]).await,
        STATUS_SUCCESS
    );
    assert_eq!(user_xattrs(&f), ["user.DUP", "user.new"]);
}

#[tokio::test]
async fn the_server_and_samba_names_cannot_be_set() {
    let Some(td) = root() else {
        return;
    };
    let f = td.path().join("f.txt");
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    for name in [
        "DosStream.s",
        "dosattrib",
        "smb-server.streams",
        "SAMBA_PAI",
    ] {
        assert_eq!(
            set(&mut c, "f.txt", &[("ok", b"1"), (name, b"x")]).await,
            STATUS_ACCESS_DENIED,
            "{name}"
        );
    }
    assert_eq!(user_xattrs(&f), Vec::<String>::new());
}

/// True when the tests run as root, whom file modes do not stop.
fn as_root() -> bool {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root is not held back by file modes");
        return true;
    }
    false
}

#[tokio::test]
async fn a_read_only_file_refuses_extended_attributes() {
    let Some(td) = root() else {
        return;
    };
    if as_root() {
        return;
    }
    let f = td.path().join("f.txt");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    let id = c
        .open("f.txt", FILE_READ_ATTRIBUTES | 0x10, SHARE_ALL)
        .await
        .unwrap();
    assert_eq!(
        c.set_info(id, FULL_EA, ea_list(&[("n", b"v")])).await,
        STATUS_ACCESS_DENIED
    );
    c.close(id).await;
    assert_eq!(user_xattrs(&f), Vec::<String>::new());
    let mode = std::fs::metadata(&f).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o444);
}

#[tokio::test]
async fn entries_whose_attributes_cannot_be_read_still_open() {
    let Some(td) = root() else {
        return;
    };
    if as_root() {
        return;
    }
    // A directory the server may only traverse, with an extended attribute
    // it cannot read.
    let dir = td.path().join("t");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("f.txt"), b"data").unwrap();
    set_xattr(&dir, "user.n", b"v");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o311)).unwrap();
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    for (name, access) in [("t", FILE_READ_ATTRIBUTES), ("t\\f.txt", FILE_GENERIC_READ)] {
        let id = c.open(name, access, SHARE_ALL).await;
        let id = id.unwrap_or_else(|status| panic!("open {name}: {status:#x}"));
        let (status, info) = c.query_info(id, INFO_FILE, EA_INFORMATION, 4).await;
        assert_eq!((status, u32_at(&info, 0)), (STATUS_SUCCESS, 0), "{name}");
        c.close(id).await;
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn a_set_the_filesystem_has_no_room_for_changes_nothing() {
    let Some(td) = root() else {
        return;
    };
    // Room for all of a file's extended attributes is one block on ext4.
    let probe = td.path().join("probe");
    std::fs::write(&probe, b"").unwrap();
    let big = vec![7u8; 60000];
    match rustix::fs::setxattr(&probe, "user.big", &big, rustix::fs::XattrFlags::empty()) {
        Err(rustix::io::Errno::NOSPC | rustix::io::Errno::TOOBIG) => {}
        probe => {
            eprintln!("skipping: 60000 bytes of extended attributes gave {probe:?}");
            return;
        }
    }
    let f = td.path().join("f.txt");
    set_xattr(&f, "user.keep", b"1");
    let server = Server::public(LocalFsBackend::new(td.path()).unwrap()).await;
    let mut c = server.client().await;
    assert_eq!(
        set(
            &mut c,
            "f.txt",
            &[("keep", b"2"), ("small", b"s"), ("big", &big)]
        )
        .await,
        STATUS_EA_TOO_LARGE
    );
    assert_eq!(user_xattrs(&f), ["user.keep"]);
    assert_eq!(xattr(&f, "user.keep").unwrap(), b"1");
}

#[tokio::test]
async fn a_create_context_sets_and_an_overwrite_clears_them() {
    let Some(td) = root() else {
        return;
    };
    let server = Server::start(
        smb_server::SmbServer::builder()
            .share(Share::new("share", LocalFsBackend::new(td.path()).unwrap()).public()),
    )
    .await;
    let mut c = server.client().await;
    let mut contexts = Vec::new();
    CreateContext::encode_chain(
        &[CreateContext {
            name: CreateContext::NAME_EXTA.to_vec(),
            data: ea_list(&[("made", b"1")]),
        }],
        &mut contexts,
    )
    .unwrap();
    let created = c
        .create(Create {
            name: "new.txt",
            disposition: FILE_CREATE,
            contexts,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(created.file_id).await;
    let new = td.path().join("new.txt");
    assert_eq!(xattr(&new, "user.made").unwrap(), b"1");

    let over = c
        .create(Create {
            name: "new.txt",
            disposition: FILE_OVERWRITE_IF,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(over.file_id).await;
    assert_eq!(user_xattrs(&new), Vec::<String>::new());
}
