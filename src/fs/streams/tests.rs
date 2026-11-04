use std::path::Path;
use std::time::{Duration, SystemTime};

use tempfile::TempDir;

use super::*;
use crate::backend::{OpenOptions, ShareBackend};
use crate::fs::LocalFsBackend;
use crate::path::SmbPath;

/// A backend on a new directory beside the test binary, on the build's
/// filesystem, or `None` where that filesystem has no user extended
/// attributes.
fn backend() -> Option<(TempDir, LocalFsBackend)> {
    let exe = std::env::current_exe().unwrap();
    let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
    let backend = LocalFsBackend::new(td.path()).unwrap();
    if !backend.capabilities().named_streams {
        let probe = rustix::fs::getxattr_query(td.path(), "user.DosStream.");
        eprintln!(
            "skipping: no user extended attributes on {} ({probe:?})",
            td.path().display()
        );
        return None;
    }
    Some((td, backend))
}

/// The file id of `path` below `td`, as the backend reports it.
fn id(td: &TempDir, path: &str) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(td.path().join(path)).unwrap().ino()
}

fn p(s: &str) -> SmbPath {
    s.parse().unwrap()
}

fn name(s: &str) -> StreamName {
    s.parse().unwrap()
}

fn opts(intent: OpenIntent, write: bool) -> OpenOptions {
    OpenOptions {
        read: true,
        write,
        write_attributes: write,
        intent,
        directory: false,
        non_directory: false,
        delete_on_close: false,
    }
}

/// Opens the stream `stream` of `path` as CREATE does: the file first,
/// created unless `intent` only opens, then the stream through it.
async fn open(
    backend: &LocalFsBackend,
    path: &str,
    stream: &str,
    intent: OpenIntent,
) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
    let path = p(path);
    let file_intent = match intent {
        OpenIntent::Open | OpenIntent::Truncate => OpenIntent::Open,
        _ => OpenIntent::OpenOrCreate,
    };
    let (file, _) = backend.open(&path, opts(file_intent, false)).await?;
    backend
        .open_stream(file, &path, &name(stream), opts(intent, true))
        .await
}

async fn create(backend: &LocalFsBackend, path: &str, stream: &str, data: &[u8]) {
    let (h, _) = open(backend, path, stream, OpenIntent::OpenOrCreate)
        .await
        .unwrap();
    if !data.is_empty() {
        h.write(0, data).await.unwrap();
    }
    h.close().await.unwrap();
}

async fn read_all(h: &dyn Handle) -> Vec<u8> {
    h.read(0, u32::MAX).await.unwrap().to_vec()
}

/// The value of the extended attribute `attr` of `path`.
fn xattr(path: &Path, attr: &str) -> Option<Vec<u8>> {
    let len = rustix::fs::getxattr_query(path, attr).ok()?;
    let mut buf = vec![0; len];
    let len = rustix::fs::getxattr(path, attr, &mut buf[..]).unwrap();
    buf.truncate(len);
    Some(buf)
}

fn set_xattr(path: &Path, attr: &str, value: &[u8]) {
    rustix::fs::setxattr(path, attr, value, XattrFlags::empty()).unwrap();
}

/// The streams of `path` by name, with their sizes, sorted.
async fn streams(backend: &LocalFsBackend, path: &str) -> Vec<(String, u64)> {
    let (h, _) = backend
        .open(&p(path), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    let mut out: Vec<_> = h
        .streams()
        .await
        .unwrap()
        .into_iter()
        .map(|s| (s.name.as_str().to_string(), s.size))
        .collect();
    h.close().await.unwrap();
    out.sort();
    out
}

#[tokio::test]
async fn streams_are_extended_attributes_with_a_trailing_nul() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", b"hello").await;
    create(&backend, "f.txt", "empty", b"").await;
    let f = td.path().join("f.txt");
    assert_eq!(xattr(&f, "user.DosStream.s:$DATA").unwrap(), b"hello\0");
    assert_eq!(xattr(&f, "user.DosStream.empty:$DATA").unwrap(), b"\0");
    assert_eq!(std::fs::read(&f).unwrap(), b"");
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("empty".to_string(), 0), ("s".to_string(), 5)]
    );
}

#[tokio::test]
async fn streams_stored_by_samba_are_read_without_the_nul() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"data").unwrap();
    set_xattr(
        &f,
        "user.DosStream.Zone.Identifier:$DATA",
        b"[ZoneTransfer]\0",
    );
    let tags = "com.apple.metadata\u{F022}_kMDItemUserTags";
    set_xattr(&f, &format!("user.DosStream.{tags}:$DATA"), b"bplist\0");
    // Attributes that hold no stream this server can name.
    set_xattr(&f, "user.other", b"x");
    set_xattr(&f, "user.DosStream.untyped", b"x\0");
    set_xattr(&f, "user.DosStream.a:b:$DATA", b"x\0");
    set_xattr(&f, "user.DosStream.:$DATA", b"x\0");

    assert_eq!(
        streams(&backend, "f.txt").await,
        [("Zone.Identifier".to_string(), 14), (tags.to_string(), 6)]
    );
    let (h, action) = open(&backend, "f.txt", "zone.IDENTIFIER", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert_eq!(read_all(h.as_ref()).await, b"[ZoneTransfer]");
    assert_eq!(&h.read(5, 4).await.unwrap()[..], b"Tran");
    assert!(h.read(100, 4).await.unwrap().is_empty());
    h.write(1, b"z").await.unwrap();
    h.close().await.unwrap();
    assert_eq!(
        xattr(&f, "user.DosStream.Zone.Identifier:$DATA").unwrap(),
        b"[zoneTransfer]\0"
    );
}

#[tokio::test]
async fn streams_open_under_any_case_and_keep_their_first_spelling() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "Zone", b"one").await;
    let (h, action) = open(&backend, "f.txt", "ZONE", OpenIntent::OpenOrCreate)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert_eq!(read_all(h.as_ref()).await, b"one");
    h.close().await.unwrap();
    assert!(matches!(
        open(&backend, "f.txt", "zone", OpenIntent::Create).await,
        Err(SmbError::Exists)
    ));
    assert_eq!(streams(&backend, "f.txt").await, [("Zone".to_string(), 3)]);
    assert!(xattr(&td.path().join("f.txt"), "user.DosStream.ZONE:$DATA").is_none());
}

#[tokio::test]
async fn dispositions_open_create_and_truncate_streams() {
    let Some((td, backend)) = backend() else {
        return;
    };
    std::fs::write(td.path().join("f.txt"), b"").unwrap();
    for intent in [OpenIntent::Open, OpenIntent::Truncate] {
        assert!(matches!(
            open(&backend, "f.txt", "s", intent).await,
            Err(SmbError::NotFound)
        ));
    }
    let (h, action) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Created);
    h.write(0, b"data").await.unwrap();
    h.close().await.unwrap();
    for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
        let (h, action) = open(&backend, "f.txt", "s", intent).await.unwrap();
        assert_eq!(action, OpenAction::Overwritten);
        assert_eq!(h.stat().await.unwrap().end_of_file, 0);
        h.write(0, b"data").await.unwrap();
        h.close().await.unwrap();
    }
    let (h, action) = open(&backend, "f.txt", "t", OpenIntent::OverwriteOrCreate)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Created);
    h.close().await.unwrap();
}

#[tokio::test]
async fn names_too_long_for_an_attribute_are_invalid() {
    let Some((_td, backend)) = backend() else {
        return;
    };
    let longest = "x".repeat(234);
    create(&backend, "f.txt", &longest, b"x").await;
    assert!(matches!(
        open(
            &backend,
            "f.txt",
            &format!("{longest}x"),
            OpenIntent::OpenOrCreate
        )
        .await,
        Err(SmbError::NameInvalid)
    ));
}

#[tokio::test]
async fn writes_past_what_an_attribute_holds_fail_and_change_nothing() {
    let Some((_td, backend)) = backend() else {
        return;
    };
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    h.write(0, b"abc").await.unwrap();
    assert!(matches!(
        h.write(65535, b"x").await,
        Err(SmbError::DiskFull)
    ));
    assert!(matches!(h.truncate(65536).await, Err(SmbError::DiskFull)));
    assert_eq!(read_all(h.as_ref()).await, b"abc");
    // Whether a stream this large fits depends on the filesystem: ext4
    // keeps all of a file's extended attributes in one block.
    match h.write(0, &[7; 60000]).await {
        Ok(n) => {
            assert_eq!(n, 60000);
            assert_eq!(h.stat().await.unwrap().end_of_file, 60000);
        }
        Err(SmbError::DiskFull) => assert_eq!(read_all(h.as_ref()).await, b"abc"),
        Err(e) => panic!("{e:?}"),
    }
    h.close().await.unwrap();
}

#[tokio::test]
async fn writes_extend_with_zeros_and_truncate_cuts() {
    let Some((_td, backend)) = backend() else {
        return;
    };
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    assert_eq!(h.write(4, b"xy").await.unwrap(), 2);
    assert_eq!(read_all(h.as_ref()).await, b"\0\0\0\0xy");
    h.truncate(5).await.unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"\0\0\0\0x");
    h.truncate(7).await.unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"\0\0\0\0x\0\0");
    let info = h.stat().await.unwrap();
    assert_eq!((info.end_of_file, info.allocation_size), (7, 7));
    h.close().await.unwrap();
}

#[tokio::test]
async fn stream_changes_move_the_last_write_time_of_the_file() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"data").unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    let set_old = || {
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(old)
            .unwrap();
    };
    let modified = || std::fs::metadata(&f).unwrap().modified().unwrap();

    set_old();
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    assert_eq!(modified(), old, "a new stream leaves the file alone");
    h.write(0, b"x").await.unwrap();
    assert!(modified() > old);
    set_old();
    h.truncate(0).await.unwrap();
    assert!(modified() > old);
    h.close().await.unwrap();
    set_old();
    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            Some(&name("s")),
            Some(&name("t")),
            false,
        )
        .await
        .unwrap();
    assert!(modified() > old);
    set_old();
    let (h, _) = open(&backend, "f.txt", "t", OpenIntent::OverwriteOrCreate)
        .await
        .unwrap();
    assert!(modified() > old);
    // Times set through the stream are the file's.
    h.set_times(FileTimes {
        last_write_time: Some(crate::utils::system_time_to_filetime(old)),
        ..FileTimes::default()
    })
    .await
    .unwrap();
    assert_eq!(modified(), old);
    h.close().await.unwrap();
}

#[tokio::test]
async fn stream_handles_follow_renames_of_the_file_and_the_stream() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    h.write(0, b"one").await.unwrap();
    std::fs::rename(td.path().join("f.txt"), td.path().join("g.txt")).unwrap();
    h.write(3, b"two").await.unwrap();
    assert_eq!(
        xattr(&td.path().join("g.txt"), "user.DosStream.s:$DATA").unwrap(),
        b"onetwo\0"
    );

    let (other, _) = open(&backend, "g.txt", "S", OpenIntent::Open)
        .await
        .unwrap();
    backend
        .rename_stream(
            &p("g.txt"),
            id(&td, "g.txt"),
            Some(&name("S")),
            Some(&name("New")),
            false,
        )
        .await
        .unwrap();
    h.write(6, b"!").await.unwrap();
    assert_eq!(read_all(other.as_ref()).await, b"onetwo!");
    assert_eq!(other.stat().await.unwrap().end_of_file, 7);
    assert_eq!(streams(&backend, "g.txt").await, [("New".to_string(), 7)]);
    h.close().await.unwrap();
    other.close().await.unwrap();
}

#[tokio::test]
async fn a_file_replaced_before_its_stream_opens_is_not_found() {
    let Some((td, backend)) = backend() else {
        return;
    };
    std::fs::write(td.path().join("f.txt"), b"old").unwrap();
    std::fs::write(td.path().join("new.txt"), b"new").unwrap();
    let (file, _) = backend
        .open(&p("f.txt"), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    std::fs::rename(td.path().join("new.txt"), td.path().join("f.txt")).unwrap();
    assert!(matches!(
        backend
            .open_stream(
                file,
                &p("f.txt"),
                &name("s"),
                opts(OpenIntent::OpenOrCreate, true)
            )
            .await,
        Err(SmbError::NotFound)
    ));
    assert!(streams(&backend, "f.txt").await.is_empty());
}

#[tokio::test]
async fn renames_between_named_streams() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let f = td.path().join("f.txt");
    create(&backend, "f.txt", "a", b"data").await;
    create(&backend, "f.txt", "b", b"").await;
    create(&backend, "f.txt", "full", b"x").await;

    let file_id = id(&td, "f.txt");
    let rename = |from: &str, to: &str, replace| {
        let (from, to) = (name(from), name(to));
        let backend = &backend;
        async move {
            backend
                .rename_stream(&p("f.txt"), file_id, Some(&from), Some(&to), replace)
                .await
        }
    };
    assert!(matches!(
        rename("A", "B", false).await,
        Err(SmbError::Exists)
    ));
    assert!(matches!(
        rename("missing", "c", false).await,
        Err(SmbError::NotFound)
    ));
    assert_eq!(
        streams(&backend, "f.txt").await,
        [
            ("a".to_string(), 4),
            ("b".to_string(), 0),
            ("full".to_string(), 1)
        ]
    );
    // The replaced stream goes, and the renamed one takes the new spelling.
    rename("A", "B", true).await.unwrap();
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("B".to_string(), 4), ("full".to_string(), 1)]
    );
    assert!(xattr(&f, "user.DosStream.b:$DATA").is_none());
    assert!(xattr(&f, "user.DosStream.a:$DATA").is_none());
    rename("B", "c", false).await.unwrap();
    assert_eq!(xattr(&f, "user.DosStream.c:$DATA").unwrap(), b"data\0");
}

#[tokio::test]
async fn renames_to_and_from_the_default_stream_move_the_data() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"contents").unwrap();
    backend
        .rename_stream(&p("f.txt"), id(&td, "f.txt"), None, Some(&name("s")), false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"");
    assert_eq!(xattr(&f, "user.DosStream.s:$DATA").unwrap(), b"contents\0");

    assert!(matches!(
        backend
            .rename_stream(&p("f.txt"), id(&td, "f.txt"), Some(&name("s")), None, false)
            .await,
        Err(SmbError::Exists)
    ));
    backend
        .rename_stream(&p("f.txt"), id(&td, "f.txt"), Some(&name("S")), None, true)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"contents");
    assert!(streams(&backend, "f.txt").await.is_empty());

    // A file too large for a stream stays as it is.
    let big = vec![1u8; 65536];
    std::fs::write(&f, &big).unwrap();
    assert!(matches!(
        backend
            .rename_stream(&p("f.txt"), id(&td, "f.txt"), None, Some(&name("s")), false)
            .await,
        Err(SmbError::DiskFull)
    ));
    assert_eq!(std::fs::read(&f).unwrap(), big);
    assert!(streams(&backend, "f.txt").await.is_empty());
}

#[tokio::test]
async fn removal_finds_the_stream_under_any_case() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "Keep", b"1").await;
    create(&backend, "f.txt", "Gone", b"2").await;
    backend
        .remove_stream(&p("f.txt"), id(&td, "f.txt"), &name("GONE"))
        .await
        .unwrap();
    assert!(matches!(
        backend
            .remove_stream(&p("f.txt"), id(&td, "f.txt"), &name("gone"))
            .await,
        Err(SmbError::NotFound)
    ));
    assert_eq!(streams(&backend, "f.txt").await, [("Keep".to_string(), 1)]);
}

#[tokio::test]
async fn overwriting_the_file_keeps_its_streams_for_the_server_to_remove() {
    let Some((_td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", b"stream").await;
    let (h, action) = backend
        .open(&p("f.txt"), opts(OpenIntent::Truncate, true))
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Overwritten);
    assert_eq!(h.streams().await.unwrap().len(), 1);
    h.close().await.unwrap();
}

#[tokio::test]
async fn directories_and_the_share_root_have_streams() {
    let Some((td, backend)) = backend() else {
        return;
    };
    std::fs::create_dir(td.path().join("d")).unwrap();
    create(&backend, "d", "ds", b"dir").await;
    create(&backend, "", "rs", b"root").await;
    assert_eq!(
        xattr(&td.path().join("d"), "user.DosStream.ds:$DATA").unwrap(),
        b"dir\0"
    );
    let (h, _) = open(&backend, "d", "ds", OpenIntent::Open).await.unwrap();
    let info = h.stat().await.unwrap();
    assert!(info.is_directory);
    assert_eq!(info.end_of_file, 3);
    assert!(matches!(
        h.set_attributes(FILE_ATTRIBUTE_READONLY).await,
        Err(SmbError::NotSupported)
    ));
    h.close().await.unwrap();
    let (root, _) = backend
        .open(
            &SmbPath::root(),
            OpenOptions {
                directory: true,
                ..opts(OpenIntent::Open, false)
            },
        )
        .await
        .unwrap();
    let listed: Vec<_> = root.streams().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name.as_str(), "rs");
    root.close().await.unwrap();
}

#[tokio::test]
async fn a_read_only_backend_reads_streams_and_changes_none() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", b"data").await;
    let backend = LocalFsBackend::new(td.path()).unwrap().read_only();
    assert!(backend.capabilities().named_streams);
    let (file, _) = backend
        .open(&p("f.txt"), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    let (h, _) = backend
        .open_stream(file, &p("f.txt"), &name("s"), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"data");
    assert!(matches!(
        h.write(0, b"x").await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(h.truncate(0).await, Err(SmbError::AccessDenied)));
    h.close().await.unwrap();
    let (file, _) = backend
        .open(&p("f.txt"), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    assert!(matches!(
        backend
            .open_stream(
                file,
                &p("f.txt"),
                &name("t"),
                opts(OpenIntent::OpenOrCreate, true)
            )
            .await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        backend
            .remove_stream(&p("f.txt"), id(&td, "f.txt"), &name("s"))
            .await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        backend
            .rename_stream(
                &p("f.txt"),
                id(&td, "f.txt"),
                Some(&name("s")),
                Some(&name("t")),
                false
            )
            .await,
        Err(SmbError::AccessDenied)
    ));
}

#[tokio::test]
async fn a_filesystem_without_user_attributes_has_no_streams() {
    let Ok(backend) = LocalFsBackend::new("/proc") else {
        eprintln!("no /proc; skipping");
        return;
    };
    assert!(!backend.capabilities().named_streams);
}

#[tokio::test]
async fn removals_and_renames_leave_a_file_put_in_its_place_alone() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", b"old").await;
    let old_id = id(&td, "f.txt");
    // Another file with a stream of the same name takes the name.
    create(&backend, "new.txt", "s", b"new").await;
    std::fs::rename(td.path().join("new.txt"), td.path().join("f.txt")).unwrap();

    assert!(matches!(
        backend.remove_stream(&p("f.txt"), old_id, &name("s")).await,
        Err(SmbError::NotFound)
    ));
    for (from, to) in [(Some(name("s")), Some(name("t"))), (Some(name("s")), None)] {
        assert!(matches!(
            backend
                .rename_stream(&p("f.txt"), old_id, from.as_ref(), to.as_ref(), true)
                .await,
            Err(SmbError::NotFound)
        ));
    }
    let f = td.path().join("f.txt");
    assert_eq!(xattr(&f, "user.DosStream.s:$DATA").unwrap(), b"new\0");
    assert_eq!(std::fs::read(&f).unwrap(), b"");
}

#[tokio::test]
async fn attributes_differing_in_case_are_one_stream() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"").unwrap();
    set_xattr(&f, "user.DosStream.zone:$DATA", b"lower\0");
    set_xattr(&f, "user.DosStream.Zone:$DATA", b"upper\0");
    set_xattr(&f, "user.DosStream.ZONE:$DATA", b"all\0");

    // "ZONE" sorts first; every spelling reaches it.
    assert_eq!(streams(&backend, "f.txt").await, [("ZONE".to_string(), 3)]);
    for spelling in ["zone", "Zone", "ZONE", "zONE"] {
        let (h, _) = open(&backend, "f.txt", spelling, OpenIntent::Open)
            .await
            .unwrap();
        assert_eq!(read_all(h.as_ref()).await, b"all", "{spelling}");
        h.close().await.unwrap();
    }
    assert!(matches!(
        open(&backend, "f.txt", "zone", OpenIntent::Create).await,
        Err(SmbError::Exists)
    ));

    // A rename moves the stream and frees the name entirely.
    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            Some(&name("zone")),
            Some(&name("Other")),
            false,
        )
        .await
        .unwrap();
    assert_eq!(streams(&backend, "f.txt").await, [("Other".to_string(), 3)]);

    // Replacing a stream replaces all its attributes, and a removal
    // removes them all.
    set_xattr(&f, "user.DosStream.t:$DATA", b"\0");
    set_xattr(&f, "user.DosStream.T:$DATA", b"hidden\0");
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("Other".to_string(), 3), ("T".to_string(), 6)]
    );
    set_xattr(&f, "user.DosStream.T:$DATA", b"\0");
    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            Some(&name("other")),
            Some(&name("t")),
            true,
        )
        .await
        .unwrap();
    assert_eq!(streams(&backend, "f.txt").await, [("t".to_string(), 3)]);
    assert!(xattr(&f, "user.DosStream.T:$DATA").is_none());
    set_xattr(&f, "user.DosStream.T:$DATA", b"x\0");
    backend
        .remove_stream(&p("f.txt"), id(&td, "f.txt"), &name("t"))
        .await
        .unwrap();
    assert!(streams(&backend, "f.txt").await.is_empty());
}
