use std::path::Path;
use std::time::{Duration, SystemTime};

use tempfile::TempDir;

use super::*;
use crate::backend::{FILE_ATTRIBUTE_READONLY, OpenOptions, ShareBackend};
use crate::fs::LocalFsBackend;
use crate::fs::local::tests::{mkfifo, release};
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

/// Set in the child process [`alone_in_child`] starts.
const CHILD: &str = "SMB_SERVER_STREAMS_TEST_CHILD";

/// Whether to run the test body here. In the test process, runs the test
/// `name` of this module alone in a child process of the test binary,
/// asserts that it passed there and returns false; in that child, returns
/// true. A child can lower its descriptor limit without starving the tests
/// that run beside it.
fn alone_in_child(name: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let module = module_path!().split_once("::").unwrap().1;
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([&format!("{module}::{name}"), "--exact", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// Lowers the soft descriptor limit of this process to `headroom` above
/// the descriptors it holds.
fn limit_descriptors(headroom: libc::rlim_t) {
    let open = std::fs::read_dir("/proc/self/fd").unwrap().count() as libc::rlim_t;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for both calls to read and write.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = open + headroom;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
}

/// Bytes that differ from one offset to the next.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The store directory of `path` below `td`, from its record.
fn entry(td: &TempDir, path: &str) -> std::path::PathBuf {
    let record = xattr(&td.path().join(path), "user.smb-server.streams").expect("a record");
    td.path().join(".smb-streams").join(hex(&record[..16]))
}

/// Where the stream `stream` of `path` below `td` is kept once spilled.
fn spilled(td: &TempDir, path: &str, stream: &str) -> std::path::PathBuf {
    entry(td, path).join(hex(stream.as_bytes()))
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

    // A file larger than an attribute holds moves to the store and back.
    let big = pattern(1 << 20);
    std::fs::write(&f, &big).unwrap();
    backend
        .rename_stream(&p("f.txt"), id(&td, "f.txt"), None, Some(&name("s")), false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"");
    assert_eq!(std::fs::read(spilled(&td, "f.txt", "s")).unwrap(), big);
    backend
        .rename_stream(&p("f.txt"), id(&td, "f.txt"), Some(&name("s")), None, true)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), big);
    assert!(streams(&backend, "f.txt").await.is_empty());
    assert!(!spilled(&td, "f.txt", "s").exists());
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
    // On Unix a directory reports no READONLY.
    h.set_attributes(FILE_ATTRIBUTE_READONLY).await.unwrap();
    assert!(!h.stat().await.unwrap().read_only);
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

#[tokio::test]
async fn a_stream_past_what_an_attribute_holds_moves_to_the_store() {
    use std::os::unix::fs::PermissionsExt as _;

    let Some((td, backend)) = backend() else {
        return;
    };
    let f = td.path().join("f.txt");
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    h.write(0, b"abc").await.unwrap();
    assert_eq!(h.write(65535, b"x").await.unwrap(), 1);
    assert!(xattr(&f, "user.DosStream.s:$DATA").is_none());
    let mut expected = b"abc".to_vec();
    expected.resize(65535, 0);
    expected.push(b'x');
    assert_eq!(std::fs::read(spilled(&td, "f.txt", "s")).unwrap(), expected);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&td.path().join(".smb-streams")), 0o700);
    assert_eq!(mode(&entry(&td, "f.txt")), 0o700);
    assert_eq!(h.stat().await.unwrap().end_of_file, 65536);
    assert_eq!(&h.read(65534, 10).await.unwrap()[..], b"\0x");
    assert_eq!(streams(&backend, "f.txt").await, [("s".to_string(), 65536)]);

    // Writes go to the stored file in place.
    let big = pattern(1 << 20);
    h.write(0, &big).await.unwrap();
    assert_eq!(std::fs::read(spilled(&td, "f.txt", "s")).unwrap(), big);
    h.truncate(10).await.unwrap();
    assert_eq!(
        std::fs::read(spilled(&td, "f.txt", "s")).unwrap(),
        &big[..10]
    );

    // Cut to zero, it is an attribute again.
    h.truncate(0).await.unwrap();
    assert_eq!(xattr(&f, "user.DosStream.s:$DATA").unwrap(), b"\0");
    assert!(!spilled(&td, "f.txt", "s").exists());
    h.write(0, b"small").await.unwrap();
    assert_eq!(xattr(&f, "user.DosStream.s:$DATA").unwrap(), b"small\0");
    h.close().await.unwrap();
}

#[tokio::test]
async fn a_stream_the_filesystem_has_no_room_for_reads_back_whole() {
    let Some((_td, backend)) = backend() else {
        return;
    };
    // ext4 keeps all of a file's extended attributes in one block, so
    // there these go to the store; elsewhere they stay attributes.
    let data = pattern(8192);
    create(&backend, "f.txt", "a", &data).await;
    create(&backend, "f.txt", "b", &data).await;
    for stream in ["a", "b"] {
        let (h, _) = open(&backend, "f.txt", stream, OpenIntent::Open)
            .await
            .unwrap();
        assert_eq!(read_all(h.as_ref()).await, data, "{stream}");
        h.close().await.unwrap();
    }
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("a".to_string(), 8192), ("b".to_string(), 8192)]
    );
}

#[tokio::test]
async fn spilled_streams_rename_and_remove_like_kept_ones() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let big = pattern(100_000);
    create(&backend, "f.txt", "s", &big).await;
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Open)
        .await
        .unwrap();
    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            Some(&name("s")),
            Some(&name("T")),
            false,
        )
        .await
        .unwrap();
    h.write(0, b"!").await.unwrap();
    let mut expected = big.clone();
    expected[0] = b'!';
    assert_eq!(std::fs::read(spilled(&td, "f.txt", "T")).unwrap(), expected);
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("T".to_string(), 100_000)]
    );
    h.close().await.unwrap();

    // A spilled stream renamed over a stream kept in an attribute replaces
    // it and stays in the store.
    create(&backend, "f.txt", "small", b"x").await;
    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            Some(&name("t")),
            Some(&name("small")),
            true,
        )
        .await
        .unwrap();
    assert!(xattr(&td.path().join("f.txt"), "user.DosStream.small:$DATA").is_none());
    assert_eq!(
        std::fs::read(spilled(&td, "f.txt", "small")).unwrap(),
        expected
    );

    backend
        .remove_stream(&p("f.txt"), id(&td, "f.txt"), &name("SMALL"))
        .await
        .unwrap();
    assert!(streams(&backend, "f.txt").await.is_empty());
    let left: Vec<_> = std::fs::read_dir(entry(&td, "f.txt"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["owner"]);
}

/// Gives `to` the record of `from`, as a host copy with extended
/// attributes does.
fn copy_record(td: &TempDir, from: &str, to: &str) {
    let record = xattr(&td.path().join(from), "user.smb-server.streams").unwrap();
    set_xattr(&td.path().join(to), "user.smb-server.streams", &record);
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[tokio::test]
async fn removed_files_leave_their_streams_for_a_sweep() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "a.txt", "s", &pattern(70_000)).await;
    let dir = entry(&td, "a.txt");
    // A copy made on the host, with extended attributes, and not used
    // through the server yet.
    std::fs::copy(td.path().join("a.txt"), td.path().join("a.bak")).unwrap();
    copy_record(&td, "a.txt", "a.bak");
    backend.unlink(&p("a.txt")).await.unwrap();
    assert!(dir.exists());
    let (h, _) = open(&backend, "a.bak", "s", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, pattern(70_000));
    h.close().await.unwrap();
    for _ in 0..3 {
        assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    }
    assert!(dir.exists());

    // Once nothing refers to it, the second sweep in a row removes it.
    std::fs::remove_file(td.path().join("a.bak")).unwrap();
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    assert!(dir.exists());
    assert_eq!(backend.sweep_streams().await.unwrap(), 1);
    assert!(!dir.exists());
}

#[tokio::test]
async fn a_copy_made_on_the_host_gets_streams_of_its_own_when_they_change() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let big = pattern(70_000);
    create(&backend, "f.txt", "s", &big).await;
    let (f, g) = (td.path().join("f.txt"), td.path().join("g.txt"));
    std::fs::copy(&f, &g).unwrap();
    copy_record(&td, "f.txt", "g.txt");

    // Read, the copy shows the streams it was copied with.
    assert_eq!(
        streams(&backend, "g.txt").await,
        [("s".to_string(), 70_000)]
    );
    let (h, _) = open(&backend, "g.txt", "s", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, big);
    assert_eq!(entry(&td, "g.txt"), entry(&td, "f.txt"));
    h.write(0, b"copy").await.unwrap();
    h.close().await.unwrap();
    assert_ne!(entry(&td, "g.txt"), entry(&td, "f.txt"));
    assert_eq!(std::fs::read(spilled(&td, "f.txt", "s")).unwrap(), big);
    assert_eq!(
        &std::fs::read(spilled(&td, "g.txt", "s")).unwrap()[..4],
        b"copy"
    );
}

#[tokio::test]
async fn sweeping_takes_two_passes_and_spares_what_is_used() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "keep.txt", "s", &pattern(70_000)).await;
    create(&backend, "gone.txt", "s", &pattern(70_000)).await;
    std::fs::create_dir(td.path().join("d")).unwrap();
    create(&backend, "d\\deep.txt", "s", &pattern(70_000)).await;
    let (keep, gone) = (entry(&td, "keep.txt"), entry(&td, "gone.txt"));
    std::fs::write(keep.join("~~73"), b"left by a write").unwrap();
    std::fs::remove_file(td.path().join("gone.txt")).unwrap();

    // The record of keep.txt is out of sight for a sweep, and the stream
    // is used before the next.
    let f = td.path().join("keep.txt");
    let record = xattr(&f, "user.smb-server.streams").unwrap();
    rustix::fs::removexattr(&f, "user.smb-server.streams").unwrap();
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    set_xattr(&f, "user.smb-server.streams", &record);
    let (h, _) = open(&backend, "keep.txt", "s", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, pattern(70_000));
    h.close().await.unwrap();
    rustix::fs::removexattr(&f, "user.smb-server.streams").unwrap();
    assert_eq!(backend.sweep_streams().await.unwrap(), 1);
    set_xattr(&f, "user.smb-server.streams", &record);
    assert!(!gone.exists());
    let mut kept: Vec<_> = std::fs::read_dir(td.path().join(".smb-streams"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.len() != 32)
        .collect();
    kept.sort();
    assert_eq!(kept, ["store-id"]);
    assert!(keep.join("73").exists());
    assert!(entry(&td, "d/deep.txt").exists());
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    assert!(!keep.join("~~73").exists());

    // A file an editor replaced with a copy keeps its streams: the copy
    // takes them over when they change, and the old entry goes.
    std::fs::write(td.path().join("new.tmp"), b"saved").unwrap();
    copy_record(&td, "keep.txt", "new.tmp");
    std::fs::rename(td.path().join("new.tmp"), &f).unwrap();
    let (h, _) = open(&backend, "keep.txt", "s", OpenIntent::Open)
        .await
        .unwrap();
    h.write(0, b"!").await.unwrap();
    h.close().await.unwrap();
    assert_ne!(entry(&td, "keep.txt"), keep);
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    assert_eq!(backend.sweep_streams().await.unwrap(), 1);
    assert!(!keep.exists());
    let mut expected = pattern(70_000);
    expected[0] = b'!';
    assert_eq!(
        std::fs::read(spilled(&td, "keep.txt", "s")).unwrap(),
        expected
    );
}

#[tokio::test]
async fn a_sweep_walks_wide_trees() {
    if !alone_in_child("a_sweep_walks_wide_trees") {
        return;
    }
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    for i in 0..3000 {
        let dir = td.path().join(format!("d{i}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("x"), b"x").unwrap();
    }
    // A descriptor kept per directory would run out.
    limit_descriptors(16);
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    assert!(entry(&td, "f.txt").exists());
}

#[tokio::test]
async fn a_file_a_sweep_cannot_read_stops_it_before_anything_goes() {
    use std::os::unix::fs::PermissionsExt as _;

    let Some((td, backend)) = backend() else {
        return;
    };
    if is_root() {
        eprintln!("skipping: root reads every file");
        return;
    }
    create(&backend, "gone.txt", "s", &pattern(70_000)).await;
    let gone = entry(&td, "gone.txt");
    std::fs::remove_file(td.path().join("gone.txt")).unwrap();
    let locked = td.path().join("locked.txt");
    std::fs::write(&locked, b"x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    for _ in 0..2 {
        assert!(backend.sweep_streams().await.is_err());
    }
    assert!(gone.exists());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn forged_and_foreign_records_reach_no_other_file() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "a.txt", "s", &pattern(70_000)).await;
    let a_entry = entry(&td, "a.txt");
    let record = xattr(&td.path().join("a.txt"), "user.smb-server.streams").unwrap();
    // The id of a.txt's entry with another identity.
    let mut forged = record[..16].to_vec();
    forged.extend_from_slice(&[0; 21]);
    for (file, value) in [("b.txt", forged), ("c.txt", b"not a record".to_vec())] {
        let path = td.path().join(file);
        std::fs::write(&path, b"").unwrap();
        set_xattr(&path, "user.smb-server.streams", &value);
        assert!(streams(&backend, file).await.is_empty(), "{file}");
        let (h, _) = open(&backend, file, "s", OpenIntent::Create).await.unwrap();
        assert!(matches!(
            h.write(0, &pattern(70_000)).await,
            Err(SmbError::DiskFull)
        ));
        h.write(0, b"small").await.unwrap();
        h.close().await.unwrap();
        assert_eq!(
            xattr(&path, "user.smb-server.streams").unwrap(),
            value,
            "{file}"
        );
    }
    assert_eq!(
        std::fs::read(a_entry.join(hex(b"s"))).unwrap(),
        pattern(70_000)
    );
}

#[tokio::test]
async fn overlapping_shares_leave_each_others_records_alone() {
    let Some((td, outer)) = backend() else {
        return;
    };
    std::fs::create_dir(td.path().join("sub")).unwrap();
    create(&outer, "sub\\f.txt", "s", &pattern(70_000)).await;
    let f = td.path().join("sub").join("f.txt");
    let record = xattr(&f, "user.smb-server.streams").unwrap();
    let inner = LocalFsBackend::new(td.path().join("sub")).unwrap();
    // The inner share's store has no entry for the record.
    create(&inner, "other.txt", "t", &pattern(70_000)).await;
    assert!(streams(&inner, "f.txt").await.is_empty());
    let (h, _) = open(&inner, "f.txt", "t", OpenIntent::Create)
        .await
        .unwrap();
    assert!(matches!(
        h.write(0, &pattern(70_000)).await,
        Err(SmbError::DiskFull)
    ));
    h.close().await.unwrap();
    assert_eq!(inner.sweep_streams().await.unwrap(), 0);
    assert_eq!(inner.sweep_streams().await.unwrap(), 0);
    assert_eq!(xattr(&f, "user.smb-server.streams").unwrap(), record);
    let (h, _) = open(&outer, "sub\\f.txt", "s", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, pattern(70_000));
    h.close().await.unwrap();
}

#[tokio::test]
async fn a_stream_left_both_spilled_and_in_an_attribute_reads_the_spilled_one() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    // As a crash between the move to the store and the removal of the
    // attribute leaves it.
    let f = td.path().join("f.txt");
    set_xattr(&f, "user.DosStream.s:$DATA", b"old\0");
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("s".to_string(), 70_000)]
    );
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, pattern(70_000));
    h.truncate(0).await.unwrap();
    assert!(read_all(h.as_ref()).await.is_empty());
    h.close().await.unwrap();
    assert!(!spilled(&td, "f.txt", "s").exists());
    assert_eq!(xattr(&f, "user.DosStream.s:$DATA").unwrap(), b"\0");
}

#[tokio::test]
async fn new_streams_past_the_most_a_file_has_are_disk_full() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s0", &pattern(70_000)).await;
    let dir = entry(&td, "f.txt");
    for i in 1..4096 {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(hex(format!("s{i}").as_bytes())))
            .unwrap();
    }
    assert_eq!(streams(&backend, "f.txt").await.len(), 4096);
    assert!(matches!(
        open(&backend, "f.txt", "new", OpenIntent::Create).await,
        Err(SmbError::DiskFull)
    ));
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    assert!(matches!(
        backend
            .rename_stream(
                &p("f.txt"),
                id(&td, "f.txt"),
                None,
                Some(&name("new")),
                false
            )
            .await,
        Err(SmbError::DiskFull)
    ));
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
    let (h, _) = open(&backend, "f.txt", "s4095", OpenIntent::Open)
        .await
        .unwrap();
    h.close().await.unwrap();
}

#[tokio::test]
async fn the_store_is_out_of_reach_of_clients_under_any_name() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let id_dir = entry(&td, "f.txt");
    let id = id_dir.file_name().unwrap().to_str().unwrap().to_string();
    std::os::unix::fs::symlink(".smb-streams", td.path().join("link")).unwrap();
    std::os::unix::fs::symlink(".smb-streams", td.path().join(".SMB-Streams")).unwrap();
    std::fs::create_dir_all(td.path().join("d").join(".smb-streams")).unwrap();
    let root = backend
        .open(
            &SmbPath::root(),
            OpenOptions {
                directory: true,
                ..opts(OpenIntent::Open, false)
            },
        )
        .await
        .unwrap()
        .0;
    let mut names: Vec<_> = root
        .list_dir(None)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.info.name)
        .collect();
    names.sort();
    assert_eq!(names, ["d", "f.txt"]);
    root.close().await.unwrap();
    for path in [
        ".smb-streams".to_string(),
        "link".to_string(),
        ".SMB-Streams".to_string(),
        format!("link\\{id}"),
        format!(".smb-streams\\{id}\\73"),
    ] {
        assert!(
            matches!(
                backend.open(&p(&path), opts(OpenIntent::Open, false)).await,
                Err(SmbError::NotFound)
            ),
            "{path}"
        );
        assert!(matches!(
            backend
                .open(&p(&path), opts(OpenIntent::OpenOrCreate, true))
                .await,
            Err(SmbError::AccessDenied)
        ));
        if !matches!(path.as_str(), "link" | ".SMB-Streams") {
            assert!(matches!(
                backend.unlink(&p(&path)).await,
                Err(SmbError::NotFound)
            ));
        }
    }
    assert!(matches!(
        backend
            .rename(&p("f.txt"), &p(&format!("link\\{id}\\x")), true)
            .await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        backend.rename(&p("f.txt"), &p(".smb-streams"), true).await,
        Err(SmbError::AccessDenied)
    ));
    // Elsewhere the name is an ordinary one.
    backend
        .open(
            &p("d\\.smb-streams"),
            OpenOptions {
                directory: true,
                ..opts(OpenIntent::Open, false)
            },
        )
        .await
        .unwrap()
        .0
        .close()
        .await
        .unwrap();
    assert!(id_dir.exists());
    // Removing a symlink to the store removes the link.
    backend.unlink(&p("link")).await.unwrap();
    assert!(td.path().join("link").symlink_metadata().is_err());
    assert!(id_dir.exists());

    // Before the store exists, clients cannot make its name.
    let Some((_fresh_td, fresh)) = self::backend() else {
        return;
    };
    assert!(matches!(
        fresh
            .open(
                &p(".smb-streams"),
                OpenOptions {
                    directory: true,
                    ..opts(OpenIntent::Create, true)
                }
            )
            .await,
        Err(SmbError::AccessDenied)
    ));
}

#[tokio::test]
async fn symlinks_and_links_lead_nowhere_from_the_store() {
    let Some((td, backend)) = backend() else {
        return;
    };
    // A store that is a symlink to elsewhere is not used.
    let outside = tempfile::tempdir_in(td.path().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(outside.path(), td.path().join(".smb-streams")).unwrap();
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    assert!(h.write(0, &pattern(70_000)).await.is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    assert_eq!(h.stat().await.unwrap().end_of_file, 0);
    h.close().await.unwrap();
    std::fs::remove_file(td.path().join(".smb-streams")).unwrap();

    // A stream file that is a symlink or a hard link to another file's
    // stream is refused.
    create(&backend, "a.txt", "s", &pattern(70_000)).await;
    for (file, link) in [("b.txt", "sym"), ("c.txt", "hard")] {
        create(&backend, file, "t", &pattern(70_001)).await;
        let target = spilled(&td, file, "t");
        std::fs::remove_file(&target).unwrap();
        if link == "sym" {
            std::os::unix::fs::symlink(spilled(&td, "a.txt", "s"), &target).unwrap();
        } else {
            std::fs::hard_link(spilled(&td, "a.txt", "s"), &target).unwrap();
        }
        let (h, _) = open(&backend, file, "t", OpenIntent::Open).await.unwrap();
        assert!(h.write(0, b"x").await.is_err(), "{link}");
        assert!(h.read(0, 10).await.is_err(), "{link}");
        h.close().await.unwrap();
    }
    assert_eq!(
        std::fs::read(spilled(&td, "a.txt", "s")).unwrap(),
        pattern(70_000)
    );
}

#[tokio::test]
async fn a_store_others_can_reach_is_not_used() {
    use std::os::unix::fs::PermissionsExt as _;

    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let store = td.path().join(".smb-streams");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(streams(&backend, "f.txt").await.is_empty());
    let (h, _) = open(&backend, "f.txt", "t", OpenIntent::Create)
        .await
        .unwrap();
    assert!(h.write(0, &pattern(70_000)).await.is_err());
    h.close().await.unwrap();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("s".to_string(), 70_000), ("t".to_string(), 0)]
    );

    let open_store = tempfile::tempdir_in(td.path().parent().unwrap()).unwrap();
    std::fs::set_permissions(open_store.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(
        LocalFsBackend::new(td.path())
            .unwrap()
            .stream_store(open_store.path())
            .is_err()
    );
    std::fs::create_dir(td.path().join("inside")).unwrap();
    std::fs::set_permissions(
        td.path().join("inside"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(
        LocalFsBackend::new(td.path())
            .unwrap()
            .stream_store(td.path().join("inside"))
            .is_err()
    );
    assert!(
        LocalFsBackend::new(td.path())
            .unwrap()
            .stream_store(td.path())
            .is_err()
    );
}

#[tokio::test]
async fn a_store_the_embedder_names_is_used_instead() {
    let Some((td, backend)) = backend() else {
        return;
    };
    use std::os::unix::fs::PermissionsExt as _;

    drop(backend);
    let store = tempfile::tempdir_in(td.path().parent().unwrap()).unwrap();
    std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let backend = LocalFsBackend::new(td.path())
        .unwrap()
        .stream_store(store.path())
        .unwrap();
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    assert!(!td.path().join(".smb-streams").exists());
    let record = xattr(&td.path().join("f.txt"), "user.smb-server.streams").unwrap();
    let file = store.path().join(hex(&record[..16])).join(hex(b"s"));
    assert_eq!(std::fs::read(file).unwrap(), pattern(70_000));
    std::fs::remove_file(td.path().join("f.txt")).unwrap();
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    assert_eq!(backend.sweep_streams().await.unwrap(), 1);
}

#[tokio::test]
async fn a_path_swapped_for_a_symlink_after_its_lookup_stays_out_of_the_store() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let id = entry(&td, "f.txt").file_name().unwrap().to_owned();
    // `x\73` and `y` are plain files; between the lookup of a path and its
    // open, `x` and `y` become symlinks into the store.
    std::fs::create_dir(td.path().join("x")).unwrap();
    std::fs::write(td.path().join("x").join("73"), b"real").unwrap();
    std::fs::write(td.path().join("y"), b"real").unwrap();
    let root = td.path().to_path_buf();
    let swaps = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&swaps);
    let backend = LocalFsBackend::new(&root).unwrap().after_locate(move || {
        let store = std::path::Path::new(".smb-streams").join(&id);
        if root
            .join("x")
            .symlink_metadata()
            .is_ok_and(|md| md.is_dir())
        {
            std::fs::rename(root.join("x"), root.join("x.real")).unwrap();
            std::os::unix::fs::symlink(&store, root.join("x")).unwrap();
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        } else if root
            .join("y")
            .symlink_metadata()
            .is_ok_and(|md| md.is_file())
        {
            std::fs::remove_file(root.join("y")).unwrap();
            std::os::unix::fs::symlink(store.join("73"), root.join("y")).unwrap();
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let (h, _) = backend
        .open(&p("x\\73"), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"real");
    h.close().await.unwrap();
    assert!(matches!(
        backend.open(&p("y"), opts(OpenIntent::Open, false)).await,
        Err(SmbError::NotFound)
    ));
    assert_eq!(swaps.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_record_of_this_store_whose_entry_is_gone_gets_a_new_one() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let f = td.path().join("f.txt");
    let old = xattr(&f, "user.smb-server.streams").unwrap();
    std::fs::remove_dir_all(entry(&td, "f.txt")).unwrap();
    assert!(streams(&backend, "f.txt").await.is_empty());
    create(&backend, "f.txt", "t", &pattern(70_001)).await;
    let new = xattr(&f, "user.smb-server.streams").unwrap();
    assert_ne!(new[..16], old[..16]);
    assert_eq!(new[16..32], old[16..32], "the same store");
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("t".to_string(), 70_001)]
    );
}

#[tokio::test]
async fn a_writable_share_makes_its_store_before_any_client_request() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let store = td.path().join(".smb-streams");
    assert!(!store.exists());
    let read_only = LocalFsBackend::new(td.path()).unwrap().read_only();
    let _ = read_only
        .open(&p("missing"), opts(OpenIntent::Open, false))
        .await;
    assert!(!store.exists());
    let _ = backend
        .open(&p("missing"), opts(OpenIntent::Open, false))
        .await;
    assert_eq!(std::fs::read(store.join("store-id")).unwrap().len(), 16);
}

#[tokio::test]
async fn an_owner_file_that_cannot_be_read_fails_the_request() {
    use std::os::unix::fs::PermissionsExt as _;

    let Some((td, backend)) = backend() else {
        return;
    };
    if is_root() {
        eprintln!("skipping: root reads every file");
        return;
    }
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let owner = entry(&td, "f.txt").join("owner");
    std::fs::set_permissions(&owner, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (file, _) = backend
        .open(&p("f.txt"), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    assert!(file.streams().await.is_err());
    file.close().await.unwrap();
    std::fs::set_permissions(&owner, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("s".to_string(), 70_000)]
    );
}

#[tokio::test]
async fn a_sweep_keeps_entries_that_records_of_other_layouts_name() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let dir = entry(&td, "f.txt");
    let f = td.path().join("f.txt");
    let mut later = xattr(&f, "user.smb-server.streams").unwrap()[..16].to_vec();
    later.extend_from_slice(b"a layout of a later version");
    set_xattr(&f, "user.smb-server.streams", &later);
    for _ in 0..3 {
        assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    }
    assert!(dir.exists());
}

#[tokio::test]
async fn removing_and_renaming_symlinks_acts_on_the_links() {
    use std::os::unix::fs::symlink;

    let Some((td, backend)) = backend() else {
        return;
    };
    // The store exists, so paths are looked up one name at a time.
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let root = td.path();
    let outside = tempfile::tempdir().unwrap();
    let t1 = outside.path().join("t1");
    std::fs::write(&t1, b"t1").unwrap();
    for name in ["t2", "t3"] {
        std::fs::write(root.join(name), name).unwrap();
    }
    std::fs::write(root.join("a"), b"a").unwrap();
    symlink(&t1, root.join("l1")).unwrap();
    symlink("t2", root.join("l2")).unwrap();
    symlink("t3", root.join("l3")).unwrap();

    backend.unlink(&p("l1")).await.unwrap();
    assert!(root.join("l1").symlink_metadata().is_err());
    assert_eq!(std::fs::read(&t1).unwrap(), b"t1");

    backend.rename(&p("l2"), &p("moved"), false).await.unwrap();
    assert!(root.join("moved").symlink_metadata().unwrap().is_symlink());
    assert_eq!(std::fs::read(root.join("t2")).unwrap(), b"t2");

    backend.rename(&p("a"), &p("l3"), true).await.unwrap();
    assert!(root.join("l3").symlink_metadata().unwrap().is_file());
    assert_eq!(std::fs::read(root.join("l3")).unwrap(), b"a");
    assert_eq!(std::fs::read(root.join("t3")).unwrap(), b"t3");
}

#[tokio::test]
async fn an_overwrite_of_a_name_swapped_after_its_lookup_truncates_nothing() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let target = spilled(&td, "f.txt", "s");
    let t = td.path().join("t");
    let root = td.path().to_path_buf();
    let link = target.strip_prefix(&root).unwrap().to_path_buf();
    let backend = LocalFsBackend::new(&root).unwrap().after_locate(move || {
        if root
            .join("t")
            .symlink_metadata()
            .is_ok_and(|md| md.is_file())
        {
            std::fs::remove_file(root.join("t")).unwrap();
            std::os::unix::fs::symlink(&link, root.join("t")).unwrap();
        }
    });
    for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
        if t.symlink_metadata().is_ok() {
            std::fs::remove_file(&t).unwrap();
        }
        std::fs::write(&t, b"real").unwrap();
        assert!(backend.open(&p("t"), opts(intent, true)).await.is_err());
        assert!(t.symlink_metadata().unwrap().is_symlink());
    }
    assert_eq!(std::fs::read(&target).unwrap(), pattern(70_000));
}

#[tokio::test]
async fn deep_paths_resolve_with_few_descriptors() {
    if !alone_in_child("deep_paths_resolve_with_few_descriptors") {
        return;
    }
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let depth = 1500;
    let rel: std::path::PathBuf = std::iter::repeat_n("a", depth).collect();
    std::fs::create_dir_all(td.path().join(&rel)).unwrap();
    std::fs::write(td.path().join(&rel).join("f"), b"deep").unwrap();
    // A descriptor kept per level would run out.
    limit_descriptors(16);
    let path = format!("{}\\f", vec!["a"; depth].join("\\"));
    let (h, _) = backend
        .open(&p(&path), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"deep");
    h.close().await.unwrap();
    // A symlink to the directory it is in leads up a level and back.
    std::os::unix::fs::symlink("../a", td.path().join(&rel).join("l")).unwrap();
    let (h, _) = backend
        .open(
            &p(&format!("{}\\l\\f", vec!["a"; depth].join("\\"))),
            opts(OpenIntent::Open, false),
        )
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"deep");
    h.close().await.unwrap();
    // Removed one level at a time: a recursive removal holds a descriptor
    // per level.
    let mut dir = td.path().join(&rel);
    std::fs::remove_file(dir.join("f")).unwrap();
    std::fs::remove_file(dir.join("l")).unwrap();
    while dir != td.path() {
        std::fs::remove_dir(&dir).unwrap();
        dir.pop();
    }
}

#[tokio::test]
async fn backends_starting_together_share_one_store_id() {
    use std::os::unix::fs::MetadataExt as _;

    let Some((td, _backend)) = backend() else {
        return;
    };
    let root = td.path().to_path_buf();
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let root = root.clone();
            tokio::spawn(async move {
                let backend = LocalFsBackend::new(&root).unwrap();
                let _ = backend
                    .open(&p("missing"), opts(OpenIntent::Open, false))
                    .await;
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    let id = root.join(".smb-streams").join("store-id");
    assert_eq!(std::fs::metadata(&id).unwrap().nlink(), 1);
    assert_eq!(std::fs::read(&id).unwrap().len(), 16);
    let names: Vec<_> = std::fs::read_dir(root.join(".smb-streams"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["store-id"]);
}

#[tokio::test]
async fn a_lost_store_id_comes_back_from_the_entries() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let id_file = td.path().join(".smb-streams").join("store-id");
    let id = std::fs::read(&id_file).unwrap();
    std::fs::remove_file(&id_file).unwrap();
    let backend = LocalFsBackend::new(td.path()).unwrap();
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("s".to_string(), 70_000)]
    );
    assert_eq!(std::fs::read(&id_file).unwrap(), id);
}

#[tokio::test]
async fn an_unreadable_store_id_leaves_streams_in_attributes() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "big", &pattern(70_000)).await;
    create(&backend, "f.txt", "small", b"x").await;
    std::fs::write(td.path().join(".smb-streams").join("store-id"), b"bad").unwrap();
    let backend = LocalFsBackend::new(td.path()).unwrap();
    assert_eq!(streams(&backend, "f.txt").await, [("small".to_string(), 1)]);
    let (h, _) = open(&backend, "f.txt", "small", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"x");
    assert!(matches!(
        h.write(0, &pattern(70_000)).await,
        Err(SmbError::DiskFull)
    ));
    h.close().await.unwrap();
}

#[tokio::test]
async fn a_store_id_is_made_where_renames_cannot_refuse_to_replace() {
    use std::os::unix::fs::MetadataExt as _;

    if !alone_in_child("a_store_id_is_made_where_renames_cannot_refuse_to_replace") {
        return;
    }
    let Some((td, backend)) = backend() else {
        return;
    };
    super::spill::NO_RENAME_NOREPLACE.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = backend
        .open(&p("missing"), opts(OpenIntent::Open, false))
        .await;
    let id_file = td.path().join(".smb-streams").join("store-id");
    let id = std::fs::read(&id_file).unwrap();
    assert_eq!(id.len(), 16);
    assert_eq!(std::fs::metadata(&id_file).unwrap().nlink(), 1);
    create(&backend, "f.txt", "small", b"x").await;
    // A store id left short in a store no record refers to is made again.
    std::fs::write(&id_file, b"short").unwrap();
    let again = LocalFsBackend::new(td.path()).unwrap();
    let _ = again
        .open(&p("missing"), opts(OpenIntent::Open, false))
        .await;
    super::spill::NO_RENAME_NOREPLACE.store(false, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(std::fs::read(&id_file).unwrap().len(), 16);
    assert_eq!(streams(&again, "f.txt").await, [("small".to_string(), 1)]);
    create(&again, "f.txt", "big", &pattern(70_000)).await;
    assert_eq!(streams(&again, "f.txt").await.len(), 2);
}

#[tokio::test]
async fn an_entry_a_crash_left_empty_does_not_block_store_id_recovery() {
    use std::os::unix::fs::PermissionsExt as _;

    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let store = td.path().join(".smb-streams");
    let id = std::fs::read(store.join("store-id")).unwrap();
    let empty = store.join("00112233445566778899aabbccddeeff");
    std::fs::create_dir(&empty).unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_file(store.join("store-id")).unwrap();
    let backend = LocalFsBackend::new(td.path()).unwrap();
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("s".to_string(), 70_000)]
    );
    assert_eq!(std::fs::read(store.join("store-id")).unwrap(), id);
    assert_eq!(backend.sweep_streams().await.unwrap(), 0);
    assert_eq!(backend.sweep_streams().await.unwrap(), 1);
    assert!(!empty.exists());
}

#[tokio::test]
async fn a_directory_moved_while_its_path_is_looked_up_is_not_found() {
    if !alone_in_child("a_directory_moved_while_its_path_is_looked_up_is_not_found") {
        return;
    }
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "s", &pattern(70_000)).await;
    let root = td.path().to_path_buf();
    for op in ["open", "unlink", "rename"] {
        std::fs::create_dir_all(root.join("p").join("c")).unwrap();
        std::fs::create_dir_all(root.join("q")).unwrap();
        std::fs::write(root.join("p").join("f"), b"f").unwrap();
        std::fs::write(root.join("q").join("f"), b"f").unwrap();
        std::os::unix::fs::symlink("..", root.join("p").join("c").join("up")).unwrap();
        // Going up from `c`, the lookup finds it moved to `q`.
        let (from, to) = (root.join("p").join("c"), root.join("q").join("c"));
        *crate::fs::local::BEFORE_PARENT.lock().unwrap() = Some(Box::new(move || {
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }));
        let path = p("p\\c\\up\\f");
        let result = match op {
            "open" => backend
                .open(&path, opts(OpenIntent::Open, false))
                .await
                .map(drop),
            "unlink" => backend.unlink(&path).await,
            _ => backend.rename(&path, &p("g"), false).await,
        };
        *crate::fs::local::BEFORE_PARENT.lock().unwrap() = None;
        assert!(
            matches!(result, Err(SmbError::NotFound | SmbError::PathNotFound)),
            "{op}: {result:?}"
        );
        assert!(root.join("p").join("f").exists(), "{op}");
        assert!(root.join("q").join("f").exists(), "{op}");
        std::fs::remove_dir_all(root.join("p")).unwrap();
        std::fs::remove_dir_all(root.join("q")).unwrap();
    }
}

/// What a peek from the share root of `backend` finds of each of
/// `streams` of each of `entries`.
async fn peek(
    backend: &LocalFsBackend,
    entries: &[&str],
    streams: &[(&str, u32)],
) -> Vec<Vec<Option<(u64, Vec<u8>)>>> {
    let dir_opts = OpenOptions {
        directory: true,
        ..opts(OpenIntent::Open, false)
    };
    let (dir, _) = backend.open(&SmbPath::root(), dir_opts).await.unwrap();
    let streams: Vec<_> = streams.iter().map(|&(s, max)| (name(s), max)).collect();
    let asked: Vec<_> = entries.iter().map(|&e| (e, &streams[..])).collect();
    let peeked = dir.peek_streams(&asked).await.unwrap();
    dir.close().await.unwrap();
    peeked
        .into_iter()
        .map(|found| {
            found
                .into_iter()
                .map(|f| f.map(|(size, data)| (size, data.to_vec())))
                .collect()
        })
        .collect()
}

#[tokio::test]
async fn peeks_give_the_size_and_start_of_kept_and_spilled_streams() {
    let Some((td, backend)) = backend() else {
        return;
    };
    create(&backend, "f.txt", "AFP_AfpInfo", &pattern(60)).await;
    create(&backend, "f.txt", "AFP_Resource", &pattern(70_000)).await;
    assert!(spilled(&td, "f.txt", "AFP_Resource").exists());
    std::fs::create_dir(td.path().join("d")).unwrap();
    create(&backend, "d", "s", b"dir data").await;
    std::fs::write(td.path().join("plain.txt"), b"x").unwrap();
    let streams = [
        ("afp_afpinfo", 60),
        ("AFP_AfpInfo", 8),
        ("AFP_Resource", 0),
        ("AFP_Resource", 100),
        ("S", 100),
        ("missing", 60),
    ];
    let peeked = peek(&backend, &["f.txt", "d", "plain.txt"], &streams).await;
    assert_eq!(
        peeked[0],
        [
            Some((60, pattern(60))),
            Some((60, pattern(8))),
            Some((70_000, Vec::new())),
            Some((70_000, pattern(100))),
            None,
            None
        ]
    );
    assert_eq!(
        peeked[1],
        [
            None,
            None,
            None,
            None,
            Some((8, b"dir data".to_vec())),
            None
        ]
    );
    assert_eq!(peeked[2], vec![None; 6]);
}

#[tokio::test]
async fn a_peek_reads_files_and_directories_and_nothing_else() {
    let Some((td, backend)) = backend() else {
        return;
    };
    let outside = tempfile::tempdir_in(td.path().parent().unwrap()).unwrap();
    let outside_backend = LocalFsBackend::new(outside.path()).unwrap();
    create(&outside_backend, "f.txt", "AFP_AfpInfo", &pattern(60)).await;
    create(&backend, "f.txt", "AFP_AfpInfo", &pattern(60)).await;
    create(&backend, "spilled.txt", "AFP_Resource", &pattern(70_000)).await;
    assert!(spilled(&td, "spilled.txt", "AFP_Resource").exists());
    std::fs::create_dir(td.path().join("d")).unwrap();
    create(&backend, "d", "AFP_AfpInfo", &pattern(60)).await;
    let fifo = td.path().join("fifo");
    mkfifo(&fifo);
    std::os::unix::fs::symlink("f.txt", td.path().join("in.txt")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("f.txt"), td.path().join("out.txt")).unwrap();

    let entries = [
        "f.txt",
        "spilled.txt",
        "d",
        "fifo",
        "in.txt",
        "out.txt",
        "gone.txt",
    ];
    let streams = [("AFP_AfpInfo", 60), ("AFP_Resource", 0)];
    let peeking = peek(&backend, &entries, &streams);
    let Ok(peeked) = tokio::time::timeout(Duration::from_secs(10), peeking).await else {
        release(&fifo);
        panic!("the peek blocked");
    };
    let info = Some((60, pattern(60)));
    assert_eq!(
        peeked,
        [
            vec![info.clone(), None],
            vec![None, Some((70_000, Vec::new()))],
            vec![info.clone(), None],
            vec![None, None],
            vec![info, None],
            vec![None, None],
            vec![None, None],
        ]
    );
}
