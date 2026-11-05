use std::path::Path;
use std::time::{Duration, SystemTime};

use tempfile::TempDir;

use super::*;
use crate::backend::{FILE_ATTRIBUTE_READONLY, OpenOptions, ShareBackend};
use crate::fs::LocalFsBackend;
use crate::path::SmbPath;

/// A backend on a new directory beside the test binary, on the build's
/// volume.
fn backend() -> (TempDir, LocalFsBackend) {
    let exe = std::env::current_exe().unwrap();
    let td = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
    let backend = LocalFsBackend::new(td.path()).unwrap();
    assert!(backend.capabilities().named_streams);
    (td, backend)
}

/// Bytes that differ from one offset to the next.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// The `AFP_AfpInfo` stream of a text file with a red label.
fn labeled_afp_info() -> Vec<u8> {
    let mut info = hex::decode("414650000000010000000000800000005445585474747874000c").unwrap();
    info.resize(60, 0);
    info
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

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// The value of the extended attribute `attr` of `path`.
fn xattr(path: &Path, attr: &str) -> Option<Vec<u8>> {
    match get(&File::open(path).unwrap(), &c(attr)) {
        Ok(value) => Some(value),
        Err(e) if is_missing(&e) => None,
        Err(e) => panic!("{e}"),
    }
}

fn set_xattr(path: &Path, attr: &str, value: &[u8]) {
    write_value(&File::open(path).unwrap(), &c(attr), value, 0, 0).unwrap();
}

/// The names of the extended attributes of `path`, sorted.
fn xattr_names(path: &Path) -> Vec<String> {
    let names = list_names(&File::open(path).unwrap()).unwrap();
    let mut out: Vec<String> = names
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty())
        .map(|n| String::from_utf8(n.to_vec()).unwrap())
        .collect();
    out.sort();
    out
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
async fn streams_are_extended_attributes_named_as_macos_means_them() {
    let (td, backend) = backend();
    let tags = "com.apple.metadata\u{F022}_kMDItemUserTags";
    create(&backend, "f.txt", tags, b"bplist00").await;
    create(&backend, "f.txt", "org.example.test", b"hello").await;
    create(&backend, "f.txt", "empty", b"").await;
    let f = td.path().join("f.txt");
    assert_eq!(
        xattr(&f, "com.apple.metadata:_kMDItemUserTags").unwrap(),
        b"bplist00"
    );
    assert_eq!(xattr(&f, "org.example.test").unwrap(), b"hello");
    assert_eq!(xattr(&f, "empty").unwrap(), b"");
    assert_eq!(std::fs::read(&f).unwrap(), b"");
    assert_eq!(
        streams(&backend, "f.txt").await,
        [
            (tags.to_string(), 8),
            ("empty".to_string(), 0),
            ("org.example.test".to_string(), 5)
        ]
    );

    // Set on the host, the Finder comment lists under the name a macOS
    // client sends for it.
    set_xattr(&f, "com.apple.metadata:kMDItemFinderComment", b"note");
    set_xattr(&f, "a\\b", b"x");
    let comment = "com.apple.metadata\u{F022}kMDItemFinderComment";
    let (h, _) = open(&backend, "f.txt", comment, OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"note");
    h.close().await.unwrap();
    let listed = streams(&backend, "f.txt").await;
    assert!(listed.contains(&(comment.to_string(), 4)), "{listed:?}");
    assert!(
        listed.contains(&("a\u{F026}b".to_string(), 1)),
        "{listed:?}"
    );
}

#[tokio::test]
async fn attributes_no_stream_name_leads_to_are_left_out() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"").unwrap();
    for attr in [
        "a/b",
        "x\u{F021}y",
        "com.apple.finderinfo",
        "afp_resource",
        "kept*?",
    ] {
        set_xattr(&f, attr, b"v");
    }
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("kept\u{F021}\u{F025}".to_string(), 1)]
    );
}

#[tokio::test]
async fn reserved_and_overlong_stream_names_are_refused() {
    let (td, backend) = backend();
    std::fs::write(td.path().join("f.txt"), b"").unwrap();
    for invalid in [
        "com.apple.FinderInfo",
        "COM.APPLE.RESOURCEFORK",
        "n".repeat(128).as_str(),
        "\u{E9}".repeat(64).as_str(),
    ] {
        assert!(
            matches!(
                open(&backend, "f.txt", invalid, OpenIntent::OpenOrCreate).await,
                Err(SmbError::NameInvalid)
            ),
            "{invalid:?}"
        );
    }
    create(&backend, "f.txt", &"n".repeat(127), b"").await;
}

#[tokio::test]
async fn each_attribute_has_one_stream_name() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    create(&backend, "f.txt", "a\u{F021}b", b"star").await;
    assert_eq!(xattr(&f, "a*b").unwrap(), b"star");
    set_xattr(&f, "trail ", b"space");
    assert_eq!(
        streams(&backend, "f.txt").await,
        [
            ("a\u{F021}b".to_string(), 4),
            ("trail\u{F028}".to_string(), 5)
        ]
    );
    let (h, _) = open(&backend, "f.txt", "TRAIL\u{F028}", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"space");
    h.close().await.unwrap();

    // The characters the private-use ones stand for name no stream.
    let file_id = id(&td, "f.txt");
    for literal in ["a*b", "A*B", "trail ", "x\u{1}"] {
        assert!(
            matches!(
                open(&backend, "f.txt", literal, OpenIntent::Open).await,
                Err(SmbError::NameInvalid)
            ),
            "{literal:?}"
        );
        assert!(matches!(
            backend
                .remove_stream(&p("f.txt"), file_id, &name(literal))
                .await,
            Err(SmbError::NameInvalid)
        ));
        for (from, to) in [(literal, "c"), ("a\u{F021}b", literal)] {
            assert!(matches!(
                backend
                    .rename_stream(
                        &p("f.txt"),
                        file_id,
                        Some(&name(from)),
                        Some(&name(to)),
                        false
                    )
                    .await,
                Err(SmbError::NameInvalid)
            ));
        }
    }
    assert_eq!(xattr_names(&f), ["a*b", "trail "]);
    backend
        .remove_stream(&p("f.txt"), file_id, &name("A\u{F021}B"))
        .await
        .unwrap();
    assert_eq!(xattr_names(&f), ["trail "]);
}

#[tokio::test]
async fn values_past_what_a_plain_stream_holds_are_refused() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"").unwrap();
    let big = pattern(MAX_PLAIN as usize + 1);
    set_xattr(&f, "BIG", &big);
    set_xattr(&f, "big", b"");
    create(&backend, "f.txt", "s", b"x").await;
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("BIG".to_string(), MAX_PLAIN + 1), ("s".to_string(), 1)]
    );
    let (h, _) = open(&backend, "f.txt", "big", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(h.stat().await.unwrap().end_of_file, MAX_PLAIN + 1);
    assert!(matches!(h.read(0, 10).await, Err(SmbError::AccessDenied)));
    assert!(matches!(h.write(0, b"x").await, Err(SmbError::DiskFull)));
    assert!(matches!(h.truncate(1).await, Err(SmbError::DiskFull)));
    h.close().await.unwrap();
    let file_id = id(&td, "f.txt");
    for (from, to) in [("big", "t"), ("s", "big")] {
        assert!(matches!(
            backend
                .rename_stream(
                    &p("f.txt"),
                    file_id,
                    Some(&name(from)),
                    Some(&name(to)),
                    true
                )
                .await,
            Err(SmbError::DiskFull)
        ));
    }
    assert_eq!(xattr(&f, "BIG").unwrap(), big);
    assert_eq!(xattr_names(&f), ["BIG", "big", "s"]);

    // The resource fork holds more, and moves into no plain stream.
    create(&backend, "f.txt", "AFP_Resource", &big).await;
    assert!(matches!(
        backend
            .rename_stream(
                &p("f.txt"),
                file_id,
                Some(&name("AFP_Resource")),
                Some(&name("t")),
                false
            )
            .await,
        Err(SmbError::DiskFull)
    ));
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), big);
}

#[tokio::test]
async fn afp_info_is_the_finder_info_in_its_layout() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"text").unwrap();
    let labeled = labeled_afp_info();
    assert_eq!(afp_info(&labeled[16..48]).as_slice(), labeled);

    // A client reads the AfpInfo of a file without Finder info, then writes
    // it back with its own.
    assert!(matches!(
        open(&backend, "f.txt", "AFP_AfpInfo", OpenIntent::Open).await,
        Err(SmbError::NotFound)
    ));
    let (h, action) = open(&backend, "f.txt", "AFP_AfpInfo", OpenIntent::OpenOrCreate)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Created);
    assert_eq!(read_all(h.as_ref()).await, afp_info(&[]));
    assert_eq!(h.stat().await.unwrap().end_of_file, 60);
    assert!(streams(&backend, "f.txt").await.is_empty());
    assert_eq!(h.write(0, &labeled).await.unwrap(), 60);
    h.close().await.unwrap();
    assert_eq!(xattr(&f, "com.apple.FinderInfo").unwrap(), &labeled[16..48]);
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("AFP_AfpInfo".to_string(), 60)]
    );

    let (h, action) = open(&backend, "f.txt", "afp_afpinfo", OpenIntent::OpenOrCreate)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert_eq!(read_all(h.as_ref()).await, labeled);
    assert_eq!(h.read(16, 8).await.unwrap().as_ref(), b"TEXTttxt");
    let mut bad_magic = labeled.clone();
    bad_magic[0] = b'X';
    for (offset, data) in [
        (0, &labeled[..59]),
        (0, bad_magic.as_slice()),
        (1, &labeled[..]),
        (0, &[labeled.as_slice(), b"x"].concat()[..]),
    ] {
        assert!(
            matches!(h.write(offset, data).await, Err(SmbError::InvalidParameter)),
            "{offset} {}",
            data.len()
        );
    }
    assert!(matches!(h.truncate(61).await, Err(SmbError::DiskFull)));
    h.truncate(30).await.unwrap();
    assert_eq!(read_all(h.as_ref()).await, labeled);

    // A cut to zero removes the Finder info, as do Finder info of all
    // zeros and an overwrite.
    h.truncate(0).await.unwrap();
    assert!(xattr(&f, "com.apple.FinderInfo").is_none());
    assert_eq!(read_all(h.as_ref()).await, afp_info(&[]));
    h.write(0, &labeled).await.unwrap();
    h.write(0, &afp_info(&[])).await.unwrap();
    assert!(xattr(&f, "com.apple.FinderInfo").is_none());
    assert!(streams(&backend, "f.txt").await.is_empty());
    h.close().await.unwrap();

    create(&backend, "f.txt", "AFP_AfpInfo", &labeled).await;
    let (h, action) = open(
        &backend,
        "f.txt",
        "AFP_AfpInfo",
        OpenIntent::OverwriteOrCreate,
    )
    .await
    .unwrap();
    assert_eq!(action, OpenAction::Overwritten);
    assert!(xattr(&f, "com.apple.FinderInfo").is_none());
    h.close().await.unwrap();

    // Set on the host, it reads as AfpInfo.
    set_xattr(&f, "com.apple.FinderInfo", &labeled[16..48]);
    let (h, _) = open(&backend, "f.txt", "AFP_AfpInfo", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, labeled);
    h.close().await.unwrap();
    backend
        .remove_stream(&p("f.txt"), id(&td, "f.txt"), &name("AFP_AFPINFO"))
        .await
        .unwrap();
    assert!(xattr(&f, "com.apple.FinderInfo").is_none());
    assert_eq!(std::fs::read(&f).unwrap(), b"text");
}

#[tokio::test]
async fn the_resource_fork_is_read_and_written_in_place() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    let fork = pattern(16 << 20);
    let (h, action) = open(&backend, "f.txt", "AFP_Resource", OpenIntent::OpenOrCreate)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Created);
    assert_eq!(h.stat().await.unwrap().end_of_file, 0);
    assert!(streams(&backend, "f.txt").await.is_empty());
    // Out of order, the last chunk first.
    let chunk = 1 << 20;
    for i in (0..16).rev() {
        let at = i * chunk;
        h.write(at as u64, &fork[at..at + chunk]).await.unwrap();
    }
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), fork);
    assert_eq!(
        h.read(5 << 20, 100).await.unwrap().as_ref(),
        &fork[5 << 20..(5 << 20) + 100]
    );
    assert_eq!(h.read((16 << 20) - 10, 100).await.unwrap().len(), 10);
    assert!(h.read(16 << 20, 100).await.unwrap().is_empty());
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("AFP_Resource".to_string(), 16 << 20)]
    );

    // A write at the start leaves the rest.
    h.write(0, b"head").await.unwrap();
    let value = xattr(&f, "com.apple.ResourceFork").unwrap();
    assert_eq!(value.len(), 16 << 20);
    assert_eq!(&value[..4], b"head");
    assert_eq!(&value[4..], &fork[4..]);
    assert!(matches!(
        h.write((16 << 20) - 1, b"xy").await,
        Err(SmbError::DiskFull)
    ));
    assert!(matches!(
        h.truncate((16 << 20) + 1).await,
        Err(SmbError::DiskFull)
    ));

    h.truncate(1000).await.unwrap();
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), value[..1000]);
    h.truncate(1500).await.unwrap();
    let grown = [&value[..1000], &[0; 500][..]].concat();
    assert_eq!(read_all(h.as_ref()).await, grown);
    h.truncate(0).await.unwrap();
    assert!(xattr(&f, "com.apple.ResourceFork").is_none());
    assert!(read_all(h.as_ref()).await.is_empty());
    assert_eq!(h.stat().await.unwrap().end_of_file, 0);
    h.write(3, b"x").await.unwrap();
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), b"\0\0\0x");
    h.close().await.unwrap();

    std::fs::create_dir(td.path().join("d")).unwrap();
    assert!(matches!(
        open(&backend, "d", "AFP_Resource", OpenIntent::OpenOrCreate).await,
        Err(SmbError::AccessDenied)
    ));
}

#[tokio::test]
async fn streams_open_under_any_case_and_keep_their_first_spelling() {
    let (td, backend) = backend();
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
    assert_eq!(xattr_names(&td.path().join("f.txt")), ["Zone"]);
}

#[tokio::test]
async fn attributes_differing_in_case_are_one_stream() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"").unwrap();
    set_xattr(&f, "tag", b"lower");
    set_xattr(&f, "TAG", b"upper");
    assert_eq!(streams(&backend, "f.txt").await, [("TAG".to_string(), 5)]);
    let (h, _) = open(&backend, "f.txt", "Tag", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"upper");
    h.close().await.unwrap();
    backend
        .remove_stream(&p("f.txt"), id(&td, "f.txt"), &name("tag"))
        .await
        .unwrap();
    assert!(xattr_names(&f).is_empty());
}

#[tokio::test]
async fn dispositions_open_create_and_truncate_streams() {
    let (td, backend) = backend();
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
    create(&backend, "f.txt", "AFP_Resource", b"fork").await;
    let (h, action) = open(&backend, "f.txt", "AFP_Resource", OpenIntent::Truncate)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Overwritten);
    assert_eq!(h.stat().await.unwrap().end_of_file, 0);
    h.close().await.unwrap();
    assert!(xattr(&td.path().join("f.txt"), "com.apple.ResourceFork").is_none());
}

#[tokio::test]
async fn writes_extend_with_zeros_and_truncate_cuts() {
    let (_td, backend) = backend();
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
    assert!(matches!(
        h.write(MAX_PLAIN, b"x").await,
        Err(SmbError::DiskFull)
    ));
    assert!(matches!(
        h.truncate(MAX_PLAIN + 1).await,
        Err(SmbError::DiskFull)
    ));
    h.close().await.unwrap();
}

#[tokio::test]
async fn stream_changes_move_the_last_write_time_of_the_file() {
    let (td, backend) = backend();
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
    for stream in ["AFP_Resource", "AFP_AfpInfo"] {
        set_old();
        let (h, _) = open(&backend, "f.txt", stream, OpenIntent::OpenOrCreate)
            .await
            .unwrap();
        h.write(0, &labeled_afp_info()).await.unwrap();
        assert!(modified() > old, "{stream}");
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
}

#[tokio::test]
async fn stream_handles_follow_renames_of_the_file_and_the_stream() {
    let (td, backend) = backend();
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    h.write(0, b"one").await.unwrap();
    std::fs::rename(td.path().join("f.txt"), td.path().join("g.txt")).unwrap();
    h.write(3, b"two").await.unwrap();
    assert_eq!(xattr(&td.path().join("g.txt"), "s").unwrap(), b"onetwo");

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
async fn renames_between_named_streams() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    create(&backend, "f.txt", "a", b"data").await;
    create(&backend, "f.txt", "b", b"").await;
    create(&backend, "f.txt", "empty", b"").await;

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
    // The replaced stream goes, and the renamed one takes the new spelling.
    rename("A", "B", true).await.unwrap();
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("B".to_string(), 4), ("empty".to_string(), 0)]
    );
    assert_eq!(xattr_names(&f), ["B", "empty"]);

    // Into the resource fork and out again.
    rename("B", "AFP_Resource", false).await.unwrap();
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), b"data");
    rename("afp_resource", "c", false).await.unwrap();
    assert_eq!(xattr_names(&f), ["c", "empty"]);
    // An empty fork and AfpInfo without Finder info do not exist, so
    // nothing moves into them.
    for to in ["AFP_Resource", "AFP_AfpInfo"] {
        assert!(matches!(
            rename("empty", to, false).await,
            Err(SmbError::InvalidParameter)
        ));
    }
    assert!(matches!(
        rename("c", "AFP_AfpInfo", false).await,
        Err(SmbError::InvalidParameter)
    ));
    assert_eq!(xattr_names(&f), ["c", "empty"]);

    // AfpInfo moves as its 60 bytes.
    create(&backend, "f.txt", "AFP_AfpInfo", &labeled_afp_info()).await;
    rename("AFP_AfpInfo", "saved", false).await.unwrap();
    assert_eq!(xattr(&f, "saved").unwrap(), labeled_afp_info());
    rename("saved", "AFP_AfpInfo", false).await.unwrap();
    assert_eq!(
        xattr(&f, "com.apple.FinderInfo").unwrap(),
        &labeled_afp_info()[16..48]
    );
}

#[tokio::test]
async fn renames_to_and_from_the_default_stream_move_the_data() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"contents").unwrap();
    backend
        .rename_stream(&p("f.txt"), id(&td, "f.txt"), None, Some(&name("s")), false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"");
    assert_eq!(xattr(&f, "s").unwrap(), b"contents");

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

    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            None,
            Some(&name("AFP_Resource")),
            false,
        )
        .await
        .unwrap();
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), b"contents");
    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            Some(&name("AFP_Resource")),
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"contents");
    assert!(xattr_names(&f).is_empty());

    // A file larger than a stream holds stays where it is.
    let big = pattern(MAX_PLAIN as usize + 1);
    std::fs::write(&f, &big).unwrap();
    assert!(matches!(
        backend
            .rename_stream(&p("f.txt"), id(&td, "f.txt"), None, Some(&name("s")), false)
            .await,
        Err(SmbError::DiskFull)
    ));
    assert_eq!(std::fs::read(&f).unwrap(), big);
    assert!(xattr_names(&f).is_empty());
    // The resource fork holds it.
    backend
        .rename_stream(
            &p("f.txt"),
            id(&td, "f.txt"),
            None,
            Some(&name("AFP_Resource")),
            false,
        )
        .await
        .unwrap();
    assert_eq!(xattr(&f, "com.apple.ResourceFork").unwrap(), big);
    assert_eq!(std::fs::read(&f).unwrap(), b"");
}

#[tokio::test]
async fn overwriting_the_file_keeps_its_streams_for_the_server_to_remove() {
    let (_td, backend) = backend();
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
    let (td, backend) = backend();
    std::fs::create_dir(td.path().join("d")).unwrap();
    create(&backend, "d", "ds", b"dir").await;
    create(&backend, "d", "AFP_AfpInfo", &labeled_afp_info()).await;
    create(&backend, "", "rs", b"root").await;
    assert_eq!(xattr(&td.path().join("d"), "ds").unwrap(), b"dir");
    let (h, _) = open(&backend, "d", "ds", OpenIntent::Open).await.unwrap();
    let info = h.stat().await.unwrap();
    assert!(info.is_directory);
    assert_eq!(info.end_of_file, 3);
    // On Unix a directory reports no READONLY.
    h.set_attributes(FILE_ATTRIBUTE_READONLY).await.unwrap();
    assert!(!h.stat().await.unwrap().read_only);
    h.close().await.unwrap();
    assert_eq!(
        streams(&backend, "d").await,
        [("AFP_AfpInfo".to_string(), 60), ("ds".to_string(), 3)]
    );
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
async fn protected_attributes_refuse_access() {
    let (_td, backend) = backend();
    assert!(matches!(
        open(
            &backend,
            "f.txt",
            "com.apple.system.Security",
            OpenIntent::OpenOrCreate
        )
        .await,
        Err(SmbError::AccessDenied)
    ));
}

#[tokio::test]
async fn a_read_only_backend_reads_streams_and_changes_none() {
    let (td, backend) = backend();
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
async fn removals_and_renames_leave_a_file_put_in_its_place_alone() {
    let (td, backend) = backend();
    create(&backend, "f.txt", "s", b"old").await;
    let old_id = id(&td, "f.txt");
    std::fs::remove_file(td.path().join("f.txt")).unwrap();
    create(&backend, "f.txt", "s", b"new").await;
    assert!(matches!(
        backend.remove_stream(&p("f.txt"), old_id, &name("s")).await,
        Err(SmbError::NotFound)
    ));
    assert!(matches!(
        backend
            .rename_stream(
                &p("f.txt"),
                old_id,
                Some(&name("s")),
                Some(&name("t")),
                false
            )
            .await,
        Err(SmbError::NotFound)
    ));
    assert_eq!(streams(&backend, "f.txt").await, [("s".to_string(), 3)]);
}

/// A disk image with a FAT volume, attached and detached on drop.
struct Fat(TempDir);

impl Fat {
    fn attach() -> Option<Self> {
        let td = tempfile::tempdir().unwrap();
        let image = td.path().join("fat.dmg");
        let mount = td.path().join("mnt");
        let hdiutil = |command: &str| {
            let mut c = std::process::Command::new("hdiutil");
            c.arg(command).arg("-quiet");
            c
        };
        let created = hdiutil("create")
            .args(["-size", "4m", "-fs", "MS-DOS", "-o"])
            .arg(&image)
            .status()
            .is_ok_and(|s| s.success());
        let attached = created
            && hdiutil("attach")
                .args(["-nobrowse", "-mountpoint"])
                .arg(&mount)
                .arg(&image)
                .status()
                .is_ok_and(|s| s.success());
        if !attached {
            eprintln!("skipping: no FAT disk image could be attached");
            return None;
        }
        Some(Self(td))
    }

    fn mount(&self) -> std::path::PathBuf {
        self.0.path().join("mnt")
    }
}

impl Drop for Fat {
    fn drop(&mut self) {
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", "-quiet"])
            .arg(self.mount())
            .status();
    }
}

#[tokio::test]
async fn a_volume_with_attributes_only_in_dot_underscore_files_has_no_streams() {
    let Some(fat) = Fat::attach() else {
        return;
    };
    let backend = LocalFsBackend::new(fat.mount()).unwrap();
    assert!(!backend.capabilities().named_streams);
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
async fn peeks_read_the_finder_info_and_fork_attributes_the_host_set() {
    let (td, backend) = backend();
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"x").unwrap();
    set_xattr(&path, "com.apple.FinderInfo", &labeled_afp_info()[16..48]);
    set_xattr(&path, "com.apple.ResourceFork", &pattern(5000));
    set_xattr(&path, "com.apple.metadata:_kMDItemUserTags", b"tags");
    std::fs::write(td.path().join("plain.txt"), b"x").unwrap();
    let streams = [
        ("AFP_AfpInfo", 60),
        ("afp_resource", 0),
        ("com.apple.metadata\u{F022}_kMDItemUserTags", 60),
        ("other", 60),
    ];
    let peeked = peek(&backend, &["f.txt", "plain.txt"], &streams).await;
    assert_eq!(
        peeked[0],
        [
            Some((60, labeled_afp_info())),
            Some((5000, Vec::new())),
            Some((4, b"tags".to_vec())),
            None
        ]
    );
    assert_eq!(peeked[1], vec![None; 4]);
}

#[tokio::test]
async fn a_peek_reads_files_and_directories_and_nothing_else() {
    let (td, backend) = backend();
    let outside = tempfile::tempdir_in(td.path().parent().unwrap()).unwrap();
    let finder_info = &labeled_afp_info()[16..48];
    for dir in [td.path(), outside.path()] {
        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        set_xattr(&dir.join("f.txt"), "com.apple.FinderInfo", finder_info);
    }
    set_xattr(
        &td.path().join("f.txt"),
        "com.apple.ResourceFork",
        &pattern(5000),
    );
    std::fs::create_dir(td.path().join("d")).unwrap();
    set_xattr(&td.path().join("d"), "com.apple.FinderInfo", finder_info);
    let fifo = std::ffi::CString::new(td.path().join("fifo").into_os_string().into_encoded_bytes())
        .unwrap();
    // SAFETY: `fifo` is a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
    std::os::unix::fs::symlink("f.txt", td.path().join("in.txt")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("f.txt"), td.path().join("out.txt")).unwrap();

    let entries = ["f.txt", "d", "fifo", "in.txt", "out.txt", "gone.txt"];
    let streams = [("AFP_AfpInfo", 60), ("AFP_Resource", 0)];
    let peeked = tokio::time::timeout(Duration::from_secs(10), peek(&backend, &entries, &streams))
        .await
        .expect("the peek returns");
    let info = Some((60, labeled_afp_info()));
    let fork = Some((5000, Vec::new()));
    assert_eq!(
        peeked,
        [
            vec![info.clone(), fork.clone()],
            vec![info.clone(), None],
            vec![None, None],
            vec![info, fork],
            vec![None, None],
            vec![None, None],
        ]
    );
}
