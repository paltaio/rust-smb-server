use std::time::{Duration, SystemTime};

use tempfile::TempDir;

use super::*;
use crate::backend::{FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, ShareBackend};
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

/// True if `td` is on ReFS, which cannot rename streams.
fn on_refs(td: &TempDir) -> bool {
    let dir = Dir::open_ambient_dir(td.path(), cap_std::ambient_authority()).unwrap();
    volume(&dir).unwrap().refs
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

/// The file id of `path`, as the backend reports it.
async fn id(backend: &LocalFsBackend, path: &str) -> u64 {
    let (h, _) = backend
        .open(&p(path), opts(OpenIntent::Open, false))
        .await
        .unwrap();
    let id = h.stat().await.unwrap().file_index;
    h.close().await.unwrap();
    id
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
    h.read(0, 1 << 20).await.unwrap().to_vec()
}

/// The stream `stream` of `path` below `td`, read on the host.
fn host_stream(td: &TempDir, path: &str, stream: &str) -> Option<Vec<u8>> {
    use std::io::Read as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(td.path().join(format!("{path}:{stream}")))
        .ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    Some(data)
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
async fn streams_are_ntfs_streams_under_the_names_clients_send() {
    let (td, backend) = backend();
    let tags = "com.apple.metadata\u{F022}_kMDItemUserTags";
    create(&backend, "f.txt", tags, b"bplist00").await;
    create(&backend, "f.txt", "Zone.Identifier", b"[ZoneTransfer]").await;
    create(&backend, "f.txt", "empty", b"").await;
    create(&backend, "f.txt", "a*b?", b"x").await;
    assert_eq!(host_stream(&td, "f.txt", tags).unwrap(), b"bplist00");
    assert_eq!(
        host_stream(&td, "f.txt", "zone.identifier").unwrap(),
        b"[ZoneTransfer]"
    );
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"");
    assert_eq!(
        streams(&backend, "f.txt").await,
        [
            ("Zone.Identifier".to_string(), 14),
            ("a*b?".to_string(), 1),
            (tags.to_string(), 8),
            ("empty".to_string(), 0),
        ]
    );

    // Made on the host, a stream is listed and read.
    std::fs::write(td.path().join("f.txt:host"), b"from the host").unwrap();
    let (h, _) = open(&backend, "f.txt", "HOST", OpenIntent::Open)
        .await
        .unwrap();
    assert_eq!(read_all(h.as_ref()).await, b"from the host");
    let info = h.stat().await.unwrap();
    assert_eq!(info.end_of_file, 13);
    assert!(info.allocation_size >= 13);
    assert!(!info.is_directory);
    h.close().await.unwrap();
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
    // Under any case, the stream opens and is not made again.
    let (h, action) = open(&backend, "f.txt", "S", OpenIntent::OpenOrCreate)
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert_eq!(read_all(h.as_ref()).await, b"data");
    h.close().await.unwrap();
    assert!(matches!(
        open(&backend, "f.txt", "S", OpenIntent::Create).await,
        Err(SmbError::Exists)
    ));
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
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("s".to_string(), 4), ("t".to_string(), 0)]
    );
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
    assert_eq!(h.stat().await.unwrap().end_of_file, 7);
    assert!(h.read(100, 10).await.unwrap().is_empty());
    h.close().await.unwrap();
}

#[tokio::test]
async fn times_set_through_a_stream_are_the_files() {
    let (td, backend) = backend();
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"data").unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    let modified = || std::fs::metadata(&f).unwrap().modified().unwrap();

    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
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
    let (td, backend) = backend();
    if on_refs(&td) {
        eprintln!("skipping: ReFS cannot rename streams");
        return;
    }
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Create)
        .await
        .unwrap();
    h.write(0, b"one").await.unwrap();
    std::fs::rename(td.path().join("f.txt"), td.path().join("g.txt")).unwrap();
    h.write(3, b"two").await.unwrap();
    assert_eq!(host_stream(&td, "g.txt", "s").unwrap(), b"onetwo");

    let (other, _) = open(&backend, "g.txt", "S", OpenIntent::Open)
        .await
        .unwrap();
    backend
        .rename_stream(
            &p("g.txt"),
            id(&backend, "g.txt").await,
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
    if on_refs(&td) {
        eprintln!("skipping: ReFS cannot rename streams");
        return;
    }
    create(&backend, "f.txt", "a", b"data").await;
    create(&backend, "f.txt", "b", b"").await;
    let file_id = id(&backend, "f.txt").await;
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
        [("a".to_string(), 4), ("b".to_string(), 0)]
    );
    // The replaced stream goes, also under another spelling, and the
    // renamed one takes the new spelling.
    rename("A", "B", true).await.unwrap();
    assert_eq!(streams(&backend, "f.txt").await, [("B".to_string(), 4)]);
    rename("B", "c", false).await.unwrap();
    assert_eq!(host_stream(&td, "f.txt", "c").unwrap(), b"data");
    assert_eq!(streams(&backend, "f.txt").await, [("c".to_string(), 4)]);
}

#[tokio::test]
async fn renames_to_and_from_the_default_stream_move_the_data() {
    let (td, backend) = backend();
    if on_refs(&td) {
        eprintln!("skipping: ReFS cannot rename streams");
        return;
    }
    let f = td.path().join("f.txt");
    std::fs::write(&f, b"contents").unwrap();
    let file_id = id(&backend, "f.txt").await;
    backend
        .rename_stream(&p("f.txt"), file_id, None, Some(&name("s")), false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"");
    assert_eq!(host_stream(&td, "f.txt", "s").unwrap(), b"contents");
    backend
        .rename_stream(&p("f.txt"), file_id, Some(&name("S")), None, true)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"contents");
    assert!(streams(&backend, "f.txt").await.is_empty());

    // Into an empty stream that exists, which it replaces.
    create(&backend, "f.txt", "e", b"").await;
    assert!(matches!(
        backend
            .rename_stream(&p("f.txt"), file_id, None, Some(&name("E")), false)
            .await,
        Err(SmbError::Exists)
    ));
    backend
        .rename_stream(&p("f.txt"), file_id, None, Some(&name("E")), true)
        .await
        .unwrap();
    assert_eq!(streams(&backend, "f.txt").await, [("E".to_string(), 8)]);
}

#[tokio::test]
async fn removing_a_stream_leaves_the_others() {
    let (_td, backend) = backend();
    create(&backend, "f.txt", "Keep", b"1").await;
    create(&backend, "f.txt", "Gone", b"2").await;
    let file_id = id(&backend, "f.txt").await;
    backend
        .remove_stream(&p("f.txt"), file_id, &name("GONE"))
        .await
        .unwrap();
    assert!(matches!(
        backend
            .remove_stream(&p("f.txt"), file_id, &name("gone"))
            .await,
        Err(SmbError::NotFound)
    ));
    assert_eq!(streams(&backend, "f.txt").await, [("Keep".to_string(), 1)]);
}

#[tokio::test]
async fn overwriting_the_file_keeps_its_streams_for_the_server_to_remove() {
    let (_td, backend) = backend();
    create(&backend, "f.txt", "s", b"stream").await;
    for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
        let (h, action) = backend.open(&p("f.txt"), opts(intent, true)).await.unwrap();
        assert_eq!(action, OpenAction::Overwritten);
        assert_eq!(h.streams().await.unwrap().len(), 1);
        h.close().await.unwrap();
    }
}

#[tokio::test]
async fn directories_and_the_share_root_have_streams() {
    let (td, backend) = backend();
    std::fs::create_dir(td.path().join("dir")).unwrap();
    create(&backend, "dir", "ds", b"dir").await;
    create(&backend, "", "rs", b"root").await;
    assert_eq!(host_stream(&td, "dir", "ds").unwrap(), b"dir");
    let (h, _) = open(&backend, "dir", "ds", OpenIntent::Open).await.unwrap();
    let info = h.stat().await.unwrap();
    assert!(info.is_directory);
    assert_eq!(info.end_of_file, 3);
    // Through a stream, the directory takes the attribute.
    h.set_attributes(FILE_ATTRIBUTE_READONLY).await.unwrap();
    assert!(h.stat().await.unwrap().read_only);
    h.set_attributes(0).await.unwrap();
    assert!(!h.stat().await.unwrap().read_only);
    h.close().await.unwrap();
    // So does a file.
    create(&backend, "f.txt", "s", b"x").await;
    let (h, _) = open(&backend, "f.txt", "s", OpenIntent::Open)
        .await
        .unwrap();
    h.set_attributes(FILE_ATTRIBUTE_HIDDEN).await.unwrap();
    h.close().await.unwrap();
    let md = std::fs::metadata(td.path().join("f.txt")).unwrap();
    let attributes = std::os::windows::fs::MetadataExt::file_attributes(&md);
    assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN, 0);
    assert_eq!(streams(&backend, "dir").await, [("ds".to_string(), 3)]);
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
    std::fs::create_dir(td.path().join("empty")).unwrap();
    assert!(streams(&backend, "empty").await.is_empty());
}

#[tokio::test]
async fn a_read_only_backend_reads_streams_and_changes_none() {
    let (td, backend) = backend();
    create(&backend, "f.txt", "s", b"data").await;
    let file_id = id(&backend, "f.txt").await;
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
    assert!(matches!(
        backend
            .remove_stream(&p("f.txt"), file_id, &name("s"))
            .await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        backend
            .rename_stream(
                &p("f.txt"),
                file_id,
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
    let old_id = id(&backend, "f.txt").await;
    std::fs::write(td.path().join("new.txt"), b"").unwrap();
    std::fs::write(td.path().join("new.txt:s"), b"new").unwrap();
    std::fs::rename(td.path().join("new.txt"), td.path().join("f.txt")).unwrap();
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

#[test]
fn stream_listings_parse_whole_entries_only() {
    let entry = |name: &str, size: u64, last: bool| {
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let len = 24 + units.len();
        let next = if last {
            0
        } else {
            len.next_multiple_of(8) as u32
        };
        let mut out = Vec::new();
        out.extend_from_slice(&next.to_le_bytes());
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.next_multiple_of(8).to_le_bytes());
        out.extend_from_slice(&units);
        if !last {
            out.resize(next as usize, 0);
        }
        out
    };
    let mut buf = entry("::$DATA", 4, false);
    buf.extend(entry(":s:$DATA", 3, false));
    buf.extend(entry(":bad:$INDEX_ALLOCATION", 0, false));
    buf.extend(entry(":last:$DATA", 1, true));
    let parsed: Vec<_> = parse_listing(&buf)
        .into_iter()
        .map(|s| (s.name.as_str().to_string(), s.size, s.allocation_size))
        .collect();
    assert_eq!(
        parsed,
        [("s".to_string(), 3, 8), ("last".to_string(), 1, 8)]
    );
    // A list cut short keeps the entries that are whole, and an offset
    // past the end ends it.
    let cut = &buf[..buf.len() - 4];
    assert_eq!(parse_listing(cut).len(), 1);
    let mut far = buf.clone();
    far[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_listing(&far).is_empty());
}

#[test]
fn names_compare_as_ntfs_compares_them() {
    assert!(same_name(
        &name("Zone.Identifier"),
        &name("zone.IDENTIFIER")
    ));
    assert!(same_name(&name("\u{E9}t\u{E9}"), &name("\u{C9}T\u{C9}")));
    // Final and medial sigma share an uppercase form; sharp s has no
    // one-character uppercase form.
    assert!(same_name(&name("\u{3C2}"), &name("\u{3C3}")));
    assert!(!same_name(&name("\u{DF}"), &name("\u{1E9E}")));
    assert!(!same_name(&name("a"), &name("b")));
}

#[tokio::test]
async fn renames_on_refs_are_refused_before_anything_changes() {
    let (td, backend) = backend();
    create(&backend, "f.txt", "a", b"data").await;
    create(&backend, "f.txt", "b", b"").await;
    let root = Arc::new(Dir::open_ambient_dir(td.path(), cap_std::ambient_authority()).unwrap());
    let place = Place {
        root,
        root_dev: None,
        read_only: false,
        volume: Volume { refs: true },
    };
    let renamed = place
        .rename_stream(
            PathBuf::from("f.txt"),
            0,
            Some(name("a")),
            Some(name("b")),
            true,
        )
        .await;
    assert!(matches!(renamed, Err(SmbError::InvalidParameter)));
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("a".to_string(), 4), ("b".to_string(), 0)]
    );
}

#[tokio::test]
async fn a_stream_to_replace_that_is_open_elsewhere_fails_the_rename_first() {
    let (td, backend) = backend();
    if on_refs(&td) {
        eprintln!("skipping: ReFS cannot rename streams");
        return;
    }
    create(&backend, "f.txt", "a", b"data").await;
    create(&backend, "f.txt", "b", b"").await;
    let file_id = id(&backend, "f.txt").await;
    let held = std::fs::File::open(td.path().join("f.txt:b")).unwrap();
    assert!(matches!(
        backend
            .rename_stream(
                &p("f.txt"),
                file_id,
                Some(&name("a")),
                Some(&name("B")),
                true
            )
            .await,
        Err(SmbError::InvalidParameter)
    ));
    assert_eq!(
        streams(&backend, "f.txt").await,
        [("a".to_string(), 4), ("b".to_string(), 0)]
    );
    drop(held);
    backend
        .rename_stream(
            &p("f.txt"),
            file_id,
            Some(&name("a")),
            Some(&name("B")),
            true,
        )
        .await
        .unwrap();
    assert_eq!(streams(&backend, "f.txt").await, [("B".to_string(), 4)]);
}

#[tokio::test]
async fn streams_with_the_longest_names_are_all_listed() {
    let (_td, backend) = backend();
    let names: Vec<String> = (0..40)
        .map(|i| format!("{i:02}{}", "\u{E9}".repeat(253)))
        .collect();
    for n in &names {
        create(&backend, "f.txt", n, b"x").await;
    }
    let listed = streams(&backend, "f.txt").await;
    assert_eq!(listed.len(), names.len());
    assert!(
        listed
            .iter()
            .all(|(n, size)| n.encode_utf16().count() == 255 && *size == 1)
    );
}

#[tokio::test]
async fn a_stream_to_replace_goes_while_other_opens_do_not_use_its_data() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let (td, backend) = backend();
    if on_refs(&td) {
        eprintln!("skipping: ReFS cannot rename streams");
        return;
    }
    create(&backend, "f.txt", "a", b"data").await;
    create(&backend, "f.txt", "b", b"").await;
    let file_id = id(&backend, "f.txt").await;
    // An open of the file that may delete it, and one that reads only the
    // attributes of the stream to replace.
    let file = std::fs::OpenOptions::new()
        .access_mode(DELETE | FILE_GENERIC_READ)
        .open(td.path().join("f.txt"))
        .unwrap();
    let attributes = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .open(td.path().join("f.txt:b"))
        .unwrap();
    backend
        .rename_stream(
            &p("f.txt"),
            file_id,
            Some(&name("a")),
            Some(&name("B")),
            true,
        )
        .await
        .unwrap();
    // The replaced stream is deleted under a name of its own, and goes
    // once the last handle on it closes.
    let listed = streams(&backend, "f.txt").await;
    assert_eq!(listed[0], ("B".to_string(), 4));
    assert_eq!(listed.len(), 2);
    assert!(
        listed[1..]
            .iter()
            .all(|(n, _)| n.starts_with("smb-server-replaced-"))
    );
    drop((file, attributes));
    assert_eq!(streams(&backend, "f.txt").await, [("B".to_string(), 4)]);
}

/// Bytes that differ from one offset to the next.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// What a peek from the share root of `backend` finds of each of
/// `streams` of each of `entries`.
async fn peek(
    backend: &LocalFsBackend,
    entries: &[&str],
    streams: &[(&str, u32)],
) -> Vec<Vec<Option<(u64, Vec<u8>)>>> {
    let dir_opts = crate::backend::OpenOptions {
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
async fn peeks_give_the_size_and_start_of_ntfs_streams() {
    let (td, backend) = backend();
    create(&backend, "f.txt", "AFP_AfpInfo", &pattern(60)).await;
    create(&backend, "f.txt", "AFP_Resource", &pattern(70_000)).await;
    std::fs::create_dir(td.path().join("d")).unwrap();
    create(&backend, "d", "s", b"dir data").await;
    std::fs::write(td.path().join("plain.txt"), b"x").unwrap();
    let streams = [
        ("afp_afpinfo", 60),
        ("AFP_Resource", 0),
        ("AFP_Resource", 100),
        ("S", 100),
    ];
    let peeked = peek(&backend, &["f.txt", "d", "plain.txt"], &streams).await;
    assert_eq!(
        peeked[0],
        [
            Some((60, pattern(60))),
            Some((70_000, Vec::new())),
            Some((70_000, pattern(100))),
            None
        ]
    );
    assert_eq!(
        peeked[1],
        [None, None, None, Some((8, b"dir data".to_vec()))]
    );
    assert_eq!(peeked[2], vec![None; 4]);
}

/// Symlinks are checked where the host lets the test make them.
#[tokio::test]
async fn a_peek_reads_files_and_directories_and_nothing_else() {
    let (td, backend) = backend();
    let outside = tempfile::tempdir_in(td.path().parent().unwrap()).unwrap();
    let outside_backend = LocalFsBackend::new(outside.path()).unwrap();
    create(&outside_backend, "f.txt", "AFP_AfpInfo", &pattern(60)).await;
    create(&backend, "f.txt", "AFP_AfpInfo", &pattern(60)).await;
    std::fs::create_dir(td.path().join("d")).unwrap();
    create(&backend, "d", "AFP_AfpInfo", &pattern(60)).await;
    let links = std::os::windows::fs::symlink_file("f.txt", td.path().join("in.txt")).is_ok()
        && std::os::windows::fs::symlink_file(
            outside.path().join("f.txt"),
            td.path().join("out.txt"),
        )
        .is_ok();
    let mut entries = vec!["f.txt", "d", "gone.txt"];
    if links {
        entries.extend(["in.txt", "out.txt"]);
    } else {
        eprintln!("no symlinks on {}", td.path().display());
    }
    let streams = [("AFP_AfpInfo", 60), ("AFP_Resource", 0)];
    let peeked = peek(&backend, &entries, &streams).await;
    let info = Some((60, pattern(60)));
    let mut expected = vec![
        vec![info.clone(), None],
        vec![info.clone(), None],
        vec![None, None],
    ];
    if links {
        expected.extend([vec![info, None], vec![None, None]]);
    }
    assert_eq!(peeked, expected);
}

#[tokio::test]
async fn a_junction_out_of_the_share_has_no_streams() {
    let (td, backend) = backend();
    let outside = tempfile::tempdir_in(td.path().parent().unwrap()).unwrap();
    std::fs::create_dir(outside.path().join("d")).unwrap();
    let outside_backend = LocalFsBackend::new(outside.path()).unwrap();
    create(&outside_backend, "d", "AFP_AfpInfo", &pattern(60)).await;
    let made = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(td.path().join("j"))
        .arg(outside.path().join("d"))
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    assert!(td.path().join("j").is_dir());
    // The junction has a stream of its own, which only a peek that kept
    // the junction itself would find.
    let dir = Dir::open_ambient_dir(td.path(), cap_std::ambient_authority()).unwrap();
    {
        use std::os::windows::io::AsHandle as _;
        let (junction, _) = nt_open(
            dir.as_handle().as_raw_handle() as HANDLE,
            "j".encode_utf16().collect(),
            FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
        .unwrap();
        assert!(is_link(&junction).unwrap());
        let (own, _) = open_relative(
            &junction,
            Some(&name("AFP_AfpInfo")),
            FILE_GENERIC_WRITE,
            SHARE_ALL,
            FILE_CREATE,
        )
        .unwrap();
        own.seek_write(&[7; 60], 0).unwrap();
    }
    let opened = open_entry(&dir, "j");
    assert!(opened.is_err(), "{opened:?}");
    let peeked = peek(&backend, &["j"], &[("AFP_AfpInfo", 60)]).await;
    assert_eq!(peeked, [vec![None]]);
}
