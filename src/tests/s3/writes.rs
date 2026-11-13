//! Files and directories made and changed through a writable backend.

use std::fs;
use std::future::Future as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::task::{Context, Waker};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinSet;

use super::fixture::{MIB, foreground, pattern, put};
use super::proxy::{Fault, Reply};
use super::share::{
    FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, READ, Rig, Spec, WRITE,
    WRITE_ATTRIBUTES, filetime, is_data_read, listings, names, put_with, reads, wait_for_requests,
    wait_until_async,
};
use crate::backend::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY};
use crate::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_UNEXPECTED_IO_ERROR,
};
use crate::s3::record::{EntryRecord, Record};
use crate::utils::now_filetime;
use crate::{FileTimes, OpenIntent, OpenOptions, ShareBackend, SmbError, SmbPath};

const RW: u32 = READ | WRITE;

pub(super) fn create_file() -> Spec {
    Spec::FILE.access(RW).disposition(FILE_CREATE)
}

pub(super) fn open_rw() -> Spec {
    Spec::FILE.access(RW)
}

pub(super) fn create_dir() -> Spec {
    Spec::DIR.access(RW).disposition(FILE_CREATE)
}

/// Requests that changed the bucket.
pub(super) fn changes(rig: &Rig) -> usize {
    rig.proxy
        .count(|seen| !matches!(seen.method.as_str(), "GET" | "HEAD"))
}

/// The entry records in the cache directory of `rig`.
pub(super) fn records(rig: &Rig) -> Vec<EntryRecord> {
    entry_records(rig.cache_dir())
}

pub(super) fn entry_records(cache: &Path) -> Vec<EntryRecord> {
    let mut found = Vec::new();
    for file in fs::read_dir(cache.join("records")).unwrap() {
        let bytes = fs::read(file.unwrap().path()).unwrap();
        if let Record::Entry(entry) = Record::decode(&bytes).unwrap() {
            found.push(*entry);
        }
    }
    found.sort_by(|a, b| a.key.cmp(&b.key));
    found
}

/// The ranges the record of `key` claims, and its length.
fn claimed(rig: &Rig, key: &str) -> (u64, Vec<(u64, u64)>) {
    let record = records(rig)
        .into_iter()
        .find(|record| record.key == key)
        .unwrap_or_else(|| panic!("no record for {key}"));
    let local = record.local.expect("local data");
    (
        local.len,
        local.present.iter().map(|r| (r.start, r.end)).collect(),
    )
}

#[tokio::test]
async fn a_file_written_through_the_share_reads_back_with_its_size_and_times() {
    let mut rig = Rig::writable().await;
    let before = now_filetime();
    let file = rig.smb.create("notes.txt", create_file()).await.unwrap();
    assert_eq!(file.action, 2, "FILE_CREATED");
    assert_eq!(file.size, 0);
    assert!(
        file.times
            .iter()
            .all(|&t| t >= before && t <= now_filetime())
    );
    assert_eq!(rig.smb.write(file.id, 0, b"hello").await, Ok(5));
    assert_eq!(rig.smb.write(file.id, 3, b"LO world").await, Ok(8));
    assert_eq!(rig.smb.read(file.id, 0, 100).await.unwrap(), b"helLO world");
    rig.smb.close(file.id).await;

    assert_eq!(rig.smb.contents("notes.txt", 4).await, b"helLO world");
    let again = rig.smb.open("notes.txt").await.unwrap();
    assert_eq!((again.size, again.allocation), (11, 4096));
    assert_eq!(again.times[0], file.times[0], "creation time stays");
    assert!(again.times[2] >= file.times[2]);
    assert_eq!(again.times[2], again.times[3]);
    assert_eq!(changes(&rig), 0, "nothing reaches the bucket");
    assert_eq!(reads(&rig.proxy), 0);
}

#[tokio::test]
async fn a_write_past_the_end_leaves_zeros() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("gap.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, b"x").await, Ok(1));
    let mut expected = vec![0u8; 10];
    expected.push(b'x');
    assert_eq!(rig.smb.read(file.id, 0, 100).await.unwrap(), expected);
    assert_eq!(rig.smb.write(file.id, 3, b"abc").await, Ok(3));
    expected[3..6].copy_from_slice(b"abc");
    assert_eq!(rig.smb.read(file.id, 0, 100).await.unwrap(), expected);
}

#[tokio::test]
async fn truncating_and_extending_change_the_size_and_extend_with_zeros() {
    let mut rig = Rig::writable().await;
    let data = pattern(0, 100);
    let file = rig.smb.create("t.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, &data).await, Ok(100));
    assert_eq!(rig.smb.set_size(file.id, 40).await, 0);
    assert_eq!(rig.smb.read(file.id, 0, 200).await.unwrap(), &data[..40]);
    assert_eq!(rig.smb.set_size(file.id, 70).await, 0);
    let mut expected = data[..40].to_vec();
    expected.resize(70, 0);
    assert_eq!(rig.smb.read(file.id, 0, 200).await.unwrap(), expected);
    assert_eq!(rig.smb.open("t.bin").await.unwrap().size, 70);
    assert_eq!(rig.smb.set_size(file.id, 0).await, 0);
    assert_eq!(rig.smb.open("t.bin").await.unwrap().size, 0);
    assert_eq!(
        rig.smb.write(file.id, 0, b"new").await,
        Ok(3),
        "a file that was emptied takes writes"
    );
    assert_eq!(rig.smb.contents("t.bin", 10).await, b"new");
}

#[tokio::test]
async fn a_write_into_the_middle_of_an_object_reads_back_mixed_with_the_object() {
    let mut rig = Rig::writable().await;
    let data = pattern(0, 3 * MIB + 17);
    let etag = put(rig.store(), "big.bin", &data).await;
    let file = rig.smb.create("big.bin", open_rw()).await.unwrap();
    assert_eq!(file.size, data.len() as u64);

    let patch = vec![0xAAu8; 5000];
    assert_eq!(rig.smb.write(file.id, 1_500_000, &patch).await, Ok(5000));
    assert_eq!(reads(&rig.proxy), 0, "a write does not wait for a download");

    let mut expected = data.to_vec();
    expected[1_500_000..1_505_000].copy_from_slice(&patch);
    assert_eq!(rig.smb.contents("big.bin", 60_000).await, expected);
    assert!(reads(&rig.proxy) > 0, "the rest comes from the object");
    assert!(
        rig.proxy
            .seen()
            .iter()
            .filter(|seen| is_data_read(seen))
            .all(|seen| seen.header("if-match") == Some(etag.as_str())),
        "every read of the object names its version"
    );

    let before = reads(&rig.proxy);
    assert_eq!(
        rig.smb.read(file.id, 1_500_100, 100).await.unwrap(),
        &patch[100..200]
    );
    assert_eq!(reads(&rig.proxy), before, "written bytes are not fetched");
    assert_eq!(changes(&rig), 0);
    let head = rig
        .store()
        .head_object("big.bin", foreground())
        .await
        .unwrap();
    assert_eq!(head.etag, etag, "the object in the bucket is as it was");

    // Reading does not make the bytes read local.
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert_eq!(
        claimed(&rig, "big.bin"),
        (data.len() as u64, vec![(1_500_000, 1_505_000)])
    );
}

#[tokio::test]
async fn a_read_never_mixes_the_bytes_of_a_changed_object_into_a_file() {
    let mut rig = Rig::writable().await;
    put(rig.store(), "f.bin", pattern(0, 300_000)).await;
    let file = rig.smb.create("f.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 100, &[7; 10]).await, Ok(10));
    put(rig.store(), "f.bin", pattern(9, 300_000)).await;

    assert_eq!(rig.smb.read(file.id, 100, 10).await.unwrap(), [7; 10]);
    assert_eq!(
        rig.smb.read(file.id, 0, 50).await,
        Err(crate::ntstatus::STATUS_UNEXPECTED_IO_ERROR),
        "the bytes below the write are those of an object that is gone"
    );
    assert_eq!(rig.smb.read(file.id, 100, 10).await.unwrap(), [7; 10]);
}

#[tokio::test]
async fn a_write_whose_request_is_dropped_still_lands() {
    let rig = Rig::writable().await;
    let (handle, _) = rig
        .backend
        .open(&"w.bin".parse::<SmbPath>().unwrap(), create_options(false))
        .await
        .unwrap();
    // The request is polled once, which starts the write, and then dropped.
    let mut request = Box::pin(handle.write(0, b"abc"));
    let mut context = Context::from_waker(Waker::noop());
    let _ = request.as_mut().poll(&mut context);
    drop(request);
    wait_until_async("the write to land", async || {
        handle.stat().await.unwrap().end_of_file == 3
    })
    .await;
    assert_eq!(handle.read(0, 10).await.unwrap(), "abc");
}

#[tokio::test]
async fn writes_from_two_handles_at_once_all_land() {
    let rig = Rig::writable().await;
    let path: SmbPath = "two.bin".parse().unwrap();
    let (first, _) = rig
        .backend
        .open(&path, create_options(false))
        .await
        .unwrap();
    let opts = OpenOptions {
        write: true,
        ..OpenOptions::default()
    };
    let (second, _) = rig.backend.open(&path, opts).await.unwrap();
    let (first, second) = (std::sync::Arc::new(first), std::sync::Arc::new(second));
    let mut tasks = JoinSet::new();
    for n in 0..40u64 {
        let handle = if n % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        tasks.spawn(async move {
            let piece = vec![n as u8 + 1; 1000];
            handle.write(n * 1000, &piece).await.unwrap();
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.unwrap();
    }
    let all = first.read(0, 100_000).await.unwrap();
    assert_eq!(all.len(), 40_000);
    for n in 0..40usize {
        assert!(
            all[n * 1000..(n + 1) * 1000]
                .iter()
                .all(|&b| b == n as u8 + 1),
            "piece {n}"
        );
    }
    assert_eq!(second.stat().await.unwrap().end_of_file, 40_000);
}

#[tokio::test]
async fn a_file_cut_below_its_object_and_grown_again_has_zeros_where_it_grew() {
    let mut rig = Rig::writable().await;
    let data = pattern(0, 300);
    put(rig.store(), "o.bin", &data).await;
    let file = rig.smb.create("o.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_size(file.id, 100).await, 0);
    assert_eq!(rig.smb.read(file.id, 0, 500).await.unwrap(), &data[..100]);
    assert_eq!(rig.smb.set_size(file.id, 150).await, 0);
    let mut expected = data[..100].to_vec();
    expected.resize(150, 0);
    assert_eq!(rig.smb.read(file.id, 0, 500).await.unwrap(), expected);
    assert_eq!(rig.smb.set_size(file.id, 400).await, 0);
    expected.resize(400, 0);
    assert_eq!(rig.smb.read(file.id, 0, 500).await.unwrap(), expected);
    assert_eq!(rig.smb.write(file.id, 390, b"end").await, Ok(3));
    expected[390..393].copy_from_slice(b"end");
    assert_eq!(rig.smb.contents("o.bin", 77).await, expected);
}

#[tokio::test]
async fn bytes_between_the_end_of_a_cut_file_and_a_later_write_are_zeros_not_the_object() {
    let mut rig = Rig::writable().await;
    let data = pattern(0, 300);
    put(rig.store(), "g.bin", &data).await;
    let file = rig.smb.create("g.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_size(file.id, 100).await, 0);
    assert_eq!(rig.smb.write(file.id, 200, b"zz").await, Ok(2));
    let mut expected = data[..100].to_vec();
    expected.resize(200, 0);
    expected.extend_from_slice(b"zz");
    assert_eq!(rig.smb.read(file.id, 0, 500).await.unwrap(), expected);
}

#[tokio::test]
async fn a_second_handle_reads_what_the_first_wrote() {
    let mut rig = Rig::writable().await;
    let first = rig.smb.create("shared.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(first.id, 0, b"abc").await, Ok(3));
    let second = rig.smb.create("shared.txt", open_rw()).await.unwrap();
    assert_eq!(second.size, 3);
    assert_eq!(rig.smb.read(second.id, 0, 10).await.unwrap(), b"abc");
    assert_eq!(rig.smb.write(second.id, 3, b"def").await, Ok(3));
    assert_eq!(rig.smb.read(first.id, 0, 10).await.unwrap(), b"abcdef");
    assert_eq!(rig.backend.overlay_len(), 1, "one entry for the object");
    rig.smb.close(first.id).await;
    rig.smb.close(second.id).await;
    assert_eq!(rig.backend.overlay_len(), 1, "it has local data to keep");
}

#[tokio::test]
async fn an_entry_with_nothing_to_keep_leaves_the_overlay_with_its_last_handle() {
    let mut rig = Rig::writable().await;
    put(rig.store(), "plain.txt", b"data").await;
    let first = rig.smb.open("plain.txt").await.unwrap();
    let second = rig.smb.open("plain.txt").await.unwrap();
    assert_eq!(rig.backend.overlay_len(), 1);
    rig.smb.close(first.id).await;
    assert_eq!(rig.backend.overlay_len(), 1);
    rig.smb.close(second.id).await;
    assert_eq!(rig.backend.overlay_len(), 0);
    assert!(rig.smb.open_dir("").await.is_ok());
    assert_eq!(rig.backend.overlay_len(), 0, "the root is not an entry");
}

#[tokio::test]
async fn a_read_only_file_refuses_writes_and_overwrites_but_opens_for_attributes() {
    let mut rig = Rig::writable().await;
    put_with(rig.store(), "ro.txt", b"data", &[("smb-attributes", "1")]).await;
    let status = |result: Result<_, u32>| result.map(|_: super::share::Opened| ()).unwrap_err();
    assert_eq!(
        status(rig.smb.create("ro.txt", Spec::FILE.access(WRITE)).await),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        status(
            rig.smb
                .create("ro.txt", Spec::FILE.disposition(FILE_OVERWRITE))
                .await
        ),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        status(
            rig.smb
                .create("ro.txt", Spec::FILE.disposition(FILE_OVERWRITE_IF))
                .await
        ),
        STATUS_ACCESS_DENIED
    );
    let attributes = rig
        .smb
        .create("ro.txt", Spec::FILE.access(READ | WRITE_ATTRIBUTES))
        .await
        .unwrap();
    assert_eq!(attributes.attributes, FILE_ATTRIBUTE_READONLY);
    assert_eq!(rig.smb.contents("ro.txt", 10).await, b"data");

    // Clearing the attribute lets the file be written.
    assert_eq!(rig.smb.set_basic(attributes.id, [0; 4], 0x80).await, 0);
    let file = rig
        .smb
        .create("ro.txt", Spec::FILE.access(WRITE))
        .await
        .unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"DA").await, Ok(2));
    assert_eq!(rig.smb.contents("ro.txt", 10).await, b"DAta");
    assert_eq!(changes(&rig), 0);
}

#[tokio::test]
async fn an_open_that_overwrites_empties_the_file_and_says_so() {
    let mut rig = Rig::writable().await;
    put(rig.store(), "o.txt", b"old contents").await;
    let file = rig
        .smb
        .create(
            "o.txt",
            Spec::FILE.access(RW).disposition(FILE_OVERWRITE_IF),
        )
        .await
        .unwrap();
    assert_eq!(file.action, 3, "FILE_OVERWRITTEN");
    assert_eq!(file.size, 0);
    assert_eq!(
        rig.smb.read(file.id, 0, 10).await,
        Err(crate::ntstatus::STATUS_END_OF_FILE)
    );
    assert_eq!(rig.smb.write(file.id, 0, b"new").await, Ok(3));
    assert_eq!(rig.smb.contents("o.txt", 10).await, b"new");

    put(rig.store(), "t.txt", b"old contents").await;
    let file = rig
        .smb
        .create("t.txt", Spec::FILE.access(RW).disposition(FILE_OVERWRITE))
        .await
        .unwrap();
    assert_eq!((file.action, file.size), (3, 0));
    let missing = rig
        .smb
        .create(
            "missing.txt",
            Spec::FILE.access(RW).disposition(FILE_OVERWRITE),
        )
        .await;
    assert_eq!(missing.unwrap_err(), STATUS_OBJECT_NAME_NOT_FOUND);

    let new = rig
        .smb
        .create(
            "new.txt",
            Spec::FILE.access(RW).disposition(FILE_OVERWRITE_IF),
        )
        .await
        .unwrap();
    assert_eq!(
        (new.action, new.size),
        (2, 0),
        "created when it was missing"
    );
    let there = rig
        .smb
        .create("new.txt", Spec::FILE.access(RW).disposition(FILE_OPEN_IF))
        .await
        .unwrap();
    assert_eq!(there.action, 1);
}

#[tokio::test]
async fn names_that_differ_in_case_are_two_names_when_the_backend_counts_case() {
    let mut rig = Rig::writable_with(|builder| builder.case_insensitive(false)).await;
    let upper = rig.smb.create("Name.txt", create_file()).await.unwrap();
    let lower = rig.smb.create("name.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(upper.id, 0, b"upper").await, Ok(5));
    assert_eq!(rig.smb.write(lower.id, 0, b"lower!").await, Ok(6));
    assert_eq!(rig.smb.contents("Name.txt", 10).await, b"upper");
    assert_eq!(rig.smb.contents("name.txt", 10).await, b"lower!");
    let root = rig.smb.open_dir("").await.unwrap();
    assert_eq!(
        names(&rig.smb.list(root.id, "*").await),
        ["Name.txt", "name.txt"]
    );
    assert_eq!(
        rig.smb.create("NAME.TXT", create_file()).await.map(|_| ()),
        Ok(()),
        "a third spelling is a third name"
    );
}

#[tokio::test]
async fn a_name_made_here_is_found_in_any_case_and_keeps_the_spelling_it_was_made_with() {
    let mut rig = Rig::writable().await;
    rig.smb.create("Docs", create_dir()).await.unwrap();
    let file = rig
        .smb
        .create("docs\\Read Me.TXT", create_file())
        .await
        .unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"x").await, Ok(1));
    assert_eq!(rig.smb.contents("DOCS\\read me.txt", 10).await, b"x");
    let docs = rig.smb.open_dir("DOCS").await.unwrap();
    assert_eq!(names(&rig.smb.list(docs.id, "*").await), ["Read Me.TXT"]);
    assert_eq!(
        names(&rig.smb.list(docs.id, "READ ME.txt").await),
        ["Read Me.TXT"]
    );
    let root = rig.smb.open_dir("").await.unwrap();
    assert_eq!(names(&rig.smb.list(root.id, "*").await), ["Docs"]);
    assert!(
        records(&rig).is_empty(),
        "the file had no flush and the directory is in the bucket"
    );
    // The key of a new name uses the spelling of its directory in the store.
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let keys: Vec<String> = records(&rig).into_iter().map(|r| r.key).collect();
    assert_eq!(keys, ["Docs/Read Me.TXT"]);
}

#[tokio::test]
async fn a_create_of_a_name_that_exists_fails_whether_it_is_in_the_bucket_or_not() {
    let mut rig = Rig::writable().await;
    put(rig.store(), "stored.txt", b"x").await;
    for name in ["stored.txt", "STORED.TXT"] {
        let status = rig.smb.create(name, create_file()).await.unwrap_err();
        assert_eq!(status, STATUS_OBJECT_NAME_COLLISION, "{name}");
    }
    rig.smb.create("fresh.txt", create_file()).await.unwrap();
    for name in ["fresh.txt", "Fresh.TXT"] {
        let status = rig.smb.create(name, create_file()).await.unwrap_err();
        assert_eq!(status, STATUS_OBJECT_NAME_COLLISION, "{name}");
    }
    let status = rig.smb.create("a\\b.txt", create_file()).await.unwrap_err();
    assert_eq!(status, STATUS_OBJECT_PATH_NOT_FOUND);
}

pub(super) fn create_options(directory: bool) -> OpenOptions {
    OpenOptions {
        write: true,
        intent: OpenIntent::Create,
        directory,
        ..OpenOptions::default()
    }
}

#[tokio::test]
async fn of_many_creates_of_one_name_exactly_one_succeeds() {
    for directory in [false, true] {
        let rig = Rig::writable().await;
        let mut tasks = JoinSet::new();
        for n in 0..16 {
            let backend = rig.backend.clone();
            let name = if n % 2 == 0 { "Race" } else { "race" };
            tasks.spawn(async move {
                let path: SmbPath = name.parse().unwrap();
                backend.open(&path, create_options(directory)).await
            });
        }
        let (mut created, mut exists) = (Vec::new(), 0);
        while let Some(done) = tasks.join_next().await {
            match done.unwrap() {
                Ok((handle, action)) => {
                    assert_eq!(action, crate::OpenAction::Created);
                    created.push(handle);
                }
                Err(SmbError::Exists) => exists += 1,
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!((created.len(), exists), (1, 15), "directory {directory}");
        let puts = rig.proxy.count(|seen| seen.method == "PUT");
        assert_eq!(puts, usize::from(directory), "directory {directory}");
        assert_eq!(listed(&rig).await.len(), 1);
    }
}

async fn listed(rig: &Rig) -> Vec<String> {
    let handle = rig
        .backend
        .open(&SmbPath::root(), OpenOptions::default())
        .await
        .unwrap()
        .0;
    let entries = handle.list_dir(None).await.unwrap();
    entries.into_iter().map(|entry| entry.info.name).collect()
}

#[tokio::test]
async fn a_directory_create_puts_its_marker_before_it_answers_and_keeps_no_record() {
    let mut rig = Rig::writable().await;
    let before = now_filetime();
    let dir = rig.smb.create("made", create_dir()).await.unwrap();
    assert_eq!(dir.action, 2);
    assert_ne!(dir.attributes & FILE_ATTRIBUTE_DIRECTORY, 0);
    assert!(
        dir.times
            .iter()
            .all(|&t| t >= before && t <= now_filetime())
    );

    let head = rig
        .store()
        .head_object("made/", foreground())
        .await
        .unwrap();
    assert_eq!(head.size, 0);
    assert_eq!(head.metadata.user.get("smb-attributes").unwrap(), "0");
    assert_eq!(
        head.metadata.user.get("mtime").unwrap().len(),
        "1700000000.123456789".len()
    );
    assert_eq!(changes(&rig), 1, "one request changed the bucket");
    assert_eq!(rig.proxy.count(|s| s.method == "PUT"), 1);

    assert!(records(&rig).is_empty(), "the marker carries the times");
    rig.smb.close(dir.id).await;
    assert_eq!(rig.backend.overlay_len(), 0, "nothing is left to keep");

    // The directory is there for lookups, listings and new names in it.
    assert!(rig.smb.open_dir("made").await.is_ok());
    let inner = rig.smb.create("made\\inner", create_dir()).await.unwrap();
    rig.smb.create("made\\f.txt", create_file()).await.unwrap();
    assert!(inner.attributes & FILE_ATTRIBUTE_DIRECTORY != 0);
    let root = rig.smb.open_dir("").await.unwrap();
    let in_root = rig.smb.list(root.id, "*").await;
    assert_eq!(names(&in_root), ["made"]);
    assert_eq!(in_root[0].times, dir.times);
    let made = rig.smb.open_dir("made").await.unwrap();
    assert_eq!(names(&rig.smb.list(made.id, "*").await), ["f.txt", "inner"]);
    assert_eq!(
        rig.smb
            .create("nothing\\deeper", create_dir())
            .await
            .unwrap_err(),
        STATUS_OBJECT_PATH_NOT_FOUND
    );
    let again = rig
        .smb
        .create("MADE", Spec::DIR.access(RW).disposition(FILE_OPEN_IF))
        .await
        .unwrap();
    assert_eq!(again.action, 1);
}

/// Checks that `name` was not made: no record, no entry, no name in lookups
/// or listings.
async fn assert_not_made(rig: &mut Rig, name: &str) {
    assert!(records(rig).is_empty());
    assert_eq!(rig.backend.overlay_len(), 0);
    assert_eq!(
        rig.smb.open_dir(name).await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    let root = rig.smb.open_dir("").await.unwrap();
    assert!(rig.smb.list(root.id, "*").await.is_empty());
    rig.smb.close(root.id).await;
}

/// Checks that `name` is not made, not after a restart either, and that the
/// create works when tried again.
async fn assert_not_made_and_made_again(mut rig: Rig, name: &str) {
    assert_not_made(&mut rig, name).await;
    let mut rig = rig.restart().await;
    assert_not_made(&mut rig, name).await;
    rig.proxy.clear_rules();
    assert_eq!(rig.smb.create(name, create_dir()).await.unwrap().action, 2);
    assert!(rig.smb.open_dir(name).await.is_ok());
}

#[tokio::test]
async fn a_directory_whose_marker_the_store_refuses_is_not_made() {
    let mut rig = Rig::writable().await;
    let path = format!("/{}/refused/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == path,
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    let status = rig.smb.create("refused", create_dir()).await.unwrap_err();
    assert_eq!(status, STATUS_ACCESS_DENIED);
    assert_not_made_and_made_again(rig, "refused").await;
}

#[tokio::test]
async fn a_directory_whose_record_cannot_be_written_is_not_made() {
    let mut rig = Rig::writable().await;
    rig.backend.hooks().record_writes.store(1, SeqCst);
    let status = rig.smb.create("d", create_dir()).await.unwrap_err();
    assert_eq!(status, STATUS_UNEXPECTED_IO_ERROR);
    assert_eq!(changes(&rig), 0, "the marker is put after the record");
    assert_not_made_and_made_again(rig, "d").await;
}

#[tokio::test]
async fn a_marker_put_that_may_have_landed_does_not_leave_the_name_unknown() {
    let mut rig = Rig::writable_with(|b| b.request_timeout(Duration::from_secs(2))).await;
    let path = format!("/{}/lost/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == path,
        Fault::DropAnswer,
        usize::MAX,
    );
    let status = rig.smb.create("lost", create_dir()).await.unwrap_err();
    assert_eq!(status, STATUS_UNEXPECTED_IO_ERROR);
    assert!(records(&rig).is_empty());
    assert_eq!(rig.backend.overlay_len(), 0);
    rig.proxy.clear_rules();
    assert!(
        rig.smb.open_dir("lost").await.is_ok(),
        "the lookup asks the store again, which has the directory"
    );
}

#[tokio::test]
async fn a_directory_that_cannot_be_taken_back_stays_as_it_is() {
    let mut rig = Rig::writable().await;
    let path = format!("/{}/stuck/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == path,
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    rig.backend.hooks().record_removals.store(1, SeqCst);
    let status = rig.smb.create("stuck", create_dir()).await.unwrap_err();
    assert_eq!(status, STATUS_ACCESS_DENIED, "the error of the put");
    let records = records(&rig);
    assert_eq!(records.len(), 1, "the record is still on disk");
    assert!(records[0].marker_pending);
    assert_eq!(rig.backend.overlay_len(), 1, "and the entry still holds it");
}

#[tokio::test]
async fn a_directory_changed_while_its_marker_is_put_keeps_its_record() {
    let rig = Rig::writable().await;
    let release = Arc::new(Notify::new());
    let path = format!("/{}/busy/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == path,
        Fault::Hold(Arc::clone(&release)),
        1,
    );
    let backend = rig.backend.clone();
    let creating = tokio::spawn(async move {
        backend
            .open(&"busy".parse::<SmbPath>().unwrap(), create_options(true))
            .await
            .map(|_| ())
    });
    wait_for_requests(&rig.proxy, 1, |seen| seen.method == "PUT").await;
    let (handle, _) = rig
        .backend
        .open(&"busy".parse::<SmbPath>().unwrap(), OpenOptions::default())
        .await
        .unwrap();
    let written = filetime(1_500_000_000, 0);
    let times = FileTimes {
        last_write_time: Some(written),
        ..FileTimes::default()
    };
    handle.set_times(times).await.unwrap();
    release.notify_one();
    creating.await.unwrap().unwrap();

    let records = records(&rig);
    assert_eq!(records.len(), 1);
    assert!(records[0].meta_pending && !records[0].marker_pending);
    assert_eq!(records[0].times[2], written);
    handle.close().await.unwrap();
    assert_eq!(rig.backend.overlay_len(), 1, "the times are still to go");
}

#[tokio::test]
async fn a_directory_the_store_already_has_as_a_directory_counts_as_made() {
    let mut rig = Rig::writable().await;
    let path = format!("/{}/dup/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == path,
        Fault::Reply(Reply::error(409, "ExistingObjectIsDirectory")),
        usize::MAX,
    );
    let dir = rig.smb.create("dup", create_dir()).await.unwrap();
    assert_eq!(dir.action, 2);
    assert!(records(&rig).is_empty(), "the skipped marker counts as put");
    rig.smb.close(dir.id).await;
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn a_failed_write_is_cut_back_and_makes_the_next_flush_seal() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("w.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, &[1; 10]).await, Ok(10));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let sealed = records(&rig)[0].generation;
    let data = rig
        .cache_dir()
        .join("data")
        .join(records(&rig)[0].id.as_str());

    // The failure leaves bytes of the write in the file.
    rig.backend.hooks().data_writes.store(1, SeqCst);
    assert_eq!(
        rig.smb.write(file.id, 50, &[2; 4]).await,
        Err(STATUS_UNEXPECTED_IO_ERROR)
    );
    assert_eq!(fs::metadata(&data).unwrap().len(), 10, "cut back");
    assert_eq!(rig.smb.open("w.bin").await.unwrap().size, 10);
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let flushed = records(&rig)[0].generation;
    assert!(
        flushed > sealed,
        "the flush sealed what the write may have changed"
    );

    rig.backend.hooks().data_writes.store(1, SeqCst);
    assert_eq!(
        rig.smb.write(file.id, 2, &[3; 4]).await,
        Err(STATUS_UNEXPECTED_IO_ERROR)
    );
    assert_eq!(fs::metadata(&data).unwrap().len(), 10);
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert!(records(&rig)[0].generation > flushed);
    assert_eq!(rig.smb.write(file.id, 0, &[4; 2]).await, Ok(2));
}

#[tokio::test]
async fn only_the_first_flush_of_a_file_syncs_the_data_directory() {
    let mut rig = Rig::writable().await;
    let syncs = |rig: &Rig| rig.backend.hooks().data_dir_syncs.load(SeqCst);
    let first = rig.smb.create("a.bin", create_file()).await.unwrap();
    assert_eq!(syncs(&rig), 0, "a create syncs nothing");
    assert_eq!(rig.smb.write(first.id, 0, b"abc").await, Ok(3));
    assert_eq!(rig.smb.flush(first.id).await, 0);
    assert_eq!(syncs(&rig), 1);
    assert_eq!(rig.smb.write(first.id, 3, b"def").await, Ok(3));
    assert_eq!(rig.smb.flush(first.id).await, 0);
    assert_eq!(syncs(&rig), 1);
    let second = rig.smb.create("b.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.flush(second.id).await, 0);
    assert_eq!(syncs(&rig), 2);
}

#[tokio::test]
async fn a_change_of_times_waits_for_the_turn_to_change_the_data_file() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("t.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"abc").await, Ok(3));
    let (handle, _) = rig
        .backend
        .open(&"t.bin".parse::<SmbPath>().unwrap(), OpenOptions::default())
        .await
        .unwrap();
    let hold = rig.backend.hold_io("t.bin").unwrap();
    let times = FileTimes {
        last_write_time: Some(filetime(1_500_000_000, 0)),
        ..FileTimes::default()
    };
    let handle = Arc::new(handle);
    let changing = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { handle.set_times(times).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!changing.is_finished(), "the change took the turn first");
    drop(hold);
    changing.await.unwrap().unwrap();
    assert_eq!(
        handle.stat().await.unwrap().last_write_time,
        filetime(1_500_000_000, 0)
    );
}

#[tokio::test]
async fn an_entry_that_a_directory_took_the_name_of_takes_no_more_changes() {
    let rig = Rig::writable_with(|b| b.metadata_ttl(Duration::ZERO)).await;
    put(rig.store(), "x", b"object").await;
    let path: SmbPath = "x".parse().unwrap();
    let write = OpenOptions {
        write: true,
        ..OpenOptions::default()
    };
    let (old, _) = rig.backend.open(&path, write).await.unwrap();
    assert!(!old.stat().await.unwrap().is_directory);

    // The object is replaced by a directory of the name.
    rig.store().delete_object("x", foreground()).await.unwrap();
    put(rig.store(), "x/inner", b"in").await;
    let (new, _) = rig
        .backend
        .open(&path, OpenOptions::default())
        .await
        .unwrap();
    assert!(new.stat().await.unwrap().is_directory);

    assert!(matches!(
        old.write(0, b"lost").await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(old.truncate(1).await, Err(SmbError::AccessDenied)));
    assert!(matches!(
        old.set_times(FileTimes {
            last_write_time: Some(filetime(1_500_000_000, 0)),
            ..FileTimes::default()
        })
        .await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        old.set_attributes(FILE_ATTRIBUTE_HIDDEN).await,
        Err(SmbError::AccessDenied)
    ));
    assert!(records(&rig).is_empty());
    assert_eq!(
        fs::read_dir(rig.cache_dir().join("data")).unwrap().count(),
        0
    );
    assert_eq!(rig.backend.overlay_len(), 1, "only the directory is held");
}

#[tokio::test]
async fn the_deadline_of_a_directory_create_starts_with_the_open() {
    let rig = Rig::writable_with(|b| b.request_timeout(Duration::from_secs(2))).await;
    let wait = Arc::new(Notify::new());
    let head = format!("/{}/slow", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "HEAD" && seen.target == head,
        Fault::Hold(Arc::clone(&wait)),
        1,
    );
    let marker = format!("/{}/slow/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == marker,
        Fault::Stall,
        usize::MAX,
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        wait.notify_one();
    });
    let started = std::time::Instant::now();
    let result = rig
        .backend
        .open(&"slow".parse::<SmbPath>().unwrap(), create_options(true))
        .await;
    let took = started.elapsed();
    assert!(matches!(result, Err(SmbError::Io(_))));
    assert!(
        took < Duration::from_millis(2600),
        "the lookup and the put share the deadline of the open: {took:?}"
    );
}

#[tokio::test]
async fn flush_and_the_close_of_the_last_handle_seal_the_ranges_written() {
    let mut rig = Rig::writable().await;
    let base = pattern(0, 100);
    put(rig.store(), "s.bin", &base).await;
    let file = rig.smb.create("s.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, &[b'a'; 10]).await, Ok(10));
    assert_eq!(rig.smb.write(file.id, 20, &[b'b'; 5]).await, Ok(5));
    assert!(records(&rig).is_empty(), "no record before a flush");
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert_eq!(claimed(&rig, "s.bin"), (100, vec![(0, 10), (20, 25)]));

    let record = &records(&rig)[0];
    assert_eq!(record.base.as_ref().unwrap().key, "s.bin");
    assert_eq!(record.base.as_ref().unwrap().head.size, 100);
    let data = fs::read(rig.cache_dir().join("data").join(record.id.as_str())).unwrap();
    assert_eq!(data.len(), 100);
    assert_eq!(&data[..10], &[b'a'; 10]);
    assert_eq!(&data[20..25], &[b'b'; 5]);

    // Later writes are not in the record until the next flush or the close of
    // the last handle.
    assert_eq!(rig.smb.write(file.id, 30, b"cc").await, Ok(2));
    assert_eq!(claimed(&rig, "s.bin"), (100, vec![(0, 10), (20, 25)]));
    rig.smb.close(file.id).await;
    let all = (100, vec![(0, 10), (20, 25), (30, 32)]);
    assert_eq!(claimed(&rig, "s.bin"), all);
    let file = rig.smb.create("s.bin", open_rw()).await.unwrap();
    assert_eq!(file.size, 100);
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert_eq!(claimed(&rig, "s.bin"), all);
    let mut expected = base.to_vec();
    expected[..10].fill(b'a');
    expected[20..25].fill(b'b');
    expected[30..32].copy_from_slice(b"cc");
    assert_eq!(rig.smb.contents("s.bin", 40).await, expected);
}

#[tokio::test]
async fn a_flush_of_a_file_made_here_claims_all_of_it() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("n.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, &[b'a'; 10]).await, Ok(10));
    assert_eq!(rig.smb.write(file.id, 20, &[b'b'; 5]).await, Ok(5));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert_eq!(claimed(&rig, "n.bin"), (25, vec![(0, 25)]));
    let record = &records(&rig)[0];
    assert!(record.base.is_none() && !record.remote);
    let data = fs::read(rig.cache_dir().join("data").join(record.id.as_str())).unwrap();
    assert_eq!(&data[10..20], &[0; 10]);
    let empty = rig.smb.create("e.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.flush(empty.id).await, 0);
    assert_eq!(claimed(&rig, "e.bin"), (0, vec![]));
}

#[tokio::test]
async fn a_truncate_below_the_sealed_length_seals_at_once() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("s.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, &[b'a'; 100]).await, Ok(100));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert_eq!(claimed(&rig, "s.bin"), (100, vec![(0, 100)]));

    assert_eq!(rig.smb.set_size(file.id, 150).await, 0);
    assert_eq!(
        claimed(&rig, "s.bin"),
        (100, vec![(0, 100)]),
        "growing seals nothing"
    );
    assert_eq!(rig.smb.set_size(file.id, 60).await, 0);
    assert_eq!(claimed(&rig, "s.bin"), (60, vec![(0, 60)]));
    let record = &records(&rig)[0];
    let data = fs::read(rig.cache_dir().join("data").join(record.id.as_str())).unwrap();
    assert_eq!(data.len(), 60);
    assert_eq!(rig.smb.contents("s.bin", 1000).await, vec![b'a'; 60]);

    // A file that was never flushed has nothing to replace.
    let other = rig.smb.create("o.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(other.id, 0, b"xyz").await, Ok(3));
    assert_eq!(rig.smb.set_size(other.id, 1).await, 0);
    assert_eq!(records(&rig).len(), 1);
}

#[tokio::test]
async fn an_explicit_write_time_stays_through_later_writes_and_others_follow_the_write() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("t.txt", create_file()).await.unwrap();
    let before = now_filetime();
    assert_eq!(rig.smb.write(file.id, 0, b"a").await, Ok(1));
    let wrote = rig.smb.open("t.txt").await.unwrap();
    assert!(wrote.times[2] >= before && wrote.times[3] >= before);

    let fixed = filetime(1_500_000_000, 0);
    assert_eq!(
        rig.smb.set_basic(file.id, [0, 0, fixed as i64, 0], 0).await,
        0
    );
    assert_eq!(rig.smb.write(file.id, 1, b"b").await, Ok(1));
    let after = rig.smb.open("t.txt").await.unwrap();
    assert_eq!(after.times[2], fixed, "the write time stays as it was set");
    assert!(after.times[3] >= before, "the change time moved");
    assert_eq!(after.size, 2);
}

#[tokio::test]
async fn times_and_attributes_set_on_a_file_show_in_opens_and_listings() {
    let mut rig = Rig::writable().await;
    put(rig.store(), "f.txt", b"data").await;
    let file = rig
        .smb
        .create("f.txt", Spec::FILE.access(READ | WRITE_ATTRIBUTES))
        .await
        .unwrap();
    let times = [
        filetime(1_400_000_000, 0),
        filetime(1_410_000_000, 500),
        filetime(1_420_000_000, 1_000),
        filetime(1_430_000_000, 0),
    ];
    let wanted = times.map(|t| t as i64);
    assert_eq!(
        rig.smb
            .set_basic(file.id, wanted, FILE_ATTRIBUTE_HIDDEN)
            .await,
        0
    );
    let again = rig.smb.open("f.txt").await.unwrap();
    assert_eq!(again.times, times);
    assert_eq!(again.attributes, FILE_ATTRIBUTE_HIDDEN);
    let root = rig.smb.open_dir("").await.unwrap();
    let listed = rig.smb.list(root.id, "*").await;
    assert_eq!(listed[0].times, times);
    assert_eq!(listed[0].attributes, FILE_ATTRIBUTE_HIDDEN);
    assert_eq!(listed[0].size, 4);
    assert_eq!(records(&rig).len(), 1, "the record was written at once");
    assert_eq!(changes(&rig), 0);
}

#[tokio::test]
async fn the_share_root_keeps_its_times_in_memory() {
    let mut rig = Rig::writable().await;
    let spec = Spec::DIR.access(READ | WRITE_ATTRIBUTES);
    let root = rig.smb.create("", spec).await.unwrap();
    let times = [filetime(1_400_000_000, 0), 0, filetime(1_420_000_000, 0), 0].map(|t| t as i64);
    assert_eq!(rig.smb.set_basic(root.id, times, 0).await, 0);
    let again = rig.smb.open_dir("").await.unwrap();
    assert_eq!(again.times[0], filetime(1_400_000_000, 0));
    assert_eq!(again.times[2], filetime(1_420_000_000, 0));
    assert!(records(&rig).is_empty());
    assert_eq!(changes(&rig), 0);
}

#[tokio::test]
async fn listings_merge_the_overlay_with_the_objects_of_the_store() {
    let mut rig = Rig::writable().await;
    put(rig.store(), "old.txt", b"old").await;
    put(rig.store(), "sub/in.txt", b"in").await;
    let new = rig.smb.create("new.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(new.id, 0, b"fresh").await, Ok(5));
    rig.smb.create("newdir", create_dir()).await.unwrap();
    rig.smb
        .create("sub\\added.txt", create_file())
        .await
        .unwrap();
    let old = rig.smb.create("old.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(old.id, 3, b"er and longer").await, Ok(13));

    let root = rig.smb.open_dir("").await.unwrap();
    let listed = rig.smb.list(root.id, "*").await;
    assert_eq!(names(&listed), ["new.txt", "newdir", "old.txt", "sub"]);
    let size = |name: &str| listed.iter().find(|e| e.name == name).unwrap().size;
    assert_eq!((size("new.txt"), size("old.txt")), (5, 16));
    assert!(listed.iter().find(|e| e.name == "newdir").unwrap().is_dir());
    assert!(listed.iter().find(|e| e.name == "sub").unwrap().is_dir());
    let new_row = listed.iter().find(|e| e.name == "new.txt").unwrap();
    assert_eq!(new_row.times[0], new.times[0]);
    assert_eq!(rig.smb.open("new.txt").await.unwrap().times, new_row.times);

    let sub = rig.smb.open_dir("sub").await.unwrap();
    assert_eq!(
        names(&rig.smb.list(sub.id, "*").await),
        ["added.txt", "in.txt"]
    );
    assert_eq!(
        names(&rig.smb.list(root.id, "n*").await),
        ["new.txt", "newdir"]
    );
    assert_eq!(
        names(&rig.smb.list(root.id, "*.TXT").await),
        ["new.txt", "old.txt"]
    );

    // A name without a wildcard is found without listing the directory.
    let before = listings(&rig.proxy);
    for pattern in ["new.txt", "NEW.TXT", "newdir"] {
        assert_eq!(rig.smb.list(root.id, pattern).await.len(), 1, "{pattern}");
    }
    assert!(rig.smb.list(root.id, "absent.txt").await.is_empty());
    assert_eq!(listings(&rig.proxy), before);
    assert_eq!(changes(&rig), 1, "only the marker of the directory");
}
