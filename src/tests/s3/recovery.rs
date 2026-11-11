//! A writable backend rebuilt on the cache directory of an earlier one, and
//! the use of the directory itself.

use std::fs;
use std::sync::Arc;

use tokio::sync::Notify;
use tokio::task::JoinSet;

use super::fixture::{TestBucket, foreground, pattern, put};
use super::gateway::REGION;
use super::proxy::{Fault, Reply};
use super::share::{
    Listed, READ, Rig, Smb, Spec, WRITE_ATTRIBUTES, filetime, names, wait_for_requests, wait_until,
    wait_until_async, writable_builder,
};
use super::writes::{changes, create_dir, create_file, open_rw, records};
use crate::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
use crate::s3::record::{Record, RecordId, TombstoneRecord};
use crate::{OpenIntent, OpenOptions, S3Backend, S3Error, ShareBackend, SmbPath};

/// What a directory listing and the files in it say, for comparing.
type Seen = Vec<(String, u64, u32, [u64; 4])>;

fn seen(listed: &[Listed]) -> Seen {
    let mut seen: Seen = listed
        .iter()
        .map(|e| (e.name.clone(), e.size, e.attributes, e.times))
        .collect();
    seen.sort();
    seen
}

async fn listing(smb: &mut Smb, dir: &str) -> Seen {
    let opened = smb.open_dir(dir).await.unwrap();
    let listed = smb.list(opened.id, "*").await;
    smb.close(opened.id).await;
    seen(&listed)
}

#[tokio::test]
async fn files_directories_times_and_attributes_come_back_after_a_restart() {
    let mut rig = Rig::writable().await;
    let big = pattern(7, 2 * (1 << 20) + 333);
    let based = pattern(1, 200_000);
    put(rig.store(), "stored.bin", &based).await;
    put(rig.store(), "untouched.txt", b"as it is").await;

    // A directory with a name that needs encoding, and files in it.
    let dir = rig.smb.create("dir one", create_dir()).await.unwrap();
    let name = "dir one\\f+ile%1 \u{e9}.txt";
    let made = rig.smb.create(name, create_file()).await.unwrap();
    for (at, piece) in big.chunks(60_000).enumerate() {
        assert_eq!(
            rig.smb.write(made.id, (at * 60_000) as u64, piece).await,
            Ok(piece.len() as u32)
        );
    }
    assert_eq!(rig.smb.flush(made.id).await, 0);
    let empty = rig.smb.create("empty.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.flush(empty.id).await, 0);
    let small = rig
        .smb
        .create("dir one\\small.txt", create_file())
        .await
        .unwrap();
    assert_eq!(rig.smb.write(small.id, 0, b"tiny").await, Ok(4));
    assert_eq!(rig.smb.flush(small.id).await, 0);

    // An object with pieces written into it, and a time on it.
    let patched = rig.smb.create("stored.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(patched.id, 10, &[9; 100]).await, Ok(100));
    assert_eq!(
        rig.smb.write(patched.id, 150_000, &[8; 4000]).await,
        Ok(4000)
    );
    assert_eq!(rig.smb.set_size(patched.id, 199_000).await, 0);
    assert_eq!(rig.smb.flush(patched.id).await, 0);
    let mut patched_data = based.to_vec();
    patched_data[10..110].fill(9);
    patched_data[150_000..154_000].fill(8);
    patched_data.truncate(199_000);

    // Times and attributes on an object nothing else changed.
    let marked = rig
        .smb
        .create("untouched.txt", Spec::FILE.access(READ | WRITE_ATTRIBUTES))
        .await
        .unwrap();
    let times = [
        filetime(1_400_000_000, 0),
        filetime(1_410_000_000, 7_000),
        filetime(1_420_000_000, 0),
        filetime(1_430_000_000, 100),
    ];
    assert_eq!(
        rig.smb
            .set_basic(marked.id, times.map(|t| t as i64), 0x2)
            .await,
        0
    );
    for id in [dir.id, made.id, empty.id, small.id, patched.id, marked.id] {
        rig.smb.close(id).await;
    }

    let root_before = listing(&mut rig.smb, "").await;
    let dir_before = listing(&mut rig.smb, "dir one").await;
    assert_eq!(
        root_before.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(),
        ["dir one", "empty.txt", "stored.bin", "untouched.txt"]
    );
    let records_before = records(&rig);
    assert_eq!(records_before.len(), 5);
    let entries_before = rig.backend.overlay_len();
    let puts = changes(&rig);
    assert_eq!(puts, 1, "only the directory reached the bucket");

    for round in 0..2 {
        rig = rig.restart().await;
        assert_eq!(rig.backend.overlay_len(), entries_before, "round {round}");
        assert_eq!(
            listing(&mut rig.smb, "").await,
            root_before,
            "round {round}"
        );
        assert_eq!(listing(&mut rig.smb, "dir one").await, dir_before);
        assert_eq!(rig.smb.contents(name, 50_000).await, big.to_vec());
        assert_eq!(rig.smb.contents("dir one\\small.txt", 10).await, b"tiny");
        assert_eq!(rig.smb.contents("empty.txt", 10).await, b"");
        assert_eq!(rig.smb.contents("stored.bin", 40_000).await, patched_data);
        assert_eq!(rig.smb.contents("untouched.txt", 10).await, b"as it is");
        let marked = rig.smb.open("untouched.txt").await.unwrap();
        assert_eq!((marked.times, marked.attributes), (times, 0x2));
        assert_eq!(records(&rig), records_before, "round {round}");
        assert_eq!(
            changes(&rig),
            puts,
            "a restart changes nothing in the bucket"
        );
    }
}

#[tokio::test]
async fn bytes_written_past_the_flushed_ranges_are_not_kept() {
    let mut rig = Rig::writable().await;
    let base = pattern(0, 100);
    put(rig.store(), "f.bin", &base).await;
    let file = rig.smb.create("f.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, &[b'a'; 10]).await, Ok(10));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert_eq!(rig.smb.write(file.id, 50, &[b'b'; 10]).await, Ok(10));
    assert_eq!(rig.smb.write(file.id, 90, &[b'c'; 20]).await, Ok(20));
    rig.smb.close(file.id).await;

    let mut rig = rig.restart().await;
    let mut expected = base.to_vec();
    expected[..10].fill(b'a');
    assert_eq!(rig.smb.contents("f.bin", 30).await, expected);
}

#[tokio::test]
async fn a_name_that_was_made_before_a_restart_cannot_be_made_again() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("Kept.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let mut rig = rig.restart().await;
    assert_eq!(
        rig.smb.create("kept.TXT", create_file()).await.unwrap_err(),
        crate::ntstatus::STATUS_OBJECT_NAME_COLLISION
    );
    let again = rig.smb.open("kept.txt").await.unwrap();
    assert_eq!(again.size, 0);
    let root = rig.smb.open_dir("").await.unwrap();
    assert_eq!(names(&rig.smb.list(root.id, "*").await), ["Kept.txt"]);
}

#[tokio::test]
async fn ids_are_random_and_not_made_from_the_name() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("same.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let first = records(&rig)[0].id.clone();

    let (bucket, proxy, _cache) = rig.stop().await;
    let mut rig = Rig::start(bucket, proxy, tempfile::tempdir().unwrap(), |b| b).await;
    let file = rig.smb.create("same.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert_ne!(first, records(&rig)[0].id);
}

#[tokio::test]
async fn a_cache_directory_in_use_cannot_be_used_by_another_backend() {
    let rig = Rig::writable().await;
    let second = writable_builder(&rig.bucket, rig.proxy.addr, rig.cache_dir())
        .build()
        .await;
    let Err(S3Error::InvalidArgument(why)) = second.map(|_| ()) else {
        panic!("a second backend took the directory");
    };
    assert!(why.contains("in use"), "{why}");
}

#[tokio::test]
async fn a_cache_directory_of_another_bucket_prefix_endpoint_or_case_setting_is_refused() {
    let rig = Rig::writable().await;
    let (bucket, proxy, cache) = rig.stop().await;
    let other_bucket = TestBucket::new().await;
    let credentials = (&bucket.gateway.access_key, &bucket.gateway.secret_key);
    for (what, built) in [
        (
            "bucket",
            S3Backend::builder(format!("http://{}", proxy.addr), REGION, &other_bucket.name)
                .credentials(credentials.0, credentials.1)
                .cache_dir(cache.path())
                .build()
                .await,
        ),
        (
            "prefix",
            S3Backend::builder(format!("http://{}", proxy.addr), REGION, &bucket.name)
                .credentials(credentials.0, credentials.1)
                .prefix("elsewhere")
                .cache_dir(cache.path())
                .build()
                .await,
        ),
        (
            "endpoint",
            S3Backend::builder(
                format!("http://{}", bucket.gateway.addr),
                REGION,
                &bucket.name,
            )
            .credentials(credentials.0, credentials.1)
            .cache_dir(cache.path())
            .build()
            .await,
        ),
        (
            "case setting",
            S3Backend::builder(format!("http://{}", proxy.addr), REGION, &bucket.name)
                .credentials(credentials.0, credentials.1)
                .case_insensitive(false)
                .cache_dir(cache.path())
                .build()
                .await,
        ),
    ] {
        let Err(S3Error::InvalidArgument(why)) = built.map(|_| ()) else {
            panic!("{what} was not refused");
        };
        assert!(why.contains("belongs to another"), "{what}: {why}");
    }
}

#[tokio::test]
async fn a_build_that_fails_on_the_bucket_leaves_the_cache_directory_as_it_was() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("kept.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"kept").await, Ok(4));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let (bucket, proxy, cache) = rig.stop().await;
    let junk = cache.path().join("records").join("1".repeat(32));
    fs::write(&junk, b"garbage").unwrap();
    let stray = cache.path().join("data").join("2".repeat(32));
    fs::write(&stray, b"no record").unwrap();

    proxy.inject(
        |seen| seen.method == "GET" && seen.has_param("list-type"),
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    let failed = writable_builder(&bucket, proxy.addr, cache.path())
        .build()
        .await;
    assert!(failed.is_err());
    assert!(junk.exists() && stray.exists());
    assert!(names_in(&cache.path().join("conflicts")).is_empty());

    proxy.clear_rules();
    let mut rig = Rig::start(bucket, proxy, cache, |builder| builder).await;
    assert!(!junk.exists() && !stray.exists());
    assert_eq!(rig.smb.contents("kept.txt", 10).await, b"kept");
}

fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn records_and_data_that_cannot_be_used_move_to_conflicts_and_the_rest_comes_back() {
    let mut rig = Rig::writable().await;
    for name in ["good.txt", "short.txt", "gone.txt"] {
        let file = rig.smb.create(name, create_file()).await.unwrap();
        assert_eq!(rig.smb.write(file.id, 0, b"0123456789").await, Ok(10));
        assert_eq!(rig.smb.flush(file.id).await, 0);
        rig.smb.close(file.id).await;
    }
    let all = records(&rig);
    let by_key = |key: &str| all.iter().find(|r| r.key == key).unwrap().clone();
    let (short, gone) = (by_key("short.txt"), by_key("gone.txt"));
    let (bucket, proxy, cache) = rig.stop().await;

    let data = cache.path().join("data");
    fs::OpenOptions::new()
        .write(true)
        .open(data.join(short.id.as_str()))
        .unwrap()
        .set_len(4)
        .unwrap();
    fs::remove_file(data.join(gone.id.as_str())).unwrap();

    let mut rig = Rig::start(bucket, proxy, cache, |builder| builder).await;

    assert_eq!(rig.smb.contents("good.txt", 100).await, b"0123456789");
    for name in ["short.txt", "gone.txt"] {
        assert_eq!(
            rig.smb.open(name).await.unwrap_err(),
            STATUS_OBJECT_NAME_NOT_FOUND,
            "{name}"
        );
    }
    assert_eq!(rig.backend.overlay_len(), 1);
}

#[tokio::test]
async fn a_move_to_conflicts_is_logged_at_error_level() {
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let junk = "2".repeat(32);
    let sink = Sink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let sink = sink.clone();
            move || sink.clone()
        })
        .with_ansi(false)
        .finish();
    {
        let _logging = tracing::subscriber::set_default(subscriber);
        let dir = crate::s3::cachedir::CacheDir::open(temp.path(), "identity").unwrap();
        fs::write(temp.path().join("records").join(&junk), b"junk").unwrap();
        dir.recover("", false).unwrap();
    }
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("ERROR"), "{log}");
    assert!(log.contains(&junk), "{log}");
    assert!(log.contains("conflicts"), "{log}");
    assert!(
        !log.contains("junk"),
        "the contents of the record are not logged"
    );
}

#[tokio::test]
async fn a_key_to_delete_is_hidden_from_lookups_and_listings() {
    let rig = Rig::writable().await;
    put(rig.store(), "gone.txt", b"x").await;
    put(rig.store(), "kept.txt", b"y").await;
    let (bucket, proxy, cache) = rig.stop().await;
    let record = Record::Tombstone(TombstoneRecord {
        id: RecordId::parse(&"a".repeat(32)).unwrap(),
        keys: vec!["gone.txt".to_owned()],
    });
    fs::write(
        cache.path().join("records").join("a".repeat(32)),
        record.encode(),
    )
    .unwrap();
    let mut rig = Rig::start(bucket, proxy, cache, |builder| builder).await;
    assert_eq!(
        rig.smb.open("gone.txt").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert!(rig.smb.open("kept.txt").await.is_ok());
    let root = rig.smb.open_dir("").await.unwrap();
    assert_eq!(names(&rig.smb.list(root.id, "*").await), ["kept.txt"]);
    assert!(rig.smb.list(root.id, "gone.txt").await.is_empty());
}

fn tombstone(id: &str, keys: &[&str]) -> Record {
    Record::Tombstone(TombstoneRecord {
        id: RecordId::parse(id).unwrap(),
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
    })
}

#[tokio::test]
async fn a_file_made_where_a_key_waits_to_be_deleted_may_exist_in_the_bucket() {
    let rig = Rig::writable().await;
    put(rig.store(), "gone.txt", b"old").await;
    let (bucket, proxy, cache) = rig.stop().await;
    let id = "b".repeat(32);
    fs::write(
        cache.path().join("records").join(&id),
        tombstone(&id, &["gone.txt"]).encode(),
    )
    .unwrap();
    let mut rig = Rig::start(bucket, proxy, cache, |builder| builder).await;
    for name in ["gone.txt", "fresh.txt"] {
        let file = rig.smb.create(name, create_file()).await.unwrap();
        assert_eq!(file.action, 2, "{name}");
        assert_eq!(rig.smb.flush(file.id).await, 0);
    }
    let remote = |key: &str| {
        records(&rig)
            .into_iter()
            .find(|record| record.key == key)
            .unwrap()
            .remote
    };
    assert!(remote("gone.txt"));
    assert!(!remote("fresh.txt"));
}

#[tokio::test]
async fn an_entry_is_not_hidden_by_a_key_to_delete_of_its_name() {
    let mut rig = Rig::writable().await;
    let file = rig.smb.create("both.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"new").await, Ok(3));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    put(rig.store(), "both.txt", b"old").await;
    put(rig.store(), "gone.txt", b"old").await;
    let (bucket, proxy, cache) = rig.stop().await;
    let id = "c".repeat(32);
    fs::write(
        cache.path().join("records").join(&id),
        tombstone(&id, &["both.txt", "gone.txt"]).encode(),
    )
    .unwrap();

    let mut rig = Rig::start(bucket, proxy, cache, |builder| builder).await;
    assert_eq!(rig.smb.contents("both.txt", 10).await, b"new");
    assert_eq!(
        rig.smb.open("gone.txt").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_directory_wins_over_an_object_of_its_name_when_entries_are_below_it() {
    let mut rig = Rig::writable().await;
    rig.smb.create("x", create_dir()).await.unwrap();
    let inner = rig.smb.create("x\\inner.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(inner.id, 0, b"in").await, Ok(2));
    assert_eq!(rig.smb.flush(inner.id).await, 0);
    let (bucket, proxy, cache) = rig.stop().await;
    bucket
        .client
        .delete_object("x/", foreground())
        .await
        .unwrap();
    put(&bucket.client, "x", b"an object").await;

    let mut rig = Rig::start(bucket, proxy, cache, |builder| builder).await;
    let dir = rig.smb.open_dir("x").await.unwrap();
    assert_eq!(names(&rig.smb.list(dir.id, "*").await), ["inner.txt"]);
    assert_eq!(rig.smb.contents("x\\inner.txt", 10).await, b"in");
    let root = rig.smb.open_dir("").await.unwrap();
    let listed = rig.smb.list(root.id, "*").await;
    assert_eq!(names(&listed), ["x"]);
    assert!(listed[0].is_dir());
    assert_eq!(
        rig.smb
            .create("x", Spec::FILE.access(READ))
            .await
            .unwrap_err(),
        crate::ntstatus::STATUS_FILE_IS_A_DIRECTORY
    );
}

#[tokio::test]
async fn a_directory_that_only_entries_below_it_imply_lists_and_opens() {
    let mut rig = Rig::writable().await;
    rig.smb.create("d", create_dir()).await.unwrap();
    let file = rig.smb.create("d\\f.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"in d").await, Ok(4));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let (bucket, proxy, cache) = rig.stop().await;

    // With no marker in the bucket, only the file below the directory holds
    // it up.
    bucket
        .client
        .delete_object("d/", foreground())
        .await
        .unwrap();

    let mut rig = Rig::start(bucket, proxy, cache, |builder| builder).await;
    let root = rig.smb.open_dir("").await.unwrap();
    let listed = rig.smb.list(root.id, "*").await;
    assert_eq!(names(&listed), ["d"]);
    assert!(listed[0].is_dir());
    let d = rig.smb.open_dir("d").await.unwrap();
    assert_eq!(names(&rig.smb.list(d.id, "*").await), ["f.txt"]);
    assert_eq!(rig.smb.contents("d\\f.txt", 10).await, b"in d");
    let made = rig.smb.create("d\\g.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(made.id, 0, b"x").await, Ok(1));
    assert_eq!(names(&rig.smb.list(d.id, "*").await), ["f.txt", "g.txt"]);
    assert_eq!(
        rig.smb.open_dir("d").await.map(|d| d.attributes & 0x10),
        Ok(0x10)
    );
}

#[tokio::test]
async fn a_directory_with_entries_is_not_empty() {
    let mut rig = Rig::writable().await;
    rig.smb.create("d", create_dir()).await.unwrap();
    let dir = rig
        .backend
        .open(&"d".parse::<SmbPath>().unwrap(), OpenOptions::default())
        .await
        .unwrap()
        .0;
    assert!(dir.dir_is_empty().await.unwrap());
    rig.smb.create("d\\f.txt", create_file()).await.unwrap();
    assert!(!dir.dir_is_empty().await.unwrap());
}

#[tokio::test]
async fn the_volume_is_the_one_that_holds_the_cache_directory() {
    let rig = Rig::writable().await;
    let info = rig.backend.volume_info().await.unwrap();
    assert_ne!(info, crate::VolumeInfo::default());
    let held = volume_of(rig.cache_dir());
    assert_eq!(info.total_allocation_units, held.total_allocation_units);
    assert_eq!(info.allocation_unit(), held.allocation_unit());
    assert_eq!(info.serial_number, held.serial_number);
    assert_eq!(info.max_name_length, held.max_name_length);
    assert!(info.caller_available_allocation_units <= info.total_allocation_units);
    assert!(info.actual_available_allocation_units <= info.total_allocation_units);
}

/// The volume that holds the directory `dir`.
fn volume_of(dir: &std::path::Path) -> crate::VolumeInfo {
    #[cfg(unix)]
    {
        let st = rustix::fs::statvfs(dir).unwrap();
        crate::host::volume_info(&st, st.f_fsid)
    }
    #[cfg(windows)]
    {
        crate::host::volume_info_of(&fs::File::open(dir.join("lock")).unwrap()).unwrap()
    }
}

#[tokio::test]
async fn a_directory_create_whose_request_is_dropped_still_finishes() {
    let rig = Rig::writable().await;
    let release = Arc::new(Notify::new());
    let path = format!("/{}/held/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == path,
        Fault::Hold(Arc::clone(&release)),
        1,
    );
    let opts = OpenOptions {
        write: true,
        intent: OpenIntent::Create,
        directory: true,
        ..OpenOptions::default()
    };
    let backend = rig.backend.clone();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        backend
            .open(&"held".parse::<SmbPath>().unwrap(), opts)
            .await
            .map(|_| ())
    });
    wait_for_requests(&rig.proxy, 1, |seen| seen.method == "PUT").await;
    assert_eq!(rig.proxy.count(|seen| seen.method == "PUT"), 1);
    let held = records(&rig);
    assert_eq!(
        held.len(),
        1,
        "the record is written before the marker is put"
    );
    assert!(held[0].marker_pending);
    assert!(
        rig.store()
            .head_object("held/", foreground())
            .await
            .is_err()
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    release.notify_one();
    wait_until_async("the marker to land", async || {
        rig.store().head_object("held/", foreground()).await.is_ok()
    })
    .await;
    wait_until("the record to go", || {
        records(&rig).is_empty() && rig.backend.overlay_len() == 0
    })
    .await;
    assert!(records(&rig).is_empty(), "the marker carries the times");
    assert_eq!(rig.backend.overlay_len(), 0);
}
