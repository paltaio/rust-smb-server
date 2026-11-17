//! Changes that reach the bucket through the background worker.

use std::fs;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;

use super::fixture::{MIB, foreground, is_missing, pattern, put, range};
use super::moves::{crash, make, path};
use super::proxy::{Fault, Proxy, Reply, Seen};
use super::share::{
    FILE_OVERWRITE_IF, Rig, Smb, filetime, is_data_read, listing_reply, names, run_bounded,
    wait_for_requests, wait_until, wait_until_async,
};
use super::writes::{create_dir, create_file, entry_records, open_rw, records};
use crate::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
use crate::proto::messages::FileId;
use crate::s3::encode::{hex, uri_encode};
use crate::s3::object::{Metadata, ObjectHead};
use crate::s3::record::{EntryRecord, Record, RecordId};
use crate::{OpenOptions, S3Backend, S3BackendBuilder, S3Error, ShareBackend, SmbPath};

/// How long a changed file rests before the backend stores it.
const DELAY: Duration = Duration::from_millis(150);

const PART: u64 = 5 << 20;

/// Settings for a backend that stores changes, in parts of 5 MiB.
pub(super) fn uploading(builder: S3BackendBuilder) -> S3BackendBuilder {
    builder
        .held_uploads(false)
        .upload_delay(DELAY)
        .part_size(PART)
}

/// Settings for a backend that stores nothing until a test lets it, with the
/// delay and part size of [`uploading`].
pub(crate) fn held(builder: S3BackendBuilder) -> S3BackendBuilder {
    builder.upload_delay(DELAY).part_size(PART)
}

pub(crate) async fn sync(backend: &S3Backend) -> Result<(), S3Error> {
    tokio::time::timeout(Duration::from_secs(60), backend.sync())
        .await
        .expect("sync returns")
}

/// [`sync`] for a rig with a lot to store. It has no deadline of its own and
/// panics when a minute passes with no change in the entries of the overlay,
/// the records in the cache directory and the requests the proxy saw.
pub(super) async fn sync_while_progressing(rig: &Rig) -> Result<(), S3Error> {
    const STALL: Duration = Duration::from_secs(60);
    let progress = || {
        (
            rig.backend.overlay_len(),
            left(rig, "records"),
            rig.proxy.count(|_| true),
        )
    };
    let sync = rig.backend.sync();
    tokio::pin!(sync);
    let mut seen = progress();
    loop {
        match tokio::time::timeout(STALL, &mut sync).await {
            Ok(done) => return done,
            Err(_) => {
                let now = progress();
                assert_ne!(now, seen, "nothing changed in {STALL:?}");
                seen = now;
            }
        }
    }
}

fn sha(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// The bytes and the description of the object `key`, read from the bucket
/// itself.
pub(super) async fn stored(rig: &Rig, key: &str) -> (Vec<u8>, ObjectHead) {
    let head = rig.store().head_object(key, foreground()).await.unwrap();
    if head.size == 0 {
        return (Vec::new(), head);
    }
    let object = rig
        .store()
        .get_object(key, range(0, head.size), None, foreground())
        .await
        .unwrap();
    (object.data.to_vec(), head)
}

/// How many files are in `dir` of the cache directory.
pub(super) fn left(rig: &Rig, dir: &str) -> usize {
    fs::read_dir(rig.cache_dir().join(dir)).unwrap().count()
}

/// Writes `data` from the start of the open `id`.
pub(super) async fn fill(smb: &mut Smb, id: FileId, data: &[u8]) {
    const PIECE: usize = 60_000;
    for (at, piece) in data.chunks(PIECE).enumerate() {
        assert_eq!(
            smb.write(id, (at * PIECE) as u64, piece).await,
            Ok(piece.len() as u32)
        );
    }
}

pub(super) fn is_put_of(bucket: &str, key: &str) -> impl Fn(&Seen) -> bool + Send + Sync + 'static {
    let target = format!("/{bucket}/{}", uri_encode(key, true));
    move |seen| {
        seen.method == "PUT"
            && !seen.has_param("partNumber")
            && seen.target.split('?').next() == Some(target.as_str())
    }
}

pub(super) fn is_head_of(
    bucket: &str,
    key: &str,
) -> impl Fn(&Seen) -> bool + Send + Sync + 'static {
    let target = format!("/{bucket}/{}", uri_encode(key, true));
    move |seen| seen.method == "HEAD" && seen.target.split('?').next() == Some(target.as_str())
}

/// A request that reads data of the object `key`.
pub(super) fn is_get_of(bucket: &str, key: &str) -> impl Fn(&Seen) -> bool + Send + Sync + 'static {
    let target = format!("/{bucket}/{}", uri_encode(key, true));
    move |seen| seen.method == "GET" && seen.target.split('?').next() == Some(target.as_str())
}

fn is_part_put(seen: &Seen) -> bool {
    seen.method == "PUT" && seen.has_param("partNumber")
}

/// The upload id of the last part `proxy` was sent.
fn last_part_upload_id(proxy: &Proxy) -> String {
    let part = proxy
        .seen()
        .into_iter()
        .rfind(is_part_put)
        .expect("a part was sent");
    param(&part, "uploadId")
}

fn is_create_upload(seen: &Seen) -> bool {
    seen.method == "POST" && seen.has_param("uploads")
}

/// A request that starts a multipart upload of `key`.
pub(super) fn is_create_of(
    bucket: &str,
    key: &str,
) -> impl Fn(&Seen) -> bool + Send + Sync + 'static {
    let target = format!("/{bucket}/{}", uri_encode(key, true));
    move |seen| is_create_upload(seen) && seen.target.split('?').next() == Some(target.as_str())
}

pub(super) fn is_complete(seen: &Seen) -> bool {
    seen.method == "POST" && seen.has_param("uploadId")
}

fn is_abort(seen: &Seen) -> bool {
    seen.method == "DELETE" && seen.has_param("uploadId")
}

/// The value of the query parameter `name` of `seen`.
fn param(seen: &Seen, name: &str) -> String {
    seen.query()
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} in {}", seen.query()))
        .to_owned()
}

fn unavailable() -> Fault {
    Fault::Reply(Reply::error(503, "ServiceUnavailable"))
}

/// Rewrites the only record of the cache directory.
fn rewrite_record(cache: &std::path::Path, change: impl FnOnce(&mut EntryRecord)) {
    let mut found = entry_records(cache);
    assert_eq!(found.len(), 1);
    let mut record = found.remove(0);
    change(&mut record);
    let path = cache.join("records").join(record.id.as_str());
    fs::write(path, Record::Entry(Box::new(record)).encode()).unwrap();
}

/// Writes the record of the directory `path`, whose marker object is not in
/// the bucket, into the cache directory `cache`.
fn write_pending_dir(cache: &std::path::Path, id: u8, path: &str) {
    let id = RecordId::from_bytes(&[id; 16]);
    let record = EntryRecord {
        id: id.clone(),
        is_dir: true,
        path: path.to_owned(),
        key: path.to_owned(),
        gone: Vec::new(),
        base: None,
        remote: true,
        local: None,
        times: [filetime(1_500_000_000, 0); 4],
        attributes: 0,
        generation: 1,
        upload_id: None,
        upload_key: None,
        failed: false,
        meta_pending: true,
        marker_pending: true,
    };
    fs::write(
        cache.join("records").join(id.as_str()),
        Record::Entry(Box::new(record)).encode(),
    )
    .unwrap();
}

#[tokio::test]
async fn files_reach_the_bucket_whole_and_in_parts_with_their_times() {
    let mut rig = Rig::writable_with(held).await;
    let small = pattern(3, 100_000);
    let big = pattern(11, 12 * MIB + 123);
    let times = [
        filetime(1_400_000_000, 0),
        filetime(1_410_000_000, 7_000),
        filetime(1_420_000_000, 123_400),
        filetime(1_430_000_000, 100),
    ];
    let dir = rig.smb.create("docs", create_dir()).await.unwrap();
    rig.smb.close(dir.id).await;
    let a = rig
        .smb
        .create("docs\\small.bin", create_file())
        .await
        .unwrap();
    fill(&mut rig.smb, a.id, &small).await;
    assert_eq!(
        rig.smb.set_basic(a.id, times.map(|t| t as i64), 0x22).await,
        0
    );
    let b = rig.smb.create("big.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, b.id, &big).await;
    let empty = rig.smb.create("empty.bin", create_file()).await.unwrap();
    for id in [a.id, b.id, empty.id] {
        rig.smb.close(id).await;
    }
    rig.backend.hold_uploads(false);

    sync(&rig.backend).await.unwrap();

    let (data, head) = stored(&rig, "docs/small.bin").await;
    assert_eq!(sha(&data), sha(&small));
    let user = &head.metadata.user;
    assert_eq!(user["btime"], "1400000000.000000000");
    assert_eq!(user["atime"], "1410000000.000007000");
    assert_eq!(user["mtime"], "1420000000.000123400");
    assert_eq!(user["ctime"], "1430000000.000000100");
    assert_eq!(user["smb-attributes"], "22");
    assert_eq!(
        head.metadata.content_type.as_deref(),
        Some("application/octet-stream")
    );
    let (data, head) = stored(&rig, "big.bin").await;
    assert_eq!(sha(&data), sha(&big));
    assert!(head.metadata.user.contains_key("mtime"));
    assert_eq!(stored(&rig, "empty.bin").await.0, b"");

    let key_puts = |key: &str| rig.proxy.count(is_put_of(&rig.bucket.name, key));
    assert_eq!(
        key_puts("docs/small.bin"),
        1,
        "one request for a small file"
    );
    assert_eq!(key_puts("big.bin"), 0);
    assert_eq!(rig.proxy.count(is_part_put), 3, "5 MiB, 5 MiB and the rest");
    assert_eq!(rig.proxy.count(is_create_upload), 1);
    assert_eq!(rig.proxy.count(is_complete), 1);

    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
    assert!(rig.backend.failures().is_empty());

    // After the sync, the share reads the objects, with the stored times and
    // attributes.
    assert_eq!(rig.smb.contents("big.bin", 60_000).await, big.to_vec());
    let reopened = rig.smb.open("docs\\small.bin").await.unwrap();
    assert_eq!((reopened.times, reopened.attributes), (times, 0x22));
    assert_eq!(reopened.size, small.len() as u64);
}

#[tokio::test]
async fn an_upload_keeps_the_metadata_the_object_had() {
    let mut rig = Rig::writable_with(uploading).await;
    let metadata = Metadata {
        user: [("owner".to_owned(), "someone".to_owned())].into(),
        content_type: Some("text/plain".to_owned()),
        cache_control: Some("max-age=60".to_owned()),
        ..Metadata::default()
    };
    rig.store()
        .put_object(
            "note.txt",
            Bytes::from_static(b"hello world"),
            &metadata,
            foreground(),
        )
        .await
        .unwrap();
    let file = rig.smb.create("note.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"HELLO").await, Ok(5));
    rig.smb.close(file.id).await;

    sync(&rig.backend).await.unwrap();

    let (data, head) = stored(&rig, "note.txt").await;
    assert_eq!(data, b"HELLO world");
    assert_eq!(head.metadata.user["owner"], "someone");
    assert_eq!(head.metadata.content_type.as_deref(), Some("text/plain"));
    assert_eq!(head.metadata.cache_control.as_deref(), Some("max-age=60"));
    assert!(head.metadata.user.contains_key("mtime"));
}

#[tokio::test]
async fn a_file_that_stays_open_and_idle_is_stored() {
    let mut rig = Rig::writable_with(uploading).await;
    let file = rig.smb.create("open.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"still open").await, Ok(10));
    let key = "open.txt";
    wait_until_async("the file is stored while it is open", async || {
        rig.store().head_object(key, foreground()).await.is_ok()
    })
    .await;
    assert_eq!(stored(&rig, key).await.0, b"still open");
    assert_eq!(rig.smb.read(file.id, 0, 100).await.unwrap(), b"still open");
    wait_until_async("the bytes held are dropped", async || {
        left(&rig, "data") == 0 && left(&rig, "records") == 0
    })
    .await;
    assert_eq!(rig.backend.overlay_len(), 1, "the handle keeps the entry");
    assert_eq!(rig.smb.write(file.id, 6, b"OPEN").await, Ok(4));
    assert_eq!(rig.smb.read(file.id, 0, 100).await.unwrap(), b"still OPEN");
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, key).await.0, b"still OPEN");
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn an_object_written_through_an_open_handle_is_stored_while_the_handle_stays_open() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "doc.txt", b"0123456789").await;
    let file = rig.smb.create("doc.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 2, b"__").await, Ok(2));
    wait_until_async("the changed object is stored", async || {
        stored(&rig, "doc.txt").await.0 == b"01__456789"
    })
    .await;
    assert_eq!(rig.smb.read(file.id, 0, 100).await.unwrap(), b"01__456789");
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_write_during_an_upload_makes_another_that_stores_the_final_bytes() {
    let mut rig = Rig::writable_with(held).await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "f.bin"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    let file = rig.smb.create("f.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"first version").await, Ok(13));
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "f.bin")).await;

    assert_eq!(rig.smb.write(file.id, 0, b"second").await, Ok(6));
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(stored(&rig, "f.bin").await.0, b"secondversion");
    let puts: Vec<Seen> = rig
        .proxy
        .seen()
        .into_iter()
        .filter(is_put_of(&rig.bucket.name, "f.bin"))
        .collect();
    assert_eq!(puts.len(), 2);
    assert_eq!(puts[0].body, b"first version");
    assert_eq!(puts[1].body, b"secondversion");
    rig.smb.close(file.id).await;
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_record_stays_when_an_upload_lands_after_a_change_and_the_new_record_fails() {
    let mut rig = Rig::writable_with(uploading).await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "f.bin"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    let file = rig.smb.create("f.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"first version").await, Ok(13));
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "f.bin")).await;
    assert_eq!(rig.smb.write(file.id, 0, b"second").await, Ok(6));

    rig.backend.hooks().record_writes.store(2, SeqCst);
    gate.notify_one();
    wait_until_async("the job fails", async || rig.backend.failures().len() == 1).await;

    let found = records(&rig);
    assert_eq!(
        found.len(),
        1,
        "the record of the bytes the bucket may not have stays"
    );
    assert_eq!(found[0].local.as_ref().unwrap().len, 13);
    assert_eq!(
        rig.smb.read(file.id, 0, 100).await.unwrap(),
        b"secondversion"
    );
    rig.smb.close(file.id).await;
}

#[tokio::test]
async fn a_write_during_a_multipart_upload_aborts_it_and_the_next_one_stores_the_final_bytes() {
    let mut rig = Rig::writable_with(|b| uploading(b).upload_concurrency(1)).await;
    let data = pattern(2, 11 * MIB);
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_part_put, Fault::Hold(Arc::clone(&gate)), 1);
    let file = rig.smb.create("m.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    wait_for_requests(&rig.proxy, 1, is_part_put).await;
    let id = last_part_upload_id(&rig.proxy);
    let noted: Vec<EntryRecord> = records(&rig);
    assert_eq!(
        noted[0].upload_id.as_deref(),
        Some(id.as_str()),
        "the record names the upload before a part goes up"
    );

    rig.backend.hold_uploads(true);
    assert_eq!(rig.smb.write(file.id, 0, b"changed").await, Ok(7));
    gate.notify_one();
    wait_for_requests(&rig.proxy, 1, is_abort).await;
    wait_until_async("the record forgets the upload", async || {
        records(&rig)[0].upload_id.is_none()
    })
    .await;
    assert_eq!(
        rig.proxy.count(is_part_put),
        1,
        "no part starts after a stop"
    );
    assert_eq!(rig.proxy.count(is_complete), 0);
    let refused = rig
        .store()
        .upload_part("m.bin", &id, 2, Bytes::from_static(b"x"), foreground())
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Some("NoSuchUpload"), "{refused:?}");
    assert!(is_missing(rig.store(), "m.bin").await, "nothing landed");

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let mut expected = data.to_vec();
    expected[..7].copy_from_slice(b"changed");
    assert_eq!(sha(&stored(&rig, "m.bin").await.0), sha(&expected));
    rig.smb.close(file.id).await;
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_write_that_lands_while_the_missing_bytes_are_fetched_is_never_overwritten() {
    let mut rig = Rig::writable_with(held).await;
    let base = pattern(5, 3 * MIB);
    put(rig.store(), "big.bin", &base).await;
    let file = rig.smb.create("big.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 100, &[1; 50]).await, Ok(50));
    rig.smb.close(file.id).await;

    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_data_read, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_data_read).await;

    let again = rig.smb.create("big.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(again.id, 150_000, &[2; 20]).await, Ok(20));
    assert_eq!(rig.smb.write(again.id, 40, &[3; 10]).await, Ok(10));
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    let mut expected = base.to_vec();
    expected[100..150].fill(1);
    expected[40..50].fill(3);
    expected[150_000..150_020].fill(2);
    assert_eq!(sha(&stored(&rig, "big.bin").await.0), sha(&expected));
    assert_eq!(
        rig.smb.read(again.id, 0, 200).await.unwrap(),
        expected[..200]
    );
    rig.smb.close(again.id).await;
    assert_eq!(left(&rig, "data"), 0);
}

/// Runs the fill conflict of an object that `outside` changes after the file
/// took bytes of it. Returns the rig and the error `sync` gave.
async fn fill_conflict(outside: impl AsyncFnOnce(&Rig)) -> (Rig, S3Error) {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "base.bin", &pattern(1, MIB)).await;
    let file = rig.smb.create("base.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, &[9; 20]).await, Ok(20));
    rig.smb.close(file.id).await;
    outside(&rig).await;

    let waiting = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.sync().await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    rig.backend.hold_uploads(false);
    let error = tokio::time::timeout(Duration::from_secs(60), waiting)
        .await
        .expect("sync returns")
        .unwrap()
        .unwrap_err();

    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
    let mut kept: Vec<String> = fs::read_dir(rig.cache_dir().join("conflicts"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    kept.sort();
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert!(kept[0].ends_with(".data") && kept[1].ends_with(".record"));
    assert_eq!(rig.backend.overlay_len(), 0);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "base.bin")), 0);
    assert!(sync(&rig.backend).await.is_ok(), "the entry is gone");
    (rig, error)
}

#[tokio::test]
async fn an_object_changed_outside_moves_the_file_to_conflicts() {
    let other = pattern(77, 2 * MIB + 5);
    let (mut rig, error) = fill_conflict(async |rig| {
        put(rig.store(), "base.bin", &other).await;
    })
    .await;
    assert_eq!(error.http_status(), Some(412));
    assert_eq!(stored(&rig, "base.bin").await.0, other.to_vec());
    assert_eq!(rig.smb.contents("base.bin", 60_000).await, other.to_vec());
}

#[tokio::test]
async fn an_object_deleted_outside_moves_the_file_to_conflicts() {
    let (mut rig, error) = fill_conflict(async |rig| {
        rig.store()
            .delete_object("base.bin", foreground())
            .await
            .unwrap();
    })
    .await;
    assert!(matches!(error.http_status(), Some(404 | 412)), "{error:?}");
    assert!(is_missing(rig.store(), "base.bin").await);
    assert_eq!(
        rig.smb.open("base.bin").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_file_whose_object_is_deleted_outside_is_not_found_as_soon_as_its_changes_are_kept() {
    let hour = Duration::from_secs(3600);
    let mut rig = Rig::writable_with(|builder| held(builder).metadata_ttl(hour)).await;
    put(rig.store(), "base.bin", &pattern(1, MIB)).await;
    let file = rig.smb.create("base.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, &[9; 20]).await, Ok(20));
    rig.smb.close(file.id).await;
    assert!(rig.backend.cached_object("base.bin"), "a lookup found it");
    rig.store()
        .delete_object("base.bin", foreground())
        .await
        .unwrap();
    let (reached, resume) = rig.backend.pause_after_conflict();
    // The job waits on a thread of its own, which a failed assertion has to
    // let go of for the runtime to end.
    let _resume = Resume(resume);
    rig.backend.hold_uploads(false);
    reached.notified().await;

    assert_eq!(rig.backend.overlay_len(), 0, "the entry has left");
    assert!(
        !rig.backend.cached_object("base.bin"),
        "the cache forgot the object before the entry left"
    );
    assert_eq!(
        rig.smb.open("base.bin").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

/// Lets the job that waits at a pause go on when it is dropped.
struct Resume(Arc<Notify>);

impl Drop for Resume {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[tokio::test]
async fn requests_the_store_fails_are_tried_again() {
    let mut rig = Rig::writable_with(held).await;
    let big = pattern(4, 11 * MIB);
    let small = pattern(6, 1000);
    rig.proxy.inject(is_create_upload, unavailable(), 1);
    rig.proxy.inject(is_part_put, unavailable(), 2);
    rig.proxy.inject(is_complete, unavailable(), 1);
    rig.proxy
        .inject(is_put_of(&rig.bucket.name, "small.bin"), unavailable(), 2);
    let a = rig.smb.create("big.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, a.id, &big).await;
    let b = rig.smb.create("small.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, b.id, &small).await;
    rig.smb.close(a.id).await;
    rig.smb.close(b.id).await;
    rig.backend.hold_uploads(false);

    sync(&rig.backend).await.unwrap();

    assert_eq!(sha(&stored(&rig, "big.bin").await.0), sha(&big));
    assert_eq!(stored(&rig, "small.bin").await.0, small.to_vec());
    assert_eq!(rig.proxy.count(is_create_upload), 2);
    assert_eq!(rig.proxy.count(is_part_put), 5);
    assert_eq!(rig.proxy.count(is_complete), 2);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "small.bin")), 3);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn uploads_run_the_upload_concurrency_at_a_time_and_parts_too() {
    let mut rig = Rig::writable_with(|b| held(b).upload_concurrency(2)).await;
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_part_put, Fault::Hold(Arc::clone(&gate)), usize::MAX);
    let big = pattern(21, 22 * MIB);
    let file = rig.smb.create("big.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &big).await;
    rig.smb.close(file.id).await;
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 2, is_part_put).await;
    tokio::time::sleep(4 * DELAY).await;
    assert_eq!(
        rig.proxy.count(is_part_put),
        2,
        "two parts in flight at most"
    );
    rig.proxy.clear_rules();
    gate.notify_waiters();
    sync(&rig.backend).await.unwrap();
    assert_eq!(rig.proxy.count(is_part_put), 5);
    assert_eq!(sha(&stored(&rig, "big.bin").await.0), sha(&big));

    let gate = Arc::new(Notify::new());
    let single = |seen: &Seen| seen.method == "PUT" && !seen.has_param("partNumber");
    rig.proxy
        .inject(single, Fault::Hold(Arc::clone(&gate)), usize::MAX);
    rig.backend.hold_uploads(true);
    for name in ["a.txt", "b.txt", "c.txt", "d.txt"] {
        let file = rig.smb.create(name, create_file()).await.unwrap();
        assert_eq!(rig.smb.write(file.id, 0, name.as_bytes()).await, Ok(5));
        rig.smb.close(file.id).await;
    }
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 2, single).await;
    tokio::time::sleep(4 * DELAY).await;
    assert_eq!(rig.proxy.count(single), 2, "two jobs at once at most");
    rig.proxy.clear_rules();
    gate.notify_waiters();
    sync(&rig.backend).await.unwrap();
    assert_eq!(rig.proxy.count(single), 4);
}

#[tokio::test]
async fn the_file_that_rested_longest_is_stored_first() {
    let mut rig = Rig::writable_with(|b| held(b).upload_concurrency(1)).await;
    let names = ["first.txt", "second.txt", "third.txt", "fourth.txt"];
    for name in names {
        let file = rig.smb.create(name, create_file()).await.unwrap();
        assert_eq!(
            rig.smb.write(file.id, 0, name.as_bytes()).await,
            Ok(name.len() as u32)
        );
        rig.smb.close(file.id).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let order: Vec<String> = rig
        .proxy
        .seen()
        .into_iter()
        .filter(|seen| seen.method == "PUT")
        .map(|seen| seen.target.rsplit('/').next().unwrap().to_owned())
        .collect();
    assert_eq!(order, names);
}

#[tokio::test]
async fn a_complete_whose_answer_is_lost_is_confirmed_by_a_lookup_of_the_object() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "old.bin", &pattern(1, 13 * MIB)).await;
    let new = pattern(2, 12 * MIB);
    rig.proxy.inject(is_complete, Fault::DropAnswer, 1);
    rig.proxy.inject(
        is_complete,
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        1,
    );
    let file = rig
        .smb
        .create("old.bin", open_rw().disposition(FILE_OVERWRITE_IF))
        .await
        .unwrap();
    fill(&mut rig.smb, file.id, &new).await;
    rig.smb.close(file.id).await;
    let head = is_head_of(&rig.bucket.name, "old.bin");
    let heads_before = rig.proxy.count(&head);

    sync(&rig.backend).await.unwrap();

    assert_eq!(rig.proxy.count(is_complete), 2);
    assert_eq!(rig.proxy.count(&head), heads_before + 1);
    assert_eq!(sha(&stored(&rig, "old.bin").await.0), sha(&new));
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn files_flushed_before_a_restart_are_stored_by_the_next_backend() {
    let mut rig = Rig::writable_with(held).await;
    let big = pattern(8, 6 * MIB + 17);
    let a = rig.smb.create("a.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(a.id, 0, b"flushed").await, Ok(7));
    assert_eq!(rig.smb.flush(a.id).await, 0);
    let b = rig.smb.create("b.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, b.id, &big).await;
    assert_eq!(rig.smb.flush(b.id).await, 0);
    let dir = rig.smb.create("made", create_dir()).await.unwrap();
    rig.smb.close(dir.id).await;
    assert_eq!(rig.proxy.count(is_part_put), 0);

    let mut rig = rig.restart_with(uploading).await;
    assert_eq!(rig.backend.overlay_len(), 2);
    sync(&rig.backend).await.unwrap();

    assert_eq!(stored(&rig, "a.txt").await.0, b"flushed");
    assert_eq!(sha(&stored(&rig, "b.bin").await.0), sha(&big));
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.smb.contents("a.txt", 100).await, b"flushed");
}

fn is_root_listing(seen: &Seen) -> bool {
    seen.method == "GET" && seen.has_param("delimiter") && !seen.has_param("prefix")
}

/// The names the backend lists in the share root, sorted.
async fn root_names(backend: &S3Backend) -> Vec<String> {
    let (root, _) = backend
        .open(&SmbPath::root(), OpenOptions::default())
        .await
        .unwrap();
    let mut listed: Vec<String> = root
        .list_dir(None)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.info.name)
        .collect();
    root.close().await.unwrap();
    listed.sort();
    listed
}

/// Starts a listing of the share root from the store. The store answers with
/// the objects `before`, as they were when the listing began, and the answer
/// is held until the gate returned is notified.
async fn listing_in_flight(
    rig: &Rig,
    before: &[(&str, u64)],
) -> (Arc<Notify>, tokio::task::JoinHandle<Vec<String>>) {
    listing_in_flight_with(rig, before, &[]).await
}

/// [`listing_in_flight`] for a store that also has the directories `prefixes`.
async fn listing_in_flight_with(
    rig: &Rig,
    before: &[(&str, u64)],
    prefixes: &[&str],
) -> (Arc<Notify>, tokio::task::JoinHandle<Vec<String>>) {
    let backend = rig.backend.clone();
    read_in_flight(
        rig,
        before,
        prefixes,
        async move { root_names(&backend).await },
    )
    .await
}

/// Runs `read`, which asks for the listing of the share root, with the cache
/// empty. The store answers with the objects `before` and the directories
/// `prefixes`, once the gate returned is notified.
async fn read_in_flight<T: Send + 'static>(
    rig: &Rig,
    before: &[(&str, u64)],
    prefixes: &[&str],
    read: impl std::future::Future<Output = T> + Send + 'static,
) -> (Arc<Notify>, tokio::task::JoinHandle<T>) {
    rig.backend.limit_listing_rows(100_000);
    let asked = rig.proxy.count(is_root_listing);
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_root_listing,
        Fault::HoldReply(Arc::clone(&gate), listing_reply(before, prefixes)),
        1,
    );
    let read = tokio::spawn(read);
    wait_for_requests(&rig.proxy, asked + 1, is_root_listing).await;
    (gate, read)
}

/// Whether the backend finds nothing at `name` in the share root. With names
/// matched without regard to case, a miss reads the listing of the root.
async fn is_not_found(backend: &S3Backend, name: &str) -> bool {
    backend
        .open(&path(name), OpenOptions::default())
        .await
        .is_err()
}

/// Lists the share root from the store while the backend stores what it holds.
/// The answer of the store arrives after the last request of the backend ended.
async fn list_while_stored(rig: &Rig, before: &[(&str, u64)]) -> Vec<String> {
    let (gate, listing) = listing_in_flight(rig, before).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    gate.notify_one();
    listing.await.unwrap()
}

/// Lists the share root while `act` runs. It runs once the listing has the
/// rows of the store, and ends before the listing reads what the backend holds.
async fn list_between(rig: &Rig, act: impl std::future::Future<Output = ()>) -> Vec<String> {
    let (reached, resume) = rig.backend.pause_after_rows();
    let listing = tokio::spawn({
        let backend = rig.backend.clone();
        async move { root_names(&backend).await }
    });
    reached.notified().await;
    act.await;
    resume.notify_one();
    listing.await.unwrap()
}

fn strings(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[tokio::test]
async fn a_file_stored_while_its_directory_is_listed_is_in_the_listing() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "a.txt", b"a").await;
    make(&mut rig, "b.txt", b"b").await;

    let during = list_while_stored(&rig, &[]).await;
    let after = root_names(&rig.backend).await;
    let want = strings(&["a.txt", "b.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_a_restart_brings_back_is_in_a_listing_that_overlaps_its_upload() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "a.txt", b"a").await;
    make(&mut rig, "b.txt", b"b").await;
    let rig = rig.restart_with(held).await;

    let during = list_while_stored(&rig, &[]).await;
    let after = root_names(&rig.backend).await;
    let want = strings(&["a.txt", "b.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_stored_after_a_listing_has_its_rows_is_in_the_listing() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "a.txt", b"a").await;
    make(&mut rig, "b.txt", b"b").await;

    let during = list_between(&rig, async {
        rig.backend.hold_uploads(false);
        sync(&rig.backend).await.unwrap();
    })
    .await;
    let after = root_names(&rig.backend).await;
    let want = strings(&["a.txt", "b.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_deleted_while_its_directory_is_listed_is_not_listed_again() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "gone.txt", b"x").await;
    put(rig.store(), "kept.txt", b"y").await;
    rig.backend.unlink(&path("gone.txt")).await.unwrap();

    let during = list_while_stored(&rig, &[("gone.txt", 1), ("kept.txt", 1)]).await;
    let after = root_names(&rig.backend).await;
    let want = strings(&["kept.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_renamed_while_its_directory_is_listed_is_listed_once() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "x.txt", b"x").await;
    let (gate, listing) = listing_in_flight(&rig, &[("x.txt", 1)]).await;
    rig.backend
        .rename(&path("x.txt"), &path("y.txt"), false)
        .await
        .unwrap();
    gate.notify_one();
    assert_eq!(listing.await.unwrap(), strings(&["y.txt"]));
}

#[tokio::test]
async fn a_stored_file_renamed_and_moved_while_its_directory_is_listed_is_listed_once() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "x.txt", b"x").await;
    let (gate, listing) = listing_in_flight(&rig, &[("x.txt", 1)]).await;
    rig.backend
        .rename(&path("x.txt"), &path("y.txt"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    let want = strings(&["y.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_changed_file_renamed_and_stored_while_its_directory_is_listed_is_listed_once() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"old").await;
    let file = rig.smb.create("a.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"NEW").await, Ok(3));
    rig.smb.close(file.id).await;
    let (gate, listing) = listing_in_flight(&rig, &[("a.txt", 3)]).await;
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    let want = strings(&["b.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_made_and_deleted_while_its_directory_is_listed_is_not_listed() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "e.txt", b"e").await;
    let (gate, listing) = listing_in_flight(&rig, &[]).await;
    rig.backend.unlink(&path("e.txt")).await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    assert_eq!([during, after], [Vec::<String>::new(), Vec::new()]);
}

#[tokio::test]
async fn a_changed_file_deleted_and_stored_while_its_directory_is_listed_is_not_listed() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "e.txt", b"old").await;
    let file = rig.smb.create("e.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"NEW").await, Ok(3));
    rig.smb.close(file.id).await;
    let (gate, listing) = listing_in_flight(&rig, &[("e.txt", 3)]).await;
    rig.backend.unlink(&path("e.txt")).await.unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    assert_eq!([during, after], [Vec::<String>::new(), Vec::new()]);
}

#[tokio::test]
async fn a_file_stored_and_deleted_while_its_directory_is_listed_is_not_listed() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "e.txt", b"e").await;
    let (gate, listing) = listing_in_flight(&rig, &[]).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    rig.backend.unlink(&path("e.txt")).await.unwrap();
    sync(&rig.backend).await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    assert_eq!([during, after], [Vec::<String>::new(), Vec::new()]);
}

#[tokio::test]
async fn a_file_stored_and_renamed_while_its_directory_is_listed_is_listed_once() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "e.txt", b"e").await;
    let (gate, listing) = listing_in_flight(&rig, &[]).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    rig.backend
        .rename(&path("e.txt"), &path("f.txt"), false)
        .await
        .unwrap();
    sync(&rig.backend).await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    let want = strings(&["f.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_changed_file_renamed_and_stored_after_its_directory_was_read_is_listed_once() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"old").await;
    let file = rig.smb.create("a.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"NEW").await, Ok(3));
    rig.smb.close(file.id).await;
    let during = list_between(&rig, async {
        rig.backend
            .rename(&path("a.txt"), &path("b.txt"), false)
            .await
            .unwrap();
        rig.backend.hold_uploads(false);
        sync(&rig.backend).await.unwrap();
    })
    .await;
    let after = root_names(&rig.backend).await;
    let want = strings(&["b.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_stored_and_opened_by_another_handle_after_its_directory_was_read_is_listed() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "a.txt", b"a").await;
    let (reached, resume) = rig.backend.pause_after_rows();
    let listing = tokio::spawn({
        let backend = rig.backend.clone();
        async move { root_names(&backend).await }
    });
    reached.notified().await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let open = rig.smb.open("a.txt").await.unwrap();
    resume.notify_one();
    let during = listing.await.unwrap();
    rig.smb.close(open.id).await;
    let after = root_names(&rig.backend).await;
    let want = strings(&["a.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_stored_and_opened_by_another_handle_while_the_store_is_read_is_listed() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "a.txt", b"a").await;
    let (gate, listing) = listing_in_flight(&rig, &[]).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let open = rig.smb.open("a.txt").await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    rig.smb.close(open.id).await;
    let after = root_names(&rig.backend).await;
    let want = strings(&["a.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_listing_read_during_a_burst_of_stores_and_a_delete_shows_every_file_and_is_kept() {
    const FILES: usize = 1100;
    // The listing waits for the stores of a thousand files, and the reads of
    // their metadata follow it. Either may take longer than the default request
    // timeout or the time the cache trusts a listing.
    let hour = Duration::from_secs(3600);
    let mut rig =
        Rig::writable_with(|builder| held(builder).request_timeout(hour).metadata_ttl(hour)).await;
    put(rig.store(), "x.txt", b"x").await;
    rig.backend.unlink(&path("x.txt")).await.unwrap();
    for n in 0..FILES {
        make(&mut rig, &format!("f{n:04}.txt"), b"f").await;
    }
    let (gate, listing) = listing_in_flight(&rig, &[("x.txt", 1)]).await;
    rig.backend.hold_uploads(false);
    sync_while_progressing(&rig).await.unwrap();
    let open = rig.smb.open("f0000.txt").await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    rig.smb.close(open.id).await;
    let reads = rig.proxy.count(is_root_listing);
    let after = root_names(&rig.backend).await;
    assert_eq!(
        rig.proxy.count(is_root_listing),
        reads,
        "the listing was read from the store again"
    );
    let want: Vec<String> = (0..FILES).map(|n| format!("f{n:04}.txt")).collect();
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_directory_renamed_while_its_parent_is_listed_is_listed_once() {
    for stored in [false, true] {
        let rig = Rig::writable_with(held).await;
        put(rig.store(), "d/f.txt", b"f").await;
        let (gate, listing) = listing_in_flight_with(&rig, &[], &["d/"]).await;
        rig.backend
            .rename(&path("d"), &path("e"), false)
            .await
            .unwrap();
        if stored {
            rig.backend.hold_uploads(false);
            sync(&rig.backend).await.unwrap();
        }
        gate.notify_one();
        let during = listing.await.unwrap();
        let after = root_names(&rig.backend).await;
        let want = strings(&["e"]);
        assert_eq!([during, after], [want.clone(), want], "stored {stored}");
    }
}

#[tokio::test]
async fn a_file_deleted_and_made_again_in_another_case_while_its_directory_is_listed_is_listed_once()
 {
    for stored in [false, true] {
        let mut rig = Rig::writable_with(held).await;
        put(rig.store(), "File.txt", b"a").await;
        let (gate, listing) = listing_in_flight(&rig, &[("File.txt", 1)]).await;
        rig.backend.unlink(&path("File.txt")).await.unwrap();
        make(&mut rig, "file.txt", b"new").await;
        if stored {
            rig.backend.hold_uploads(false);
            sync(&rig.backend).await.unwrap();
        }
        gate.notify_one();
        let during = listing.await.unwrap();
        let after = root_names(&rig.backend).await;
        assert!(
            during.len() == 1 && after.len() == 1,
            "stored {stored}: {during:?} then {after:?}"
        );
    }
}

#[tokio::test]
async fn a_directory_with_no_marker_is_listed_once_a_file_lands_below_it_while_its_parent_is_read()
{
    let mut rig = Rig::writable_with(held).await;
    let (gate, listing) = listing_in_flight(&rig, &[]).await;
    put(rig.store(), "x/y/seed.txt", b"s").await;
    make(&mut rig, "x\\y\\new.txt", b"n").await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    gate.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    let want = strings(&["x"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_stored_after_a_cached_listing_was_read_is_listed() {
    let mut rig = Rig::writable_with(held).await;
    rig.backend.limit_listing_rows(100_000);
    make(&mut rig, "a.txt", b"a").await;
    assert_eq!(root_names(&rig.backend).await, strings(&["a.txt"]));
    let reads = rig.proxy.count(is_root_listing);
    make(&mut rig, "b.txt", b"b").await;
    let during = list_between(&rig, async {
        rig.backend.hold_uploads(false);
        sync(&rig.backend).await.unwrap();
    })
    .await;
    assert_eq!(
        rig.proxy.count(is_root_listing),
        reads,
        "the store was read"
    );
    let after = root_names(&rig.backend).await;
    let want = strings(&["a.txt", "b.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_file_renamed_while_the_overlay_is_read_for_its_directory_is_listed_once() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "x.txt", b"x").await;
    let reads = rig.proxy.count(is_root_listing);
    let (reached, resume) = rig.backend.pause_after_below();
    let listing = tokio::spawn({
        let backend = rig.backend.clone();
        async move { root_names(&backend).await }
    });
    reached.notified().await;
    rig.backend
        .rename(&path("x.txt"), &path("y.txt"), false)
        .await
        .unwrap();
    resume.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    let want = strings(&["y.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
    assert_eq!(
        rig.proxy.count(is_root_listing) - reads,
        1,
        "the listing was made again from the store"
    );
}

#[tokio::test]
async fn a_file_made_after_the_overlay_is_watched_and_before_it_is_read_is_listed() {
    let mut rig = Rig::writable_with(held).await;
    let (reached, resume) = rig.backend.pause_after_watch();
    let listing = tokio::spawn({
        let backend = rig.backend.clone();
        async move { root_names(&backend).await }
    });
    reached.notified().await;
    make(&mut rig, "n.txt", b"n").await;
    resume.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    let want = strings(&["n.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_listing_of_a_directory_that_changes_during_every_read_is_read_a_few_times_and_not_kept()
{
    let rig = Rig::writable_with(held).await;
    for name in ["a.txt", "b.txt", "c.txt"] {
        put(rig.store(), name, b"x").await;
    }
    rig.backend.limit_listing_rows(100_000);
    let want = strings(&["a.txt", "b.txt", "c.txt"]);
    let start = rig.proxy.count(is_root_listing);
    let attempts = S3Backend::listing_attempts();

    rig.backend.change_listings(usize::MAX);
    assert_eq!(root_names(&rig.backend).await, want);
    assert_eq!(rig.proxy.count(is_root_listing) - start, attempts);

    rig.backend.change_listings(0);
    assert_eq!(root_names(&rig.backend).await, want);
    assert_eq!(rig.proxy.count(is_root_listing) - start, attempts + 1);
    assert_eq!(root_names(&rig.backend).await, want);
    assert_eq!(rig.proxy.count(is_root_listing) - start, attempts + 1);
}

#[tokio::test]
async fn a_listing_that_took_over_half_the_request_timeout_is_not_read_again() {
    let mut rig =
        Rig::writable_with(|builder| held(builder).request_timeout(Duration::from_secs(8))).await;
    make(&mut rig, "a.txt", b"a").await;
    // The rows are dropped from the cache once the read has them, so a read
    // made again would go to the store.
    rig.backend.change_listings(1);
    let (gate, listing) = listing_in_flight(&rig, &[]).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    tokio::time::sleep(Duration::from_millis(4200)).await;
    let reads = rig.proxy.count(is_root_listing);
    gate.notify_one();
    assert_eq!(listing.await.unwrap(), strings(&["a.txt"]));
    assert_eq!(rig.proxy.count(is_root_listing), reads);
}

#[tokio::test]
async fn a_listing_made_again_that_stalls_gives_the_one_made_before_well_before_the_timeout() {
    let timeout = Duration::from_secs(8);
    let rig = Rig::writable_with(|builder| held(builder).request_timeout(timeout)).await;
    let want = strings(&["a.txt", "b.txt", "c.txt"]);
    for name in &want {
        put(rig.store(), name, b"x").await;
    }
    rig.backend.limit_listing_rows(100_000);
    let start = rig.proxy.count(is_root_listing);
    rig.backend.change_listings(1);
    let (reached, resume) = rig.backend.pause_after_rows();
    let began = std::time::Instant::now();
    let listing = tokio::spawn({
        let backend = rig.backend.clone();
        async move { root_names(&backend).await }
    });
    reached.notified().await;
    rig.proxy.inject(is_root_listing, Fault::Stall, usize::MAX);
    resume.notify_one();
    assert_eq!(listing.await.unwrap(), want);
    let took = began.elapsed();
    assert!(took < timeout / 2, "the listing took {took:?}");
    assert_eq!(rig.proxy.count(is_root_listing) - start, 2);
    assert_eq!(rig.backend.listing_reads(), 0);
}

#[tokio::test]
async fn a_listing_dropped_while_the_store_is_read_leaves_no_read_behind() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"a").await;
    let (gate, listing) = listing_in_flight(&rig, &[("a.txt", 1)]).await;
    assert_eq!(rig.backend.listing_reads(), 1);
    listing.abort();
    assert!(listing.await.unwrap_err().is_cancelled());
    assert_eq!(rig.backend.listing_reads(), 0);
    gate.notify_one();
    assert_eq!(root_names(&rig.backend).await, strings(&["a.txt"]));
    assert_eq!(rig.backend.listing_reads(), 0);
}

#[tokio::test]
async fn a_listing_made_again_that_fails_gives_the_one_made_before() {
    let rig = Rig::writable_with(held).await;
    let want = strings(&["a.txt", "b.txt", "c.txt"]);
    for name in &want {
        put(rig.store(), name, b"x").await;
    }
    rig.backend.limit_listing_rows(100_000);
    let start = rig.proxy.count(is_root_listing);
    rig.backend.change_listings(1);
    let (reached, resume) = rig.backend.pause_after_rows();
    let listing = tokio::spawn({
        let backend = rig.backend.clone();
        async move { root_names(&backend).await }
    });
    reached.notified().await;
    rig.proxy.inject(
        is_root_listing,
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    resume.notify_one();
    assert_eq!(listing.await.unwrap(), want);
    assert_eq!(rig.proxy.count(is_root_listing) - start, 2);
    assert_eq!(rig.backend.listing_reads(), 0);
}

#[tokio::test]
async fn a_lookup_that_reads_a_directory_while_files_land_in_it_leaves_it_cached() {
    const ROUNDS: usize = 4;
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "seed.txt", b"s").await;
    let mut stored = vec!["seed.txt".to_owned()];
    for round in 0..ROUNDS {
        let name = format!("f{round}.txt");
        rig.backend.hold_uploads(true);
        make(&mut rig, &name, b"f").await;
        let start = rig.proxy.count(is_root_listing);
        let before: Vec<(&str, u64)> = stored.iter().map(|name| (name.as_str(), 1)).collect();
        let (gate, lookup) = read_in_flight(&rig, &before, &[], {
            let backend = rig.backend.clone();
            async move { is_not_found(&backend, "absent.txt").await }
        })
        .await;
        rig.backend.hold_uploads(false);
        sync(&rig.backend).await.unwrap();
        gate.notify_one();
        assert!(lookup.await.unwrap());

        let read = rig.proxy.count(is_root_listing);
        assert!(is_not_found(&rig.backend, "other.txt").await);
        stored.push(name);
        assert_eq!(root_names(&rig.backend).await, {
            let mut want = stored.clone();
            want.sort();
            want
        });
        assert_eq!(
            rig.proxy.count(is_root_listing),
            read,
            "round {round}: the listing was read from the store again"
        );
        assert_eq!(read - start, 1, "round {round}");
        assert_eq!(rig.backend.listing_reads(), 0);
    }
}

#[tokio::test]
async fn a_file_stored_after_the_rows_took_in_one_stored_during_the_read_is_listed() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "a.txt", b"a").await;
    let (reached, resume) = rig.backend.pause_after_rows();
    let (gate, listing) = listing_in_flight(&rig, &[]).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    rig.backend.hold_uploads(true);
    make(&mut rig, "b.txt", b"b").await;
    gate.notify_one();
    reached.notified().await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    resume.notify_one();
    let during = listing.await.unwrap();
    let after = root_names(&rig.backend).await;
    let want = strings(&["a.txt", "b.txt"]);
    assert_eq!([during, after], [want.clone(), want]);
}

#[tokio::test]
async fn a_listing_read_while_files_land_is_made_again_from_the_cache() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "seed.txt", b"s").await;
    make(&mut rig, "a.txt", b"a").await;
    make(&mut rig, "b.txt", b"b").await;
    let (gate, listing) = listing_in_flight(&rig, &[("seed.txt", 1)]).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let reads = rig.proxy.count(is_root_listing);
    gate.notify_one();
    let want = strings(&["a.txt", "b.txt", "seed.txt"]);
    assert_eq!(listing.await.unwrap(), want);
    assert_eq!(rig.proxy.count(is_root_listing), reads);
    assert_eq!(root_names(&rig.backend).await, want);
    assert_eq!(rig.proxy.count(is_root_listing), reads);
}

const CYCLES: usize = 200;

/// Makes files, builds a backend over their records that stores them at once,
/// and lists the share root right away, over and over.
async fn list_files_left_by_an_earlier_backend() {
    let mut rig = Rig::writable_with(held).await;
    let mut missing = Vec::new();
    for cycle in 0..CYCLES {
        let wanted: Vec<String> = (0..3).map(|n| format!("c{cycle:03}-{n}.txt")).collect();
        for name in &wanted {
            make(&mut rig, name, name.as_bytes()).await;
        }
        rig = rig.restart_with(uploading).await;
        let root = rig.smb.open_dir("").await.unwrap();
        let listed = rig.smb.list(root.id, "*").await;
        rig.smb.close(root.id).await;
        let seen = names(&listed);
        if wanted.iter().any(|name| !seen.contains(&name.as_str())) {
            missing.push(cycle);
        }
        sync(&rig.backend).await.unwrap();
        for name in &wanted {
            rig.store().delete_object(name, foreground()).await.unwrap();
        }
        rig = rig.restart_with(held).await;
    }
    assert!(
        missing.is_empty(),
        "files were missing in cycles {missing:?}"
    );
}

#[test]
fn files_an_earlier_backend_left_are_listed_at_once_while_they_are_stored() {
    run_bounded(
        "the cycles did not end",
        Duration::from_secs(600),
        list_files_left_by_an_earlier_backend,
    );
}

#[tokio::test]
async fn a_pending_marker_is_put_when_the_backend_is_built() {
    let rig = Rig::writable_with(held).await;
    let (bucket, proxy, cache) = rig.stop().await;
    write_pending_dir(cache.path(), 7, "newdir");

    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();

    let (data, head) = stored(&rig, "newdir/").await;
    assert!(data.is_empty());
    assert_eq!(head.metadata.user["mtime"], "1500000000.000000000");
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
    let root = rig.smb.open_dir("").await.unwrap();
    assert_eq!(rig.smb.list(root.id, "*").await.len(), 1);
}

#[tokio::test]
async fn a_multipart_upload_left_by_an_earlier_backend_is_aborted() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(9, 6 * MIB);
    let file = rig.smb.create("left.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let id = rig
        .store()
        .create_multipart_upload("left.bin", &Metadata::default(), foreground())
        .await
        .unwrap();
    rig.store()
        .upload_part(
            "left.bin",
            &id,
            1,
            Bytes::from(vec![1; PART as usize]),
            foreground(),
        )
        .await
        .unwrap();
    let (bucket, proxy, cache) = rig.stop().await;
    rewrite_record(cache.path(), |record| {
        record.upload_id = Some(id.clone());
        record.upload_key = Some("left.bin".to_owned());
    });

    let rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();

    let aborts: Vec<Seen> = rig.proxy.seen().into_iter().filter(is_abort).collect();
    assert_eq!(aborts.len(), 1);
    assert_eq!(param(&aborts[0], "uploadId"), id);
    let refused = rig
        .store()
        .upload_part("left.bin", &id, 2, Bytes::from_static(b"x"), foreground())
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Some("NoSuchUpload"));
    assert_eq!(sha(&stored(&rig, "left.bin").await.0), sha(&data));
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_stale_upload_is_aborted_against_the_key_it_was_made_for() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(4, 6 * MIB);
    let file = rig.smb.create("renamed.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let id = rig
        .store()
        .create_multipart_upload("first.bin", &Metadata::default(), foreground())
        .await
        .unwrap();
    let (bucket, proxy, cache) = rig.stop().await;
    rewrite_record(cache.path(), |record| {
        record.upload_id = Some(id.clone());
        record.upload_key = Some("first.bin".to_owned());
    });

    let rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();

    let aborts: Vec<Seen> = rig.proxy.seen().into_iter().filter(is_abort).collect();
    assert_eq!(aborts.len(), 1);
    assert_eq!(
        aborts[0].target.split('?').next(),
        Some(format!("/{}/first.bin", rig.bucket.name).as_str())
    );
    assert_eq!(param(&aborts[0], "uploadId"), id);
    assert_eq!(sha(&stored(&rig, "renamed.bin").await.0), sha(&data));
}

#[tokio::test]
async fn keys_an_entry_owns_to_delete_go_once_its_content_is_stored() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "old/name.txt", b"old").await;
    let file = rig.smb.create("new.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"new").await, Ok(3));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    let (bucket, proxy, cache) = rig.stop().await;
    rewrite_record(cache.path(), |record| {
        record.gone = vec!["old/name.txt".to_owned()];
    });

    let rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();

    assert_eq!(stored(&rig, "new.txt").await.0, b"new");
    assert!(is_missing(rig.store(), "old/name.txt").await);
    let seen = rig.proxy.seen();
    let put_at = seen
        .iter()
        .position(is_put_of(&rig.bucket.name, "new.txt"))
        .unwrap();
    let delete_at = seen
        .iter()
        .position(|s| s.method == "POST" && s.has_param("delete"))
        .unwrap();
    assert!(put_at < delete_at, "the content goes up first");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn sync_reports_a_failure_the_store_will_not_fix_and_a_rebuild_tries_again() {
    let mut rig = Rig::writable_with(uploading).await;
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "denied.txt"),
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    let file = rig.smb.create("denied.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"kept here").await, Ok(9));
    rig.smb.close(file.id).await;
    let ok = rig.smb.create("fine.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(ok.id, 0, b"stored").await, Ok(6));
    rig.smb.close(ok.id).await;

    let error = sync(&rig.backend).await.unwrap_err();
    assert_eq!(error.http_status(), Some(403));
    let failures = rig.backend.failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, "denied.txt");
    assert_eq!(failures[0].1.http_status(), Some(403));
    assert_eq!(rig.smb.contents("denied.txt", 100).await, b"kept here");
    wait_until_async("the record says the upload failed", async || {
        records(&rig)
            .iter()
            .any(|r| r.key == "denied.txt" && r.failed)
    })
    .await;
    assert!(sync(&rig.backend).await.is_err(), "it stays failed");
    wait_until("the other file is stored", || {
        rig.backend.overlay_len() == 1
    })
    .await;
    tokio::time::sleep(4 * DELAY).await;
    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "denied.txt")),
        1,
        "no other attempt while this backend runs"
    );
    assert_eq!(stored(&rig, "fine.txt").await.0, b"stored");

    rig.proxy.clear_rules();
    let mut rig = rig.restart_with(uploading).await;
    assert!(rig.backend.failures().is_empty());
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "denied.txt").await.0, b"kept here");
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.smb.contents("denied.txt", 100).await, b"kept here");
}

#[tokio::test]
async fn a_file_that_changes_between_the_hash_and_the_send_is_hashed_again() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("moving.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, &[b'a'; 50_000]).await, Ok(50_000));
    rig.smb.close(file.id).await;
    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    reached.notified().await;

    let data_file = fs::read_dir(rig.cache_dir().join("data"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::OpenOptions::new()
        .write(true)
        .open(data_file)
        .unwrap()
        .write_all(b"TAMPERED")
        .unwrap();
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    let mut expected = vec![b'a'; 50_000];
    expected[..8].copy_from_slice(b"TAMPERED");
    assert_eq!(stored(&rig, "moving.bin").await.0, expected);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_change_between_the_hash_and_the_send_stops_the_job_before_it_sends() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("timed.bin", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"same bytes").await, Ok(10));
    rig.smb.close(file.id).await;
    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    reached.notified().await;

    let again = rig.smb.create("timed.bin", open_rw()).await.unwrap();
    let times = [filetime(1_300_000_000, 0); 4].map(|t| t as i64);
    assert_eq!(rig.smb.set_basic(again.id, times, 0).await, 0);
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "timed.bin")), 1);
    let (data, head) = stored(&rig, "timed.bin").await;
    assert_eq!(data, b"same bytes");
    assert_eq!(head.metadata.user["btime"], "1300000000.000000000");
    rig.smb.close(again.id).await;
}

#[tokio::test]
async fn a_marker_the_store_has_as_a_directory_already_is_skipped() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "taken/inside.txt", b"x").await;
    let (bucket, proxy, cache) = rig.stop().await;
    write_pending_dir(cache.path(), 8, "taken");
    let target = format!("/{}/taken/", bucket.name);
    proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == target,
        Fault::Reply(Reply::error(409, "ExistingObjectIsDirectory")),
        usize::MAX,
    );

    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();

    assert!(rig.backend.failures().is_empty());
    assert_eq!(rig.proxy.count(|seen| seen.method == "PUT"), 1);
    assert_eq!(left(&rig, "records"), 0, "the skipped marker counts as put");
    assert_eq!(rig.backend.overlay_len(), 0);
    assert_eq!(rig.smb.contents("taken\\inside.txt", 10).await, b"x");
}

#[tokio::test]
async fn dropping_the_backend_ends_the_worker_before_it_starts_anything() {
    let mut rig = Rig::writable_with(|b| held(b).upload_delay(Duration::from_secs(2))).await;
    rig.backend.hold_uploads(false);
    let file = rig.smb.create("late.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"queued").await, Ok(6));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let (_bucket, proxy, cache) = rig.stop().await;
    assert_eq!(
        proxy.count(|seen| !matches!(seen.method.as_str(), "GET" | "HEAD")),
        0
    );
    assert_eq!(entry_records(cache.path()).len(), 1, "the record waits");
}

#[tokio::test]
async fn dropping_the_backend_stops_a_running_upload_and_leaves_its_id_for_the_next_build() {
    let rig = Rig::writable_with(|b| uploading(b).upload_concurrency(1)).await;
    let Rig {
        bucket,
        proxy,
        backend,
        mut smb,
        cache,
    } = rig;
    let cache = cache.unwrap();
    let data = pattern(13, 11 * MIB);
    let gate = Arc::new(Notify::new());
    proxy.inject(is_part_put, Fault::Hold(Arc::clone(&gate)), 1);
    let file = smb.create("long.bin", create_file()).await.unwrap();
    fill(&mut smb, file.id, &data).await;
    assert_eq!(smb.flush(file.id).await, 0);
    wait_for_requests(&proxy, 1, is_part_put).await;
    let id = last_part_upload_id(&proxy);

    smb.close_all().await;
    drop(smb);
    let mut exited = backend.worker_exited();
    drop(backend);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!*exited.borrow(), "the request in flight is waited for");
    gate.notify_one();
    tokio::time::timeout(Duration::from_secs(10), exited.wait_for(|exited| *exited))
        .await
        .expect("the worker ends")
        .unwrap();

    assert_eq!(proxy.count(is_part_put), 1, "no part starts after the drop");
    assert_eq!(proxy.count(is_abort), 0);
    assert_eq!(proxy.count(is_complete), 0);
    let found = entry_records(cache.path());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].upload_id.as_deref(), Some(id.as_str()));

    let rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(rig.proxy.count(is_abort), 1);
    assert_eq!(sha(&stored(&rig, "long.bin").await.0), sha(&data));
}

#[tokio::test]
async fn sync_succeeds_on_a_read_only_backend() {
    let rig = Rig::new().await;
    sync(&rig.backend).await.unwrap();
}

#[tokio::test]
async fn a_file_that_is_opened_and_closed_often_is_stored_all_the_same() {
    let mut rig = Rig::writable_with(uploading).await;
    let file = rig.smb.create("busy.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"busy").await, Ok(4));
    rig.smb.close(file.id).await;

    let put = is_put_of(&rig.bucket.name, "busy.txt");
    let mut put_seen = false;
    for _ in 0..100 {
        let open = rig.smb.create("busy.txt", open_rw()).await.unwrap();
        rig.smb.close(open.id).await;
        tokio::time::sleep(DELAY / 4).await;
        if rig.proxy.count(&put) > 0 {
            put_seen = true;
            break;
        }
    }
    assert!(put_seen, "opens and closes held the upload off");
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "busy.txt").await.0, b"busy");
}

#[tokio::test]
async fn a_crash_after_the_object_lands_leaves_a_record_the_next_backend_can_use() {
    let mut rig = Rig::writable_with(held).await;
    let base = pattern(1, MIB);
    put(rig.store(), "base.bin", &base).await;
    let file = rig.smb.create("base.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, &[9; 20]).await, Ok(20));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;

    let (reached, resume) = rig.backend.pause_after_store();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    let (bucket, proxy, cache) = crash(rig, resume).await;

    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();

    let mut expected = base.to_vec();
    expected[10..30].fill(9);
    assert_eq!(sha(&stored(&rig, "base.bin").await.0), sha(&expected));
    assert_eq!(left(&rig, "conflicts"), 0);
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "base.bin")), 2);
    assert_eq!(rig.smb.contents("base.bin", 60_000).await, expected);
}

#[tokio::test]
async fn the_record_of_a_file_says_its_key_may_exist_before_the_key_is_written() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("new.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"new").await, Ok(3));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    assert!(!records(&rig)[0].remote);

    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "new.txt"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "new.txt")).await;
    assert!(records(&rig)[0].remote, "the request is on its way");
    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_full_cache_disk_makes_a_job_rest_and_try_again() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("full.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"bytes").await, Ok(5));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;

    rig.backend.hooks().disk_full.store(true, SeqCst);
    rig.backend.hooks().record_writes.store(1, SeqCst);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(
        rig.backend.hooks().record_writes.load(SeqCst),
        0,
        "the job met the full disk"
    );
    assert_eq!(stored(&rig, "full.txt").await.0, b"bytes");
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "full.txt")), 1);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_job_that_met_a_full_disk_rests_a_second_even_with_no_upload_delay() {
    let mut rig = Rig::writable_with(|b| held(b).upload_delay(Duration::ZERO)).await;
    let file = rig.smb.create("full.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"bytes").await, Ok(5));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;

    rig.backend.hooks().disk_full.store(true, SeqCst);
    rig.backend.hooks().record_writes.store(1, SeqCst);
    rig.backend.hold_uploads(false);
    wait_until_async("the job meets the full disk", async || {
        rig.backend.hooks().record_writes.load(SeqCst) == 0
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let put = is_put_of(&rig.bucket.name, "full.txt");
    assert_eq!(rig.proxy.count(&put), 0, "the job rests");

    sync(&rig.backend).await.unwrap();
    assert_eq!(rig.proxy.count(&put), 1);
    assert_eq!(stored(&rig, "full.txt").await.0, b"bytes");
}

#[tokio::test]
async fn another_local_error_fails_the_job_and_the_next_backend_tries_again() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("local.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"bytes").await, Ok(5));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;

    rig.backend.hooks().record_writes.store(1, SeqCst);
    rig.backend.hold_uploads(false);
    let error = sync(&rig.backend).await.unwrap_err();

    assert!(matches!(error, S3Error::Cache(_)), "{error:?}");
    assert_eq!(rig.backend.failures().len(), 1);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "local.txt")), 0);
    wait_until_async("the record says the upload failed", async || {
        records(&rig).iter().any(|r| r.failed)
    })
    .await;

    let rig = rig.restart_with(uploading).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "local.txt").await.0, b"bytes");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_record_that_cannot_be_removed_when_the_object_lands_stays_for_the_next_backend() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("keep.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"keep me").await, Ok(7));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;

    rig.backend.hooks().record_removals.store(1, SeqCst);
    rig.backend.hold_uploads(false);
    let error = sync(&rig.backend).await.unwrap_err();

    assert!(matches!(error, S3Error::Cache(_)), "{error:?}");
    assert_eq!(stored(&rig, "keep.txt").await.0, b"keep me");
    assert_eq!(rig.backend.failures().len(), 1);
    let found = records(&rig);
    assert_eq!(found.len(), 1);
    assert!(found[0].failed);
    assert_eq!(left(&rig, "data"), 1);
    assert_eq!(rig.smb.contents("keep.txt", 100).await, b"keep me");

    let rig = rig.restart_with(uploading).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "keep.txt")), 2);
    assert_eq!(stored(&rig, "keep.txt").await.0, b"keep me");
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn a_conflict_that_cannot_be_moved_keeps_the_file_and_fails_the_job() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "base.bin", &pattern(1, MIB)).await;
    let file = rig.smb.create("base.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, &[9; 20]).await, Ok(20));
    rig.smb.close(file.id).await;
    put(rig.store(), "base.bin", &pattern(77, MIB)).await;

    rig.backend.hooks().data_moves.store(1, SeqCst);
    rig.backend.hold_uploads(false);
    let error = sync(&rig.backend).await.unwrap_err();

    assert!(matches!(error, S3Error::Cache(_)), "{error:?}");
    assert_eq!(rig.backend.failures().len(), 1);
    assert_eq!(left(&rig, "conflicts"), 0);
    assert_eq!(left(&rig, "records"), 1);
    assert_eq!(left(&rig, "data"), 1);

    let rig = rig.restart_with(uploading).await;
    let error = sync(&rig.backend).await.unwrap_err();
    assert_eq!(error.http_status(), Some(412));
    assert_eq!(left(&rig, "conflicts"), 2);
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn sync_returns_when_the_worker_is_gone() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("late.txt", create_file()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"queued").await, Ok(6));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let waiting = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.sync().await }
    });
    tokio::time::sleep(DELAY).await;
    assert!(!waiting.is_finished(), "the upload is held");

    rig.backend.panic_worker();
    let result = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("sync returns")
        .unwrap();
    assert!(matches!(result, Err(S3Error::Stopped)), "{result:?}");
}
