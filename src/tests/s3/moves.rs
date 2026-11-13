//! Deleting and renaming files: what the share shows at once, and what
//! reaches the bucket afterwards.

use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use tokio::sync::Notify;

use super::fixture::{MIB, TestBucket, foreground, pattern, put};
use super::proxy::{Fault, Proxy, Reply, Seen};
use super::share::{
    DELETE, READ, Rig, Spec, WRITE_ATTRIBUTES, is_data_read, names, open_handle, wait_for_requests,
    wait_until, wait_until_async,
};
use super::uploads::{
    fill, held, is_complete, is_create_of, is_get_of, is_head_of, is_put_of, left, stored, sync,
    uploading,
};
use super::writes::{create_dir, create_file, open_rw};
use crate::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
};
use crate::s3::object::Metadata;
use crate::s3::record::{EntryRecord, Record, RecordId, TombstoneRecord};
use crate::{OpenOptions, ShareBackend, SmbError, SmbPath};

pub(super) fn path(name: &str) -> SmbPath {
    name.parse().unwrap()
}

pub(super) fn is_delete(seen: &Seen) -> bool {
    (seen.method == "POST" && seen.has_param("delete"))
        || (seen.method == "DELETE" && !seen.has_param("uploadId"))
}

pub(super) fn is_copy(seen: &Seen) -> bool {
    seen.method == "PUT"
        && seen.header("x-amz-copy-source").is_some()
        && !seen.has_param("partNumber")
}

fn is_part_copy(seen: &Seen) -> bool {
    seen.method == "PUT"
        && seen.header("x-amz-copy-source").is_some()
        && seen.has_param("partNumber")
}

pub(super) fn deletes(rig: &Rig) -> usize {
    rig.proxy.count(is_delete)
}

pub(super) fn copies(rig: &Rig) -> usize {
    rig.proxy.count(is_copy)
}

/// The bytes of the object `key` in the bucket, if it is there.
pub(super) async fn remote(rig: &Rig, key: &str) -> Option<Vec<u8>> {
    match rig.store().head_object(key, foreground()).await {
        Ok(_) => Some(stored(rig, key).await.0),
        Err(e) if e.is_no_such_key() => None,
        Err(e) => panic!("{e}"),
    }
}

/// Makes the file `name` through the share with `data`, and closes it.
pub(super) async fn make(rig: &mut Rig, name: &str, data: &[u8]) {
    let file = rig.smb.create(name, create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, data).await;
    rig.smb.close(file.id).await;
}

/// Whether the gateway holds `Mixed` and `mixed` as one object, as one on a
/// file system that ignores case does.
pub(super) async fn folds_case(rig: &Rig) -> bool {
    put(rig.store(), "Mixed.case", b"x").await;
    remote(rig, "mixed.case").await.is_some()
}

pub(super) async fn exists(rig: &mut Rig, name: &str) -> bool {
    rig.smb.open(name).await.is_ok()
}

/// A request that deletes `key`, among others.
fn deletes_key(key: &str) -> impl Fn(&Seen) -> bool + Send + Sync + 'static {
    let named = format!("<Key>{key}</Key>");
    move |seen| is_delete(seen) && String::from_utf8_lossy(&seen.body).contains(&named)
}

/// Checks the end of a test that names one file in two cases: `live` holds
/// `content` in the bucket and through the share, `old` is gone from the
/// bucket unless the store treats both names as one (`folds`), and no file
/// failed.
async fn assert_only_spelling(rig: &mut Rig, live: &str, old: &str, content: &[u8], folds: bool) {
    assert_eq!(remote(rig, live).await.unwrap(), content);
    if !folds {
        assert_eq!(remote(rig, old).await, None);
    }
    assert_eq!(rig.smb.contents(live, 100).await, content);
    assert!(rig.backend.failures().is_empty());
}

/// A rig whose store answers the first `times` puts of the marker of `dir/`
/// with `status` and `code`, after `dir/only.txt`, the only object in `dir/`,
/// is unlinked.
async fn unlink_last_file_with_marker_refused(status: u16, code: &str, times: usize) -> Rig {
    let rig = Rig::writable_with(uploading).await;
    put(rig.store(), "dir/only.txt", b"x").await;
    let marker = format!("/{}/dir/", rig.bucket.name);
    rig.proxy.inject(
        move |s| s.method == "PUT" && s.target.split('?').next() == Some(marker.as_str()),
        Fault::Reply(Reply::error(status, code)),
        times,
    );
    rig.backend.unlink(&path("dir/only.txt")).await.unwrap();
    rig
}

/// Deletes `sweep.marker`, which the test put in the bucket before its first
/// lookup, and waits until the keys to delete have been swept: every key that
/// was due and free has gone with it.
async fn sweep(rig: &Rig) {
    rig.backend.unlink(&path("sweep.marker")).await.unwrap();
    wait_until_async("the keys to delete are swept", async || {
        let head = rig.store().head_object("sweep.marker", foreground()).await;
        head.is_err_and(|e| e.is_no_such_key())
    })
    .await;
}

/// Changes `Case.TXT`, then renames it to `CASE.txt`, and lets the backend
/// store it. With `write`, the change is bytes, and the file is stored again;
/// else it is a time, and the object is copied. The object has to be in the
/// bucket afterwards under the new spelling, or under both names on a store
/// that ignores case.
async fn rename_changed_file_by_case(write: bool) {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "Case.TXT", b"data").await;
    let file = rig.smb.create("case.txt", open_rw()).await.unwrap();
    if write {
        assert_eq!(rig.smb.write(file.id, 0, b"DATA").await, Ok(4));
    } else {
        assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
    }
    rig.smb.close(file.id).await;
    rig.backend
        .rename(&path("case.txt"), &path("CASE.txt"), false)
        .await
        .unwrap();
    let folds = folds_case(&rig).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    let want: &[u8] = if write { b"DATA" } else { b"data" };
    assert_eq!(remote(&rig, "CASE.txt").await.unwrap(), want);
    if !folds {
        assert_eq!(remote(&rig, "Case.TXT").await, None);
    }
    assert_eq!(rig.smb.contents("case.txt", 10).await, want);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

/// Every record in the cache directory, by id. A record the backend removes
/// while the directory is read is left out.
pub(super) fn all_records(rig: &Rig) -> Vec<Record> {
    let mut found: Vec<Record> = std::fs::read_dir(rig.cache_dir().join("records"))
        .unwrap()
        .filter_map(|file| std::fs::read(file.unwrap().path()).ok())
        .map(|bytes| Record::decode(&bytes).unwrap())
        .collect();
    found.sort_by(|a, b| a.id().as_str().cmp(b.id().as_str()));
    found
}

pub(super) fn entry_of(record: &Record) -> &EntryRecord {
    match record {
        Record::Entry(entry) => entry,
        other => panic!("not an entry record: {other:?}"),
    }
}

/// Renames the files at `names` in a ring: each takes the name of the next, and
/// the last takes the name of the first, through a temporary name.
async fn rotate(rig: &Rig, names: &[&str]) {
    let temp = "ring.tmp";
    rig.backend
        .rename(&path(names[0]), &path(temp), false)
        .await
        .unwrap();
    for pair in names.windows(2) {
        rig.backend
            .rename(&path(pair[1]), &path(pair[0]), false)
            .await
            .unwrap();
    }
    rig.backend
        .rename(&path(temp), &path(names[names.len() - 1]), false)
        .await
        .unwrap();
}

/// Lets the upload of a 6 MiB file over the 6 MiB object at `key` run, with
/// Complete requests the store never runs: the first answer is an error to
/// try again, and the second says there is no such upload. The object is
/// as long as the file, so only the ETag it had before tells that nothing
/// was stored.
async fn lost_complete(rig: &Rig, key: &str) {
    rig.proxy.inject(
        is_complete,
        Fault::Reply(Reply::error(503, "ServiceUnavailable")),
        1,
    );
    rig.proxy.inject(
        is_complete,
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        1,
    );
    rig.backend.hold_uploads(false);
    let error = sync(&rig.backend).await.unwrap_err();
    assert_eq!(error.code(), Some("NoSuchUpload"));
    assert!(
        stored(rig, key).await.0 == pattern(1, 6 * MIB).to_vec(),
        "the object is the one that was there"
    );
    assert_eq!(rig.backend.failures().len(), 1);
}

/// Ends the backend while a job waits at a pause, as a crash does, then lets
/// the job go. Returns what a new backend is built on.
pub(super) async fn crash(rig: Rig, resume: Arc<Notify>) -> (TestBucket, Proxy, tempfile::TempDir) {
    rig.stop_after(|| resume.notify_one()).await
}

/// A file whose base is a key another file has taken and left again is
/// unlinked, or replaced by a rename: the key stays.
async fn leave_a_stale_base(unlink: bool) {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "doc.txt", b"version 1").await;
    put(rig.store(), "other.txt", b"other").await;
    rig.backend
        .rename(&path("doc.txt"), &path("old.txt"), false)
        .await
        .unwrap();
    make(&mut rig, "doc.txt", b"version 2").await;
    // The file at old.txt is written over and flushed, so it no longer
    // needs doc.txt, and the new file can take it.
    let file = rig.smb.create("old.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"VERSION 1").await, Ok(9));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "old.txt"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    rig.backend.hold_uploads(false);
    wait_until_async("the new file is stored and has left", async || {
        rig.backend.overlay_len() == 1
            && remote(&rig, "doc.txt").await.as_deref() == Some(b"version 2".as_slice())
    })
    .await;
    // The file at old.txt has not landed: its base is still doc.txt.
    if unlink {
        rig.backend.unlink(&path("old.txt")).await.unwrap();
    } else {
        rig.backend
            .rename(&path("other.txt"), &path("old.txt"), true)
            .await
            .unwrap();
    }
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "doc.txt").await.unwrap(), b"version 2");
    assert_eq!(rig.smb.contents("doc.txt", 100).await, b"version 2");
    if unlink {
        assert_eq!(remote(&rig, "old.txt").await, None);
    } else {
        assert_eq!(remote(&rig, "old.txt").await.unwrap(), b"other");
        assert_eq!(remote(&rig, "other.txt").await, None);
    }
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn an_unlinked_file_is_gone_at_once_and_deleted_from_the_bucket_later() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "doc.txt", b"remote").await;
    assert_eq!(rig.smb.contents("doc.txt", 100).await, b"remote");

    rig.backend.unlink(&path("doc.txt")).await.unwrap();

    assert_eq!(
        rig.smb.open("doc.txt").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    let root = rig.smb.open_dir("").await.unwrap();
    assert!(rig.smb.list(root.id, "*").await.is_empty());
    assert_eq!(remote(&rig, "doc.txt").await.unwrap(), b"remote");
    assert_eq!(left(&rig, "records"), 1);
    assert_eq!(deletes(&rig), 0);

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "doc.txt").await, None);
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(deletes(&rig), 1);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn an_unlinked_file_that_never_reached_the_bucket_causes_no_delete() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "fresh.txt", b"never sent").await;
    assert_eq!(left(&rig, "data"), 1);

    rig.backend.unlink(&path("fresh.txt")).await.unwrap();
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(deletes(&rig), 0);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "fresh.txt")), 0);
    assert_eq!(remote(&rig, "fresh.txt").await, None);
}

#[tokio::test]
async fn an_unlink_stops_the_upload_of_a_changed_file_and_deletes_its_object() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "big.bin", &pattern(1, MIB)).await;
    let file = rig.smb.create("big.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 5, b"changed").await, Ok(7));
    rig.smb.close(file.id).await;

    rig.backend.unlink(&path("big.bin")).await.unwrap();
    assert_eq!(left(&rig, "data"), 0);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "big.bin").await, None);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "big.bin")), 0);
}

#[tokio::test]
async fn a_write_through_a_handle_that_outlived_the_unlink_fails() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "open.txt", b"abc").await;
    let file = rig.smb.create("open.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"xyz").await, Ok(3));

    rig.backend.unlink(&path("open.txt")).await.unwrap();

    assert!(rig.smb.write(file.id, 0, b"late").await.is_err());
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "open.txt").await, None);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "open.txt")), 0);
}

#[tokio::test]
async fn a_name_made_again_after_an_unlink_is_never_deleted() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "same.txt", b"old").await;
    rig.backend.unlink(&path("same.txt")).await.unwrap();
    make(&mut rig, "same.txt", b"new content").await;

    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "same.txt").await.unwrap(), b"new content");
    assert_eq!(
        deletes(&rig),
        0,
        "the new file supersedes the key to delete"
    );
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.smb.contents("same.txt", 100).await, b"new content");
}

#[tokio::test]
async fn a_key_to_delete_that_a_live_entry_holds_is_not_deleted() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "held.txt", b"old").await;
    rig.backend.unlink(&path("held.txt")).await.unwrap();
    make(&mut rig, "held.txt", b"new").await;
    rig.backend.hold_uploads(false);
    // The tombstone is due before the new file is stored, and the file holds
    // the key meanwhile.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(deletes(&rig), 0);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "held.txt").await.unwrap(), b"new");
}

#[tokio::test]
async fn unowned_keys_are_deleted_in_batches() {
    let rig = Rig::writable_with(held).await;
    for n in 0..5 {
        put(rig.store(), &format!("d/f{n}"), b"x").await;
    }
    put(rig.store(), "d/keep", b"x").await;
    for n in 0..5 {
        rig.backend.unlink(&path(&format!("d/f{n}"))).await.unwrap();
    }
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(deletes(&rig), 1, "one DeleteObjects for the five keys");
    for n in 0..5 {
        assert_eq!(remote(&rig, &format!("d/f{n}")).await, None);
    }
    assert!(remote(&rig, "d/keep").await.is_some());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn the_last_file_of_an_implied_directory_leaves_a_marker_when_it_is_unlinked() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "dir/only.txt", b"x").await;
    rig.backend.unlink(&path("dir/only.txt")).await.unwrap();

    let dir = rig.smb.open_dir("dir").await.unwrap();
    assert!(rig.smb.list(dir.id, "*").await.is_empty());
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "dir/only.txt").await, None);
    assert!(
        remote(&rig, "dir/").await.is_some(),
        "the marker is in the bucket"
    );
    assert!(rig.smb.open_dir("dir").await.is_ok());
    let seen = rig.proxy.seen();
    let marker = seen
        .iter()
        .position(|s| s.method == "PUT" && s.target.contains("/dir/") && !s.target.contains("only"))
        .expect("a marker was put");
    let delete = seen.iter().position(is_delete).unwrap();
    assert!(marker < delete, "the marker goes first");
}

#[tokio::test]
async fn a_directory_with_other_files_gets_no_marker() {
    let rig = Rig::writable_with(uploading).await;
    put(rig.store(), "dir/a.txt", b"x").await;
    put(rig.store(), "dir/b.txt", b"x").await;
    rig.backend.unlink(&path("dir/a.txt")).await.unwrap();
    sync(&rig.backend).await.unwrap();
    assert_eq!(
        rig.proxy.count(|s| s.method == "PUT"),
        0,
        "nothing but deletes reach the bucket"
    );
}

#[tokio::test]
async fn a_file_marked_for_deletion_through_the_share_is_deleted_when_it_closes() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "gone.txt", b"x").await;
    let spec = Spec::FILE.access(READ | DELETE);
    let file = rig.smb.create("gone.txt", spec).await.unwrap();
    assert_eq!(rig.smb.set_delete(file.id).await, 0);
    rig.smb.close(file.id).await;
    assert!(!exists(&mut rig, "gone.txt").await);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "gone.txt").await, None);
}

#[tokio::test]
async fn a_remote_file_renamed_is_there_at_once_and_copied_in_the_background() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(3, 5000);
    put(rig.store(), "a.bin", &data).await;

    rig.backend
        .rename(&path("a.bin"), &path("b.bin"), false)
        .await
        .unwrap();

    assert_eq!(rig.smb.contents("b.bin", 4096).await, data);
    assert_eq!(
        rig.smb.open("a.bin").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(remote(&rig, "b.bin").await, None);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "b.bin").await.unwrap(), data);
    assert_eq!(remote(&rig, "a.bin").await, None);
    assert_eq!(copies(&rig), 1);
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.smb.contents("b.bin", 4096).await, data);
}

#[tokio::test]
async fn a_read_of_a_renamed_file_whose_object_is_copied_and_deleted_meanwhile_gets_the_copy() {
    let rig = Rig::writable_with(held).await;
    let data = pattern(3, 5000);
    put(rig.store(), "a.bin", &data).await;
    rig.backend
        .rename(&path("a.bin"), &path("b.bin"), false)
        .await
        .unwrap();

    // The read plans from a.bin, and its request waits at the proxy until the
    // copy at b.bin has landed and a.bin is deleted.
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_get_of(&rig.bucket.name, "a.bin"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    let handle = open_handle(&rig.backend, "b.bin").await;
    let reading = tokio::spawn(async move { handle.read(0, 4096).await });
    wait_for_requests(&rig.proxy, 1, is_get_of(&rig.bucket.name, "a.bin")).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "a.bin").await, None);

    gate.notify_one();
    assert_eq!(reading.await.unwrap().unwrap(), &data[..4096]);
    assert!(rig.backend.failures().is_empty());
}

/// A read of a file that has local data over part of its object plans from
/// that object, and its request waits at the proxy until the job of the file
/// has stored it, at the key of the object or, with `rename`, at another. The
/// read gets the bytes of the file.
async fn read_while_the_job_stores_the_file(rename: bool) {
    let mut rig = Rig::writable_with(held).await;
    let base = pattern(1, 3000);
    put(rig.store(), "edit.bin", &base).await;
    let file = rig.smb.create("edit.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, b"EDITED").await, Ok(6));
    rig.smb.close(file.id).await;
    let mut expected = base.to_vec();
    expected[10..16].copy_from_slice(b"EDITED");
    let name = if rename { "moved.bin" } else { "edit.bin" };
    if rename {
        rig.backend
            .rename(&path("edit.bin"), &path(name), false)
            .await
            .unwrap();
    }

    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_get_of(&rig.bucket.name, "edit.bin"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    let handle = open_handle(&rig.backend, name).await;
    let reading = tokio::spawn(async move { handle.read(0, 4096).await });
    wait_for_requests(&rig.proxy, 1, is_get_of(&rig.bucket.name, "edit.bin")).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, name).await.unwrap(), expected);
    assert_eq!(remote(&rig, "edit.bin").await.is_some(), !rename);

    gate.notify_one();
    assert_eq!(reading.await.unwrap().unwrap(), expected);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_read_over_local_data_whose_object_the_job_stored_over_gets_the_bytes_of_the_file() {
    read_while_the_job_stores_the_file(false).await;
}

#[tokio::test]
async fn a_read_over_local_data_whose_object_the_job_moved_gets_the_bytes_of_the_file() {
    read_while_the_job_stores_the_file(true).await;
}

#[tokio::test]
async fn a_rename_makes_no_store_request_beyond_the_lookups() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "a.bin", b"x").await;
    let before = rig
        .proxy
        .count(|s| !matches!(s.method.as_str(), "GET" | "HEAD"));
    rig.backend
        .rename(&path("a.bin"), &path("b.bin"), false)
        .await
        .unwrap();
    assert_eq!(
        rig.proxy
            .count(|s| !matches!(s.method.as_str(), "GET" | "HEAD")),
        before
    );
}

#[tokio::test]
async fn a_file_with_changes_renamed_is_stored_at_the_new_key_with_its_changes() {
    let mut rig = Rig::writable_with(held).await;
    let base = pattern(1, 3000);
    put(rig.store(), "edit.bin", &base).await;
    let file = rig.smb.create("edit.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, b"EDITED").await, Ok(6));
    rig.smb.close(file.id).await;

    rig.backend
        .rename(&path("edit.bin"), &path("moved.bin"), false)
        .await
        .unwrap();
    let mut expected = base.to_vec();
    expected[10..16].copy_from_slice(b"EDITED");
    assert_eq!(rig.smb.contents("moved.bin", 999).await, expected);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "moved.bin").await.unwrap(), expected);
    assert_eq!(remote(&rig, "edit.bin").await, None);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "edit.bin")), 0);
}

#[tokio::test]
async fn a_new_file_renamed_before_it_is_stored_goes_up_once_at_the_new_key() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "new.txt", b"fresh").await;
    rig.backend
        .rename(&path("new.txt"), &path("newer.txt"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "newer.txt").await.unwrap(), b"fresh");
    assert_eq!(remote(&rig, "new.txt").await, None);
    assert_eq!(deletes(&rig), 0, "the old key was never in the bucket");
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "new.txt")), 0);
}

#[tokio::test]
async fn a_rename_onto_a_file_needs_replace_and_replaces_it() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "from.txt", b"from").await;
    put(rig.store(), "to.txt", b"to").await;

    let refused = rig
        .backend
        .rename(&path("from.txt"), &path("to.txt"), false)
        .await;
    assert!(matches!(refused, Err(SmbError::Exists)));
    assert_eq!(rig.smb.contents("to.txt", 10).await, b"to");
    assert_eq!(rig.smb.contents("from.txt", 10).await, b"from");

    rig.backend
        .rename(&path("from.txt"), &path("to.txt"), true)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("to.txt", 10).await, b"from");
    assert!(!exists(&mut rig, "from.txt").await);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "to.txt").await.unwrap(), b"from");
    assert_eq!(remote(&rig, "from.txt").await, None);
}

#[tokio::test]
async fn a_replaced_file_with_changes_loses_them() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "from.txt", b"from").await;
    put(rig.store(), "to.txt", b"to").await;
    let file = rig.smb.create("to.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"TOTO").await, Ok(4));
    rig.smb.close(file.id).await;

    rig.backend
        .rename(&path("from.txt"), &path("to.txt"), true)
        .await
        .unwrap();
    assert_eq!(left(&rig, "data"), 0);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "to.txt").await.unwrap(), b"from");
    assert_eq!(copies(&rig), 1);
    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "to.txt")),
        1,
        "only the copy writes the key"
    );
}

#[tokio::test]
async fn a_rename_onto_a_directory_or_into_a_missing_one_fails() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "f.txt", b"x").await;
    put(rig.store(), "d/x", b"x").await;
    let onto_dir = rig.backend.rename(&path("f.txt"), &path("d"), true).await;
    assert!(matches!(onto_dir, Err(SmbError::AccessDenied)));
    let missing = rig
        .backend
        .rename(&path("f.txt"), &path("nope/f.txt"), false)
        .await;
    assert!(matches!(missing, Err(SmbError::PathNotFound)));
    let under_file = rig
        .backend
        .rename(&path("f.txt"), &path("d/x/y"), false)
        .await;
    assert!(matches!(under_file, Err(SmbError::PathNotFound)));
    assert_eq!(rig.smb.contents("f.txt", 10).await, b"x");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_rename_through_the_share_reports_the_same_failures() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "f.txt", b"x").await;
    put(rig.store(), "g.txt", b"y").await;
    put(rig.store(), "d/x", b"x").await;
    let spec = Spec::FILE.access(READ | DELETE);
    let file = rig.smb.create("f.txt", spec).await.unwrap();
    assert_eq!(
        rig.smb.rename(file.id, "g.txt").await,
        STATUS_OBJECT_NAME_COLLISION
    );
    assert_eq!(rig.smb.rename(file.id, "d").await, STATUS_ACCESS_DENIED);
    assert_eq!(
        rig.smb.rename(file.id, "nope\\f.txt").await,
        STATUS_OBJECT_PATH_NOT_FOUND
    );
    assert_eq!(rig.smb.rename_with(file.id, "g.txt", true).await, 0);
    rig.smb.close(file.id).await;
    assert_eq!(rig.smb.contents("g.txt", 10).await, b"x");
}

#[tokio::test]
async fn a_rename_that_only_changes_the_case_moves_the_object_to_the_new_spelling() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "Case.TXT", b"data").await;
    rig.backend
        .rename(&path("case.txt"), &path("CASE.txt"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("case.txt", 10).await, b"data");
    let root = rig.smb.open_dir("").await.unwrap();
    let listed = rig.smb.list(root.id, "*").await;
    assert_eq!(names(&listed), ["CASE.txt"]);
    let folds = folds_case(&rig).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "CASE.txt").await.unwrap(), b"data");
    if !folds {
        assert_eq!(remote(&rig, "Case.TXT").await, None);
    }
    assert_eq!(rig.smb.contents("case.txt", 10).await, b"data");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_case_only_rename_of_a_file_with_new_times_keeps_the_object() {
    rename_changed_file_by_case(false).await;
}

#[tokio::test]
async fn a_case_only_rename_of_a_file_with_new_bytes_keeps_the_object() {
    rename_changed_file_by_case(true).await;
}

#[tokio::test]
async fn a_rename_during_an_upload_stops_it_and_the_final_state_lands_at_the_new_key() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(7, 6 * MIB);
    let file = rig.smb.create("up.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close(file.id).await;

    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    rig.backend
        .rename(&path("up.bin"), &path("renamed.bin"), false)
        .await
        .unwrap();
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "renamed.bin").await.unwrap(), data);
    assert_eq!(remote(&rig, "up.bin").await, None);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "up.bin")), 0);
}

#[tokio::test]
async fn a_rename_during_a_store_request_deletes_the_key_that_request_wrote() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "w.txt", b"written").await;
    let (reached, resume) = rig.backend.pause_after_store();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    rig.backend
        .rename(&path("w.txt"), &path("x.txt"), false)
        .await
        .unwrap();
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "x.txt").await.unwrap(), b"written");
    assert_eq!(
        remote(&rig, "w.txt").await,
        None,
        "the key the first job wrote is deleted"
    );
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn an_unlink_during_a_store_request_deletes_what_the_request_wrote() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "u.txt", b"written").await;
    let (reached, resume) = rig.backend.pause_after_store();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    rig.backend.unlink(&path("u.txt")).await.unwrap();
    assert!(!exists(&mut rig, "u.txt").await);
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "u.txt").await, None);
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn an_editor_style_save_leaves_the_new_content_and_nothing_else() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "doc.txt", b"version 1").await;
    make(&mut rig, "doc.tmp", b"version 2").await;
    rig.backend
        .rename(&path("doc.txt"), &path("doc.bak"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("doc.tmp"), &path("doc.txt"), true)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("doc.txt", 100).await, b"version 2");
    assert_eq!(rig.smb.contents("doc.bak", 100).await, b"version 1");
    rig.backend.unlink(&path("doc.bak")).await.unwrap();

    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "doc.txt").await.unwrap(), b"version 2");
    assert_eq!(remote(&rig, "doc.bak").await, None);
    assert_eq!(remote(&rig, "doc.tmp").await, None);
    assert_eq!(rig.smb.contents("doc.txt", 100).await, b"version 2");
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn an_editor_save_that_keeps_the_old_file_aside_copies_it_before_the_new_one_lands() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "doc.txt", b"version 1").await;
    make(&mut rig, "doc.tmp", b"version 2").await;
    rig.backend
        .rename(&path("doc.txt"), &path("doc.bak"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("doc.tmp"), &path("doc.txt"), true)
        .await
        .unwrap();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "doc.txt").await.unwrap(), b"version 2");
    assert_eq!(remote(&rig, "doc.bak").await.unwrap(), b"version 1");
    assert_eq!(
        deletes(&rig),
        0,
        "the key the new file holds is not deleted"
    );
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_chain_of_renames_before_the_job_runs_ends_in_one_copy_and_the_delete_of_the_original() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"chain").await;
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("b.txt"), &path("c.txt"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("c.txt", 10).await, b"chain");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "c.txt").await.unwrap(), b"chain");
    assert_eq!(remote(&rig, "a.txt").await, None);
    assert_eq!(remote(&rig, "b.txt").await, None);
    assert_eq!(copies(&rig), 1);
    let copy = rig.proxy.seen().into_iter().find(is_copy).unwrap();
    assert!(
        copy.header("x-amz-copy-source")
            .unwrap()
            .ends_with("/a.txt")
    );
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "b.txt")), 0);
}

#[tokio::test]
async fn a_chain_that_ends_where_it_began_has_nothing_to_store() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"loop").await;
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("b.txt"), &path("a.txt"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(copies(&rig), 0);
    assert_eq!(deletes(&rig), 0);
    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"loop");
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn a_crash_between_the_copy_and_the_delete_is_finished_by_the_next_backend() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "old.txt", b"survives").await;
    rig.backend
        .rename(&path("old.txt"), &path("new.txt"), false)
        .await
        .unwrap();
    let (reached, resume) = rig.backend.pause_after_landing();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    assert_eq!(remote(&rig, "new.txt").await.unwrap(), b"survives");
    assert_eq!(remote(&rig, "old.txt").await.unwrap(), b"survives");

    let Rig {
        bucket,
        proxy,
        backend,
        mut smb,
        cache,
    } = rig;
    smb.close_all().await;
    drop(smb);
    let mut exited = backend.worker_exited();
    drop(backend);
    resume.notify_one();
    tokio::time::timeout(Duration::from_secs(10), exited.wait_for(|exited| *exited))
        .await
        .expect("the worker ends")
        .unwrap();

    let mut rig = Rig::start(bucket, proxy, cache.unwrap(), uploading).await;
    assert_eq!(rig.smb.contents("new.txt", 100).await, b"survives");
    assert!(!exists(&mut rig, "old.txt").await);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "old.txt").await, None);
    assert_eq!(remote(&rig, "new.txt").await.unwrap(), b"survives");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_rename_and_an_unlink_before_a_restart_come_back_as_keys_to_delete() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"x").await;
    put(rig.store(), "z.txt", b"z").await;
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    rig.backend.unlink(&path("z.txt")).await.unwrap();
    let mut rig = rig.restart_with(held).await;

    assert_eq!(rig.smb.contents("b.txt", 10).await, b"x");
    assert!(!exists(&mut rig, "a.txt").await);
    assert!(!exists(&mut rig, "z.txt").await);
    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"x");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "b.txt").await.unwrap(), b"x");
    assert_eq!(remote(&rig, "a.txt").await, None);
    assert_eq!(remote(&rig, "z.txt").await, None);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn times_set_on_a_file_without_local_data_reach_the_bucket_by_a_copy_onto_itself() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "t.txt", b"time").await;
    let file = rig.smb.create("t.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();

    let head = rig
        .store()
        .head_object("t.txt", foreground())
        .await
        .unwrap();
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
    assert_eq!(copies(&rig), 1);
    assert_eq!(stored(&rig, "t.txt").await.0, b"time");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn foreign_metadata_and_the_content_type_survive_renames_and_time_changes() {
    let mut rig = Rig::writable_with(uploading).await;
    let mut metadata = Metadata {
        content_type: Some("text/x-special".to_owned()),
        cache_control: Some("max-age=60".to_owned()),
        ..Default::default()
    };
    metadata
        .user
        .insert("owner".to_owned(), "someone".to_owned());
    rig.store()
        .put_object(
            "m.txt",
            bytes::Bytes::from_static(b"meta"),
            &metadata,
            foreground(),
        )
        .await
        .unwrap();
    rig.backend
        .rename(&path("m.txt"), &path("n.txt"), false)
        .await
        .unwrap();
    sync(&rig.backend).await.unwrap();
    let head = rig
        .store()
        .head_object("n.txt", foreground())
        .await
        .unwrap();
    assert_eq!(
        head.metadata.content_type.as_deref(),
        Some("text/x-special")
    );
    assert_eq!(head.metadata.cache_control.as_deref(), Some("max-age=60"));
    assert_eq!(
        head.metadata.user.get("owner").map(String::as_str),
        Some("someone")
    );

    let file = rig.smb.create("n.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(file.id, 1_600_000_000).await, 0);
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();
    let head = rig
        .store()
        .head_object("n.txt", foreground())
        .await
        .unwrap();
    assert_eq!(
        head.metadata.content_type.as_deref(),
        Some("text/x-special")
    );
    assert_eq!(
        head.metadata.user.get("owner").map(String::as_str),
        Some("someone")
    );
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1600000000.000000000")
    );
}

#[tokio::test]
async fn a_store_that_refuses_a_copy_onto_itself_gets_the_object_read_and_stored_again() {
    for status in [400, 501] {
        let mut rig = Rig::writable_with(uploading).await;
        put(rig.store(), "r.txt", b"rewritten").await;
        rig.proxy.inject(
            is_copy,
            Fault::Reply(Reply::error(status, "NotImplemented")),
            usize::MAX,
        );
        let file = rig.smb.create("r.txt", open_rw()).await.unwrap();
        assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
        rig.smb.close(file.id).await;
        sync(&rig.backend).await.unwrap();

        let head = rig
            .store()
            .head_object("r.txt", foreground())
            .await
            .unwrap();
        assert_eq!(
            head.metadata.user.get("mtime").map(String::as_str),
            Some("1500000000.000000000"),
            "status {status}"
        );
        assert_eq!(stored(&rig, "r.txt").await.0, b"rewritten");
        assert_eq!(
            rig.proxy.count(is_put_of(&rig.bucket.name, "r.txt")),
            2,
            "the refused copy and the rewrite"
        );
    }
}

#[tokio::test]
async fn a_change_the_store_refuses_on_an_object_above_the_part_size_is_dropped() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "huge.bin", &pattern(2, 6 * MIB)).await;
    rig.proxy.inject(
        is_copy,
        Fault::Reply(Reply::error(501, "NotImplemented")),
        usize::MAX,
    );
    let file = rig.smb.create("huge.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();

    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "huge.bin")),
        1,
        "only the refused copy"
    );
    assert_eq!(
        rig.proxy
            .count(|s| is_data_read(s) && s.target.contains("huge.bin")),
        0
    );
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn an_object_above_the_copy_limit_is_copied_in_parts() {
    let rig = Rig::writable_with(uploading).await;
    rig.backend.limit_copy(6 * MIB as u64);
    let data = pattern(5, 14 * MIB);
    put(rig.store(), "big.bin", &data).await;
    rig.backend
        .rename(&path("big.bin"), &path("big2.bin"), false)
        .await
        .unwrap();
    sync(&rig.backend).await.unwrap();

    assert_eq!(stored(&rig, "big2.bin").await.0, data);
    assert_eq!(remote(&rig, "big.bin").await, None);
    assert_eq!(rig.proxy.count(is_part_copy), 3);
    assert_eq!(copies(&rig), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_metadata_change_on_an_object_above_the_copy_limit_is_a_copy_in_parts_onto_itself() {
    let mut rig = Rig::writable_with(uploading).await;
    rig.backend.limit_copy(6 * MIB as u64);
    let data = pattern(8, 7 * MIB);
    put(rig.store(), "big.bin", &data).await;
    let file = rig.smb.create("big.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();

    let (bytes, head) = stored(&rig, "big.bin").await;
    assert_eq!(bytes, data);
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
    assert_eq!(rig.proxy.count(is_part_copy), 2);
}

#[tokio::test]
async fn deletes_the_store_refuses_per_key_are_classified() {
    let rig = Rig::writable_with(held).await;
    for key in ["k1", "k2", "k3"] {
        put(rig.store(), key, b"x").await;
        rig.backend.unlink(&path(key)).await.unwrap();
    }
    let xml = |code: &str| {
        format!(
            "<?xml version=\"1.0\"?><DeleteResult><Deleted><Key>k1</Key></Deleted>\
             <Error><Key>k2</Key><Code>{code}</Code><Message>m</Message></Error>\
             <Error><Key>k3</Key><Code>AccessDenied</Code><Message>m</Message></Error></DeleteResult>"
        )
    };
    rig.store().delete_object("k1", foreground()).await.unwrap();
    rig.proxy.inject(
        |s| s.method == "POST" && s.has_param("delete"),
        Fault::Reply(Reply::new(200, xml("SlowDown"))),
        1,
    );
    rig.backend.hold_uploads(false);
    let error = sync(&rig.backend).await.unwrap_err();

    assert_eq!(error.code(), Some("AccessDenied"));
    assert_eq!(remote(&rig, "k1").await, None);
    assert_eq!(remote(&rig, "k2").await, None, "SlowDown is asked again");
    assert!(remote(&rig, "k3").await.is_some(), "AccessDenied stays");
    assert_eq!(deletes(&rig), 2);
}

#[tokio::test]
async fn a_delete_of_a_key_that_is_gone_already_succeeds() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "once.txt", b"x").await;
    rig.backend.unlink(&path("once.txt")).await.unwrap();
    rig.store()
        .delete_object("once.txt", foreground())
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn sync_waits_for_changes_of_times_and_for_keys_to_delete() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "s.txt", b"x").await;
    put(rig.store(), "u.txt", b"x").await;
    let file = rig.smb.create("s.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
    rig.smb.close(file.id).await;
    rig.backend.unlink(&path("u.txt")).await.unwrap();

    let waiting = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.sync().await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !waiting.is_finished(),
        "nothing is stored while uploads are held"
    );
    rig.backend.hold_uploads(false);
    waiting.await.unwrap().unwrap();

    assert_eq!(remote(&rig, "u.txt").await, None);
    let head = rig
        .store()
        .head_object("s.txt", foreground())
        .await
        .unwrap();
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
}

#[tokio::test]
async fn sync_waits_for_a_rename_and_for_the_deletes_it_leaves() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "p.txt", b"x").await;
    rig.backend
        .rename(&path("p.txt"), &path("q.txt"), false)
        .await
        .unwrap();
    let waiting = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.sync().await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished());
    rig.backend.hold_uploads(false);
    waiting.await.unwrap().unwrap();
    assert_eq!(remote(&rig, "p.txt").await, None);
    assert!(remote(&rig, "q.txt").await.is_some());
}

#[tokio::test]
async fn times_set_on_an_implied_directory_reach_the_bucket_on_a_new_marker() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "impl/f.txt", b"x").await;
    let dir = rig
        .smb
        .create("impl", Spec::DIR.access(WRITE_ATTRIBUTES | READ))
        .await
        .unwrap();
    assert_eq!(rig.smb.set_write_time(dir.id, 1_500_000_000).await, 0);
    rig.smb.close(dir.id).await;
    sync(&rig.backend).await.unwrap();

    let head = rig
        .store()
        .head_object("impl/", foreground())
        .await
        .unwrap();
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
}

#[tokio::test]
async fn an_unlink_rewrites_the_record_of_the_entry_as_a_tombstone_with_its_id() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"remote").await;
    let file = rig.smb.create("a.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"local").await, Ok(5));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let before = all_records(&rig);
    assert_eq!(before.len(), 1);
    let id = before[0].id().clone();

    rig.backend.unlink(&path("a.txt")).await.unwrap();

    let after = all_records(&rig);
    assert_eq!(after.len(), 1, "one record, rewritten in place");
    match &after[0] {
        Record::Tombstone(tombstone) => {
            assert_eq!(tombstone.id, id);
            assert_eq!(tombstone.keys, ["a.txt"]);
        }
        other => panic!("the record is not a tombstone: {other:?}"),
    }
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn a_rename_keeps_the_record_id_and_names_the_old_key_in_it() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"remote").await;
    let file = rig.smb.create("a.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"local").await, Ok(5));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let id = all_records(&rig)[0].id().clone();

    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();

    let after = all_records(&rig);
    assert_eq!(after.len(), 1);
    let record = entry_of(&after[0]);
    assert_eq!(record.id, id);
    assert_eq!(
        (record.key.as_str(), record.path.as_str()),
        ("b.txt", "b.txt")
    );
    assert_eq!(record.gone, ["a.txt"]);
    assert_eq!(record.base.as_ref().unwrap().key, "a.txt");
    assert_eq!(record.local.as_ref().unwrap().len, 6);
}

#[tokio::test]
async fn a_replacing_rename_turns_the_record_of_the_replaced_entry_into_a_tombstone_first() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "from.txt", b"from").await;
    put(rig.store(), "to.txt", b"to").await;
    // The replaced entry came from `old.txt`, so its base key differs from its key.
    put(rig.store(), "old.txt", b"old").await;
    rig.backend
        .rename(&path("old.txt"), &path("to.txt"), true)
        .await
        .unwrap();
    let replaced = all_records(&rig);
    assert_eq!(replaced.len(), 1, "the entry that moved");
    let replaced_id = replaced[0].id().clone();

    rig.backend
        .rename(&path("from.txt"), &path("to.txt"), true)
        .await
        .unwrap();

    let after = all_records(&rig);
    let tombstones: Vec<_> = after
        .iter()
        .filter_map(|record| match record {
            Record::Tombstone(tombstone) => Some(tombstone),
            _ => None,
        })
        .collect();
    assert_eq!(tombstones.len(), 1);
    let converted = tombstones[0];
    assert_eq!(converted.id, replaced_id, "the record converted in place");
    assert_eq!(converted.keys, ["old.txt"], "its own key stays the target");
    let moved: Vec<_> = after
        .iter()
        .filter_map(|record| match record {
            Record::Entry(entry) => Some(entry),
            _ => None,
        })
        .collect();
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].key, "to.txt");
    assert_eq!(moved[0].gone, ["from.txt"]);
    assert!(moved[0].remote, "the replaced key may exist in the bucket");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "to.txt").await.unwrap(), b"from");
    assert_eq!(remote(&rig, "from.txt").await, None);
    assert_eq!(remote(&rig, "old.txt").await, None);
}

#[tokio::test]
async fn a_recovered_entry_at_a_key_to_delete_supersedes_it() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "x.txt", b"old").await;
    let file = rig.smb.create("x.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"new").await, Ok(3));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let (bucket, proxy, cache) = rig.stop().await;
    let id = RecordId::from_bytes(&[9; 16]);
    let tombstone = Record::Tombstone(TombstoneRecord {
        id: id.clone(),
        keys: vec!["x.txt".to_owned(), "y.txt".to_owned()],
    });
    std::fs::write(
        cache.path().join("records").join(id.as_str()),
        tombstone.encode(),
    )
    .unwrap();
    put(&bucket.client, "y.txt", b"y").await;

    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "x.txt").await.unwrap(), b"new");
    assert_eq!(remote(&rig, "y.txt").await, None);
    assert_eq!(rig.smb.contents("x.txt", 10).await, b"new");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_delete_of_an_old_key_the_store_refuses_fails_the_entry_and_sync() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "o.txt", b"x").await;
    rig.backend
        .rename(&path("o.txt"), &path("n.txt"), false)
        .await
        .unwrap();
    rig.proxy.inject(
        is_delete,
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    rig.backend.hold_uploads(false);
    let error = sync(&rig.backend).await.unwrap_err();
    assert_eq!(error.http_status(), Some(403));
    assert_eq!(remote(&rig, "n.txt").await.unwrap(), b"x");
    assert!(remote(&rig, "o.txt").await.is_some());
    let failures = rig.backend.failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, "n.txt");
}

#[tokio::test]
async fn a_rename_whose_second_record_cannot_be_written_changes_nothing() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "old.txt", b"old").await;
    put(rig.store(), "from.txt", b"from").await;
    rig.backend
        .rename(&path("old.txt"), &path("to.txt"), false)
        .await
        .unwrap();
    let before = all_records(&rig);
    assert_eq!(before.len(), 1);

    // The replaced entry's record is written first; the moved entry's fails.
    rig.backend.hooks().record_write_skips.store(1, SeqCst);
    rig.backend.hooks().record_writes.store(1, SeqCst);
    let failed = rig
        .backend
        .rename(&path("from.txt"), &path("to.txt"), true)
        .await;

    assert!(failed.is_err());
    assert_eq!(rig.smb.contents("from.txt", 10).await, b"from");
    assert_eq!(rig.smb.contents("to.txt", 10).await, b"old");
    let after = all_records(&rig);
    assert_eq!(after.len(), 1, "the replaced entry has its record again");
    let mut restored = entry_of(&after[0]).clone();
    assert!(restored.generation > entry_of(&before[0]).generation);
    restored.generation = entry_of(&before[0]).generation;
    assert_eq!(&restored, entry_of(&before[0]));
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "to.txt").await.unwrap(), b"old");
    assert_eq!(remote(&rig, "from.txt").await.unwrap(), b"from");
}

#[tokio::test]
async fn a_write_through_a_handle_open_during_a_rename_lands_at_the_new_key() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "a.txt", b"0123456789").await;
    let file = rig.smb.create("a.txt", open_rw()).await.unwrap();
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.write(file.id, 2, b"XY").await, Ok(2));
    rig.smb.close(file.id).await;
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "b.txt").await.unwrap(), b"01XY456789");
    assert_eq!(remote(&rig, "a.txt").await, None);
}

#[tokio::test]
async fn a_handle_on_a_replaced_file_can_change_nothing() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "from.txt", b"from").await;
    put(rig.store(), "to.txt", b"to").await;
    let open = rig.smb.create("to.txt", open_rw()).await.unwrap();
    rig.backend
        .rename(&path("from.txt"), &path("to.txt"), true)
        .await
        .unwrap();
    assert!(rig.smb.write(open.id, 0, b"late").await.is_err());
    rig.smb.close(open.id).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "to.txt").await.unwrap(), b"from");
}

#[tokio::test]
async fn a_name_a_rename_left_is_reused_after_the_old_content_is_copied() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "a.txt", b"was a").await;
    put(rig.store(), "c.txt", b"was c").await;
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("c.txt"), &path("a.txt"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("a.txt", 10).await, b"was c");
    assert_eq!(rig.smb.contents("b.txt", 10).await, b"was a");
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"was c");
    assert_eq!(remote(&rig, "b.txt").await.unwrap(), b"was a");
    assert_eq!(remote(&rig, "c.txt").await, None);
}

#[tokio::test]
async fn a_new_file_at_the_name_a_rename_left_waits_for_the_copy_of_the_old_content() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "doc.txt", b"version 1").await;
    rig.backend
        .rename(&path("doc.txt"), &path("old.txt"), false)
        .await
        .unwrap();
    make(&mut rig, "doc.txt", b"version 2").await;

    let gate = Arc::new(Notify::new());
    rig.proxy.inject(is_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_copy).await;
    wait_until("the new file is put off", || rig.backend.parks() == 1).await;
    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "doc.txt")),
        0,
        "the copy is still reading the old content"
    );
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "old.txt").await.unwrap(), b"version 1");
    assert_eq!(remote(&rig, "doc.txt").await.unwrap(), b"version 2");
    let seen = rig.proxy.seen();
    let copied = seen.iter().position(is_copy).unwrap();
    let put_new = seen
        .iter()
        .position(is_put_of(&rig.bucket.name, "doc.txt"))
        .unwrap();
    assert!(
        copied < put_new,
        "the old content is copied before the key is written"
    );
}

#[tokio::test]
async fn the_last_file_of_an_implied_directory_leaves_a_marker_when_it_is_renamed() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "dir/only.txt", b"x").await;
    rig.backend
        .rename(&path("dir/only.txt"), &path("elsewhere.txt"), false)
        .await
        .unwrap();

    let dir = rig.smb.open_dir("dir").await.unwrap();
    assert!(rig.smb.list(dir.id, "*").await.is_empty());
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "dir/only.txt").await, None);
    assert_eq!(remote(&rig, "elsewhere.txt").await.unwrap(), b"x");
    assert!(remote(&rig, "dir/").await.is_some());
    assert!(rig.smb.open_dir("dir").await.is_ok());
}

#[tokio::test]
async fn nested_implied_directories_each_get_a_marker() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "a/b/c/only.txt", b"x").await;
    rig.backend.unlink(&path("a/b/c/only.txt")).await.unwrap();
    sync(&rig.backend).await.unwrap();
    for dir in ["a/", "a/b/", "a/b/c/"] {
        assert!(remote(&rig, dir).await.is_some(), "{dir}");
    }
    assert!(rig.smb.open_dir("a/b/c").await.is_ok());
}

#[tokio::test]
async fn a_marker_the_store_cannot_hold_is_skipped_and_the_delete_goes_on() {
    let rig =
        unlink_last_file_with_marker_refused(409, "ExistingObjectIsDirectory", usize::MAX).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "dir/only.txt").await, None);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_marker_the_store_refuses_for_good_keeps_the_object_in_the_bucket() {
    let rig = unlink_last_file_with_marker_refused(403, "AccessDenied", usize::MAX).await;
    let error = sync(&rig.backend).await.unwrap_err();
    assert_eq!(error.http_status(), Some(403));
    assert!(
        remote(&rig, "dir/only.txt").await.is_some(),
        "the last file stays until its directory has a marker"
    );
}

#[tokio::test]
async fn a_marker_refused_with_another_conflict_keeps_the_object_in_the_bucket() {
    let rig = unlink_last_file_with_marker_refused(409, "InvalidBucketState", usize::MAX).await;
    let error = sync(&rig.backend).await.unwrap_err();
    assert_eq!(error.http_status(), Some(409));
    assert!(remote(&rig, "dir/only.txt").await.is_some());
}

#[tokio::test]
async fn an_unlink_of_a_name_that_is_not_there_says_so() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "f.txt", b"x").await;
    assert!(matches!(
        rig.backend.unlink(&path("nope.txt")).await,
        Err(SmbError::NotFound)
    ));
    assert!(matches!(
        rig.backend.unlink(&path("nope/f.txt")).await,
        Err(SmbError::PathNotFound)
    ));
    assert!(matches!(
        rig.backend.unlink(&path("f.txt/x")).await,
        Err(SmbError::PathNotFound)
    ));
    assert!(matches!(
        rig.backend
            .rename(&path("nope.txt"), &path("x.txt"), false)
            .await,
        Err(SmbError::NotFound)
    ));
}

#[tokio::test]
async fn an_unlink_during_a_store_request_keeps_the_key_from_being_deleted_until_the_request_ends()
{
    let mut rig = Rig::writable_with(held).await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "slow.txt"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    make(&mut rig, "slow.txt", b"in flight").await;
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "slow.txt")).await;

    rig.backend.unlink(&path("slow.txt")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(deletes(&rig), 0, "the request may still write the key");
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "slow.txt").await, None);
    assert_eq!(deletes(&rig), 1);
}

#[tokio::test]
async fn a_rename_onto_a_file_whose_upload_is_in_flight_waits_for_the_request() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "from.txt", b"from").await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "to.txt"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    make(&mut rig, "to.txt", b"stale upload").await;
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "to.txt")).await;

    rig.backend
        .rename(&path("from.txt"), &path("to.txt"), true)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(copies(&rig), 0, "the stale request may still write the key");
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "to.txt").await.unwrap(), b"from");
    assert_eq!(remote(&rig, "from.txt").await, None);
}

#[tokio::test]
async fn a_swap_of_two_names_through_a_third_ends_with_the_contents_swapped() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"a").await;
    put(rig.store(), "b.txt", b"b").await;
    rotate(&rig, &["a.txt", "b.txt"]).await;
    assert_eq!(rig.smb.contents("a.txt", 10).await, b"b");
    assert_eq!(rig.smb.contents("b.txt", 10).await, b"a");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"b");
    assert_eq!(remote(&rig, "b.txt").await.unwrap(), b"a");
    assert_eq!(remote(&rig, "ring.tmp").await, None);
    assert_eq!(rig.smb.contents("a.txt", 10).await, b"b");
    assert_eq!(rig.smb.contents("b.txt", 10).await, b"a");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn a_ring_of_three_names_ends_with_each_name_holding_the_next_content() {
    let mut rig = Rig::writable_with(held).await;
    for (name, body) in [("a.txt", "A"), ("b.txt", "B"), ("c.txt", "C")] {
        put(rig.store(), name, body.as_bytes()).await;
    }
    rotate(&rig, &["a.txt", "b.txt", "c.txt"]).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"B");
    assert_eq!(remote(&rig, "b.txt").await.unwrap(), b"C");
    assert_eq!(remote(&rig, "c.txt").await.unwrap(), b"A");
    assert_eq!(remote(&rig, "ring.tmp").await, None);
    assert_eq!(rig.smb.contents("c.txt", 10).await, b"A");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn a_rename_during_the_copy_of_a_rename_leaves_the_content_at_the_last_name() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"original").await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(is_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_copy).await;
    rig.backend
        .rename(&path("b.txt"), &path("c.txt"), false)
        .await
        .unwrap();
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "c.txt").await.unwrap(), b"original");
    assert_eq!(remote(&rig, "a.txt").await, None);
    assert_eq!(remote(&rig, "b.txt").await, None);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(rig.smb.contents("c.txt", 100).await, b"original");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_rename_during_the_copy_onto_itself_of_new_times_keeps_the_object_for_the_next_copy() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"original").await;
    let file = rig.smb.create("a.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
    rig.smb.close(file.id).await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(is_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_copy).await;
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    let (bytes, head) = stored(&rig, "b.txt").await;
    assert_eq!(bytes, b"original");
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
    assert_eq!(remote(&rig, "a.txt").await, None);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn an_editor_that_keeps_a_backup_twice_leaves_no_key_to_delete_behind() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "doc", b"version 1").await;
    rig.backend
        .rename(&path("doc"), &path("doc.bak"), false)
        .await
        .unwrap();
    make(&mut rig, "doc", b"version 2").await;
    rig.backend
        .rename(&path("doc"), &path("doc.bak"), true)
        .await
        .unwrap();
    let file = rig.smb.create("doc", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, b"version 3").await;
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    for record in all_records(&rig) {
        assert!(
            matches!(record, Record::Entry(_)),
            "no record names a key to delete"
        );
    }

    let mut rig = rig.restart_with(held).await;
    assert_eq!(rig.smb.contents("doc", 100).await, b"version 3");
    assert_eq!(rig.smb.contents("doc.bak", 100).await, b"version 2");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "doc").await.unwrap(), b"version 3");
    assert_eq!(remote(&rig, "doc.bak").await.unwrap(), b"version 2");
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_backup_replaced_by_a_newer_one_leaves_the_old_key_to_the_file_that_replaced_it() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "doc", b"version 1").await;
    rig.backend
        .rename(&path("doc"), &path("doc.bak"), false)
        .await
        .unwrap();
    make(&mut rig, "doc", b"version 2").await;
    rig.backend
        .rename(&path("doc"), &path("doc.bak"), true)
        .await
        .unwrap();
    let records = all_records(&rig);
    assert_eq!(records.len(), 1, "{records:?}");
    let entry = entry_of(&records[0]);
    assert_eq!(entry.key, "doc.bak");
    assert_eq!(entry.gone, ["doc"]);
}

#[tokio::test]
async fn two_files_moved_out_of_one_directory_at_once_leave_it_a_marker() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a", b"a").await;
    put(rig.store(), "d/b", b"b").await;
    rig.backend
        .rename(&path("d/a"), &path("x"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("d/b"), &path("y"), false)
        .await
        .unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_delete).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "x").await.unwrap(), b"a");
    assert_eq!(remote(&rig, "y").await.unwrap(), b"b");
    assert!(remote(&rig, "d/a").await.is_none() && remote(&rig, "d/b").await.is_none());
    assert!(
        remote(&rig, "d/").await.is_some(),
        "the directory has a marker"
    );
    assert!(rig.smb.open_dir("d").await.is_ok());
}

#[tokio::test]
async fn a_new_file_below_a_name_that_is_to_be_deleted_waits_for_the_delete() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d", b"a file").await;
    put(rig.store(), "other", b"x").await;
    rig.backend.unlink(&path("d")).await.unwrap();
    // The marker of the new directory never reaches the store, which would
    // refuse it next to the file.
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "d/"),
        Fault::Reply(Reply::new(200, "").header("etag", "\"marker\"")),
        usize::MAX,
    );
    let dir = rig.smb.create("d", create_dir()).await.unwrap();
    rig.smb.close(dir.id).await;
    let file = rig.smb.create("d/x", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, b"below").await;
    rig.smb.close(file.id).await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    // The keys to delete wait for a pause in the deletes, which this puts
    // after the time the file is due.
    rig.backend.unlink(&path("other")).await.unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "d/x").await.unwrap(), b"below");
    assert_eq!(remote(&rig, "d").await.unwrap_or_default(), b"" as &[u8]);
    let seen = rig.proxy.seen();
    let delete = seen.iter().position(is_delete).unwrap();
    let put_below = seen
        .iter()
        .position(is_put_of(&rig.bucket.name, "d/x"))
        .unwrap();
    assert!(delete < put_below, "the file goes before the key below it");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn an_upload_id_of_a_copy_in_parts_is_in_the_record_while_it_runs() {
    let rig = Rig::writable_with(held).await;
    rig.backend.limit_copy(6 * MIB as u64);
    let data = pattern(5, 14 * MIB);
    put(rig.store(), "big.bin", &data).await;
    rig.backend
        .rename(&path("big.bin"), &path("big2.bin"), false)
        .await
        .unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_part_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_part_copy).await;

    let records = all_records(&rig);
    assert_eq!(records.len(), 1);
    let record = entry_of(&records[0]);
    assert!(record.upload_id.is_some(), "{record:?}");
    assert_eq!(record.upload_key.as_deref(), Some("big2.bin"));
    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "big2.bin").await.0, data);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_swap_leaves_no_file_with_the_name_another_file_has_taken_to_delete() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"a").await;
    put(rig.store(), "b.txt", b"b").await;
    rotate(&rig, &["a.txt", "b.txt"]).await;
    let (reached, resume) = rig.backend.pause_after_landing();
    rig.backend.hold_uploads(false);
    reached.notified().await;

    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"b");
    for record in all_records(&rig) {
        let gone = &entry_of(&record).gone;
        assert!(!gone.iter().any(|key| key == "a.txt"), "{gone:?}");
    }
    resume.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"b");
    assert_eq!(remote(&rig, "b.txt").await.unwrap(), b"a");
    assert_eq!(rig.smb.contents("b.txt", 10).await, b"a");
}

#[tokio::test]
async fn a_multipart_upload_over_a_replaced_file_knows_the_etag_the_key_had() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "to.bin", &pattern(1, 6 * MIB)).await;
    let file = rig.smb.create("from.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &pattern(2, 6 * MIB)).await;
    rig.smb.close(file.id).await;
    // The replaced file was looked up, so its base ETag is known.
    let open = rig.smb.create("to.bin", open_rw()).await.unwrap();
    rig.smb.close(open.id).await;
    rig.backend
        .rename(&path("from.bin"), &path("to.bin"), true)
        .await
        .unwrap();
    lost_complete(&rig, "to.bin").await;
}

#[tokio::test]
async fn a_multipart_upload_over_a_deleted_name_asks_for_the_etag_the_key_has() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "to.bin", &pattern(1, 6 * MIB)).await;
    rig.backend.unlink(&path("to.bin")).await.unwrap();
    let file = rig.smb.create("to.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &pattern(2, 6 * MIB)).await;
    rig.smb.close(file.id).await;
    lost_complete(&rig, "to.bin").await;
    assert!(rig.proxy.count(is_head_of(&rig.bucket.name, "to.bin")) >= 1);
}

#[tokio::test]
async fn a_marker_refused_as_an_aborted_operation_is_tried_again() {
    let rig = unlink_last_file_with_marker_refused(409, "OperationAborted", 1).await;
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "dir/only.txt").await, None);
    assert!(remote(&rig, "dir/").await.is_some());
}

#[tokio::test]
async fn times_set_on_a_directory_with_a_marker_keep_the_other_metadata_of_the_marker() {
    let mut rig = Rig::writable_with(uploading).await;
    let metadata = Metadata {
        content_type: Some("application/x-directory".to_owned()),
        user: [("owner".to_owned(), "someone".to_owned())].into(),
        ..Default::default()
    };
    rig.store()
        .put_object("kept/", bytes::Bytes::new(), &metadata, foreground())
        .await
        .unwrap();
    let dir = rig
        .smb
        .create("kept", Spec::DIR.access(WRITE_ATTRIBUTES | READ))
        .await
        .unwrap();
    assert_eq!(rig.smb.set_write_time(dir.id, 1_500_000_000).await, 0);
    rig.smb.close(dir.id).await;
    sync(&rig.backend).await.unwrap();

    let head = rig
        .store()
        .head_object("kept/", foreground())
        .await
        .unwrap();
    assert_eq!(
        head.metadata.user.get("owner").map(String::as_str),
        Some("someone")
    );
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_case_only_rename_of_a_file_stored_here_and_given_times_keeps_the_object() {
    let mut rig = Rig::writable_with(uploading).await;
    make(&mut rig, "Report.txt", b"stored here").await;
    sync(&rig.backend).await.unwrap();
    let file = rig.smb.create("Report.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(file.id, 1_500_000_000).await, 0);
    rig.smb.close(file.id).await;
    rig.backend
        .rename(&path("Report.txt"), &path("report.txt"), false)
        .await
        .unwrap();
    let folds = folds_case(&rig).await;
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "report.txt").await.unwrap(), b"stored here");
    if !folds {
        assert_eq!(remote(&rig, "Report.txt").await, None);
    }
    assert_eq!(rig.smb.contents("report.txt", 100).await, b"stored here");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_case_only_rename_of_a_file_copied_in_parts_keeps_the_object() {
    let mut rig = Rig::writable_with(uploading).await;
    rig.backend.limit_copy(6 * MIB as u64);
    let data = pattern(2, 7 * MIB);
    put(rig.store(), "Big.bin", &data).await;
    rig.backend
        .rename(&path("Big.bin"), &path("big2.bin"), false)
        .await
        .unwrap();
    sync(&rig.backend).await.unwrap();
    rig.backend
        .rename(&path("big2.bin"), &path("BIG2.bin"), false)
        .await
        .unwrap();
    let folds = folds_case(&rig).await;
    sync(&rig.backend).await.unwrap();

    assert_eq!(stored(&rig, "BIG2.bin").await.0, data);
    if !folds {
        assert_eq!(remote(&rig, "big2.bin").await, None);
    }
    assert_eq!(rig.smb.contents("big2.bin", 60_000).await, data.to_vec());
}

#[tokio::test]
async fn a_key_in_another_case_than_an_open_stored_file_is_deleted_only_if_it_is_another_object() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "Doc", b"old").await;
    rig.backend.hold_sweeps(true);
    rig.backend.unlink(&path("Doc")).await.unwrap();
    let file = rig.smb.create("doc", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, b"new content").await;
    // The new file is stored, and open still, before the key `Doc` is
    // deleted.
    wait_until_async("the new file is stored", async || {
        remote(&rig, "doc").await.as_deref() == Some(b"new content".as_slice())
    })
    .await;
    rig.backend.hold_sweeps(false);
    sync(&rig.backend).await.unwrap();
    rig.smb.close(file.id).await;
    let folds = folds_case(&rig).await;

    assert_only_spelling(&mut rig, "doc", "Doc", b"new content", folds).await;
}

#[tokio::test]
async fn a_name_made_again_in_another_case_before_the_delete_runs_is_not_lost() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "Doc", b"old").await;
    rig.backend.unlink(&path("Doc")).await.unwrap();
    make(&mut rig, "doc", b"new content").await;
    // A delete that reaches the store is held, so it can land after the new
    // file does.
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    tokio::time::sleep(Duration::from_millis(600)).await;
    gate.notify_one();
    let folds = folds_case(&rig).await;
    sync(&rig.backend).await.unwrap();

    assert_only_spelling(&mut rig, "doc", "Doc", b"new content", folds).await;
}

#[tokio::test]
async fn a_crash_between_a_fill_and_its_seal_leaves_the_source_for_the_next_backend() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(3, 2 * MIB);
    put(rig.store(), "old.bin", &data).await;
    rig.backend
        .rename(&path("old.bin"), &path("new.bin"), false)
        .await
        .unwrap();
    let file = rig.smb.create("new.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"head").await, Ok(4));
    rig.smb.close(file.id).await;
    // A new file takes the name the source has.
    let newcomer = rig.smb.create("old.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, newcomer.id, b"newcomer").await;
    assert_eq!(rig.smb.flush(newcomer.id).await, 0);
    rig.smb.close(newcomer.id).await;

    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    wait_until("the newcomer is put off", || rig.backend.parks() >= 1).await;
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "new.bin")), 0);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "old.bin")), 0);
    let (bucket, proxy, cache) = crash(rig, resume).await;

    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();
    let mut want = data.to_vec();
    want[..4].copy_from_slice(b"head");
    assert_eq!(remote(&rig, "new.bin").await.unwrap(), want);
    assert_eq!(remote(&rig, "old.bin").await.unwrap(), b"newcomer");
    assert_eq!(rig.smb.contents("new.bin", 60_000).await, want);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "conflicts"), 0);
}

#[tokio::test]
async fn an_unlink_between_the_last_check_of_a_job_and_its_first_request_deletes_the_key() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "u.txt", b"abc").await;
    let file = rig.smb.create("u.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"xyz").await, Ok(3));
    rig.smb.close(file.id).await;
    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    rig.backend.unlink(&path("u.txt")).await.unwrap();
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "u.txt").await, None);
    assert!(!exists(&mut rig, "u.txt").await);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "u.txt")), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn bytes_written_over_a_whole_file_and_flushed_free_the_names_that_wait_for_its_source() {
    let mut rig = Rig::writable_with(held).await;
    for (key, body) in [("s1", "Q"), ("t1", "H"), ("u1", "P")] {
        put(rig.store(), key, body.as_bytes()).await;
    }
    // The file at s2 copies from s1 and waits for nothing. The file at s1
    // copies from t1 and waits for the one at s2. The file at t1 copies from
    // u1 and waits for the one at s1.
    for (from, to) in [("s1", "s2"), ("t1", "s1"), ("u1", "t1")] {
        rig.backend
            .rename(&path(from), &path(to), false)
            .await
            .unwrap();
    }
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(is_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_copy).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(remote(&rig, "t1").await.unwrap(), b"H", "the copy waits");

    let file = rig.smb.create("s1", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"h").await, Ok(1));
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    wait_until_async("the file at t1 is stored", async || {
        remote(&rig, "t1").await.as_deref() == Some(b"P".as_slice())
    })
    .await;
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "s1").await.unwrap(), b"h");
    assert_eq!(remote(&rig, "s2").await.unwrap(), b"Q");
    assert_eq!(remote(&rig, "u1").await, None);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn two_renames_onto_one_name_without_replace_never_both_succeed() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"a").await;
    put(rig.store(), "b.txt", b"b").await;
    let (a, b, t) = (path("a.txt"), path("b.txt"), path("t.txt"));
    let (first, second) = tokio::join!(
        rig.backend.rename(&a, &t, false),
        rig.backend.rename(&b, &t, false),
    );
    let mut done = [first, second];
    done.sort_by_key(Result::is_err);
    assert!(done[0].is_ok(), "{done:?}");
    assert!(matches!(done[1], Err(SmbError::Exists)), "{done:?}");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(remote(&rig, "t.txt").await.is_some());
    let kept = u32::from(remote(&rig, "a.txt").await.is_some())
        + u32::from(remote(&rig, "b.txt").await.is_some());
    assert_eq!(kept, 1, "the file that did not move stays");
}

#[tokio::test]
async fn a_rename_that_replaces_takes_the_name_a_concurrent_rename_took() {
    let mut rig = Rig::writable_with(held).await;
    for name in ["a.txt", "b.txt", "t.txt"] {
        put(rig.store(), name, name.as_bytes()).await;
    }
    let (a, b, t) = (path("a.txt"), path("b.txt"), path("t.txt"));
    let (first, second) = tokio::join!(
        rig.backend.rename(&a, &t, true),
        rig.backend.rename(&b, &t, true),
    );
    first.unwrap();
    second.unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let there = rig.smb.contents("t.txt", 100).await;
    assert!(there == b"a.txt" || there == b"b.txt", "{there:?}");
    assert_eq!(remote(&rig, "t.txt").await.unwrap(), there);
    assert_eq!(remote(&rig, "a.txt").await, None);
    assert_eq!(remote(&rig, "b.txt").await, None);
}

#[tokio::test]
async fn a_multipart_copy_over_a_file_whose_upload_is_in_flight_asks_for_the_etag_the_key_has() {
    let mut rig = Rig::writable_with(held).await;
    rig.backend.limit_copy(5 * MIB as u64);
    put(rig.store(), "to.bin", &pattern(1, 6 * MIB)).await;
    put(rig.store(), "from.bin", &pattern(2, 6 * MIB)).await;
    // The file at to.bin is written over, so its upload is multipart.
    let file = rig.smb.create("to.bin", open_rw()).await.unwrap();
    fill(&mut rig.smb, file.id, &pattern(3, 6 * MIB)).await;
    rig.smb.close(file.id).await;
    let (reached, resume) = rig.backend.pause_after_store();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    // The store has the new object at to.bin, which the file does not know yet.
    rig.proxy.inject(
        is_complete,
        Fault::Reply(Reply::error(503, "ServiceUnavailable")),
        1,
    );
    rig.proxy.inject(
        is_complete,
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        1,
    );
    rig.backend
        .rename(&path("from.bin"), &path("to.bin"), true)
        .await
        .unwrap();
    resume.notify_one();
    let error = sync(&rig.backend).await.unwrap_err();

    assert_eq!(error.code(), Some("NoSuchUpload"));
    assert!(stored(&rig, "to.bin").await.0 == pattern(3, 6 * MIB).to_vec());
    assert_eq!(rig.backend.failures().len(), 1);
}

#[tokio::test]
async fn a_copy_whose_record_cannot_be_written_keeps_its_source_from_being_overwritten() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "old.bin", b"original").await;
    rig.backend
        .rename(&path("old.bin"), &path("new.bin"), false)
        .await
        .unwrap();
    let newcomer = rig.smb.create("old.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, newcomer.id, b"newcomer").await;
    assert_eq!(rig.smb.flush(newcomer.id).await, 0);
    rig.smb.close(newcomer.id).await;
    // The record before the copy is written; the ones after it fail.
    rig.backend.hooks().record_write_skips.store(1, SeqCst);
    rig.backend.hooks().record_writes.store(2, SeqCst);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap_err();
    wait_until("the newcomer is put off", || rig.backend.parks() >= 1).await;

    assert_eq!(remote(&rig, "new.bin").await.unwrap(), b"original");
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "old.bin")), 0);
    assert_eq!(remote(&rig, "old.bin").await.unwrap(), b"original");
}

#[tokio::test]
async fn a_key_in_another_case_than_a_file_that_left_the_overlay_is_not_deleted_as_its_object() {
    let mut rig = Rig::writable_with(uploading).await;
    rig.backend.hold_sweeps(true);
    put(rig.store(), "Doc", b"old").await;
    rig.backend.unlink(&path("Doc")).await.unwrap();
    make(&mut rig, "doc", b"new content").await;
    wait_until_async("the new file is stored and has left", async || {
        rig.backend.overlay_len() == 0
            && remote(&rig, "doc").await.as_deref() == Some(b"new content".as_slice())
    })
    .await;
    // The file that was stored under the other spelling is no longer in the
    // overlay when the delete of `Doc` is let go.
    let folds = folds_case(&rig).await;
    rig.backend.hold_sweeps(false);
    sync(&rig.backend).await.unwrap();

    assert_only_spelling(&mut rig, "doc", "Doc", b"new content", folds).await;
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_key_another_file_owns_to_delete_in_another_case_is_not_deleted_as_the_object_stored() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "Old.txt", b"old").await;
    rig.backend
        .rename(&path("Old.txt"), &path("moved.txt"), false)
        .await
        .unwrap();
    let (reached, resume) = rig.backend.pause_after_landing();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    // The renamed file waits to delete `Old.txt`, and a new file is stored
    // under the other spelling of the name and leaves the overlay.
    make(&mut rig, "old.txt", b"new content").await;
    wait_until_async("the new file is stored and has left", async || {
        rig.backend.overlay_len() == 1
            && remote(&rig, "old.txt").await.as_deref() == Some(b"new content".as_slice())
    })
    .await;
    resume.notify_one();
    let folds = folds_case(&rig).await;
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "moved.txt").await.unwrap(), b"old");
    assert_eq!(remote(&rig, "old.txt").await.unwrap(), b"new content");
    if !folds {
        assert_eq!(remote(&rig, "Old.txt").await, None);
    }
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_file_is_not_stored_while_a_delete_of_the_same_name_in_another_case_is_in_flight() {
    let mut rig = Rig::writable_with(uploading).await;
    put(rig.store(), "Doc", b"old").await;
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.unlink(&path("Doc")).await.unwrap();
    wait_for_requests(&rig.proxy, 1, is_delete).await;
    make(&mut rig, "doc", b"new content").await;
    wait_until("the file is put off", || rig.backend.parks() >= 1).await;
    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "doc")),
        0,
        "the store may run the delete after the write"
    );
    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    let folds = folds_case(&rig).await;

    assert_only_spelling(&mut rig, "doc", "Doc", b"new content", folds).await;
}

#[tokio::test]
async fn a_key_is_not_deleted_while_a_request_stores_the_same_name_in_another_case() {
    let mut rig = Rig::writable_with(uploading).await;
    rig.backend.hold_sweeps(true);
    put(rig.store(), "Doc", b"old").await;
    put(rig.store(), "sweep.marker", b"x").await;
    rig.backend.unlink(&path("Doc")).await.unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "doc"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    make(&mut rig, "doc", b"new content").await;
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "doc")).await;
    rig.backend.hold_sweeps(false);
    sweep(&rig).await;
    assert_eq!(
        rig.proxy.count(deletes_key("Doc")),
        0,
        "the write may still land"
    );
    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    let folds = folds_case(&rig).await;

    assert_eq!(remote(&rig, "doc").await.unwrap(), b"new content");
    if !folds {
        assert_eq!(remote(&rig, "Doc").await, None);
    }
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_renamed_file_keeps_its_content_when_a_new_file_takes_its_old_name_in_another_case() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "Report.docx", b"version 1").await;
    rig.backend
        .rename(&path("Report.docx"), &path("Report.bak"), false)
        .await
        .unwrap();
    make(&mut rig, "report.docx", b"version 2").await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(is_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_copy).await;
    wait_until("the new file is put off", || rig.backend.parks() == 1).await;
    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "report.docx")),
        0,
        "the copy is still reading the old content"
    );
    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    let folds = folds_case(&rig).await;

    assert_eq!(remote(&rig, "Report.bak").await.unwrap(), b"version 1");
    assert_eq!(remote(&rig, "report.docx").await.unwrap(), b"version 2");
    if !folds {
        assert_eq!(remote(&rig, "Report.docx").await, None);
    }
    assert_eq!(rig.smb.contents("Report.bak", 100).await, b"version 1");
    assert_eq!(rig.smb.contents("report.docx", 100).await, b"version 2");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_key_to_delete_waits_while_a_file_copies_from_the_same_name_in_another_case() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "Src.txt", b"original").await;
    put(rig.store(), "sweep.marker", b"x").await;
    rig.backend
        .rename(&path("Src.txt"), &path("Dst.txt"), false)
        .await
        .unwrap();
    // A file made at the name the rename left, and deleted again, leaves
    // the delete of its key.
    make(&mut rig, "src.txt", b"scratch").await;
    rig.backend.unlink(&path("src.txt")).await.unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(is_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_copy).await;
    sweep(&rig).await;
    assert_eq!(
        rig.proxy.count(deletes_key("src.txt")),
        0,
        "the object is still being copied"
    );
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "Dst.txt").await.unwrap(), b"original");
    assert_eq!(remote(&rig, "src.txt").await, None);
    assert!(!exists(&mut rig, "src.txt").await);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn jobs_that_store_names_in_another_case_never_run_together() {
    let mut rig = Rig::writable_with(uploading).await;
    let gate = Arc::new(Notify::new());
    let first = is_put_of(&rig.bucket.name, "Doc");
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "Doc"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    make(&mut rig, "Doc", b"first").await;
    wait_for_requests(&rig.proxy, 1, first).await;
    rig.backend.unlink(&path("Doc")).await.unwrap();
    make(&mut rig, "doc", b"second").await;
    wait_until("the second job is put off", || rig.backend.parks() == 1).await;
    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "doc")),
        0,
        "the request for the other spelling is still in flight"
    );
    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    let folds = folds_case(&rig).await;

    assert_only_spelling(&mut rig, "doc", "Doc", b"second", folds).await;
}

#[tokio::test]
async fn an_unlink_deletes_the_keys_the_file_owns_and_not_the_key_it_copies_from() {
    leave_a_stale_base(true).await;
}

#[tokio::test]
async fn a_replaced_file_gives_up_the_keys_it_owns_and_not_the_key_it_copies_from() {
    leave_a_stale_base(false).await;
}

#[tokio::test]
async fn a_backend_that_ends_while_a_stored_file_settles_other_spellings_keeps_the_object() {
    let mut rig = Rig::writable_with(held).await;
    rig.backend.hold_sweeps(true);
    put(rig.store(), "Doc", b"old").await;
    rig.backend.unlink(&path("Doc")).await.unwrap();
    make(&mut rig, "doc", b"new content").await;
    let gate = Arc::new(Notify::new());
    let head = is_head_of(&rig.bucket.name, "Doc");
    let heads = rig.proxy.count(&head);
    rig.proxy.inject(
        is_head_of(&rig.bucket.name, "Doc"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, heads + 1, head).await;
    assert_eq!(
        left(&rig, "records"),
        2,
        "the file keeps its record until the keys it may replace are settled"
    );
    let (bucket, proxy, cache) = crash(rig, gate).await;

    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    sync(&rig.backend).await.unwrap();
    let folds = folds_case(&rig).await;

    assert_only_spelling(&mut rig, "doc", "Doc", b"new content", folds).await;
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_file_written_over_keeps_its_source_until_a_record_says_it_holds_every_byte() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.bin", b"alpha").await;
    rig.backend
        .rename(&path("a.bin"), &path("b.bin"), false)
        .await
        .unwrap();
    let file = rig.smb.create("b.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"BETA!").await, Ok(5));
    assert!(
        rig.backend.key_in_use("a.bin"),
        "the record the rename wrote still needs it"
    );
    assert_eq!(rig.smb.flush(file.id).await, 0);
    assert!(!rig.backend.key_in_use("a.bin"));
    rig.smb.close(file.id).await;
    make(&mut rig, "a.bin", b"newcomer").await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "b.bin").await.unwrap(), b"BETA!");
    assert_eq!(remote(&rig, "a.bin").await.unwrap(), b"newcomer");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_flushed_file_is_recovered_after_a_crash_that_follows_the_rewrite_of_its_source() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.bin", b"alpha").await;
    rig.backend
        .rename(&path("a.bin"), &path("b.bin"), false)
        .await
        .unwrap();
    let file = rig.smb.create("b.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"BETA!").await, Ok(5));
    assert!(rig.backend.key_in_use("a.bin"), "no record covers the file");
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    make(&mut rig, "a.bin", b"newcomer").await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, "b.bin"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "b.bin")).await;
    wait_until_async("the new file is stored", async || {
        remote(&rig, "a.bin").await.as_deref() == Some(b"newcomer".as_slice())
    })
    .await;
    let (bucket, proxy, cache) = crash(rig, gate).await;

    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    assert_eq!(rig.smb.contents("b.bin", 100).await, b"BETA!");
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "b.bin").await.unwrap(), b"BETA!");
    assert_eq!(remote(&rig, "a.bin").await.unwrap(), b"newcomer");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_lookup_that_found_a_name_before_it_was_unlinked_leaves_it_to_the_rename_that_takes_it() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "t.txt", b"old t").await;
    make(&mut rig, "f.txt", b"f content").await;
    let (found, resume_open) = rig.backend.pause_after_lookup();
    let backend = rig.backend.clone();
    let open = tokio::spawn(async move {
        backend
            .open(&path("t.txt"), OpenOptions::default())
            .await
            .map(|_| ())
    });
    found.notified().await;
    // The open has seen the object. It is deleted, and a rename reserves
    // its name, before the open takes a hold on anything.
    rig.backend.unlink(&path("t.txt")).await.unwrap();
    let (reserved, resume_rename) = rig.backend.pause_after_reserve();
    let backend = rig.backend.clone();
    let rename =
        tokio::spawn(async move { backend.rename(&path("f.txt"), &path("t.txt"), false).await });
    reserved.notified().await;
    resume_open.notify_one();
    let opened = open.await.unwrap();
    resume_rename.notify_one();
    rename.await.unwrap().unwrap();

    assert!(matches!(opened, Err(SmbError::NotFound)), "{opened:?}");
    assert_eq!(rig.backend.overlay_len(), 1, "one file holds the name");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "t.txt").await.unwrap(), b"f content");
    assert_eq!(remote(&rig, "f.txt").await, None);
    assert_eq!(rig.smb.contents("t.txt", 100).await, b"f content");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_multipart_upload_over_a_name_another_file_took_and_left_knows_the_etag_the_key_has() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "doc.bin", &pattern(1, 6 * MIB)).await;
    rig.backend
        .rename(&path("doc.bin"), &path("old.bin"), false)
        .await
        .unwrap();
    make(&mut rig, "doc.bin", &pattern(2, 6 * MIB)).await;
    // The file at old.bin is written over in full and flushed, so the new
    // file can take doc.bin while the old one waits to be stored.
    let file = rig.smb.create("old.bin", open_rw()).await.unwrap();
    fill(&mut rig.smb, file.id, &pattern(3, 6 * MIB)).await;
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let gate = Arc::new(Notify::new());
    let creating = is_create_of(&rig.bucket.name, "old.bin");
    rig.proxy.inject(
        is_create_of(&rig.bucket.name, "old.bin"),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, creating).await;
    wait_until_async("the new file is stored and has left", async || {
        rig.backend.overlay_len() == 1
            && remote(&rig, "doc.bin").await.as_deref() == Some(pattern(2, 6 * MIB).as_ref())
    })
    .await;
    // The file at old.bin goes back to the name, which another file has had
    // since it left. Its base is still the object that was there before.
    rig.backend
        .rename(&path("old.bin"), &path("doc.bin"), true)
        .await
        .unwrap();
    rig.proxy.inject(
        is_complete,
        Fault::Reply(Reply::error(503, "ServiceUnavailable")),
        1,
    );
    rig.proxy.inject(
        is_complete,
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        1,
    );
    gate.notify_one();
    let error = sync(&rig.backend).await.unwrap_err();

    assert_eq!(error.code(), Some("NoSuchUpload"));
    assert!(
        stored(&rig, "doc.bin").await.0 == pattern(2, 6 * MIB).to_vec(),
        "the object is the one that was there"
    );
    assert_eq!(rig.backend.failures().len(), 1);
}
