//! Files whose last handle closes are saved in the cache directory.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use tokio::sync::Notify;

use super::fixture::{pattern, put};
use super::moves::{crash, path, remote};
use super::share::Rig;
use super::uploads::{fill, held, left, stored, sync};
use super::writes::{changes, create_file, open_rw, records};
use crate::ShareBackend;
use crate::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;

/// The files of the `records` directory of `cache`, with their bytes.
fn record_files(cache: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(cache.join("records"))
        .unwrap()
        .map(|file| {
            let file = file.unwrap();
            (
                file.file_name().to_string_lossy().into_owned(),
                fs::read(file.path()).unwrap(),
            )
        })
        .collect()
}

/// Waits for the task a test paused to reach its pause. Fails if it does not
/// within 10 s.
async fn at_pause(reached: &Notify) {
    tokio::time::timeout(Duration::from_secs(10), reached.notified())
        .await
        .expect("the task reached its pause");
}

#[tokio::test]
async fn a_file_closed_without_a_flush_survives_a_crash_and_reaches_the_bucket() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(3, 150_000);
    let file = rig.smb.create("closed.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close(file.id).await;
    assert_eq!(records(&rig).len(), 1);
    assert_eq!(records(&rig)[0].local.as_ref().unwrap().len, 150_000);
    assert_eq!(changes(&rig), 0, "nothing reached the bucket yet");

    let mut rig = rig.restart_with(held).await;
    assert_eq!(rig.backend.overlay_len(), 1);
    assert_eq!(rig.smb.contents("closed.bin", 60_000).await, data.to_vec());

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "closed.bin").await.0, data.to_vec());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn a_file_that_stays_open_is_saved_when_its_upload_starts() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(5, 90_000);
    let first = rig.smb.create("shared.bin", create_file()).await.unwrap();
    let second = rig.smb.open("shared.bin").await.unwrap();
    fill(&mut rig.smb, first.id, &data).await;
    rig.smb.close(first.id).await;
    assert!(
        records(&rig).is_empty(),
        "a handle is still open on the file"
    );

    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    at_pause(&reached).await;
    let saved = records(&rig);
    assert_eq!(saved.len(), 1, "the job saved the file before it started");
    assert_eq!(saved[0].local.as_ref().unwrap().len, 90_000);
    resume.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "shared.bin").await.0, data.to_vec());
    rig.smb.close(second.id).await;
}

#[tokio::test]
async fn a_close_does_not_wait_for_the_save() {
    let mut rig = Rig::writable_with(held).await;
    let (reached, resume) = rig.backend.pause_before_close_seal();
    let file = rig.smb.create("slow.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, b"slow").await;
    tokio::time::timeout(Duration::from_secs(10), rig.smb.close_now(file.id))
        .await
        .expect("the close answers while the save waits");
    at_pause(&reached).await;
    assert!(records(&rig).is_empty());

    resume.notify_one();
    rig.smb.wait_for_saves().await;
    assert_eq!(records(&rig).len(), 1);
}

#[tokio::test]
async fn a_sync_right_after_a_close_stores_the_file_and_the_late_save_leaves_no_record() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(9, 40_000);
    let (reached, resume) = rig.backend.pause_before_close_seal();
    let file = rig.smb.create("quick.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close_now(file.id).await;
    at_pause(&reached).await;

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "quick.bin").await.0, data.to_vec());

    resume.notify_one();
    rig.smb.wait_for_saves().await;
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn the_end_of_the_backend_waits_for_the_save_of_a_closed_file() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(7, 20_000);
    let (reached, resume) = rig.backend.pause_before_close_seal();
    let file = rig.smb.create("late.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close_now(file.id).await;
    at_pause(&reached).await;
    assert!(records(&rig).is_empty());

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(rig.smb.contents("late.bin", 30_000).await, data.to_vec());
}

#[tokio::test]
async fn a_file_renamed_while_its_save_waits_comes_back_at_its_new_name() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(11, 30_000);
    let (reached, resume) = rig.backend.pause_before_close_seal();
    let file = rig.smb.create("before.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close_now(file.id).await;
    at_pause(&reached).await;
    rig.backend
        .rename(&path("before.bin"), &path("after.bin"), false)
        .await
        .unwrap();
    resume.notify_one();
    rig.smb.wait_for_saves().await;
    let keys: Vec<String> = records(&rig).into_iter().map(|record| record.key).collect();
    assert_eq!(keys, ["after.bin"]);

    let mut rig = rig.restart_with(held).await;
    assert_eq!(
        rig.smb.open("before.bin").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(rig.smb.contents("after.bin", 40_000).await, data.to_vec());
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "after.bin").await.0, data.to_vec());
    assert_eq!(remote(&rig, "before.bin").await, None);
}

#[tokio::test]
async fn a_file_deleted_while_its_save_waits_is_not_recorded_and_stays_deleted() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "doomed.bin", pattern(1, 1000)).await;
    let file = rig.smb.create("doomed.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 10, b"changed").await, Ok(7));
    let (reached, resume) = rig.backend.pause_before_close_seal();
    rig.smb.close_now(file.id).await;
    at_pause(&reached).await;
    rig.backend.unlink(&path("doomed.bin")).await.unwrap();
    let deleted = record_files(rig.cache_dir());
    assert_eq!(deleted.len(), 1, "the record of the key to delete");

    resume.notify_one();
    rig.smb.wait_for_saves().await;
    assert_eq!(record_files(rig.cache_dir()), deleted);
    assert!(records(&rig).is_empty());

    let mut rig = rig.restart_with(held).await;
    assert_eq!(
        rig.smb.open("doomed.bin").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "doomed.bin").await, None);
}
