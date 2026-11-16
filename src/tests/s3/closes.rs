//! Files whose last handle closes are saved in the cache directory.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use tokio::sync::Notify;

use super::fixture::{pattern, put};
use super::moves::{crash, make, path, remote};
#[cfg(unix)]
use super::share::{FILE_OVERWRITE_IF, READ, Spec, WRITE};
use super::share::{Rig, wait_until};
use super::uploads::{fill, held, left, stored, sync};
use super::writes::{changes, create_file, open_rw, records};
use crate::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
#[cfg(unix)]
use crate::tests::util::{
    alone_in_child, exhaust_descriptors, limit_descriptors, open_descriptors,
};
use crate::{OpenOptions, ShareBackend};

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

#[tokio::test]
async fn a_closed_file_renamed_and_rewritten_while_its_upload_runs_is_stored_as_it_ends_up() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(13, 70_000);
    make(&mut rig, "before.bin", &data).await;
    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    at_pause(&reached).await;

    rig.backend
        .rename(&path("before.bin"), &path("after.bin"), false)
        .await
        .unwrap();
    let file = rig.smb.create("after.bin", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(file.id, 0, b"REWRITTEN").await, Ok(9));
    rig.smb.close(file.id).await;
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    let mut want = data.to_vec();
    want[..9].copy_from_slice(b"REWRITTEN");
    assert_eq!(stored(&rig, "after.bin").await.0, want);
    assert_eq!(remote(&rig, "before.bin").await, None);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_handle_opened_on_a_closed_file_reads_it_after_the_file_is_deleted() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(17, 30_000);
    make(&mut rig, "gone.bin", &data).await;
    let file = rig.smb.open("gone.bin").await.unwrap();
    rig.backend.unlink(&path("gone.bin")).await.unwrap();
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(
        rig.smb.read(file.id, 0, 30_000).await.unwrap(),
        data.to_vec()
    );
    rig.smb.close(file.id).await;
}

#[cfg(unix)]
#[tokio::test]
async fn closed_files_waiting_for_their_upload_hold_no_descriptor() {
    const NAME: &str = "closed_files_waiting_for_their_upload_hold_no_descriptor";
    const FILES: usize = 300;
    // The descriptors the process may open beyond those it has at the start,
    // and the most it may have open beyond them while the files are made. Both
    // are far below the number of files.
    const HEADROOM: usize = 64;
    const SLACK: usize = 24;
    if !alone_in_child(module_path!(), NAME) {
        return;
    }
    let name = |n: usize| format!("f{n:04}.bin");
    let content = |n: usize| pattern(n, 200 + n).to_vec();

    let mut rig = Rig::writable_with(held).await;
    let start = open_descriptors();
    limit_descriptors(HEADROOM);
    let mut peak = start;
    for n in 0..FILES {
        let file = rig
            .smb
            .create(&name(n), create_file())
            .await
            .unwrap_or_else(|status| panic!("create {}: {status:#x}", name(n)));
        fill(&mut rig.smb, file.id, &content(n)).await;
        rig.smb.close(file.id).await;
        peak = peak.max(open_descriptors());
    }
    assert!(
        peak <= start + SLACK,
        "{FILES} closed files: {peak} descriptors open at most, {start} at the start"
    );

    let mut rig = rig.restart_with(held).await;
    assert_eq!(rig.backend.overlay_len(), FILES);
    let recovered = open_descriptors();
    assert!(
        recovered <= start + SLACK,
        "{FILES} files recovered: {recovered} descriptors open, {start} at the start"
    );

    let mut want: Vec<Vec<u8>> = (0..FILES).map(content).collect();
    let first = rig.smb.open(&name(0)).await.unwrap();
    assert_eq!(rig.smb.read(first.id, 0, 4096).await.unwrap(), want[0]);
    let second = rig.smb.create(&name(1), open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(second.id, 0, b"EDIT").await, Ok(4));
    want[1][..4].copy_from_slice(b"EDIT");
    assert_eq!(rig.smb.read(second.id, 0, 4096).await.unwrap(), want[1]);
    rig.smb.close(first.id).await;
    rig.smb.close(second.id).await;

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    for (n, data) in want.iter().enumerate() {
        assert_eq!(&stored(&rig, &name(n)).await.0, data, "{}", name(n));
    }
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_job_opens_the_data_file_only_when_it_has_the_turn_to_change_it() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(25, 20_000);
    make(&mut rig, "turn.bin", &data).await;
    let (reached, resume) = rig.backend.pause_after_hash();
    let hold = rig.backend.hold_io("turn.bin").unwrap();
    rig.backend.hold_uploads(false);
    assert!(
        tokio::time::timeout(Duration::from_millis(600), reached.notified())
            .await
            .is_err(),
        "the job went on without the turn"
    );

    drop(hold);
    at_pause(&reached).await;
    resume.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "turn.bin").await.0, data.to_vec());
}

#[tokio::test]
async fn a_handle_dropped_without_a_close_lets_go_of_the_descriptor() {
    let mut rig = Rig::writable_with(held).await;
    make(&mut rig, "x.bin", &pattern(21, 5_000)).await;
    assert_eq!(rig.backend.data_open("x.bin"), Some(false), "no handle yet");
    let (first, _) = rig
        .backend
        .open(&path("x.bin"), OpenOptions::default())
        .await
        .unwrap();
    let (second, _) = rig
        .backend
        .open(&path("x.bin"), OpenOptions::default())
        .await
        .unwrap();
    assert_eq!(rig.backend.data_open("x.bin"), Some(true));
    drop(first);
    assert_eq!(rig.backend.data_open("x.bin"), Some(true), "one is left");
    drop(second);
    assert_eq!(rig.backend.data_open("x.bin"), Some(false));
}

#[tokio::test]
async fn a_created_file_has_its_descriptor_open_until_its_handle_closes() {
    let mut rig = Rig::writable_with(held).await;
    let file = rig.smb.create("made.bin", create_file()).await.unwrap();
    assert_eq!(rig.backend.data_open("made.bin"), Some(true));
    rig.smb.close(file.id).await;
    assert_eq!(rig.backend.data_open("made.bin"), Some(false));
}

#[tokio::test]
async fn a_reopen_does_not_wait_for_the_save_of_the_file_it_closed() {
    let mut rig = Rig::writable_with(held).await;
    let data = pattern(19, 40_000);
    rig.backend.hooks().hold_syncs.store(true, SeqCst);
    let file = rig.smb.create("busy.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close_now(file.id).await;
    wait_until("the save is in its sync", || {
        rig.backend.hooks().data_syncs.load(SeqCst) > 0
    })
    .await;
    assert!(records(&rig).is_empty());

    let again = tokio::time::timeout(Duration::from_secs(10), rig.smb.open("busy.bin"))
        .await
        .expect("the open answers while the save is in its sync")
        .unwrap();
    assert_eq!(rig.backend.data_open("busy.bin"), Some(true));
    assert_eq!(rig.smb.read(again.id, 0, 4096).await.unwrap(), data[..4096]);

    rig.backend.hooks().hold_syncs.store(false, SeqCst);
    rig.smb.close(again.id).await;
    assert_eq!(records(&rig).len(), 1);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(stored(&rig, "busy.bin").await.0, data.to_vec());
}

#[tokio::test]
async fn closes_that_do_not_wait_for_their_saves_start_only_a_few_syncs_at_once() {
    const FILES: usize = 40;
    let mut rig = Rig::writable_with(held).await;
    let at_once = rig.backend.saves_at_once();
    assert!(at_once < FILES);
    rig.backend.hooks().hold_syncs.store(true, SeqCst);
    for n in 0..FILES {
        let file = rig
            .smb
            .create(&format!("s{n:02}.bin"), create_file())
            .await
            .unwrap();
        fill(&mut rig.smb, file.id, &pattern(n, 500)).await;
        rig.smb.close_now(file.id).await;
    }
    wait_until("the saves reach their syncs", || {
        rig.backend.hooks().data_syncs.load(SeqCst) >= at_once
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rig.backend.hooks().data_syncs.load(SeqCst), at_once);
    assert_eq!(*rig.backend.saves().borrow(), FILES, "the rest wait");

    rig.backend.hooks().hold_syncs.store(false, SeqCst);
    rig.smb.wait_for_saves().await;
    assert_eq!(rig.backend.hooks().data_syncs.load(SeqCst), FILES);
    assert_eq!(records(&rig).len(), FILES);
}

#[cfg(unix)]
#[tokio::test]
async fn closes_that_do_not_wait_for_their_saves_stay_within_the_descriptor_limit() {
    const NAME: &str = "closes_that_do_not_wait_for_their_saves_stay_within_the_descriptor_limit";
    const FILES: usize = 120;
    // The descriptors the process may open beyond those it has at the start,
    // and the most it may have open beyond them while the saves are held. Both
    // are far below the number of files.
    const HEADROOM: usize = 64;
    const SLACK: usize = 24;
    if !alone_in_child(module_path!(), NAME) {
        return;
    }
    let name = |n: usize| format!("s{n:03}.bin");
    let content = |n: usize| pattern(n, 300 + n).to_vec();

    let mut rig = Rig::writable_with(held).await;
    let start = open_descriptors();
    limit_descriptors(HEADROOM);
    rig.backend.hooks().hold_syncs.store(true, SeqCst);
    let mut peak = start;
    for n in 0..FILES {
        let file = rig
            .smb
            .create(&name(n), create_file())
            .await
            .unwrap_or_else(|status| panic!("create {}: {status:#x}", name(n)));
        fill(&mut rig.smb, file.id, &content(n)).await;
        rig.smb.close_now(file.id).await;
        peak = peak.max(open_descriptors());
    }
    assert!(
        peak <= start + SLACK,
        "{FILES} closes: {peak} descriptors open at most, {start} at the start"
    );
    rig.backend.hooks().hold_syncs.store(false, SeqCst);
    rig.smb.wait_for_saves().await;
    assert_eq!(records(&rig).len(), FILES);

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    for n in 0..FILES {
        assert_eq!(stored(&rig, &name(n)).await.0, content(n), "{}", name(n));
    }
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn an_overwrite_rests_and_lands_after_a_lack_of_descriptors() {
    const NAME: &str = "an_overwrite_rests_and_lands_after_a_lack_of_descriptors";
    const HEADROOM: usize = 64;
    if !alone_in_child(module_path!(), NAME) {
        return;
    }
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "over.bin", pattern(1, 30_000)).await;
    let data = pattern(23, 20_000);
    let file = rig
        .smb
        .create(
            "over.bin",
            Spec::FILE
                .access(READ | WRITE)
                .disposition(FILE_OVERWRITE_IF),
        )
        .await
        .unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close(file.id).await;

    limit_descriptors(HEADROOM);
    let taken = exhaust_descriptors();
    rig.backend.hold_uploads(false);
    wait_until("the job meets the limit", || {
        rig.backend.descriptor_rests() > 0
    })
    .await;
    assert!(rig.backend.failures().is_empty());

    drop(taken);
    sync(&rig.backend).await.unwrap();
    assert!(rig.backend.failures().is_empty());
    assert_eq!(stored(&rig, "over.bin").await.0, data.to_vec());
    assert_eq!(left(&rig, "data"), 0);
    assert_eq!(left(&rig, "records"), 0);
}
