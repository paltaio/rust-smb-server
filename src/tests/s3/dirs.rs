//! Directories made, deleted and renamed on a writable backend: what the
//! share shows at once, and what reaches the bucket afterwards.

use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::Notify;

use super::fixture::{MIB, foreground, pattern, put};
use super::moves::{
    all_records, copies, crash, deletes, exists, folds_case, is_delete, make, make_unrecorded,
    path, remote,
};
use super::proxy::{Fault, Reply, Seen};
use super::share::{
    DELETE, Logs, READ, Rig, Spec, filetime, listing_reply, names, put_all, put_with, run_bounded,
    wait_for_requests, wait_until, wait_until_async,
};
use super::uploads::{fill, held, is_create_of, is_head_of, is_put_of, left, sync, uploading};
use super::writes::{changes, create_dir, create_file, create_options, open_rw, records};
use crate::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
};
use crate::s3::cachedir::RecordOp;
use crate::s3::client::ListRequest;
use crate::s3::encode::uri_encode;
use crate::s3::object::Metadata;
use crate::s3::record::{Record, RecordId};
use crate::{OpenOptions, S3Error, ShareBackend, SmbError, SmbPath};

/// Every key in the bucket, in order.
async fn keys(rig: &Rig) -> Vec<String> {
    let mut found = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let request = ListRequest {
            prefix: "",
            delimited: false,
            continuation_token: token.as_deref(),
            max_keys: None,
        };
        let page = rig
            .store()
            .list_objects(&request, foreground())
            .await
            .unwrap();
        found.extend(page.objects.into_iter().map(|object| object.key));
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    found.sort();
    found
}

/// [`folds_case`], with the object it puts to find out taken out again.
async fn folds(rig: &Rig) -> bool {
    let folds = folds_case(rig).await;
    for key in ["Mixed.case", "mixed.case"] {
        let _ = rig.store().delete_object(key, foreground()).await;
    }
    folds
}

/// Puts the marker object `key`, which ends in `/`, with user metadata.
async fn mark(rig: &Rig, key: &str, pairs: &[(&str, &str)]) {
    let metadata = Metadata {
        user: pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        ..Metadata::default()
    };
    rig.store()
        .put_object(key, Bytes::new(), &metadata, foreground())
        .await
        .unwrap();
}

/// The names in the directory `dir` of the share, sorted.
async fn listed(rig: &mut Rig, dir: &str) -> Vec<String> {
    let open = rig.smb.open_dir(dir).await.unwrap();
    let entries = rig.smb.list(open.id, "*").await;
    rig.smb.close(open.id).await;
    names(&entries).into_iter().map(str::to_owned).collect()
}

/// Whether `seen` lists every key below the directory `dir` in one request
/// without a delimiter or a limit, as a rename of the directory does.
fn is_whole_listing(dir: &str) -> impl Fn(&Seen) -> bool + Send + Sync + 'static {
    let prefix = format!("prefix={}", uri_encode(&format!("{dir}/"), false));
    move |seen| {
        seen.method == "GET"
            && seen.has_param("list-type")
            && !seen.has_param("max-keys")
            && !seen.has_param("delimiter")
            && seen.query().split('&').any(|param| param == prefix)
    }
}

/// Whether `seen` lists the keys below the directory `dir` with a limit of two
/// and no delimiter, as the check of a delete does.
fn is_content_check(dir: &str) -> impl Fn(&Seen) -> bool + Send + Sync + 'static {
    let prefix = format!("prefix={}", uri_encode(&format!("{dir}/"), false));
    move |seen| {
        let has = |wanted: &str| seen.query().split('&').any(|param| param == wanted);
        seen.method == "GET"
            && seen.has_param("list-type")
            && !seen.has_param("delimiter")
            && has("max-keys=2")
            && has(&prefix)
    }
}

/// The records the cache directory wrote and removed since the log was last
/// cleared, in order.
fn record_ops(rig: &Rig) -> Vec<(RecordOp, RecordId)> {
    rig.backend.hooks().record_ops.lock().unwrap().clone()
}

/// The keys of the members of the batch record on disk, sorted.
fn batch_members(rig: &Rig) -> Vec<String> {
    let mut found: Vec<String> = all_records(rig)
        .iter()
        .filter_map(|record| match record {
            Record::Batch(batch) => Some(batch),
            _ => None,
        })
        .flat_map(|batch| batch.members.iter().map(|member| member.key.clone()))
        .collect();
    found.sort();
    found
}

/// The keys the tombstone records on disk name, sorted.
fn tombstoned(rig: &Rig) -> Vec<String> {
    let mut found: Vec<String> = all_records(rig)
        .iter()
        .filter_map(|record| match record {
            Record::Tombstone(tombstone) => Some(tombstone),
            _ => None,
        })
        .flat_map(|tombstone| tombstone.keys.clone())
        .collect();
    found.sort();
    found
}

/// Asserts that nothing of a rename that was refused is left: no record, no
/// entry, no request that changed the bucket.
fn assert_unchanged(rig: &Rig) {
    assert!(all_records(rig).is_empty());
    assert_eq!(rig.backend.overlay_len(), 0);
    assert_eq!(changes(rig), 0);
}

fn dir_delete() -> Spec {
    Spec::DIR.access(READ | DELETE)
}

// Making directories.

#[tokio::test]
async fn a_new_directory_has_a_record_and_an_entry_while_its_marker_is_put() {
    let mut rig = Rig::writable().await;
    let release = Arc::new(Notify::new());
    let target = format!("/{}/made/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == target,
        Fault::Hold(Arc::clone(&release)),
        1,
    );
    let backend = rig.backend.clone();
    let opening = tokio::spawn(async move {
        backend
            .open(&path("made"), create_options(true))
            .await
            .map(|_| ())
    });
    wait_for_requests(&rig.proxy, 1, |seen| seen.method == "PUT").await;
    let held_records = records(&rig);
    assert_eq!(
        held_records.len(),
        1,
        "the record is written before the PUT"
    );
    assert!(held_records[0].is_dir && held_records[0].marker_pending);
    assert_eq!(rig.backend.overlay_len(), 1);
    assert!(!opening.is_finished(), "the open waits for the marker");
    assert!(
        rig.store()
            .head_object("made/", foreground())
            .await
            .is_err(),
        "the marker is not in the bucket yet"
    );

    release.notify_one();
    opening.await.unwrap().unwrap();
    assert!(records(&rig).is_empty());
    assert!(rig.store().head_object("made/", foreground()).await.is_ok());
    assert!(rig.smb.open_dir("made").await.is_ok());
}

#[tokio::test]
async fn a_directory_made_where_one_was_deleted_is_not_deleted_again() {
    let mut rig = Rig::writable_with(held).await;
    mark(&rig, "again/", &[]).await;
    rig.backend.unlink(&path("again")).await.unwrap();
    assert_eq!(
        rig.smb.open_dir("again").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );

    let made = rig.smb.create("again", create_dir()).await.unwrap();
    assert_eq!(made.action, 2);
    rig.smb.close(made.id).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(
        deletes(&rig),
        0,
        "the key to delete went with the new marker"
    );
    assert_eq!(keys(&rig).await, ["again/"]);
    assert!(rig.smb.open_dir("again").await.is_ok());
    assert!(all_records(&rig).is_empty());
}

// Deleting directories.

#[tokio::test]
async fn an_empty_directory_is_deleted_with_one_listing_and_its_marker_goes_later() {
    let mut rig = Rig::writable_with(held).await;
    mark(&rig, "empty/", &[]).await;
    let open = rig.smb.open_dir("empty").await.unwrap();
    rig.smb.close(open.id).await;
    let before = rig.proxy.seen().len();

    rig.backend.unlink(&path("empty")).await.unwrap();

    let sent = rig.proxy.seen().split_off(before);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(is_content_check("empty")(&sent[0]));
    assert_eq!(
        rig.smb.open_dir("empty").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert!(listed(&mut rig, "").await.is_empty());
    assert_eq!(
        keys(&rig).await,
        ["empty/"],
        "the marker is still in the bucket"
    );
    assert_eq!(
        all_records(&rig).len(),
        1,
        "a record keeps the key to delete"
    );

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn a_directory_with_an_object_below_it_is_not_deleted() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "full/deep/x.txt", b"x").await;
    for name in ["full", "full/deep"] {
        assert!(matches!(
            rig.backend.unlink(&path(name)).await,
            Err(SmbError::NotEmpty)
        ));
    }
    let still = rig.smb.open_dir("full").await.unwrap();
    rig.smb.close(still.id).await;
    assert_unchanged(&rig);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["full/deep/x.txt"]);
}

#[tokio::test]
async fn a_directory_with_an_entry_of_the_overlay_below_it_is_not_deleted() {
    let mut rig = Rig::writable_with(held).await;
    let made = rig.smb.create("room", create_dir()).await.unwrap();
    rig.smb.close(made.id).await;
    make(&mut rig, "room\\new.txt", b"local").await;
    let before = rig.proxy.seen().len();
    assert!(matches!(
        rig.backend.unlink(&path("room")).await,
        Err(SmbError::NotEmpty)
    ));
    assert_eq!(
        rig.proxy.seen().len(),
        before,
        "the overlay answers without the store"
    );
    assert!(exists(&mut rig, "room\\new.txt").await);

    rig.backend.unlink(&path("room\\new.txt")).await.unwrap();
    rig.backend.unlink(&path("room")).await.unwrap();
    assert!(listed(&mut rig, "").await.is_empty());
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
}

#[tokio::test]
async fn a_name_made_below_a_directory_while_it_is_checked_for_a_delete_is_refused() {
    let mut rig = Rig::writable_with(uploading).await;
    mark(&rig, "x/", &[]).await;
    let open = rig.smb.open_dir("x").await.unwrap();
    rig.smb.close(open.id).await;

    // The store answers the check with the empty directory it had, and the
    // answer is delivered late.
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_content_check("x"),
        Fault::HoldReply(Arc::clone(&gate), listing_reply(&[], &[])),
        1,
    );
    let unlinking = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.unlink(&path("x")).await }
    });
    wait_for_requests(&rig.proxy, 1, is_content_check("x")).await;

    assert!(matches!(
        rig.backend.open(&path("x\\g"), create_options(false)).await,
        Err(SmbError::Sharing)
    ));
    assert!(matches!(
        rig.backend.unlink(&path("x")).await,
        Err(SmbError::Sharing)
    ));
    assert!(matches!(
        rig.backend.rename(&path("x"), &path("y"), false).await,
        Err(SmbError::Sharing)
    ));

    gate.notify_one();
    unlinking.await.unwrap().unwrap();
    assert_eq!(
        rig.smb.open_dir("x").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        rig.smb.open_dir("x\\g").await.unwrap_err(),
        STATUS_OBJECT_PATH_NOT_FOUND
    );
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_directory_whose_objects_are_all_to_be_deleted_is_empty() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "gone/x.txt", b"x").await;
    put(rig.store(), "gone/y.txt", b"y").await;
    rig.backend.unlink(&path("gone\\x.txt")).await.unwrap();
    rig.backend.unlink(&path("gone\\y.txt")).await.unwrap();
    rig.backend.unlink(&path("gone")).await.unwrap();
    assert!(listed(&mut rig, "").await.is_empty());
    assert_eq!(
        rig.smb.open_dir("gone\\x.txt").await.unwrap_err(),
        STATUS_OBJECT_PATH_NOT_FOUND
    );
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn the_marker_of_a_directory_is_deleted_after_the_objects_below_it() {
    let rig = Rig::writable_with(held).await;
    mark(&rig, "top/", &[]).await;
    put(rig.store(), "top/x.txt", b"x").await;
    rig.backend.unlink(&path("top\\x.txt")).await.unwrap();
    rig.backend.unlink(&path("top")).await.unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);

    // A store that keeps a directory for the object in it refuses to delete
    // the marker first, so the two never go in one request or in the other
    // order.
    let sent: Vec<Seen> = rig.proxy.seen().into_iter().filter(is_delete).collect();
    let body = |seen: &Seen| String::from_utf8_lossy(&seen.body).into_owned();
    let object = sent
        .iter()
        .position(|seen| body(seen).contains("<Key>top/x.txt</Key>"))
        .expect("the object is deleted");
    let marker = sent
        .iter()
        .position(|seen| body(seen).contains("<Key>top/</Key>"))
        .expect("the marker is deleted");
    assert!(object < marker, "the object goes first");
    assert!(!body(&sent[marker]).contains("top/x.txt"));
}

#[tokio::test]
async fn a_deleted_directory_stays_deleted_after_a_restart() {
    let rig = Rig::writable_with(held).await;
    mark(&rig, "old/", &[]).await;
    rig.backend.unlink(&path("old")).await.unwrap();
    let mut rig = rig.restart_with(held).await;
    assert_eq!(
        rig.smb.open_dir("old").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(keys(&rig).await, ["old/"]);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
}

#[tokio::test]
async fn deleting_a_directory_through_the_share_needs_it_empty() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "busy/x.txt", b"x").await;
    mark(&rig, "free/", &[]).await;

    let busy = rig.smb.create("busy", dir_delete()).await.unwrap();
    assert_eq!(
        rig.smb.set_delete(busy.id).await,
        STATUS_DIRECTORY_NOT_EMPTY
    );
    rig.smb.close(busy.id).await;
    assert!(rig.smb.open_dir("busy").await.is_ok());

    let free = rig.smb.create("free", dir_delete()).await.unwrap();
    assert_eq!(rig.smb.set_delete(free.id).await, 0);
    rig.smb.close(free.id).await;
    assert_eq!(listed(&mut rig, "").await, ["busy"]);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["busy/x.txt"]);
}

#[tokio::test]
async fn the_share_root_cannot_be_deleted_or_renamed() {
    let rig = Rig::writable_with(held).await;
    for result in [
        rig.backend.unlink(&SmbPath::root()).await,
        rig.backend
            .rename(&SmbPath::root(), &path("x"), false)
            .await,
        rig.backend
            .rename(&path("x"), &SmbPath::root(), false)
            .await,
    ] {
        assert!(matches!(result, Err(SmbError::AccessDenied)));
    }
}

// Renaming directories.

#[tokio::test]
async fn a_renamed_directory_shows_its_new_names_at_once_and_the_bucket_follows() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "src/a.txt", b"alpha").await;
    put(rig.store(), "src/sub/b.txt", b"beta").await;
    put(rig.store(), "src/sub/deeper/c.txt", b"gamma").await;
    mark(&rig, "src/empty/", &[]).await;
    assert_eq!(listed(&mut rig, "src").await.len(), 3);
    let before = rig.proxy.seen().len();

    rig.backend
        .rename(&path("src"), &path("dst"), false)
        .await
        .unwrap();

    let sent = rig.proxy.seen().split_off(before);
    assert!(
        sent.iter()
            .all(|seen| matches!(seen.method.as_str(), "GET" | "HEAD")),
        "only lookups and a listing: {sent:?}"
    );
    let whole_listings = sent.iter().filter(|seen| is_whole_listing("src")(seen));
    assert_eq!(whole_listings.count(), 1, "{sent:?}");
    assert_eq!(listed(&mut rig, "").await, ["dst"]);
    assert_eq!(listed(&mut rig, "dst").await, ["a.txt", "empty", "sub"]);
    assert_eq!(listed(&mut rig, "dst\\sub").await, ["b.txt", "deeper"]);
    assert_eq!(rig.smb.contents("dst\\a.txt", 100).await, b"alpha");
    assert_eq!(
        rig.smb.contents("dst\\sub\\deeper\\c.txt", 100).await,
        b"gamma"
    );
    assert_eq!(
        rig.smb.open_dir("src").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        rig.smb.open("src\\a.txt").await.unwrap_err(),
        STATUS_OBJECT_PATH_NOT_FOUND
    );
    assert_eq!(remote(&rig, "src/a.txt").await.unwrap(), b"alpha");
    assert_eq!(changes(&rig), 0);

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(
        keys(&rig).await,
        [
            "dst/",
            "dst/a.txt",
            "dst/empty/",
            "dst/sub/",
            "dst/sub/b.txt",
            "dst/sub/deeper/",
            "dst/sub/deeper/c.txt"
        ]
    );
    assert_eq!(remote(&rig, "dst/a.txt").await.unwrap(), b"alpha");
    assert_eq!(remote(&rig, "dst/sub/b.txt").await.unwrap(), b"beta");
    assert_eq!(
        remote(&rig, "dst/sub/deeper/c.txt").await.unwrap(),
        b"gamma"
    );
    assert_eq!(listed(&mut rig, "dst").await, ["a.txt", "empty", "sub"]);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn a_renamed_directory_keeps_the_metadata_of_its_marker_and_objects() {
    let mut rig = Rig::writable_with(held).await;
    mark(
        &rig,
        "src/",
        &[("mtime", "1500000000.000000000"), ("owner", "someone")],
    )
    .await;
    mark(&rig, "src/inner/", &[("mtime", "1400000000.000000000")]).await;
    let metadata = Metadata {
        user: [
            ("mtime".to_owned(), "1300000000.000000000".to_owned()),
            ("owner".to_owned(), "somebody".to_owned()),
        ]
        .into(),
        content_type: Some("text/plain".to_owned()),
        ..Metadata::default()
    };
    rig.store()
        .put_object(
            "src/f.txt",
            Bytes::from_static(b"body"),
            &metadata,
            foreground(),
        )
        .await
        .unwrap();

    rig.backend
        .rename(&path("src"), &path("dst"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(keys(&rig).await, ["dst/", "dst/f.txt", "dst/inner/"]);
    let file = rig
        .store()
        .head_object("dst/f.txt", foreground())
        .await
        .unwrap();
    assert_eq!(file.metadata.user, metadata.user);
    assert_eq!(file.metadata.content_type.as_deref(), Some("text/plain"));
    let root = rig.store().head_object("dst/", foreground()).await.unwrap();
    assert_eq!(
        root.metadata.user.get("owner").map(String::as_str),
        Some("someone")
    );
    assert_eq!(
        root.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
    let inner = rig
        .store()
        .head_object("dst/inner/", foreground())
        .await
        .unwrap();
    assert_eq!(
        inner.metadata.user.get("mtime").map(String::as_str),
        Some("1400000000.000000000")
    );
    let opened = rig.smb.open("dst\\f.txt").await.unwrap();
    assert_eq!(opened.times[2], filetime(1_300_000_000, 0));
}

#[tokio::test]
async fn the_times_of_moved_objects_the_backend_has_read_show_at_once() {
    let mut rig = Rig::writable_with(held).await;
    put_with(
        rig.store(),
        "src/f.txt",
        b"x",
        &[("mtime", "1300000000.000000000")],
    )
    .await;
    let open = rig.smb.open_dir("src").await.unwrap();
    let before = rig.smb.list(open.id, "*").await;
    assert_eq!(before[0].times[2], filetime(1_300_000_000, 0));
    rig.smb.close(open.id).await;

    rig.backend
        .rename(&path("src"), &path("dst"), false)
        .await
        .unwrap();
    let open = rig.smb.open_dir("dst").await.unwrap();
    let after = rig.smb.list(open.id, "*").await;
    assert_eq!(after[0].times[2], filetime(1_300_000_000, 0));
}

#[tokio::test]
async fn a_directory_over_the_cap_is_not_renamed_and_one_at_the_cap_is() {
    let mut rig = Rig::writable_with(|b| held(b).max_dir_rename_objects(3)).await;
    put(rig.store(), "edge/1.txt", b"1").await;
    put(rig.store(), "edge/sub/2.txt", b"2").await;
    mark(&rig, "edge/marker/", &[]).await;
    put(rig.store(), "big/1.txt", b"1").await;
    put(rig.store(), "big/2.txt", b"2").await;
    put(rig.store(), "big/sub/3.txt", b"3").await;
    put(rig.store(), "big/sub/4.txt", b"4").await;
    put(rig.store(), "mix/1.txt", b"1").await;
    put(rig.store(), "mix/2.txt", b"2").await;

    assert!(matches!(
        rig.backend.rename(&path("big"), &path("big2"), false).await,
        Err(SmbError::AccessDenied)
    ));
    assert_unchanged(&rig);
    assert_eq!(rig.smb.contents("big\\sub\\4.txt", 10).await, b"4");

    // Entries the backend holds count too.
    make(&mut rig, "mix\\3.txt", b"3").await;
    make(&mut rig, "mix\\4.txt", b"4").await;
    assert!(matches!(
        rig.backend.rename(&path("mix"), &path("mix2"), false).await,
        Err(SmbError::AccessDenied)
    ));
    assert_eq!(rig.smb.contents("mix\\4.txt", 10).await, b"4");
    assert_eq!(changes(&rig), 0);
    assert!(listed(&mut rig, "").await.contains(&"mix".to_owned()));

    rig.backend
        .rename(&path("edge"), &path("edge2"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "edge2").await, ["1.txt", "marker", "sub"]);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let all = keys(&rig).await;
    assert!(all.contains(&"edge2/marker/".to_owned()));
    assert!(all.contains(&"edge2/sub/2.txt".to_owned()));
    assert!(!all.iter().any(|key| key.starts_with("edge/")));
    assert!(all.contains(&"big/sub/4.txt".to_owned()), "{all:?}");
}

#[tokio::test]
async fn a_directory_of_many_pages_is_renamed_whole() {
    let mut rig = Rig::writable_with(|b| held(b).upload_concurrency(8)).await;
    let names: Vec<String> = (0..1010).map(|n| format!("many/{n:04}.txt")).collect();
    put_all(rig.store(), names.clone()).await;

    rig.backend
        .rename(&path("many"), &path("lots"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "lots").await.len(), 1010);
    assert_eq!(
        rig.smb.contents("lots\\1009.txt", 100).await,
        b"many/1009.txt"
    );
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let all = keys(&rig).await;
    assert_eq!(all.len(), 1011);
    assert!(all.iter().all(|key| key.starts_with("lots/")));
    assert_eq!(
        remote(&rig, "lots/0000.txt").await.unwrap(),
        b"many/0000.txt"
    );
}

#[tokio::test]
async fn files_with_changes_move_with_a_renamed_directory() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/remote.txt", b"remote").await;
    put(rig.store(), "d/times.txt", b"times").await;
    put(rig.store(), "d/plain.txt", b"plain").await;
    make(&mut rig, "d\\new.txt", b"local bytes").await;
    let changed = rig.smb.create("d\\remote.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.write(changed.id, 0, b"REMOTE").await, Ok(6));
    rig.smb.close(changed.id).await;
    let timed = rig.smb.create("d\\times.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(timed.id, 1_500_000_000).await, 0);
    rig.smb.close(timed.id).await;

    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("e\\new.txt", 100).await, b"local bytes");
    assert_eq!(rig.smb.contents("e\\remote.txt", 100).await, b"REMOTE");
    assert_eq!(rig.smb.contents("e\\plain.txt", 100).await, b"plain");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(
        keys(&rig).await,
        [
            "e/",
            "e/new.txt",
            "e/plain.txt",
            "e/remote.txt",
            "e/times.txt"
        ]
    );
    assert_eq!(remote(&rig, "e/new.txt").await.unwrap(), b"local bytes");
    assert_eq!(remote(&rig, "e/remote.txt").await.unwrap(), b"REMOTE");
    assert_eq!(remote(&rig, "e/times.txt").await.unwrap(), b"times");
    let head = rig
        .store()
        .head_object("e/times.txt", foreground())
        .await
        .unwrap();
    assert_eq!(
        head.metadata.user.get("mtime").map(String::as_str),
        Some("1500000000.000000000")
    );
    for old in ["d/new.txt", "d/remote.txt", "d/times.txt"] {
        assert_eq!(
            rig.proxy.count(is_put_of(&rig.bucket.name, old)),
            0,
            "{old}"
        );
    }
    assert_eq!(
        copies(&rig),
        2,
        "the two files with no bytes of their own are copied"
    );
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn an_upload_in_flight_when_its_directory_is_renamed_lands_at_the_new_key() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/keep.txt", b"keep").await;
    let data = pattern(3, 6 * MIB);
    let file = rig.smb.create("d\\up.bin", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, &data).await;
    rig.smb.close(file.id).await;

    let (reached, resume) = rig.backend.pause_after_hash();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(remote(&rig, "e/up.bin").await.unwrap(), data);
    assert_eq!(remote(&rig, "e/keep.txt").await.unwrap(), b"keep");
    assert_eq!(keys(&rig).await, ["e/", "e/keep.txt", "e/up.bin"]);
    assert_eq!(
        rig.proxy.count(is_create_of(&rig.bucket.name, "d/up.bin")),
        0
    );
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "d/up.bin")), 0);
}

#[tokio::test]
async fn a_write_through_a_handle_open_during_a_directory_rename_lands_at_the_new_key() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"before").await;
    let open = rig.smb.create("d\\f.txt", open_rw()).await.unwrap();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.write(open.id, 0, b"AFTER!").await, Ok(6));
    rig.smb.close(open.id).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/f.txt"]);
    assert_eq!(remote(&rig, "e/f.txt").await.unwrap(), b"AFTER!");
}

#[tokio::test]
async fn a_directory_renamed_twice_before_its_jobs_run_is_copied_once() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "one/a.txt", b"a").await;
    put(rig.store(), "one/sub/b.txt", b"b").await;
    rig.backend
        .rename(&path("one"), &path("two"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("two"), &path("three"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "").await, ["three"]);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(
        keys(&rig).await,
        ["three/", "three/a.txt", "three/sub/", "three/sub/b.txt"]
    );
    assert_eq!(copies(&rig), 2);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_directory_renamed_again_before_the_first_batch_is_recorded_ends_in_one_place() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "one/a.txt", b"a").await;
    put(rig.store(), "one/b.txt", b"b").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("one"), &path("two"), false)
        .await
        .unwrap();
    reached.notified().await;
    rig.backend
        .rename(&path("two"), &path("three"), false)
        .await
        .unwrap();
    resume.notify_one();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();

    assert_eq!(keys(&rig).await, ["three/", "three/a.txt", "three/b.txt"]);
    assert_eq!(left(&rig, "records"), 0);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn entries_of_a_moved_directory_wait_parked_until_their_records_are_written() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    put(rig.store(), "d/sub/b.txt", b"b").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend.hold_uploads(false);
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;

    // The directory, the directory its files imply and the two files wait,
    // each once.
    wait_until("the entries of the batch are parked", || {
        rig.backend.parks() == 4
    })
    .await;
    let found = all_records(&rig);
    assert_eq!(found.len(), 1);
    let Record::Batch(batch) = &found[0] else {
        panic!("not a batch record: {:?}", found[0]);
    };
    let mut moved: Vec<(&str, &[String])> = batch
        .members
        .iter()
        .map(|member| (member.key.as_str(), member.gone.as_slice()))
        .collect();
    moved.sort();
    assert_eq!(moved.len(), 4);
    assert_eq!(moved[0].0, "e");
    assert!(moved[0].1.contains(&"d/".to_owned()));
    assert_eq!(moved[1], ("e/a.txt", ["d/a.txt".to_owned()].as_slice()));
    assert_eq!(moved[2], ("e/sub", ["d/sub/".to_owned()].as_slice()));
    assert_eq!(
        moved[3],
        ("e/sub/b.txt", ["d/sub/b.txt".to_owned()].as_slice())
    );
    let batch_key = format!("\0batch {}", found[0].id());
    assert_eq!(
        rig.backend.waiting_for(&batch_key),
        4,
        "each of them waits for the batch, and for nothing else"
    );
    assert_eq!(
        changes(&rig),
        0,
        "no job ran while the batch held the entries"
    );
    assert_eq!(rig.smb.contents("e\\a.txt", 10).await, b"a");

    resume.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt", "e/sub/", "e/sub/b.txt"]);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_crash_after_the_batch_record_leaves_the_rename_whole() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"alpha").await;
    put(rig.store(), "d/sub/b.txt", b"beta").await;
    mark(&rig, "d/empty/", &[("owner", "me")]).await;
    make_unrecorded(&mut rig, "d\\new.txt", b"local bytes").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    let found = all_records(&rig);
    assert_eq!(found.len(), 1, "only the batch is on disk: {found:?}");
    assert!(matches!(&found[0], Record::Batch(batch) if batch.members.len() == 6));

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(listed(&mut rig, "").await, ["e"]);
    assert_eq!(
        listed(&mut rig, "e").await,
        ["a.txt", "empty", "new.txt", "sub"]
    );
    assert_eq!(rig.smb.contents("e\\a.txt", 100).await, b"alpha");
    assert_eq!(rig.smb.contents("e\\new.txt", 100).await, b"local bytes");
    assert_eq!(
        all_records(&rig)
            .iter()
            .filter(|r| matches!(r, Record::Batch(_)))
            .count(),
        0,
        "the entries have records of their own"
    );
    assert_eq!(left(&rig, "records"), 6);

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(
        keys(&rig).await,
        [
            "e/",
            "e/a.txt",
            "e/empty/",
            "e/new.txt",
            "e/sub/",
            "e/sub/b.txt"
        ]
    );
    assert_eq!(remote(&rig, "e/new.txt").await.unwrap(), b"local bytes");
    assert_eq!(remote(&rig, "e/sub/b.txt").await.unwrap(), b"beta");
    let marker = rig
        .store()
        .head_object("e/empty/", foreground())
        .await
        .unwrap();
    assert_eq!(
        marker.metadata.user.get("owner").map(String::as_str),
        Some("me")
    );
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(left(&rig, "data"), 0);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn records_that_could_not_all_be_written_after_a_rename_are_finished_by_the_next_backend() {
    let rig = Rig::writable_with(held).await;
    for name in ["a", "b", "c"] {
        put(rig.store(), &format!("d/{name}.txt"), name.as_bytes()).await;
    }
    // The batch record and two of the four entry records are written.
    rig.backend.hooks().record_write_skips.store(3, SeqCst);
    rig.backend.hooks().record_writes.store(1, SeqCst);
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    wait_until("the records of the entries failed", || {
        rig.backend.failures().len() == 4
    })
    .await;
    assert!(sync(&rig.backend).await.is_err());
    assert_eq!(
        changes(&rig),
        0,
        "nothing was stored for entries that were not recorded"
    );

    let mut rig = rig.restart_with(uploading).await;
    assert_eq!(listed(&mut rig, "e").await, ["a.txt", "b.txt", "c.txt"]);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt", "e/b.txt", "e/c.txt"]);
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_file_deleted_from_a_moved_directory_before_its_record_stays_deleted_after_a_crash() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/gone.txt", b"gone").await;
    put(rig.store(), "d/kept.txt", b"kept").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    rig.backend.unlink(&path("e\\gone.txt")).await.unwrap();

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    assert!(!exists(&mut rig, "e\\gone.txt").await);
    assert_eq!(rig.smb.contents("e\\kept.txt", 10).await, b"kept");
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/kept.txt"]);
}

#[tokio::test]
async fn a_rename_whose_listing_fails_changes_nothing() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "src/a.txt", b"a").await;
    let open = rig.smb.open_dir("src").await.unwrap();
    rig.smb.close(open.id).await;
    rig.proxy.inject(
        is_whole_listing("src"),
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    assert!(matches!(
        rig.backend.rename(&path("src"), &path("dst"), false).await,
        Err(SmbError::AccessDenied)
    ));
    assert_unchanged(&rig);
    assert_eq!(listed(&mut rig, "").await, ["src"]);

    rig.proxy.clear_rules();
    rig.backend
        .rename(&path("src"), &path("dst"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "").await, ["dst"]);
}

#[tokio::test]
async fn a_rename_whose_batch_record_cannot_be_written_changes_nothing() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "src/a.txt", b"a").await;
    make(&mut rig, "src\\new.txt", b"n").await;
    let records_before = all_records(&rig).len();
    rig.backend.hooks().record_writes.store(1, SeqCst);
    assert!(matches!(
        rig.backend.rename(&path("src"), &path("dst"), false).await,
        Err(SmbError::Io(_))
    ));
    assert_eq!(all_records(&rig).len(), records_before);
    assert_eq!(listed(&mut rig, "").await, ["src"]);
    assert_eq!(rig.smb.contents("src\\new.txt", 10).await, b"n");
    assert_eq!(changes(&rig), 0);

    rig.backend
        .rename(&path("src"), &path("dst"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["dst/", "dst/a.txt", "dst/new.txt"]);
}

#[tokio::test]
async fn a_directory_is_not_renamed_onto_a_name_that_is_taken_or_into_itself() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a/x.txt", b"x").await;
    put(rig.store(), "b/y.txt", b"y").await;
    put(rig.store(), "file.txt", b"f").await;
    for replace in [false, true] {
        assert!(
            matches!(
                rig.backend.rename(&path("a"), &path("b"), replace).await,
                Err(SmbError::AccessDenied)
            ),
            "onto a directory, replace {replace}"
        );
    }
    assert!(matches!(
        rig.backend
            .rename(&path("a"), &path("file.txt"), false)
            .await,
        Err(SmbError::Exists)
    ));
    assert!(matches!(
        rig.backend
            .rename(&path("a"), &path("file.txt"), true)
            .await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        rig.backend
            .rename(&path("a"), &path("a\\inside"), false)
            .await,
        Err(SmbError::InvalidParameter)
    ));
    assert!(matches!(
        rig.backend
            .rename(&path("a"), &path("nope\\a"), false)
            .await,
        Err(SmbError::PathNotFound)
    ));
    assert!(matches!(
        rig.backend
            .rename(&path("missing"), &path("z"), false)
            .await,
        Err(SmbError::NotFound)
    ));
    assert_unchanged(&rig);
    assert_eq!(listed(&mut rig, "").await, ["a", "b", "file.txt"]);
}

#[tokio::test]
async fn a_directory_is_renamed_through_the_share() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "src/a.txt", b"a").await;
    let dir = rig.smb.create("src", dir_delete()).await.unwrap();
    assert_eq!(rig.smb.rename(dir.id, "dst").await, 0);
    rig.smb.close(dir.id).await;
    assert_eq!(listed(&mut rig, "").await, ["dst"]);
    assert_eq!(rig.smb.contents("dst\\a.txt", 10).await, b"a");

    let other = rig.smb.create("dst", dir_delete()).await.unwrap();
    let made = rig.smb.create("taken", create_dir()).await.unwrap();
    rig.smb.close(made.id).await;
    assert_eq!(
        rig.smb.rename(other.id, "taken").await,
        STATUS_ACCESS_DENIED
    );
    rig.smb.close(other.id).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["dst/", "dst/a.txt", "taken/"]);
}

#[tokio::test]
async fn a_directory_renamed_to_another_case_keeps_its_objects_and_opens_its_subdirectories() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "Docs/a.txt", b"a").await;
    put(rig.store(), "Docs/sub/b.txt", b"b").await;
    let folds = folds(&rig).await;
    rig.backend
        .rename(&path("docs"), &path("DOCS"), false)
        .await
        .unwrap();
    let root = listed(&mut rig, "").await;
    assert!(root.contains(&"DOCS".to_owned()), "{root:?}");
    assert!(rig.smb.open_dir("DOCS\\sub").await.is_ok());
    assert_eq!(listed(&mut rig, "DOCS").await, ["a.txt", "sub"]);
    assert_eq!(rig.smb.contents("DOCS\\sub\\b.txt", 10).await, b"b");
    assert_eq!(rig.smb.contents("docs\\sub\\b.txt", 10).await, b"b");

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "DOCS/a.txt").await.unwrap(), b"a");
    assert_eq!(remote(&rig, "DOCS/sub/b.txt").await.unwrap(), b"b");
    if !folds {
        assert_eq!(
            keys(&rig).await,
            ["DOCS/", "DOCS/a.txt", "DOCS/sub/", "DOCS/sub/b.txt"]
        );
    }
    assert!(rig.smb.open_dir("DOCS\\sub").await.is_ok());
    assert!(rig.backend.failures().is_empty());
}

// Markers of implicit directories.

#[tokio::test]
async fn the_last_directory_renamed_out_of_an_implicit_directory_leaves_it_a_marker() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "p/q/f.txt", b"f").await;
    rig.backend
        .rename(&path("p\\q"), &path("r"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "").await, ["p", "r"]);
    assert!(listed(&mut rig, "p").await.is_empty());
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["p/", "r/", "r/f.txt"]);
    assert_eq!(listed(&mut rig, "").await, ["p", "r"]);
}

#[tokio::test]
async fn a_directory_renamed_out_of_a_directory_with_other_content_adds_no_marker() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "p/q/f.txt", b"f").await;
    put(rig.store(), "p/keep.txt", b"k").await;
    rig.backend
        .rename(&path("p\\q"), &path("r"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["p/keep.txt", "r/", "r/f.txt"]);
}

#[tokio::test]
async fn an_object_to_be_deleted_does_not_keep_a_directory_without_a_marker() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "p/q/f.txt", b"f").await;
    put(rig.store(), "p/z.txt", b"z").await;
    rig.backend.unlink(&path("p\\z.txt")).await.unwrap();
    rig.backend
        .rename(&path("p\\q"), &path("r"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["p/", "r/", "r/f.txt"]);
}

#[tokio::test]
async fn the_last_directory_deleted_from_an_implicit_directory_leaves_it_a_marker() {
    let mut rig = Rig::writable_with(held).await;
    mark(&rig, "p/q/", &[]).await;
    rig.backend.unlink(&path("p\\q")).await.unwrap();
    assert_eq!(listed(&mut rig, "p").await.len(), 0);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["p/"]);
    assert!(rig.smb.open_dir("p").await.is_ok());
}

#[tokio::test]
async fn nested_implicit_directories_keep_markers_when_their_content_moves_away() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a/b/c/f.txt", b"f").await;
    rig.backend
        .rename(&path("a\\b\\c"), &path("moved"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["a/", "a/b/", "moved/", "moved/f.txt"]);
    assert!(rig.smb.open_dir("a\\b").await.is_ok());
}

#[tokio::test]
async fn a_directory_renamed_within_an_implicit_parent_leaves_the_parent_no_marker() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "p/q/f.txt", b"f").await;
    rig.backend
        .rename(&path("p\\q"), &path("p\\w"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "p").await, ["w"]);
    assert_eq!(rig.smb.contents("p\\w\\f.txt", 10).await, b"f");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["p/w/", "p/w/f.txt"]);
}

#[tokio::test]
async fn a_directory_over_the_cap_on_a_later_page_is_not_renamed() {
    let mut rig = Rig::writable_with(|b| held(b).max_dir_rename_objects(1005)).await;
    let names: Vec<String> = (0..1010).map(|n| format!("many/{n:04}.txt")).collect();
    put_all(rig.store(), names).await;
    let before = rig.proxy.seen().len();
    assert!(matches!(
        rig.backend
            .rename(&path("many"), &path("lots"), false)
            .await,
        Err(SmbError::AccessDenied)
    ));
    let pages = rig
        .proxy
        .seen()
        .split_off(before)
        .iter()
        .filter(|seen| is_whole_listing("many")(seen))
        .count();
    assert_eq!(
        pages, 2,
        "the first page is under the cap, the second is not"
    );
    assert_unchanged(&rig);
    assert_eq!(listed(&mut rig, "").await, ["many"]);
}

#[tokio::test]
async fn directories_swapped_through_a_third_name_end_with_their_contents_swapped() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a/f.txt", b"from a").await;
    put(rig.store(), "a/sub/g.txt", b"deep a").await;
    put(rig.store(), "b/f.txt", b"from b").await;
    rig.backend
        .rename(&path("a"), &path("tmp"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("b"), &path("a"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("tmp"), &path("b"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("a\\f.txt", 100).await, b"from b");
    assert_eq!(rig.smb.contents("b\\f.txt", 100).await, b"from a");
    assert_eq!(rig.smb.contents("b\\sub\\g.txt", 100).await, b"deep a");

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let all = keys(&rig).await;
    let objects: Vec<&str> = all
        .iter()
        .map(String::as_str)
        .filter(|key| !key.ends_with('/'))
        .collect();
    assert_eq!(objects, ["a/f.txt", "b/f.txt", "b/sub/g.txt"]);
    assert!(
        all.iter()
            .all(|key| !key.ends_with('/') || ["a/", "b/", "b/sub/"].contains(&key.as_str())),
        "only the directories that exist keep a marker: {all:?}"
    );
    assert_eq!(remote(&rig, "a/f.txt").await.unwrap(), b"from b");
    assert_eq!(remote(&rig, "b/f.txt").await.unwrap(), b"from a");
    assert_eq!(remote(&rig, "b/sub/g.txt").await.unwrap(), b"deep a");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn a_file_waits_for_the_copy_that_reads_its_name_and_then_stores_its_own_content() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "a/f.txt", b"from a").await;
    put(rig.store(), "b/f.txt", b"from b").await;
    rig.backend
        .rename(&path("a"), &path("tmp"), false)
        .await
        .unwrap();
    rig.backend
        .rename(&path("b"), &path("a"), false)
        .await
        .unwrap();
    // a/f.txt is written from b/f.txt, but tmp/f.txt still copies from it.
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(super::moves::is_copy, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_until("a copy is under way", || {
        rig.proxy.count(super::moves::is_copy) == 1
    })
    .await;
    wait_until("the other file waits for the name", || {
        rig.backend.waiting_for("a/f.txt") == 1
    })
    .await;
    assert!(
        rig.backend.key_in_use("a/f.txt"),
        "the copy source is in use"
    );
    assert_eq!(
        rig.proxy.count(super::moves::is_copy),
        1,
        "nothing else is copied"
    );
    assert_eq!(
        remote(&rig, "a/f.txt").await.unwrap(),
        b"from a",
        "the source is not overwritten while a copy needs it"
    );

    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["a/", "a/f.txt", "tmp/", "tmp/f.txt"]);
    assert_eq!(remote(&rig, "a/f.txt").await.unwrap(), b"from b");
    assert_eq!(remote(&rig, "tmp/f.txt").await.unwrap(), b"from a");
    assert!(!rig.backend.key_in_use("a/f.txt"));
}

#[tokio::test]
async fn a_directory_renamed_during_a_store_request_deletes_the_key_that_request_wrote() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/old.txt", b"old").await;
    make(&mut rig, "d\\w.txt", b"written").await;
    let (reached, resume) = rig.backend.pause_after_store();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    resume.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(keys(&rig).await, ["e/", "e/old.txt", "e/w.txt"]);
    assert_eq!(remote(&rig, "e/w.txt").await.unwrap(), b"written");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

/// Holds the next PUT of the marker object `key`, which ends in `/`, at the
/// proxy until the returned `Notify` is notified.
fn hold_marker_put(rig: &Rig, key: &str) -> Arc<Notify> {
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_put_of(&rig.bucket.name, key),
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    gate
}

#[tokio::test]
async fn a_directory_renamed_while_its_marker_is_put_gets_its_marker_at_the_new_name() {
    let mut rig = Rig::writable_with(held).await;
    mark(&rig, "c/", &[]).await;
    rig.backend
        .rename(&path("c"), &path("d"), false)
        .await
        .unwrap();
    let gate = hold_marker_put(&rig, "d/");
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "d/")).await;

    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(keys(&rig).await, ["e/"]);
    assert!(rig.smb.open_dir("e").await.is_ok());
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_renamed_parent_of_a_directory_whose_marker_is_put_gets_that_marker_at_the_new_name() {
    let mut rig = Rig::writable_with(held).await;
    mark(&rig, "a/", &[]).await;
    mark(&rig, "a/s/", &[]).await;
    rig.backend
        .rename(&path("a"), &path("b"), false)
        .await
        .unwrap();
    let gate = hold_marker_put(&rig, "b/s/");
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_put_of(&rig.bucket.name, "b/s/")).await;

    rig.backend
        .rename(&path("b"), &path("c"), false)
        .await
        .unwrap();
    gate.notify_one();
    sync(&rig.backend).await.unwrap();

    assert_eq!(keys(&rig).await, ["c/", "c/s/"]);
    assert!(rig.smb.open_dir("c\\s").await.is_ok());
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_directory_made_in_a_renamed_directory_before_its_jobs_run_is_made_in_the_bucket() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    let inner = rig.smb.create("e\\inner", create_dir()).await.unwrap();
    rig.smb.close(inner.id).await;
    make(&mut rig, "e\\inner\\x.txt", b"x").await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(
        keys(&rig).await,
        ["e/", "e/f.txt", "e/inner/", "e/inner/x.txt"]
    );
}

#[tokio::test]
async fn a_new_file_deleted_from_a_moved_directory_before_its_record_leaves_no_trace() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/kept.txt", b"kept").await;
    make(&mut rig, "d\\local.txt", b"never sent").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    rig.backend.unlink(&path("e\\local.txt")).await.unwrap();
    let found = all_records(&rig);
    assert_eq!(found.len(), 1);
    assert!(
        matches!(&found[0], Record::Batch(batch) if batch.members.iter().all(|m| m.key != "e/local.txt")),
        "the batch no longer lists the file: {found:?}"
    );

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    assert!(!exists(&mut rig, "e\\local.txt").await);
    assert_eq!(left(&rig, "conflicts"), 0);
    assert_eq!(left(&rig, "data"), 0);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/kept.txt"]);
    assert_eq!(
        rig.proxy.count(is_put_of(&rig.bucket.name, "e/local.txt")),
        0
    );
}

#[tokio::test]
async fn keys_in_directories_that_differ_in_case_are_one_object_only_on_a_store_that_ignores_case()
{
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "Docs/a.txt", b"same").await;
    if folds_case(&rig).await {
        assert!(rig.backend.one_object("docs/a.txt", "DOCS/a.txt").await);
        assert!(rig.backend.one_object("docs/a.txt", "Docs/a.txt").await);
        return;
    }
    put(rig.store(), "docs/a.txt", b"same").await;
    assert!(!rig.backend.one_object("docs/a.txt", "Docs/a.txt").await);
    assert!(!rig.backend.one_object("Docs/a.txt", "docs/a.txt").await);
    put(rig.store(), "docs/b.txt", b"same").await;
    assert!(
        !rig.backend.one_object("docs/b.txt", "Docs/b.txt").await,
        "a key that is not there is not the same object"
    );
}

#[tokio::test]
async fn the_lookups_and_listings_of_one_rename_share_one_deadline() {
    let rig = Rig::writable_with(|b| held(b).request_timeout(Duration::from_secs(3))).await;
    put(rig.store(), "src/a.txt", b"a").await;
    // The lookup of the directory answers after 1.8 s or more, and the listing
    // of its keys never answers. The listing gets the time that is left of the
    // three seconds, not three seconds of its own.
    let gate = Arc::new(Notify::new());
    let target = format!("/{}/src", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "HEAD" && seen.target == target,
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    rig.proxy
        .inject(is_whole_listing("src"), Fault::Stall, usize::MAX);
    let started = Instant::now();
    let renaming = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.rename(&path("src"), &path("dst"), false).await }
    });
    wait_for_requests(&rig.proxy, 1, |seen| seen.method == "HEAD").await;
    wait_until("most of the deadline has passed", || {
        started.elapsed() >= Duration::from_millis(1800)
    })
    .await;
    let answered = started.elapsed();
    gate.notify_one();

    let result = renaming.await.unwrap();
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(SmbError::Io(_))), "{result:?}");
    assert!(elapsed >= Duration::from_millis(2700), "{elapsed:?}");
    // A listing with a deadline of its own would end three seconds after the
    // lookup answered.
    assert!(
        elapsed < answered + Duration::from_millis(2900),
        "{elapsed:?}"
    );
    assert!(rig.proxy.count(is_whole_listing("src")) >= 1);
    assert_unchanged(&rig);
}

// Directories a move implies at its destination.

#[tokio::test]
async fn trees_swapped_through_a_third_name_keep_the_directory_they_share() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a/assets/x.txt", b"from a").await;
    put(rig.store(), "b/assets/y.txt", b"from b").await;
    for (from, to) in [("a", "tmp"), ("b", "a"), ("tmp", "b")] {
        rig.backend
            .rename(&path(from), &path(to), false)
            .await
            .unwrap();
    }
    for (dir, file, body) in [("a", "y.txt", b"from b"), ("b", "x.txt", b"from a")] {
        assert_eq!(listed(&mut rig, dir).await, ["assets"]);
        assert_eq!(listed(&mut rig, &format!("{dir}\\assets")).await, [file]);
        assert_eq!(
            rig.smb
                .contents(&format!("{dir}\\assets\\{file}"), 100)
                .await,
            body
        );
    }

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(
        keys(&rig).await,
        [
            "a/",
            "a/assets/",
            "a/assets/y.txt",
            "b/",
            "b/assets/",
            "b/assets/x.txt"
        ]
    );
    assert_eq!(remote(&rig, "a/assets/y.txt").await.unwrap(), b"from b");
    assert_eq!(remote(&rig, "b/assets/x.txt").await.unwrap(), b"from a");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn a_directory_renamed_and_renamed_back_before_its_jobs_run_shows_all_its_directories() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/sub/f.txt", b"deep").await;
    put(rig.store(), "d/g.txt", b"top").await;
    for (from, to) in [("d", "e"), ("e", "d")] {
        rig.backend
            .rename(&path(from), &path(to), false)
            .await
            .unwrap();
    }
    assert_eq!(listed(&mut rig, "").await, ["d"]);
    assert_eq!(listed(&mut rig, "d").await, ["g.txt", "sub"]);
    assert_eq!(listed(&mut rig, "d\\sub").await, ["f.txt"]);
    assert_eq!(rig.smb.contents("d\\sub\\f.txt", 100).await, b"deep");

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["d/", "d/g.txt", "d/sub/", "d/sub/f.txt"]);
    assert_eq!(copies(&rig), 0, "no object moved");
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert_eq!(rig.backend.overlay_len(), 0);
}

#[tokio::test]
async fn a_renamed_directory_whose_objects_are_all_to_be_deleted_is_still_there() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    rig.backend.unlink(&path("d\\f.txt")).await.unwrap();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "").await, ["e"]);
    assert!(listed(&mut rig, "e").await.is_empty());

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/"]);
    assert!(rig.smb.open_dir("e").await.is_ok());
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn the_only_file_moved_below_an_implicit_directory_can_be_deleted_before_its_copy() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/sub/f.txt", b"f").await;
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    rig.backend.unlink(&path("e\\sub\\f.txt")).await.unwrap();
    assert_eq!(listed(&mut rig, "e").await, ["sub"]);
    assert!(listed(&mut rig, "e\\sub").await.is_empty());

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/sub/"]);
    assert!(rig.smb.open_dir("e\\sub").await.is_ok());
    assert!(rig.backend.failures().is_empty());
}

// Entries below a directory while it moves.

#[tokio::test]
async fn a_file_that_lands_while_its_directory_is_listed_moves_with_it() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/other.txt", b"other").await;
    make(&mut rig, "d\\new.txt", b"local bytes").await;
    let (listed_all, resume) = rig.backend.pause_after_listing();
    let renaming = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.rename(&path("d"), &path("e"), false).await }
    });
    listed_all.notified().await;

    rig.backend.hold_uploads(false);
    let bucket = rig.bucket.name.clone();
    wait_until("the file landed", || {
        rig.proxy.count(is_put_of(&bucket, "d/new.txt")) == 1 && left(&rig, "records") == 0
    })
    .await;
    resume.notify_one();
    renaming.await.unwrap().unwrap();

    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/new.txt", "e/other.txt"]);
    assert_eq!(remote(&rig, "e/new.txt").await.unwrap(), b"local bytes");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_file_created_in_a_directory_that_was_renamed_meanwhile_is_not_made() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    let (checked, resume) = rig.backend.pause_before_create();
    let creating = tokio::spawn({
        let backend = rig.backend.clone();
        async move {
            backend
                .open(&path("d\\new.txt"), create_options(false))
                .await
                .map(|_| ())
        }
    });
    checked.notified().await;
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    resume.notify_one();
    assert!(matches!(
        creating.await.unwrap(),
        Err(SmbError::PathNotFound)
    ));

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/f.txt"]);
    assert_eq!(left(&rig, "data"), 0);
}

#[tokio::test]
async fn names_are_not_taken_below_a_directory_while_it_is_listed_for_a_rename() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    put(rig.store(), "other/g.txt", b"g").await;
    let (listed_all, resume) = rig.backend.pause_after_listing();
    let renaming = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.rename(&path("d"), &path("e"), false).await }
    });
    listed_all.notified().await;

    assert!(matches!(
        rig.backend
            .open(&path("d\\new.txt"), create_options(false))
            .await,
        Err(SmbError::Sharing)
    ));
    assert!(matches!(
        rig.backend
            .rename(&path("other\\g.txt"), &path("d\\g.txt"), false)
            .await,
        Err(SmbError::Sharing)
    ));
    assert!(
        rig.backend
            .open(&path("d\\f.txt"), OpenOptions::default())
            .await
            .is_ok(),
        "a name that exists can still be opened"
    );
    assert_eq!(rig.smb.contents("other\\g.txt", 10).await, b"g");

    resume.notify_one();
    renaming.await.unwrap().unwrap();
    assert_eq!(listed(&mut rig, "").await, ["e", "other"]);
    assert_eq!(listed(&mut rig, "e").await, ["f.txt"]);
}

#[tokio::test]
async fn a_rename_lists_a_directory_only_after_the_deletes_in_flight_below_it_end() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/old.txt", b"old").await;
    put(rig.store(), "d/keep.txt", b"keep").await;
    rig.backend.unlink(&path("d\\old.txt")).await.unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_delete).await;
    assert!(
        rig.backend.key_in_use("d/old.txt"),
        "the delete is in flight"
    );

    let (listed_all, resume) = rig.backend.pause_after_listing();
    let renaming = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.rename(&path("d"), &path("e"), false).await }
    });
    wait_until("the rename waits for the delete", || {
        rig.backend.waits() >= 1
    })
    .await;
    assert_eq!(
        rig.proxy.count(is_whole_listing("d")),
        0,
        "the directory is not listed while a delete below it runs"
    );

    gate.notify_one();
    listed_all.notified().await;
    assert_eq!(remote(&rig, "d/old.txt").await, None, "it was deleted");
    resume.notify_one();
    renaming.await.unwrap().unwrap();
    sync(&rig.backend).await.unwrap();

    assert_eq!(keys(&rig).await, ["e/", "e/keep.txt"]);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_rename_that_waits_for_a_delete_that_is_stuck_fails_at_the_deadline() {
    let mut rig = Rig::writable_with(|b| held(b).request_timeout(Duration::from_secs(1))).await;
    put(rig.store(), "d/old.txt", b"old").await;
    put(rig.store(), "d/keep.txt", b"keep").await;
    rig.backend.unlink(&path("d\\old.txt")).await.unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_delete).await;

    let started = Instant::now();
    let renamed = rig.backend.rename(&path("d"), &path("e"), false).await;
    let waited = started.elapsed();
    assert!(matches!(renamed, Err(SmbError::Io(_))), "{renamed:?}");
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    assert_eq!(rig.proxy.count(is_whole_listing("d")), 0);

    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["d/keep.txt"]);
    assert_eq!(listed(&mut rig, "").await, ["d"]);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_directory_is_checked_for_content_only_after_the_deletes_in_flight_below_it_end() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/old.txt", b"old").await;
    rig.backend.unlink(&path("d\\old.txt")).await.unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_delete).await;
    assert!(
        rig.backend.key_in_use("d/old.txt"),
        "the delete is in flight"
    );

    let unlinking = tokio::spawn({
        let backend = rig.backend.clone();
        async move { backend.unlink(&path("d")).await }
    });
    wait_until("the unlink waits for the delete", || {
        rig.backend.waits() >= 1 || unlinking.is_finished()
    })
    .await;
    assert!(
        !unlinking.is_finished(),
        "the directory is not checked while a delete below it runs"
    );
    let checks = rig.proxy.count(is_content_check("d"));

    gate.notify_one();
    unlinking.await.unwrap().unwrap();
    assert_eq!(rig.proxy.count(is_content_check("d")), checks + 1);
    assert_eq!(remote(&rig, "d/old.txt").await, None, "it was deleted");
    assert_eq!(
        rig.smb.open_dir("d").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert!(rig.backend.failures().is_empty());
}

// What a crash leaves of a batch.

#[tokio::test]
async fn a_file_moved_back_before_the_records_of_a_batch_stays_back_after_a_crash() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    put(rig.store(), "d/g.txt", b"g").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    let made = rig.smb.create("d", create_dir()).await.unwrap();
    rig.smb.close(made.id).await;
    rig.backend
        .rename(&path("e\\f.txt"), &path("d\\f.txt"), false)
        .await
        .unwrap();

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(listed(&mut rig, "d").await, ["f.txt"]);
    assert_eq!(listed(&mut rig, "e").await, ["g.txt"]);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["d/", "d/f.txt", "e/", "e/g.txt"]);
    assert_eq!(remote(&rig, "d/f.txt").await.unwrap(), b"f");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_directory_made_where_an_implicit_one_was_renamed_away_keeps_its_marker_after_a_crash() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    let made = rig.smb.create("d", create_dir()).await.unwrap();
    rig.smb.close(made.id).await;
    assert_eq!(keys(&rig).await, ["d/", "d/f.txt"]);

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(listed(&mut rig, "").await, ["d", "e"]);
    assert_eq!(rig.smb.contents("e\\f.txt", 10).await, b"f");
    assert!(listed(&mut rig, "d").await.is_empty());
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["d/", "e/", "e/f.txt"]);
    assert!(rig.smb.open_dir("d").await.is_ok());
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn files_unlinked_from_a_batch_leave_it_in_one_rewrite_before_their_keys_go() {
    let rig = Rig::writable_with(held).await;
    for name in ["a", "b", "c"] {
        put(rig.store(), &format!("d/{name}.txt"), name.as_bytes()).await;
    }
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    assert_eq!(batch_members(&rig).len(), 4);
    let batch = all_records(&rig)[0].id().clone();
    rig.backend.hooks().record_ops.lock().unwrap().clear();

    rig.backend.unlink(&path("e\\a.txt")).await.unwrap();
    rig.backend.unlink(&path("e\\b.txt")).await.unwrap();
    assert_eq!(
        batch_members(&rig).len(),
        4,
        "their tombstone records stand for them"
    );
    let tombstones: Vec<RecordId> = all_records(&rig)
        .iter()
        .filter(|record| matches!(record, Record::Tombstone(_)))
        .map(|record| record.id().clone())
        .collect();
    assert_eq!(tombstones.len(), 2);
    assert!(
        !record_ops(&rig).contains(&(RecordOp::Write, batch.clone())),
        "the batch record is not written yet"
    );

    rig.backend.hold_uploads(false);
    wait_until("their keys are deleted", || {
        !all_records(&rig)
            .iter()
            .any(|record| matches!(record, Record::Tombstone(_)))
    })
    .await;
    assert_eq!(batch_members(&rig), ["e", "e/c.txt"]);

    // One rewrite of the batch record served both files, and it came before
    // the first tombstone record went.
    let ops = record_ops(&rig);
    let rewrites: Vec<usize> = (0..ops.len())
        .filter(|&at| ops[at] == (RecordOp::Write, batch.clone()))
        .collect();
    let first_removal = (0..ops.len())
        .find(|&at| ops[at].0 == RecordOp::Remove && tombstones.contains(&ops[at].1))
        .expect("a tombstone record went");
    assert_eq!(rewrites.len(), 1, "{ops:?}");
    assert!(rewrites[0] < first_removal, "{ops:?}");

    resume.notify_one();
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/c.txt"]);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_rename_that_fails_after_it_replaced_a_batch_member_puts_the_member_back_in_the_batch() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    put(rig.store(), "d/b.txt", b"b").await;
    put(rig.store(), "f.txt", b"f").await;
    let timed = rig.smb.create("f.txt", open_rw()).await.unwrap();
    assert_eq!(rig.smb.set_write_time(timed.id, 1_500_000_000).await, 0);
    rig.smb.close(timed.id).await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    assert_eq!(batch_members(&rig), ["e", "e/a.txt", "e/b.txt"]);

    // The tombstone record of the replaced e/b.txt is written, and the record
    // of f.txt at its new name is not.
    rig.backend.hooks().record_write_skips.store(1, SeqCst);
    rig.backend.hooks().record_writes.store(1, SeqCst);
    assert!(matches!(
        rig.backend
            .rename(&path("f.txt"), &path("e\\b.txt"), true)
            .await,
        Err(SmbError::Io(_))
    ));
    assert!(tombstoned(&rig).is_empty());

    // The batch record is written again when another file leaves it, and it
    // lists e/b.txt still.
    rig.backend.unlink(&path("e\\a.txt")).await.unwrap();
    rig.backend.hold_uploads(false);
    wait_until("the key of the deleted file is gone", || {
        tombstoned(&rig).is_empty()
    })
    .await;
    assert_eq!(batch_members(&rig), ["e", "e/b.txt"]);

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    assert_eq!(listed(&mut rig, "e").await, ["b.txt"]);
    assert_eq!(rig.smb.contents("e\\b.txt", 10).await, b"b");
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/b.txt", "f.txt"]);
    assert!(rig.backend.failures().is_empty());
}

/// Moves `d`, which holds `d/a.txt` and the file `d/new.txt` that was never
/// recorded, to `e`, and holds the move at its batch. Then the rename of
/// `f.txt` over `e/new.txt` fails: the batch record is written without
/// `e/new.txt` first, and the record of `f.txt` and the next `failing - 1`
/// record writes fail. Returns the rig, what resumes the move, the id of the
/// batch record and the id of `e/new.txt`.
async fn failed_replace_of_an_unrecorded_member(
    failing: usize,
) -> (Rig, Arc<Notify>, RecordId, RecordId) {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    put(rig.store(), "f.txt", b"f").await;
    let file = rig.smb.create("d\\new.txt", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, b"only here").await;
    rig.backend.hooks().record_writes.store(1, SeqCst);
    rig.smb.close(file.id).await;
    assert_eq!(rig.backend.hooks().record_writes.load(SeqCst), 0);
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    let found = all_records(&rig);
    assert_eq!(found.len(), 1);
    let Record::Batch(batch) = &found[0] else {
        panic!("not a batch record: {:?}", found[0]);
    };
    let member = batch
        .members
        .iter()
        .find(|member| member.key == "e/new.txt")
        .expect("the file moved with its directory");
    let ids = (batch.id.clone(), member.id.clone());

    rig.backend.hooks().record_ops.lock().unwrap().clear();
    rig.backend.hooks().record_write_skips.store(1, SeqCst);
    rig.backend.hooks().record_writes.store(failing, SeqCst);
    let failed = rig
        .backend
        .rename(&path("f.txt"), &path("e\\new.txt"), true)
        .await;
    assert!(matches!(failed, Err(SmbError::Io(_))), "{failed:?}");
    assert_eq!(rig.backend.hooks().record_writes.load(SeqCst), 0);
    (rig, resume, ids.0, ids.1)
}

#[tokio::test]
async fn a_failed_rename_puts_the_replaced_member_back_in_the_batch_before_its_record_goes() {
    let (rig, resume, batch, member) = failed_replace_of_an_unrecorded_member(1).await;
    let ops = record_ops(&rig);
    let last_batch_write = ops
        .iter()
        .rposition(|op| *op == (RecordOp::Write, batch.clone()))
        .expect("the batch record is written");
    let first_removal = ops
        .iter()
        .position(|op| *op == (RecordOp::Remove, member.clone()))
        .expect("the record of the member is dealt with");
    assert!(last_batch_write < first_removal, "{ops:?}");
    assert_eq!(batch_members(&rig), ["e", "e/a.txt", "e/new.txt"]);

    resume.notify_one();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt", "e/new.txt", "f.txt"]);
    assert_eq!(remote(&rig, "e/new.txt").await.unwrap(), b"only here");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_batch_record_that_lacks_a_member_that_came_back_is_written_before_any_record_of_its_own()
{
    let (rig, resume, batch, _) = failed_replace_of_an_unrecorded_member(2).await;
    assert_eq!(
        batch_members(&rig),
        ["e", "e/a.txt"],
        "the record could not be written with the member"
    );
    rig.backend.hooks().record_ops.lock().unwrap().clear();

    resume.notify_one();
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    let ops = record_ops(&rig);
    assert_eq!(
        ops.first(),
        Some(&(RecordOp::Write, batch.clone())),
        "{ops:?}"
    );
    assert_eq!(remote(&rig, "e/new.txt").await.unwrap(), b"only here");
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt", "e/new.txt", "f.txt"]);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_replaced_member_whose_batch_line_cannot_be_written_back_keeps_its_data_after_a_crash() {
    let (rig, resume, _, member) = failed_replace_of_an_unrecorded_member(2).await;
    assert_eq!(
        batch_members(&rig),
        ["e", "e/a.txt"],
        "the record could not be written with the member"
    );
    assert!(
        all_records(&rig)
            .iter()
            .any(|record| record.id() == &member),
        "the member has a record of its own"
    );

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(listed(&mut rig, "e").await, ["a.txt", "new.txt"]);
    assert_eq!(rig.smb.contents("e\\new.txt", 20).await, b"only here");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "e/new.txt").await.unwrap(), b"only here");
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt", "e/new.txt", "f.txt"]);
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn an_unlink_that_fails_after_the_batch_record_was_written_without_the_file_puts_it_back() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    let file = rig.smb.create("d\\local.txt", create_file()).await.unwrap();
    fill(&mut rig.smb, file.id, b"never sent").await;
    assert_eq!(rig.smb.flush(file.id).await, 0);
    rig.smb.close(file.id).await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    assert_eq!(batch_members(&rig), ["e", "e/a.txt", "e/local.txt"]);

    // The old record of the file cannot be removed.
    rig.backend.hooks().record_removals.store(1, SeqCst);
    assert!(matches!(
        rig.backend.unlink(&path("e\\local.txt")).await,
        Err(SmbError::Io(_))
    ));
    assert_eq!(batch_members(&rig), ["e", "e/a.txt", "e/local.txt"]);

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, uploading).await;
    assert_eq!(rig.smb.contents("e\\local.txt", 20).await, b"never sent");
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt", "e/local.txt"]);
}

#[tokio::test]
async fn a_rename_that_cannot_remove_the_old_record_of_a_batch_member_leaves_it_in_the_batch() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    rig.backend
        .rename(&path("d\\a.txt"), &path("d\\b.txt"), false)
        .await
        .unwrap();
    assert_eq!(records(&rig).len(), 1);
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    let made = rig.smb.create("d", create_dir()).await.unwrap();
    rig.smb.close(made.id).await;
    assert_eq!(batch_members(&rig), ["e", "e/b.txt"]);

    // The file goes back to its first name, which leaves nothing to record,
    // and its record of the earlier place cannot be removed.
    rig.backend.hooks().record_removals.store(1, SeqCst);
    let failed = rig
        .backend
        .rename(&path("e\\b.txt"), &path("d\\a.txt"), false)
        .await;
    assert!(matches!(failed, Err(SmbError::Io(_))), "{failed:?}");
    assert_eq!(rig.backend.hooks().record_removals.load(SeqCst), 0);
    assert_eq!(
        batch_members(&rig),
        ["e", "e/b.txt"],
        "the batch record lists the file again"
    );

    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(listed(&mut rig, "e").await, ["b.txt"]);
    assert!(!exists(&mut rig, "d\\a.txt").await);
    assert!(!exists(&mut rig, "d\\b.txt").await);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["d/", "e/", "e/b.txt"]);
    assert_eq!(remote(&rig, "e/b.txt").await.unwrap(), b"a");
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_file_deleted_from_a_directory_renamed_back_stays_deleted_after_a_crash() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    wait_until("the entries of the first move are recorded", || {
        batch_members(&rig).is_empty() && !all_records(&rig).is_empty()
    })
    .await;

    // The record of e/f.txt stays when the file goes back, though the file
    // has nothing to store at d/f.txt. The file is deleted before the second
    // move gives its entries records.
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("e"), &path("d"), false)
        .await
        .unwrap();
    reached.notified().await;
    rig.backend.unlink(&path("d\\f.txt")).await.unwrap();
    resume.notify_one();
    wait_until("the entries of the second move are recorded", || {
        batch_members(&rig).is_empty()
    })
    .await;
    assert_eq!(tombstoned(&rig), ["d/f.txt"]);

    let mut rig = rig.restart_with(held).await;
    assert!(!exists(&mut rig, "d\\f.txt").await);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["d/"]);
    assert!(rig.backend.failures().is_empty());
}

/// A file at a key that is still a key to delete, because the record of the
/// key could not be updated, is replaced by a rename that then fails.
async fn failed_replace_of_a_file_at_a_key_to_delete() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "to.txt", b"to").await;
    put(rig.store(), "old.txt", b"old").await;
    put(rig.store(), "from.txt", b"from").await;
    rig.backend.unlink(&path("to.txt")).await.unwrap();
    rig.backend.hooks().record_removals.store(1, SeqCst);
    rig.backend
        .rename(&path("old.txt"), &path("to.txt"), false)
        .await
        .unwrap();
    assert_eq!(rig.backend.hooks().record_removals.load(SeqCst), 0);
    assert_eq!(tombstoned(&rig), ["to.txt"], "the key is still to delete");

    // The tombstone record that takes the id of the replaced file is
    // written, and the record of from.txt at its new name is not.
    rig.backend.hooks().record_write_skips.store(1, SeqCst);
    rig.backend.hooks().record_writes.store(1, SeqCst);
    let failed = rig
        .backend
        .rename(&path("from.txt"), &path("to.txt"), true)
        .await;
    assert!(matches!(failed, Err(SmbError::Io(_))), "{failed:?}");
    assert_eq!(rig.smb.contents("to.txt", 10).await, b"old");
    assert_eq!(rig.smb.contents("from.txt", 10).await, b"from");
    assert!(tombstoned(&rig).is_empty(), "{:?}", all_records(&rig));
    assert_eq!(records(&rig).len(), 1);

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "to.txt").await.unwrap(), b"old");
    assert_eq!(remote(&rig, "from.txt").await.unwrap(), b"from");
    assert_eq!(remote(&rig, "old.txt").await, None);
    assert!(rig.backend.failures().is_empty());
}

#[test]
fn a_failed_rename_restores_a_replaced_file_whose_key_is_still_to_be_deleted() {
    run_bounded(
        "a failed rename over a file at a key to delete did not end",
        Duration::from_secs(60),
        failed_replace_of_a_file_at_a_key_to_delete,
    );
}

// Keys a move cannot carry.

#[tokio::test]
async fn a_directory_with_a_key_no_client_could_open_is_not_renamed() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/ok.txt", b"ok").await;
    for bad in [
        "d/bad:name.txt",
        "d//twice.txt",
        "d/sub//deep.txt",
        "d/sub/.",
    ] {
        rig.proxy.clear_rules();
        rig.proxy.inject(
            is_whole_listing("d"),
            Fault::Reply(listing_reply(&[("d/ok.txt", 2), (bad, 3)], &[])),
            usize::MAX,
        );
        assert!(
            matches!(
                rig.backend.rename(&path("d"), &path("e"), false).await,
                Err(SmbError::AccessDenied)
            ),
            "{bad}"
        );
        assert_unchanged(&rig);
    }
    assert_eq!(listed(&mut rig, "").await, ["d"]);

    rig.proxy.clear_rules();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    assert_eq!(listed(&mut rig, "").await, ["e"]);
}

#[tokio::test]
async fn a_file_and_a_directory_of_one_name_stop_the_rename() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "d/real.txt", b"real").await;
    rig.proxy.inject(
        is_whole_listing("d"),
        Fault::Reply(listing_reply(&[("d/a", 1), ("d/a/x", 1)], &[])),
        usize::MAX,
    );
    assert!(matches!(
        rig.backend.rename(&path("d"), &path("e"), false).await,
        Err(SmbError::AccessDenied)
    ));
    assert_unchanged(&rig);
    assert_eq!(listed(&mut rig, "").await, ["d"]);
}

#[tokio::test]
async fn keys_that_differ_in_case_only_stop_the_rename_when_they_land_on_one_name() {
    let rig = Rig::writable_with(held).await;
    if folds(&rig).await {
        return;
    }
    put(rig.store(), "d/A.txt", b"upper").await;
    put(rig.store(), "d/a.txt", b"lower").await;
    assert!(matches!(
        rig.backend.rename(&path("d"), &path("e"), false).await,
        Err(SmbError::AccessDenied)
    ));
    assert_unchanged(&rig);
}

#[tokio::test]
async fn a_key_is_to_be_deleted_only_when_its_exact_spelling_is() {
    let mut rig = Rig::writable_with(held).await;
    if folds(&rig).await {
        return;
    }
    put(rig.store(), "d/A.txt", b"upper").await;
    put(rig.store(), "d/a.txt", b"lower").await;
    rig.backend.unlink(&path("d\\A.txt")).await.unwrap();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    assert_eq!(rig.smb.contents("e\\a.txt", 10).await, b"lower");
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt"]);
    assert_eq!(remote(&rig, "e/a.txt").await.unwrap(), b"lower");
}

#[tokio::test]
async fn a_case_only_rename_onto_a_directory_of_the_new_spelling_is_refused() {
    let mut rig = Rig::writable_with(held).await;
    if folds(&rig).await {
        return;
    }
    put(rig.store(), "docs/a.txt", b"a").await;
    put(rig.store(), "DOCS/b.txt", b"b").await;
    assert!(matches!(
        rig.backend
            .rename(&path("docs"), &path("DOCS"), false)
            .await,
        Err(SmbError::AccessDenied)
    ));
    assert_unchanged(&rig);
    assert_eq!(listed(&mut rig, "").await, ["DOCS", "docs"]);
}

#[tokio::test]
async fn a_key_in_another_case_than_a_file_a_handle_holds_stops_the_rename() {
    let mut rig = Rig::writable_with(held).await;
    if folds(&rig).await {
        return;
    }
    put(rig.store(), "d/a.txt", b"lower").await;
    put(rig.store(), "d/A.txt", b"upper").await;
    let open = rig.smb.open("d\\a.txt").await.unwrap();
    assert!(matches!(
        rig.backend.rename(&path("d"), &path("e"), false).await,
        Err(SmbError::AccessDenied)
    ));
    assert!(all_records(&rig).is_empty());
    assert_eq!(changes(&rig), 0);
    assert_eq!(listed(&mut rig, "").await, ["d"]);
    rig.smb.close(open.id).await;
    assert_eq!(keys(&rig).await, ["d/A.txt", "d/a.txt"]);
}

#[tokio::test]
async fn a_marker_in_another_case_than_a_directory_a_handle_holds_stops_the_rename() {
    let mut rig = Rig::writable_with(held).await;
    if folds(&rig).await {
        return;
    }
    mark(&rig, "d/sub/", &[]).await;
    mark(&rig, "d/SUB/", &[]).await;
    let open = rig.smb.open_dir("d\\sub").await.unwrap();
    assert!(matches!(
        rig.backend.rename(&path("d"), &path("e"), false).await,
        Err(SmbError::AccessDenied)
    ));
    assert!(all_records(&rig).is_empty());
    assert_eq!(changes(&rig), 0);
    assert_eq!(listed(&mut rig, "").await, ["d"]);
    rig.smb.close(open.id).await;
    assert_eq!(keys(&rig).await, ["d/SUB/", "d/sub/"]);
}

// The records of a batch.

#[tokio::test]
async fn a_full_cache_disk_makes_the_records_of_a_moved_directory_rest_and_try_again() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    put(rig.store(), "d/b.txt", b"b").await;
    let (reached, resume) = rig.backend.pause_after_batch();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    reached.notified().await;
    rig.backend.hooks().disk_full.store(true, SeqCst);
    rig.backend.hooks().record_writes.store(1, SeqCst);
    resume.notify_one();
    wait_until("the records met the full disk", || {
        rig.backend.hooks().record_writes.load(SeqCst) == 0
    })
    .await;

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt", "e/b.txt"]);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
}

#[tokio::test]
async fn a_panic_while_the_records_of_a_moved_directory_are_written_fails_them_and_sync_returns() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    rig.backend.panic_dissolve();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    rig.backend.hold_uploads(false);
    assert!(sync(&rig.backend).await.is_err());
    assert_eq!(rig.backend.failures().len(), 2);
    assert_eq!(changes(&rig), 0);
}

#[tokio::test]
async fn a_panic_while_the_times_of_a_moved_object_are_read_is_logged_at_error_level() {
    let logs = Logs::capture();
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/a.txt", b"a").await;
    rig.backend.panic_read_base();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    let message = "the times of an object of a renamed directory";
    wait_until("the panic is logged", || logs.text().contains(message)).await;
    let log = logs.text();
    let line = log.lines().find(|line| line.contains(message)).unwrap();
    assert!(line.contains(" ERROR "), "{log}");

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/", "e/a.txt"]);
}

// Directories made while keys are deleted.

#[tokio::test]
async fn a_directory_made_while_the_delete_of_its_marker_is_in_flight_waits_for_it() {
    let rig = Rig::writable_with(held).await;
    mark(&rig, "x/", &[]).await;
    rig.backend.unlink(&path("x")).await.unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_delete).await;
    assert!(rig.backend.key_in_use("x/"), "the delete is in flight");

    let making = tokio::spawn({
        let backend = rig.backend.clone();
        async move {
            backend
                .open(&path("x"), create_options(true))
                .await
                .map(|_| ())
        }
    });
    wait_until("the create waits for the delete", || {
        rig.backend.waits() >= 1 || making.is_finished()
    })
    .await;
    assert!(!making.is_finished(), "the marker is not put yet");
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "x/")), 0);

    gate.notify_one();
    making.await.unwrap().unwrap();
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["x/"]);
    assert!(rig.backend.failures().is_empty());
}

/// Deletes the empty directory `x`, then makes it again after `spoil` has
/// made the make fail. The key of its marker is to be deleted all along, and
/// the directory is deleted for good once the backend stores.
async fn failed_make_after_delete(spoil: impl FnOnce(&Rig)) {
    let mut rig = Rig::writable_with(held).await;
    mark(&rig, "x/", &[]).await;
    rig.backend.unlink(&path("x")).await.unwrap();
    assert_eq!(tombstoned(&rig), ["x/"]);

    spoil(&rig);
    assert!(rig.smb.create("x", create_dir()).await.is_err());
    assert_eq!(tombstoned(&rig), ["x/"], "the key to delete is not let go");
    assert_eq!(rig.backend.overlay_len(), 0);

    rig.proxy.clear_rules();
    rig.backend.hooks().disk_full.store(false, SeqCst);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert_eq!(
        rig.smb.open_dir("x").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_directory_whose_marker_the_store_refuses_does_not_undo_the_delete_before_it() {
    failed_make_after_delete(|rig| {
        let target = format!("/{}/x/", rig.bucket.name);
        rig.proxy.inject(
            move |seen| seen.method == "PUT" && seen.target == target,
            Fault::Reply(Reply::error(403, "AccessDenied")),
            usize::MAX,
        );
    })
    .await;
}

#[tokio::test]
async fn a_directory_whose_record_cannot_be_written_does_not_undo_the_delete_before_it() {
    failed_make_after_delete(|rig| {
        rig.backend.hooks().disk_full.store(true, SeqCst);
        rig.backend.hooks().record_writes.store(1, SeqCst);
    })
    .await;
}

#[tokio::test]
async fn a_directory_made_while_the_delete_of_its_marker_is_stuck_fails_at_the_deadline() {
    let mut rig = Rig::writable_with(|b| held(b).request_timeout(Duration::from_secs(1))).await;
    mark(&rig, "x/", &[]).await;
    rig.backend.unlink(&path("x")).await.unwrap();
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_delete, Fault::Hold(Arc::clone(&gate)), 1);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_delete).await;

    let started = Instant::now();
    let made = rig.backend.open(&path("x"), create_options(true)).await;
    let waited = started.elapsed();
    assert!(matches!(made, Err(SmbError::Io(_))));
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    assert_eq!(
        tombstoned(&rig),
        ["x/"],
        "the delete in flight is not undone"
    );
    assert_eq!(rig.backend.overlay_len(), 0);
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "x/")), 0);

    gate.notify_one();
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert_eq!(
        rig.smb.open_dir("x").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_directory_deleted_while_its_marker_is_put_is_deleted_from_the_bucket() {
    let rig = Rig::writable_with(held).await;
    let release = Arc::new(Notify::new());
    let target = format!("/{}/x/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == target,
        Fault::Hold(Arc::clone(&release)),
        1,
    );
    let making = tokio::spawn({
        let backend = rig.backend.clone();
        async move {
            backend
                .open(&path("x"), create_options(true))
                .await
                .map(|_| ())
        }
    });
    wait_for_requests(&rig.proxy, 1, |seen| seen.method == "PUT").await;

    rig.backend.unlink(&path("x")).await.unwrap();
    assert_eq!(tombstoned(&rig), ["x/"]);
    release.notify_one();
    making.await.unwrap().unwrap();
    assert_eq!(tombstoned(&rig), ["x/"], "the new marker does not undo it");

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert!(rig.backend.failures().is_empty());
}

#[tokio::test]
async fn a_directory_deleted_while_its_marker_is_refused_stays_deleted_after_a_crash() {
    let mut rig = Rig::writable_with(held).await;
    let gate = Arc::new(Notify::new());
    let target = format!("/{}/x/", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "PUT" && seen.target == target,
        Fault::HoldReply(Arc::clone(&gate), Reply::error(403, "AccessDenied")),
        1,
    );
    let making = tokio::spawn({
        let backend = rig.backend.clone();
        async move {
            backend
                .open(&path("x"), create_options(true))
                .await
                .map(|_| ())
        }
    });
    wait_for_requests(&rig.proxy, 1, |seen| seen.method == "PUT").await;

    // Another handle opens the directory that is being made and deletes it on
    // close.
    let other = rig.smb.create("x", dir_delete()).await.unwrap();
    assert_eq!(rig.smb.set_delete(other.id).await, 0);
    rig.smb.close(other.id).await;
    assert_eq!(tombstoned(&rig), ["x/"]);

    gate.notify_one();
    assert!(making.await.unwrap().is_err());
    assert_eq!(
        tombstoned(&rig),
        ["x/"],
        "the make that failed does not undo the delete"
    );

    let mut rig = rig.restart_with(held).await;
    assert_eq!(
        rig.smb.open_dir("x").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
    assert!(rig.backend.failures().is_empty());
}

// Keys another entry takes over.

#[tokio::test]
async fn an_entry_that_cannot_record_the_loss_of_a_key_to_delete_fails_and_sync_returns() {
    let rig = Rig::writable_with(held).await;
    mark(&rig, "x/", &[]).await;
    rig.backend
        .rename(&path("x"), &path("y"), false)
        .await
        .unwrap();
    // The marker of y is put when the backend ends before the delete of x/:
    // y has nothing left to do but let x/ go.
    let (reached, resume) = rig.backend.pause_after_landing();
    rig.backend.hold_uploads(false);
    reached.notified().await;
    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(left(&rig, "records"), 1);

    // A sync that began before the new directory takes the key x/ waits for y.
    let backend = rig.backend.clone();
    let mut syncing = Box::pin(async move { backend.sync().await });
    tokio::select! {
        biased;
        _ = &mut syncing => panic!("the sync returned before y was done"),
        () = std::future::ready(()) => {}
    }
    rig.backend.hooks().record_removals.store(1, SeqCst);
    let made = rig.smb.create("x", create_dir()).await.unwrap();
    rig.smb.close(made.id).await;
    assert_eq!(rig.backend.hooks().record_removals.load(SeqCst), 0);

    let failure = tokio::time::timeout(Duration::from_secs(10), syncing)
        .await
        .expect("the sync returns")
        .unwrap_err();
    assert!(matches!(failure, S3Error::Cache(_)), "{failure:?}");
    assert_eq!(rig.backend.failures().len(), 1);

    // The record of y still names x/, and the marker of x is in the bucket:
    // after a restart x puts its marker again before y can delete it.
    let mut rig = rig.restart_with(held).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["x/", "y/"]);
    assert!(rig.backend.failures().is_empty());
    assert_eq!(left(&rig, "records"), 0);
    assert!(rig.smb.open_dir("x").await.is_ok());
}

#[tokio::test]
async fn a_file_takes_a_key_over_only_after_its_owner_has_recorded_the_loss() {
    let mut rig = Rig::writable_with(held).await;
    put(rig.store(), "a.txt", b"was a").await;
    rig.backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    make(&mut rig, "a.txt", b"is c").await;
    // The copy at b.txt has landed and not deleted a.txt yet, so the new
    // a.txt takes the key over. The record of b.txt cannot be removed once,
    // for lack of room.
    let (reached, resume) = rig.backend.pause_after_landing();
    rig.backend.hooks().disk_full.store(true, SeqCst);
    rig.backend.hooks().record_removals.store(1, SeqCst);
    rig.backend.hold_uploads(false);
    reached.notified().await;
    wait_until("the record of b.txt met the full disk", || {
        rig.backend.hooks().record_removals.load(SeqCst) == 0
    })
    .await;
    assert_eq!(rig.proxy.count(is_put_of(&rig.bucket.name, "a.txt")), 0);
    assert!(
        rig.backend.failures().is_empty(),
        "a full disk is no failure"
    );

    // The new file rests and takes the key over once the record is written.
    wait_until_async("the new a.txt is stored", async || {
        remote(&rig, "a.txt").await.as_deref() == Some(b"is c".as_slice())
    })
    .await;

    // The backend ends before b.txt deletes a.txt. What the record of b.txt
    // says must not bring the delete back.
    let (bucket, proxy, cache) = crash(rig, resume).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "a.txt").await.unwrap(), b"is c");
    assert_eq!(remote(&rig, "b.txt").await.unwrap(), b"was a");
    assert_eq!(rig.smb.contents("a.txt", 10).await, b"is c");
    assert!(rig.backend.failures().is_empty());
}

// Bases that a listing described.

#[tokio::test]
async fn the_times_of_moved_objects_are_read_in_the_background_after_the_rename() {
    let rig = Rig::writable_with(held).await;
    put_with(
        rig.store(),
        "d/f.txt",
        b"x",
        &[("mtime", "1300000000.000000000")],
    )
    .await;
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    wait_until_async("the times of the object are read", async || {
        let (dir, _) = rig
            .backend
            .open(&path("e"), OpenOptions::default())
            .await
            .unwrap();
        let entries = dir.list_dir(None).await.unwrap();
        entries
            .iter()
            .any(|entry| entry.info.last_write_time == filetime(1_300_000_000, 0))
    })
    .await;
    assert_eq!(changes(&rig), 0, "the jobs have not run");

    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(remote(&rig, "e/f.txt").await.unwrap(), b"x");
    assert_eq!(
        rig.proxy.count(is_head_of(&rig.bucket.name, "d/f.txt")),
        1,
        "the copy does not read what was read"
    );
}

#[tokio::test]
async fn a_file_deleted_while_its_job_finds_the_object_gone_stays_deleted_after_a_crash() {
    let rig = Rig::writable_with(held).await;
    put(rig.store(), "d/f.txt", b"f").await;
    // The base of e/f.txt stays the description the listing gave, so its job
    // asks the store about the object.
    rig.backend.panic_read_base();
    rig.backend
        .rename(&path("d"), &path("e"), false)
        .await
        .unwrap();
    wait_until("the entries of the move are recorded", || {
        batch_members(&rig).is_empty() && !all_records(&rig).is_empty()
    })
    .await;

    // The job of the file is asking, and the file is deleted before the store
    // answers that the object is gone.
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        is_head_of(&rig.bucket.name, "d/f.txt"),
        Fault::HoldReply(Arc::clone(&gate), Reply::new(404, "")),
        1,
    );
    rig.backend.hold_sweeps(true);
    rig.backend.hold_uploads(false);
    wait_for_requests(&rig.proxy, 1, is_head_of(&rig.bucket.name, "d/f.txt")).await;
    rig.backend.unlink(&path("e\\f.txt")).await.unwrap();
    assert_eq!(tombstoned(&rig), ["d/f.txt"]);

    // The backend ends, and the job handles the answer before the worker does.
    let (bucket, proxy, cache) = rig.stop_after(|| gate.notify_one()).await;
    let mut rig = Rig::start(bucket, proxy, cache, held).await;
    assert_eq!(left(&rig, "conflicts"), 0);
    assert_eq!(tombstoned(&rig), ["d/f.txt"]);
    assert!(!exists(&mut rig, "e\\f.txt").await);
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert_eq!(keys(&rig).await, ["e/"]);
    assert!(rig.backend.failures().is_empty());
}

/// Opens and closes each of many directories over and over from several
/// tasks while the directory is deleted.
async fn delete_directories_while_they_are_opened() {
    let rig = Rig::writable_with(held).await;
    for round in 0..150 {
        let name = format!("d{round}");
        mark(&rig, &format!("{name}/"), &[]).await;
        let target = path(&name);
        let mut storm = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let (backend, target) = (rig.backend.clone(), target.clone());
            storm.spawn(async move {
                for _ in 0..25 {
                    if let Ok((handle, _)) = backend.open(&target, OpenOptions::default()).await {
                        handle.close().await.unwrap();
                    }
                }
            });
        }
        let deleted = rig.backend.unlink(&target).await;
        assert!(
            matches!(deleted, Ok(()) | Err(SmbError::NotFound)),
            "{deleted:?}"
        );
        while let Some(done) = storm.join_next().await {
            done.unwrap();
        }
    }
    rig.backend.hold_uploads(false);
    sync(&rig.backend).await.unwrap();
    assert!(keys(&rig).await.is_empty());
}

#[test]
fn a_directory_opened_and_closed_over_and_over_while_it_is_deleted_is_deleted() {
    run_bounded(
        "deleting and opening directories deadlocked",
        Duration::from_secs(120),
        delete_directories_while_they_are_opened,
    );
}
