//! A full listing of the root that overlaps the create of an entry.
//!
//! A listing whose inner `list_dir` ran before the create does not have the
//! new entry. When it ends, the names of the root must still have it: an
//! unlink or a rename under another spelling finds the entry without listing
//! the root again, a create under another spelling meets it, and no second
//! stored entry appears.
//!
//! Time is paused and does not move, so every snapshot of the names has the
//! same age and only the count of changes decides whether a listing is kept.

use std::sync::Arc;

use super::backend::EncryptedBackend;
use super::format::MARKER_NAME;
use super::handle::EncryptedHandle;
use super::testing::{
    has, names as listed_names, names_over, open, open_dir, open_file, read_all, refused,
    seed_file, shares_node, stored_at, stored_name,
};
use crate::backend::{Handle, OpenAction, OpenIntent, ShareBackend};
use crate::error::SmbError;
use crate::path::SmbPath;
use crate::tests::faulty::Faulty;
use crate::tests::gated::{Gated, Op};
use crate::tests::memfs::MemFsBackend;
use crate::tests::util::{dir_opts, path};

type Inner = Faulty<Gated<MemFsBackend>>;
type Layer = EncryptedBackend<Inner>;
type Created = EncryptedHandle<Inner>;

/// Where the listing waits while the create runs.
#[derive(Clone, Copy)]
enum Park {
    /// After the inner backend has listed the root: the listing holds the
    /// entries from before the create.
    AfterInnerList,
    /// Before the inner backend lists the root: the listing reads the
    /// entries from after the create.
    BeforeInnerList,
}

/// A root that holds `Seed.txt`. A full listing of it waits at its inner
/// `list_dir`, `Report.docx` is created meanwhile, and the listing is released
/// and ends.
struct Scene {
    files: MemFsBackend,
    /// The inner backend of the layer, which counts the listings it serves.
    faulty: Inner,
    layer: Layer,
    /// The handle of the create, on a file that holds `hello`.
    created: Created,
    /// The names the listing returned, sorted.
    listed: Vec<String>,
}

async fn scene(park: Park) -> Scene {
    let files = MemFsBackend::new();
    let gated = Gated::new(files.clone());
    let faulty = Faulty::new(gated.clone());
    let layer = names_over(faulty.clone()).await;
    seed_file(&files, "Seed.txt", b"");
    let root = Arc::new(open_dir(&layer, "").await);

    let gate = match park {
        Park::AfterInnerList => gated.arm_after_at(Op::ListDir, ""),
        Park::BeforeInnerList => gated.arm_at(Op::ListDir, ""),
    };
    let listing = tokio::spawn({
        let root = Arc::clone(&root);
        async move { root.list_dir(None).await }
    });
    gate.reached().await;
    let (created, action) = open(&layer, "Report.docx", OpenIntent::Create).await;
    assert_eq!(action, OpenAction::Created);
    gate.release();
    let listed = listed_names(&listing.await.unwrap().unwrap());
    created.write(0, b"hello").await.unwrap();
    Scene {
        files,
        faulty,
        layer,
        created,
        listed,
    }
}

/// The names the inner store holds in its root, the marker left out, sorted.
async fn stored_root(files: &MemFsBackend) -> Vec<String> {
    let (root, _) = files
        .open(&SmbPath::root(), dir_opts(OpenIntent::Open))
        .await
        .unwrap();
    let entries = root.list_dir(None).await.unwrap();
    root.close().await.unwrap();
    let mut stored: Vec<_> = entries
        .into_iter()
        .map(|entry| entry.info.name)
        .filter(|name| name != MARKER_NAME)
        .collect();
    stored.sort();
    stored
}

/// The names the inner store holds for the names `plain`, sorted.
fn stored_names(plain: &[&str]) -> Vec<String> {
    let mut stored: Vec<_> = plain.iter().map(|name| stored_name(name)).collect();
    stored.sort();
    stored
}

#[tokio::test(start_paused = true)]
async fn a_listing_whose_inner_list_runs_after_a_create_has_the_new_name() {
    let Scene {
        files,
        layer,
        listed,
        ..
    } = scene(Park::BeforeInnerList).await;
    assert_eq!(listed, ["Report.docx", "Seed.txt"]);
    let stored = stored_names(&["Report.docx", "Seed.txt"]);
    assert_eq!(stored_root(&files).await, stored);

    let names = layer
        .shared
        .names
        .fresh("")
        .expect("the names of the root are cached");
    assert_eq!(names.len(), 2);
    assert!(
        has(&names, "Report.docx") && has(&names, "Seed.txt"),
        "listing parked before its inner list: the cached names lack an entry"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unlink_under_another_spelling_removes_a_file_created_during_a_listing() {
    let Scene {
        files,
        faulty,
        layer,
        created,
        ..
    } = scene(Park::AfterInnerList).await;
    let listings = faulty.list_calls().len();

    layer.unlink(&path("report.docx")).await.unwrap();
    assert_eq!(
        faulty.list_calls().len(),
        listings,
        "the cached names had the entry, so the root is not listed again"
    );
    assert_eq!(stored_root(&files).await, stored_names(&["Seed.txt"]));
    assert!(created.node().is_detached());
    let error = refused(&layer, "Report.docx", OpenIntent::Open).await;
    assert!(matches!(error, SmbError::NotFound), "{error:?}");
}

#[tokio::test(start_paused = true)]
async fn a_rename_under_another_spelling_moves_a_file_created_during_a_listing() {
    let Scene {
        files,
        faulty,
        layer,
        created,
        ..
    } = scene(Park::AfterInnerList).await;
    let listings = faulty.list_calls().len();

    layer
        .rename(&path("REPORT.DOCX"), &path("Final.docx"), false)
        .await
        .unwrap();
    assert_eq!(
        faulty.list_calls().len(),
        listings,
        "the cached names had the entry, so the root is not listed again"
    );
    let stored = stored_names(&["Seed.txt", "Final.docx"]);
    assert_eq!(stored_root(&files).await, stored);
    assert_eq!(created.node().path(), path(&stored_at("Final.docx")));
    let moved = open_file(&layer, "FINAL.docx").await;
    assert!(shares_node(&created, &moved));
    assert_eq!(read_all(&moved).await, b"hello");
}

#[tokio::test(start_paused = true)]
async fn create_under_another_spelling_is_exists_for_a_file_created_during_a_listing() {
    let Scene { files, layer, .. } = scene(Park::AfterInnerList).await;

    let error = refused(&layer, "REPORT.docx", OpenIntent::Create).await;
    assert!(matches!(error, SmbError::Exists), "{error:?}");
    let stored = stored_names(&["Seed.txt", "Report.docx"]);
    assert_eq!(stored_root(&files).await, stored);
}

#[tokio::test(start_paused = true)]
async fn open_or_create_under_another_spelling_opens_a_file_created_during_a_listing() {
    let Scene {
        files,
        layer,
        created,
        ..
    } = scene(Park::AfterInnerList).await;

    let (handle, action) = open(&layer, "REPORT.docx", OpenIntent::OpenOrCreate).await;
    assert_eq!(action, OpenAction::Opened);
    assert!(shares_node(&created, &handle));
    assert_eq!(handle.stat().await.unwrap().name, "Report.docx");
    assert_eq!(read_all(&handle).await, b"hello");
    let stored = stored_names(&["Seed.txt", "Report.docx"]);
    assert_eq!(stored_root(&files).await, stored);
}

#[tokio::test(start_paused = true)]
async fn overwrite_or_create_under_another_spelling_empties_a_file_created_during_a_listing() {
    let Scene {
        files,
        layer,
        created,
        ..
    } = scene(Park::AfterInnerList).await;

    let (handle, action) = open(&layer, "REPORT.docx", OpenIntent::OverwriteOrCreate).await;
    assert_eq!(action, OpenAction::Overwritten);
    assert!(shares_node(&created, &handle));
    assert_eq!(handle.stat().await.unwrap().name, "Report.docx");
    assert_eq!(read_all(&created).await, b"");
    let stored = stored_names(&["Seed.txt", "Report.docx"]);
    assert_eq!(stored_root(&files).await, stored);
}
