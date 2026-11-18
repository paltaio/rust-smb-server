//! A tree written through the layer over S3 reads back after the backends
//! are rebuilt, on the same cache directory and on a new one.

use std::collections::BTreeMap;
use std::path::Path;

use super::helpers::{BLOCK, Backend, assert_bytes, contents, mkdir, open_dir, put, shown, size};
use super::instances::s3_backend;
use crate::S3BackendBuilder;
use crate::encrypted::testing::names_over;
use crate::tests::data::pattern;
use crate::tests::s3::fixture::TestBucket;
use crate::tests::s3::share::worker_ended;
use crate::tests::s3::uploads::{held, sync};
use crate::tests::util::scratch_dir;

/// A name long enough to be stored with a side object, made of `letter`.
fn long(letter: &str) -> String {
    letter.repeat(200)
}

/// The directories of the tree, parents first.
fn dirs() -> Vec<String> {
    vec![
        "docs".to_string(),
        "docs\\edge".to_string(),
        "docs\\edge\\deep".to_string(),
        format!("docs\\{}", long("m")),
    ]
}

/// The files of the tree and what each holds.
fn files() -> Vec<(String, Vec<u8>)> {
    [
        ("empty".to_string(), 0),
        ("docs\\one".to_string(), 1),
        ("docs\\edge\\just_under".to_string(), BLOCK - 1),
        ("docs\\edge\\exact".to_string(), BLOCK),
        ("docs\\edge\\just_over".to_string(), BLOCK + 1),
        ("docs\\edge\\deep\\spans".to_string(), 3 * BLOCK + 5),
        (format!("docs\\{}", long("l")), 2 * BLOCK + 7),
        (format!("docs\\{}\\inner", long("m")), 100),
    ]
    .into_iter()
    .enumerate()
    .map(|(seed, (name, len))| (name, pattern(len, seed as u8 + 1)))
    .collect()
}

/// `name` split into its directory and its last component.
fn split(name: &str) -> (&str, &str) {
    name.rsplit_once('\\').unwrap_or(("", name))
}

/// Every directory lists exactly its entries, the sizes in the listing are
/// the sizes of the files, and each file holds its bytes.
async fn assert_tree(backend: Backend<'_>, dirs: &[String], files: &[(String, Vec<u8>)]) {
    let mut expected: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for name in dirs
        .iter()
        .map(String::as_str)
        .chain(files.iter().map(|(name, _)| name.as_str()))
    {
        let (dir, last) = split(name);
        expected.entry(dir).or_default().push(last);
    }
    for (dir, mut names) in expected {
        names.sort_unstable();
        let handle = open_dir(backend, dir).await;
        let entries = handle.list_dir(None).await.unwrap();
        handle.close().await.unwrap();
        let mut listed: Vec<_> = entries
            .iter()
            .map(|entry| entry.info.name.as_str())
            .collect();
        listed.sort_unstable();
        assert!(
            listed == names,
            "{dir}: got {:?}, expected {:?}",
            listed.iter().map(|name| shown(name)).collect::<Vec<_>>(),
            names.iter().map(|name| shown(name)).collect::<Vec<_>>()
        );
        for (name, data) in files.iter().filter(|(name, _)| split(name).0 == dir) {
            assert_eq!(
                size(&entries, split(name).1),
                Some(data.len() as u64),
                "size of {}",
                shown(name)
            );
        }
    }
    for (name, data) in files {
        assert_bytes(&contents(backend, name).await, data, &shown(name));
    }
}

#[tokio::test]
async fn a_tree_written_through_the_layer_reads_back_after_sync_and_a_rebuild() {
    let exact = |builder: S3BackendBuilder| held(builder).case_insensitive(false);
    let bucket = TestBucket::new().await;
    let cache = scratch_dir();
    let (dirs, files) = (dirs(), files());

    let (store, exited) = s3_backend(&bucket, cache.path(), exact).await.unwrap();
    let layer = names_over(store.clone()).await;
    for dir in &dirs {
        mkdir(&layer, dir).await;
    }
    for (name, data) in &files {
        put(&layer, name, data).await;
    }
    assert_tree(&layer, &dirs, &files).await;
    store.hold_uploads(false);
    sync(&store).await.unwrap();
    drop(layer);
    drop(store);
    worker_ended(exited).await;

    let fresh = scratch_dir();
    for cache in [cache.path(), fresh.path()] {
        read_back(&bucket, cache, exact, &dirs, &files).await;
    }
}

/// Builds a backend and a layer over the bucket and `cache`, and checks the
/// tree through them.
async fn read_back(
    bucket: &TestBucket,
    cache: &Path,
    exact: impl FnOnce(S3BackendBuilder) -> S3BackendBuilder,
    dirs: &[String],
    files: &[(String, Vec<u8>)],
) {
    let (store, exited) = s3_backend(bucket, cache, exact).await.unwrap();
    let layer = names_over(store).await;
    assert_tree(&layer, dirs, files).await;
    drop(layer);
    worker_ended(exited).await;
}
