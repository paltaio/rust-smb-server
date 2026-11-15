//! What open handles keep doing as their entries change, and what they report
//! about them.

use super::helpers::{
    Backend, assert_bytes, assert_refused, contents, listed, mkdir, names, open, open_dir,
    open_file, put, read_all, write,
};
use crate::backend::OpenIntent;
use crate::error::SmbError;
use crate::tests::data::nonzero_pattern;
use crate::tests::util::{opts, path};

pub(super) async fn a_file_handle_follows_a_rename(backend: Backend<'_>) {
    let (handle, _) = open(backend, "a.txt", OpenIntent::Create).await;
    write(&*handle, 0, b"hello").await;
    backend
        .rename(&path("a.txt"), &path("b.txt"), false)
        .await
        .unwrap();
    assert_eq!(handle.stat().await.unwrap().end_of_file, 5);
    assert_bytes(&read_all(&*handle).await, b"hello", "read after the rename");
    write(&*handle, 5, b" world").await;
    handle.close().await.unwrap();
    assert_bytes(
        &contents(backend, "b.txt").await,
        b"hello world",
        "the renamed file",
    );
    assert_eq!(names(backend, "").await, ["b.txt"]);
}

pub(super) async fn a_file_handle_follows_a_move_to_another_directory(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    let data = nonzero_pattern(100_000);
    put(backend, "f", &data).await;
    let handle = open_file(backend, "f").await;
    backend
        .rename(&path("f"), &path("d\\g"), false)
        .await
        .unwrap();
    assert_bytes(&read_all(&*handle).await, &data, "read after the move");
    write(&*handle, 100_000, b"more").await;
    handle.truncate(100_002).await.unwrap();
    handle.close().await.unwrap();
    let mut expected = data;
    expected.extend_from_slice(b"mo");
    assert_bytes(
        &contents(backend, "d\\g").await,
        &expected,
        "the moved file",
    );
    assert_refused(
        backend.open(&path("f"), opts(OpenIntent::Open)).await,
        SmbError::NotFound,
        "open the old name",
    );
}

pub(super) async fn a_directory_handle_follows_a_rename(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    put(backend, "d\\f", b"data").await;
    let handle = open_dir(backend, "d").await;
    backend.rename(&path("d"), &path("e"), false).await.unwrap();
    assert!(handle.stat().await.unwrap().is_directory);
    assert_eq!(listed(&*handle, None).await, ["f"]);
    handle.close().await.unwrap();
    assert_eq!(names(backend, "e").await, ["f"]);
}

pub(super) async fn link_count_is_one_for_a_file_and_a_directory(backend: Backend<'_>) {
    put(backend, "f", b"data").await;
    mkdir(backend, "d").await;
    let file = open_file(backend, "f").await;
    assert_eq!(file.link_count().await.unwrap(), 1);
    let dir = open_dir(backend, "d").await;
    assert_eq!(dir.link_count().await.unwrap(), 1);
    file.close().await.unwrap();
    dir.close().await.unwrap();
}

/// A link count of 0 means the file was deleted while open.
pub(super) async fn link_count_is_zero_once_an_open_file_is_unlinked(backend: Backend<'_>) {
    put(backend, "f", b"data").await;
    let file = open_file(backend, "f").await;
    backend.unlink(&path("f")).await.unwrap();
    assert_eq!(file.link_count().await.unwrap(), 0);
    file.close().await.unwrap();
    assert!(names(backend, "").await.is_empty());
}

/// A file reports one nonzero file index from its stat and its listing, across
/// opens and renames, and each other file reports another.
pub(super) async fn file_index_is_stable(backend: Backend<'_>) {
    put(backend, "a", b"one").await;
    put(backend, "b", b"two").await;
    let index_of = |name: &'static str| async move {
        let handle = open_file(backend, name).await;
        let index = handle.stat().await.unwrap().file_index;
        handle.close().await.unwrap();
        index
    };
    let listed_index = |name: &'static str| async move {
        let root = open_dir(backend, "").await;
        let entries = root.list_dir(None).await.unwrap();
        root.close().await.unwrap();
        entries
            .into_iter()
            .find(|entry| entry.info.name == name)
            .map(|entry| entry.info.file_index)
            .unwrap_or_else(|| panic!("{name} is listed"))
    };

    let a = index_of("a").await;
    assert_ne!(a, 0, "a file index");
    assert_eq!(index_of("a").await, a, "a second open");
    assert_eq!(listed_index("a").await, a, "the listing");
    assert_ne!(index_of("b").await, a, "another file");

    let held = open_file(backend, "a").await;
    backend.rename(&path("a"), &path("c"), false).await.unwrap();
    assert_eq!(held.stat().await.unwrap().file_index, a, "the open handle");
    held.close().await.unwrap();
    assert_eq!(index_of("c").await, a, "an open by the new name");
    assert_eq!(listed_index("c").await, a, "the listing by the new name");
}
