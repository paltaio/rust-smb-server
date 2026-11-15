//! Deleting files and directories.

use super::helpers::{
    Backend, assert_bytes, assert_refused, assert_refused_with, contents, mkdir, names, open, put,
};
use crate::backend::{OpenAction, OpenIntent};
use crate::error::SmbError;
use crate::tests::util::{dir_opts, opts, path};

pub(super) async fn unlink_removes_a_file(backend: Backend<'_>) {
    put(backend, "a", b"one").await;
    put(backend, "b", b"two").await;
    backend.unlink(&path("a")).await.unwrap();
    assert_eq!(names(backend, "").await, ["b"]);
    assert_refused(
        backend.open(&path("a"), opts(OpenIntent::Open)).await,
        SmbError::NotFound,
        "open the removed file",
    );
    assert_bytes(&contents(backend, "b").await, b"two", "the other file");
}

pub(super) async fn unlink_removes_an_empty_directory(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    mkdir(backend, "e").await;
    backend.unlink(&path("d")).await.unwrap();
    assert_eq!(names(backend, "").await, ["e"]);
    assert_refused(
        backend.open(&path("d"), dir_opts(OpenIntent::Open)).await,
        SmbError::NotFound,
        "open the removed directory",
    );
}

pub(super) async fn unlink_refuses_a_directory_with_entries(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    put(backend, "d\\f", b"data").await;
    assert_refused(
        backend.unlink(&path("d")).await,
        SmbError::NotEmpty,
        "unlink a directory with a file",
    );
    assert_eq!(names(backend, "").await, ["d"]);
    assert_eq!(names(backend, "d").await, ["f"]);
    assert_bytes(&contents(backend, "d\\f").await, b"data", "the file");

    backend.unlink(&path("d\\f")).await.unwrap();
    mkdir(backend, "d\\sub").await;
    assert_refused(
        backend.unlink(&path("d")).await,
        SmbError::NotEmpty,
        "unlink a directory with a directory",
    );
    backend.unlink(&path("d\\sub")).await.unwrap();
    backend.unlink(&path("d")).await.unwrap();
    assert!(names(backend, "").await.is_empty());
}

pub(super) async fn unlink_of_a_missing_name_is_not_found(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    for name in ["f", "d\\f"] {
        assert_refused(
            backend.unlink(&path(name)).await,
            SmbError::NotFound,
            &format!("unlink {name}"),
        );
    }
}

pub(super) async fn unlink_below_a_missing_directory_is_refused(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    for name in ["missing\\f", "d\\missing\\f"] {
        assert_refused_with(
            backend.unlink(&path(name)).await,
            &[SmbError::NotFound, SmbError::PathNotFound],
            &format!("unlink {name}"),
        );
    }
}

pub(super) async fn a_name_is_free_again_after_unlink(backend: Backend<'_>) {
    put(backend, "a", b"old contents").await;
    backend.unlink(&path("a")).await.unwrap();
    let (handle, action) = open(backend, "a", OpenIntent::Create).await;
    assert_eq!(action, OpenAction::Created);
    assert_eq!(handle.stat().await.unwrap().end_of_file, 0);
    handle.close().await.unwrap();
    assert!(contents(backend, "a").await.is_empty());
}
