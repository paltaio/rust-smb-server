//! Renaming files and directories.

use super::helpers::{
    Backend, assert_bytes, assert_refused, assert_refused_with, contents, mkdir, names, put,
};
use crate::backend::OpenIntent;
use crate::error::SmbError;
use crate::path::SmbPath;
use crate::tests::util::{dir_opts, opts, path};

pub(super) async fn rename_moves_a_file(backend: Backend<'_>) {
    put(backend, "a", b"data").await;
    backend.rename(&path("a"), &path("b"), false).await.unwrap();
    assert_eq!(names(backend, "").await, ["b"]);
    assert_bytes(&contents(backend, "b").await, b"data", "the renamed file");
    assert_refused(
        backend.open(&path("a"), opts(OpenIntent::Open)).await,
        SmbError::NotFound,
        "open the old name",
    );
}

pub(super) async fn rename_moves_a_file_to_another_directory(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    put(backend, "f", b"data").await;
    backend
        .rename(&path("f"), &path("d\\g"), false)
        .await
        .unwrap();
    assert_eq!(names(backend, "").await, ["d"]);
    assert_eq!(names(backend, "d").await, ["g"]);
    assert_bytes(&contents(backend, "d\\g").await, b"data", "the moved file");

    backend
        .rename(&path("d\\g"), &path("h"), false)
        .await
        .unwrap();
    assert_eq!(names(backend, "").await, ["d", "h"]);
    assert!(names(backend, "d").await.is_empty());
}

pub(super) async fn rename_moves_a_directory_with_its_entries(backend: Backend<'_>) {
    mkdir(backend, "old").await;
    put(backend, "old\\f", b"one").await;
    mkdir(backend, "old\\sub").await;
    put(backend, "old\\sub\\g", b"two").await;
    backend
        .rename(&path("old"), &path("new"), false)
        .await
        .unwrap();
    assert_eq!(names(backend, "").await, ["new"]);
    assert_eq!(names(backend, "new").await, ["f", "sub"]);
    assert_bytes(&contents(backend, "new\\f").await, b"one", "new\\f");
    assert_bytes(
        &contents(backend, "new\\sub\\g").await,
        b"two",
        "new\\sub\\g",
    );
    assert_refused(
        backend.open(&path("old"), dir_opts(OpenIntent::Open)).await,
        SmbError::NotFound,
        "open the old directory",
    );
    assert_refused(
        backend.open(&path("old\\f"), opts(OpenIntent::Open)).await,
        SmbError::PathNotFound,
        "open below the old directory",
    );
}

pub(super) async fn rename_onto_a_file_needs_replace(backend: Backend<'_>) {
    put(backend, "a", b"from a").await;
    put(backend, "b", b"from b").await;
    assert_refused(
        backend.rename(&path("a"), &path("b"), false).await,
        SmbError::Exists,
        "rename onto a file",
    );
    assert_eq!(names(backend, "").await, ["a", "b"]);
    assert_bytes(&contents(backend, "a").await, b"from a", "a");
    assert_bytes(&contents(backend, "b").await, b"from b", "b");

    backend.rename(&path("a"), &path("b"), true).await.unwrap();
    assert_eq!(names(backend, "").await, ["b"]);
    assert_bytes(
        &contents(backend, "b").await,
        b"from a",
        "the replaced file",
    );
}

async fn rename_onto_a_directory(backend: Backend<'_>, replace: bool) {
    mkdir(backend, "d").await;
    mkdir(backend, "e").await;
    put(backend, "f", b"data").await;
    for from in ["f", "e"] {
        let expected = if replace {
            SmbError::AccessDenied
        } else {
            SmbError::Exists
        };
        assert_refused(
            backend.rename(&path(from), &path("d"), replace).await,
            expected,
            &format!("rename {from} onto a directory, replace {replace}"),
        );
    }
    assert_eq!(names(backend, "").await, ["d", "e", "f"]);
}

pub(super) async fn rename_onto_a_directory_with_replace_is_access_denied(backend: Backend<'_>) {
    rename_onto_a_directory(backend, true).await;
}

pub(super) async fn rename_onto_a_directory_without_replace_exists(backend: Backend<'_>) {
    rename_onto_a_directory(backend, false).await;
}

pub(super) async fn rename_of_a_missing_source_is_not_found(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    for from in ["a", "d\\a"] {
        assert_refused(
            backend.rename(&path(from), &path("b"), false).await,
            SmbError::NotFound,
            &format!("rename {from}"),
        );
    }
    assert_eq!(names(backend, "").await, ["d"]);
}

pub(super) async fn rename_from_a_missing_directory_is_refused(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    for from in ["missing\\a", "d\\missing\\a"] {
        assert_refused_with(
            backend.rename(&path(from), &path("b"), false).await,
            &[SmbError::NotFound, SmbError::PathNotFound],
            &format!("rename {from}"),
        );
    }
}

pub(super) async fn rename_into_a_missing_directory_is_path_not_found(backend: Backend<'_>) {
    put(backend, "a", b"data").await;
    for to in ["missing\\b", "missing\\deeper\\b"] {
        assert_refused(
            backend.rename(&path("a"), &path(to), false).await,
            SmbError::PathNotFound,
            &format!("rename to {to}"),
        );
    }
    assert_eq!(names(backend, "").await, ["a"]);
    assert_bytes(&contents(backend, "a").await, b"data", "the file");
}

pub(super) async fn rename_of_the_root_is_refused(backend: Backend<'_>) {
    put(backend, "f", b"data").await;
    let refusals = [SmbError::AccessDenied, SmbError::NameInvalid];
    assert_refused_with(
        backend.rename(&SmbPath::root(), &path("x"), false).await,
        &refusals,
        "rename the root",
    );
    assert_refused_with(
        backend.rename(&path("f"), &SmbPath::root(), true).await,
        &refusals,
        "rename onto the root",
    );
    assert_eq!(names(backend, "").await, ["f"]);
}

pub(super) async fn rename_to_the_same_name_changes_nothing(backend: Backend<'_>) {
    put(backend, "a", b"data").await;
    mkdir(backend, "d").await;
    for replace in [false, true] {
        backend
            .rename(&path("a"), &path("a"), replace)
            .await
            .unwrap();
        backend
            .rename(&path("d"), &path("d"), replace)
            .await
            .unwrap();
    }
    assert_eq!(names(backend, "").await, ["a", "d"]);
    assert_bytes(&contents(backend, "a").await, b"data", "the file");
}

pub(super) async fn rename_changes_the_case_of_a_name(backend: Backend<'_>) {
    put(backend, "a.txt", b"data").await;
    backend
        .rename(&path("a.txt"), &path("A.TXT"), false)
        .await
        .unwrap();
    assert_eq!(names(backend, "").await, ["A.TXT"]);
    assert_bytes(&contents(backend, "A.TXT").await, b"data", "the file");

    mkdir(backend, "dir").await;
    backend
        .rename(&path("dir"), &path("Dir"), false)
        .await
        .unwrap();
    assert_eq!(names(backend, "").await, ["A.TXT", "Dir"]);
}

pub(super) async fn an_editor_save_leaves_the_new_contents(backend: Backend<'_>) {
    put(backend, "doc.txt", b"v1").await;

    put(backend, "doc.tmp", b"v2").await;
    backend
        .rename(&path("doc.txt"), &path("doc.bak"), false)
        .await
        .unwrap();
    backend
        .rename(&path("doc.tmp"), &path("doc.txt"), false)
        .await
        .unwrap();
    backend.unlink(&path("doc.bak")).await.unwrap();
    assert_eq!(names(backend, "").await, ["doc.txt"]);
    assert_bytes(
        &contents(backend, "doc.txt").await,
        b"v2",
        "after the first save",
    );

    put(backend, "doc.tmp", b"v3").await;
    backend
        .rename(&path("doc.tmp"), &path("doc.txt"), true)
        .await
        .unwrap();
    assert_eq!(names(backend, "").await, ["doc.txt"]);
    assert_bytes(
        &contents(backend, "doc.txt").await,
        b"v3",
        "after the second save",
    );
}

pub(super) async fn entries_below_a_renamed_directory_stay_reachable(backend: Backend<'_>) {
    mkdir(backend, "a").await;
    mkdir(backend, "a\\b").await;
    put(backend, "a\\b\\c", b"deep").await;
    backend.rename(&path("a"), &path("x"), false).await.unwrap();
    put(backend, "x\\b\\d", b"new").await;
    assert_eq!(names(backend, "x\\b").await, ["c", "d"]);

    backend
        .rename(&path("x\\b"), &path("x\\e"), false)
        .await
        .unwrap();
    assert_eq!(names(backend, "x").await, ["e"]);
    assert_bytes(&contents(backend, "x\\e\\c").await, b"deep", "x\\e\\c");
    backend.unlink(&path("x\\e\\c")).await.unwrap();
    assert_eq!(names(backend, "x\\e").await, ["d"]);
    assert_refused(
        backend.open(&path("a\\b\\c"), opts(OpenIntent::Open)).await,
        SmbError::PathNotFound,
        "open under the old name",
    );
}

pub(super) async fn a_renamed_directory_leaves_its_name_free(backend: Backend<'_>) {
    mkdir(backend, "a").await;
    put(backend, "a\\f", b"old").await;
    backend.rename(&path("a"), &path("x"), false).await.unwrap();
    mkdir(backend, "a").await;
    assert_eq!(names(backend, "").await, ["a", "x"]);
    assert!(names(backend, "a").await.is_empty());
    assert_eq!(names(backend, "x").await, ["f"]);
    put(backend, "a\\f", b"new").await;
    assert_bytes(&contents(backend, "x\\f").await, b"old", "x\\f");
    assert_bytes(&contents(backend, "a\\f").await, b"new", "a\\f");
}
