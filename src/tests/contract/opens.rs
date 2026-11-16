//! What each open intent does, and the errors an open answers.

use super::helpers::{
    Backend, assert_bytes, assert_refused, contents, mkdir, names, open, put, read_all, write,
};
use crate::backend::{OpenAction, OpenIntent, OpenOptions};
use crate::error::SmbError;
use crate::path::SmbPath;
use crate::tests::data::nonzero_pattern;
use crate::tests::util::{dir_opts, opts, path};

const INTENTS: [OpenIntent; 5] = [
    OpenIntent::Open,
    OpenIntent::Create,
    OpenIntent::OpenOrCreate,
    OpenIntent::OverwriteOrCreate,
    OpenIntent::Truncate,
];

pub(super) async fn create_makes_a_file(backend: Backend<'_>) {
    let (handle, action) = open(backend, "a.txt", OpenIntent::Create).await;
    assert_eq!(action, OpenAction::Created);
    let info = handle.stat().await.unwrap();
    assert!(!info.is_directory);
    assert_eq!(info.end_of_file, 0);
    handle.close().await.unwrap();
    assert_eq!(names(backend, "").await, ["a.txt"]);
}

pub(super) async fn create_refuses_a_name_that_exists(backend: Backend<'_>) {
    put(backend, "f", b"data").await;
    mkdir(backend, "d").await;
    for name in ["f", "d"] {
        assert_refused(
            backend.open(&path(name), opts(OpenIntent::Create)).await,
            SmbError::Exists,
            &format!("create {name}"),
        );
    }
    assert_bytes(&contents(backend, "f").await, b"data", "the file");
    assert_eq!(names(backend, "").await, ["d", "f"]);
}

pub(super) async fn open_or_create_opens_what_exists_and_creates_the_rest(backend: Backend<'_>) {
    let (handle, action) = open(backend, "a", OpenIntent::OpenOrCreate).await;
    assert_eq!(action, OpenAction::Created);
    write(&*handle, 0, b"abc").await;
    handle.close().await.unwrap();

    let (handle, action) = open(backend, "a", OpenIntent::OpenOrCreate).await;
    assert_eq!(action, OpenAction::Opened);
    assert_bytes(&read_all(&*handle).await, b"abc", "the file");
    handle.close().await.unwrap();
    assert_eq!(names(backend, "").await, ["a"]);
}

pub(super) async fn open_finds_only_what_exists(backend: Backend<'_>) {
    assert_refused(
        backend.open(&path("a"), opts(OpenIntent::Open)).await,
        SmbError::NotFound,
        "open a missing file",
    );
    put(backend, "a", b"abc").await;
    let (handle, action) = open(backend, "a", OpenIntent::Open).await;
    assert_eq!(action, OpenAction::Opened);
    assert_bytes(&read_all(&*handle).await, b"abc", "the file");
    handle.close().await.unwrap();
    assert_eq!(names(backend, "").await, ["a"]);
}

pub(super) async fn truncate_empties_an_existing_file(backend: Backend<'_>) {
    assert_refused(
        backend.open(&path("a"), opts(OpenIntent::Truncate)).await,
        SmbError::NotFound,
        "truncate a missing file",
    );
    put(backend, "a", &nonzero_pattern(1000)).await;
    let (handle, action) = open(backend, "a", OpenIntent::Truncate).await;
    assert_eq!(action, OpenAction::Overwritten);
    assert_eq!(handle.stat().await.unwrap().end_of_file, 0);
    handle.close().await.unwrap();
    assert!(contents(backend, "a").await.is_empty());
    assert_eq!(names(backend, "").await, ["a"]);
}

pub(super) async fn overwrite_or_create_empties_or_creates(backend: Backend<'_>) {
    put(backend, "a", &nonzero_pattern(1000)).await;
    let (handle, action) = open(backend, "a", OpenIntent::OverwriteOrCreate).await;
    assert_eq!(action, OpenAction::Overwritten);
    assert_eq!(handle.stat().await.unwrap().end_of_file, 0);
    handle.close().await.unwrap();
    assert!(contents(backend, "a").await.is_empty());

    let (handle, action) = open(backend, "b", OpenIntent::OverwriteOrCreate).await;
    assert_eq!(action, OpenAction::Created);
    handle.close().await.unwrap();
    assert_eq!(names(backend, "").await, ["a", "b"]);
}

pub(super) async fn directories_follow_their_intents(backend: Backend<'_>) {
    let try_open_dir = |name: &'static str, intent| async move {
        backend.open(&path(name), dir_opts(intent)).await
    };

    let (handle, action) = try_open_dir("d", OpenIntent::Create).await.unwrap();
    assert_eq!(action, OpenAction::Created);
    assert!(handle.stat().await.unwrap().is_directory);
    handle.close().await.unwrap();

    assert_refused(
        try_open_dir("d", OpenIntent::Create).await,
        SmbError::Exists,
        "create a directory that exists",
    );
    let (handle, action) = try_open_dir("d", OpenIntent::Open).await.unwrap();
    assert_eq!(action, OpenAction::Opened);
    handle.close().await.unwrap();
    let (handle, action) = try_open_dir("d", OpenIntent::OpenOrCreate).await.unwrap();
    assert_eq!(action, OpenAction::Opened);
    handle.close().await.unwrap();
    let (handle, action) = try_open_dir("e", OpenIntent::OpenOrCreate).await.unwrap();
    assert_eq!(action, OpenAction::Created);
    handle.close().await.unwrap();
    assert_refused(
        try_open_dir("nope", OpenIntent::Open).await,
        SmbError::NotFound,
        "open a missing directory",
    );
    assert_eq!(names(backend, "").await, ["d", "e"]);
}

pub(super) async fn a_file_does_not_open_as_a_directory(backend: Backend<'_>) {
    put(backend, "f", b"data").await;
    assert_refused(
        backend.open(&path("f"), dir_opts(OpenIntent::Open)).await,
        SmbError::NotADirectory,
        "open a file as a directory",
    );
}

pub(super) async fn a_directory_does_not_open_as_a_file(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    let not_a_directory = OpenOptions {
        non_directory: true,
        ..opts(OpenIntent::Open)
    };
    assert_refused(
        backend.open(&path("d"), not_a_directory).await,
        SmbError::IsDirectory,
        "open a directory with non_directory",
    );
    for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
        assert_refused(
            backend.open(&path("d"), opts(intent)).await,
            SmbError::IsDirectory,
            &format!("{intent:?} a directory"),
        );
    }
    assert_eq!(names(backend, "").await, ["d"]);
}

pub(super) async fn a_missing_directory_on_the_way_is_path_not_found(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    for name in ["missing\\f", "d\\missing\\f"] {
        for intent in INTENTS {
            assert_refused(
                backend.open(&path(name), opts(intent)).await,
                SmbError::PathNotFound,
                &format!("{intent:?} {name}"),
            );
        }
        for intent in [
            OpenIntent::Open,
            OpenIntent::Create,
            OpenIntent::OpenOrCreate,
        ] {
            assert_refused(
                backend.open(&path(name), dir_opts(intent)).await,
                SmbError::PathNotFound,
                &format!("{intent:?} directory {name}"),
            );
        }
    }
    assert_eq!(names(backend, "").await, ["d"]);
    assert!(names(backend, "d").await.is_empty());
}

pub(super) async fn a_missing_last_name_is_not_found(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    for intent in [OpenIntent::Open, OpenIntent::Truncate] {
        assert_refused(
            backend.open(&path("d\\f"), opts(intent)).await,
            SmbError::NotFound,
            &format!("{intent:?} d\\f"),
        );
    }
    assert_refused(
        backend
            .open(&path("d\\f"), dir_opts(OpenIntent::Open))
            .await,
        SmbError::NotFound,
        "open directory d\\f",
    );
}

pub(super) async fn a_file_on_the_way_is_path_not_found(backend: Backend<'_>) {
    put(backend, "f", b"data").await;
    for intent in [OpenIntent::Open, OpenIntent::Create] {
        assert_refused(
            backend.open(&path("f\\x"), opts(intent)).await,
            SmbError::PathNotFound,
            &format!("{intent:?} below a file"),
        );
    }
}

pub(super) async fn a_write_only_open_writes(backend: Backend<'_>) {
    let write_only = |intent| OpenOptions {
        read: false,
        write: true,
        intent,
        ..OpenOptions::default()
    };
    let (handle, action) = backend
        .open(&path("w"), write_only(OpenIntent::Create))
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Created);
    write(&*handle, 0, b"first").await;
    handle.close().await.unwrap();

    let (handle, action) = backend
        .open(&path("w"), write_only(OpenIntent::OpenOrCreate))
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Opened);
    write(&*handle, 5, b" second").await;
    handle.close().await.unwrap();
    assert_bytes(
        &contents(backend, "w").await,
        b"first second",
        "the file after the second open",
    );

    let (handle, action) = backend
        .open(&path("w"), write_only(OpenIntent::OverwriteOrCreate))
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Overwritten);
    write(&*handle, 0, b"third").await;
    handle.close().await.unwrap();
    assert_bytes(&contents(backend, "w").await, b"third", "the file");
}

pub(super) async fn the_root_is_a_directory_that_exists(backend: Backend<'_>) {
    let (handle, action) = backend
        .open(&SmbPath::root(), opts(OpenIntent::Open))
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert!(handle.stat().await.unwrap().is_directory);
    handle.close().await.unwrap();

    for options in [opts(OpenIntent::Create), dir_opts(OpenIntent::Create)] {
        assert_refused(
            backend.open(&SmbPath::root(), options).await,
            SmbError::Exists,
            "create the root",
        );
    }
    let not_a_directory = OpenOptions {
        non_directory: true,
        ..opts(OpenIntent::Open)
    };
    assert_refused(
        backend.open(&SmbPath::root(), not_a_directory).await,
        SmbError::IsDirectory,
        "open the root with non_directory",
    );
    for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
        assert_refused(
            backend.open(&SmbPath::root(), opts(intent)).await,
            SmbError::IsDirectory,
            &format!("{intent:?} the root"),
        );
    }
}

pub(super) async fn deep_trees_open_and_rename_whole(backend: Backend<'_>) {
    let levels: Vec<String> = (0..12).map(|level| format!("level{level:02}")).collect();
    let mut at = String::new();
    for level in &levels {
        at = if at.is_empty() {
            level.clone()
        } else {
            format!("{at}\\{level}")
        };
        mkdir(backend, &at).await;
        put(backend, &format!("{at}\\f"), level.as_bytes()).await;
    }
    let bottom = levels.join("\\");
    assert_bytes(
        &contents(backend, &format!("{bottom}\\f")).await,
        b"level11",
        "the bottom file",
    );
    assert_eq!(names(backend, &bottom).await, ["f"]);
    assert_eq!(names(backend, "level00\\level01").await, ["f", "level02"]);

    backend
        .rename(&path("level00"), &path("moved"), false)
        .await
        .unwrap();
    let moved = format!("moved\\{}", levels[1..].join("\\"));
    assert_bytes(
        &contents(backend, &format!("{moved}\\f")).await,
        b"level11",
        "the bottom file once moved",
    );
    assert_eq!(names(backend, "").await, ["moved"]);
    assert_refused(
        backend
            .open(&path(&format!("{bottom}\\f")), opts(OpenIntent::Open))
            .await,
        SmbError::PathNotFound,
        "open under the old name",
    );
}
