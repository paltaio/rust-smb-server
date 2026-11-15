//! Names that differ only in case: one entry when the backend reports
//! case-insensitive names, two when it reports case-sensitive ones.

use super::helpers::{
    Backend, assert_bytes, assert_refused, contents, matching, mkdir, names, open, put, read_all,
};
use crate::backend::{OpenAction, OpenIntent};
use crate::error::SmbError;
use crate::tests::util::{dir_opts, opts, path};

pub(super) async fn open_follows_the_case_rule(backend: Backend<'_>) {
    put(backend, "Report.TXT", b"data").await;
    let result = backend
        .open(&path("report.txt"), opts(OpenIntent::Open))
        .await;
    if backend.capabilities().case_sensitive {
        assert_refused(result, SmbError::NotFound, "open another case");
    } else {
        let (handle, action) = result.unwrap();
        assert_eq!(action, OpenAction::Opened);
        assert_bytes(&read_all(&*handle).await, b"data", "the file");
        handle.close().await.unwrap();
    }
    assert_eq!(names(backend, "").await, ["Report.TXT"]);
}

pub(super) async fn create_follows_the_case_rule(backend: Backend<'_>) {
    put(backend, "Foo", b"upper").await;
    if backend.capabilities().case_sensitive {
        put(backend, "foo", b"lower").await;
        let (handle, action) = open(backend, "FOO", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Created);
        handle.close().await.unwrap();
        assert_eq!(names(backend, "").await, ["FOO", "Foo", "foo"]);
        assert_bytes(&contents(backend, "Foo").await, b"upper", "Foo");
        assert_bytes(&contents(backend, "foo").await, b"lower", "foo");
        return;
    }

    assert_refused(
        backend.open(&path("foo"), opts(OpenIntent::Create)).await,
        SmbError::Exists,
        "create another case",
    );
    let (handle, action) = open(backend, "FOO", OpenIntent::OpenOrCreate).await;
    assert_eq!(action, OpenAction::Opened);
    assert_bytes(&read_all(&*handle).await, b"upper", "the file");
    handle.close().await.unwrap();
    let (handle, action) = open(backend, "fOO", OpenIntent::OverwriteOrCreate).await;
    assert_eq!(action, OpenAction::Overwritten);
    handle.close().await.unwrap();
    assert!(contents(backend, "Foo").await.is_empty());
    assert_eq!(names(backend, "").await, ["Foo"]);
}

pub(super) async fn unlink_follows_the_case_rule(backend: Backend<'_>) {
    put(backend, "Foo", b"data").await;
    let result = backend.unlink(&path("foo")).await;
    if backend.capabilities().case_sensitive {
        assert_refused(result, SmbError::NotFound, "unlink another case");
        assert_eq!(names(backend, "").await, ["Foo"]);
    } else {
        result.unwrap();
        assert!(names(backend, "").await.is_empty());
    }
}

pub(super) async fn rename_source_follows_the_case_rule(backend: Backend<'_>) {
    put(backend, "Foo", b"data").await;
    let result = backend.rename(&path("foo"), &path("bar"), false).await;
    if backend.capabilities().case_sensitive {
        assert_refused(result, SmbError::NotFound, "rename another case");
        assert_eq!(names(backend, "").await, ["Foo"]);
    } else {
        result.unwrap();
        assert_eq!(names(backend, "").await, ["bar"]);
        assert_bytes(&contents(backend, "bar").await, b"data", "the file");
    }
}

pub(super) async fn rename_target_follows_the_case_rule(backend: Backend<'_>) {
    put(backend, "a", b"from a").await;
    put(backend, "B", b"from B").await;
    let result = backend.rename(&path("a"), &path("b"), false).await;
    if backend.capabilities().case_sensitive {
        result.unwrap();
        assert_eq!(names(backend, "").await, ["B", "b"]);
        assert_bytes(&contents(backend, "B").await, b"from B", "B");
        assert_bytes(&contents(backend, "b").await, b"from a", "b");
        return;
    }

    assert_refused(result, SmbError::Exists, "rename onto another case");
    assert_eq!(names(backend, "").await, ["B", "a"]);
    backend.rename(&path("a"), &path("b"), true).await.unwrap();
    let left = names(backend, "").await;
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].to_lowercase(), "b");
    assert_bytes(
        &contents(backend, &left[0]).await,
        b"from a",
        "the replaced file",
    );
}

pub(super) async fn patterns_follow_the_case_rule(backend: Backend<'_>) {
    put(backend, "Alpha.TXT", b"").await;
    put(backend, "beta.txt", b"").await;
    let list = |pattern| matching(backend, "", Some(pattern));
    if backend.capabilities().case_sensitive {
        assert_eq!(list("*.txt").await, ["beta.txt"]);
        assert_eq!(list("*.TXT").await, ["Alpha.TXT"]);
        assert!(list("alpha.txt").await.is_empty());
        assert_eq!(list("Alpha.TXT").await, ["Alpha.TXT"]);
        assert!(list("B*").await.is_empty());
    } else {
        assert_eq!(list("*.txt").await, ["Alpha.TXT", "beta.txt"]);
        assert_eq!(list("*.TXT").await, ["Alpha.TXT", "beta.txt"]);
        assert_eq!(list("alpha.txt").await, ["Alpha.TXT"]);
        assert_eq!(list("ALPHA.TXT").await, ["Alpha.TXT"]);
        assert_eq!(list("B*").await, ["beta.txt"]);
    }
}

pub(super) async fn directories_on_the_way_follow_the_case_rule(backend: Backend<'_>) {
    mkdir(backend, "Docs").await;
    mkdir(backend, "Docs\\Sub").await;
    put(backend, "Docs\\Sub\\Note.txt", b"data").await;

    let open_other = backend
        .open(&path("docs\\sub\\note.txt"), opts(OpenIntent::Open))
        .await;
    let create_other = backend
        .open(&path("DOCS\\new.txt"), opts(OpenIntent::Create))
        .await;
    let directory_other = backend
        .open(&path("docs\\SUB"), dir_opts(OpenIntent::Open))
        .await;
    if backend.capabilities().case_sensitive {
        assert_refused(
            open_other,
            SmbError::PathNotFound,
            "open under another case",
        );
        assert_refused(
            create_other,
            SmbError::PathNotFound,
            "create under another case",
        );
        assert_refused(
            directory_other,
            SmbError::PathNotFound,
            "open a directory under another case",
        );
        assert_eq!(names(backend, "").await, ["Docs"]);
        assert_eq!(names(backend, "Docs").await, ["Sub"]);
        return;
    }

    let (handle, action) = open_other.unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert_bytes(&read_all(&*handle).await, b"data", "the file");
    handle.close().await.unwrap();
    let (handle, action) = create_other.unwrap();
    assert_eq!(action, OpenAction::Created);
    handle.close().await.unwrap();
    let (handle, action) = directory_other.unwrap();
    assert_eq!(action, OpenAction::Opened);
    handle.close().await.unwrap();
    assert_eq!(names(backend, "").await, ["Docs"]);
    assert_eq!(names(backend, "Docs").await, ["Sub", "new.txt"]);
}

pub(super) async fn files_and_directories_share_the_case_rule(backend: Backend<'_>) {
    mkdir(backend, "Dir").await;
    put(backend, "File", b"data").await;
    let dir_as_dir = backend
        .open(&path("DIR"), dir_opts(OpenIntent::Create))
        .await;
    let dir_as_file = backend.open(&path("dir"), opts(OpenIntent::Create)).await;
    let file_as_dir = backend
        .open(&path("FILE"), dir_opts(OpenIntent::Create))
        .await;
    if backend.capabilities().case_sensitive {
        for (result, what) in [
            (dir_as_dir, "DIR"),
            (dir_as_file, "dir"),
            (file_as_dir, "FILE"),
        ] {
            let (handle, action) = result.unwrap();
            assert_eq!(action, OpenAction::Created, "{what}");
            handle.close().await.unwrap();
        }
        assert_eq!(
            names(backend, "").await,
            ["DIR", "Dir", "FILE", "File", "dir"]
        );
        return;
    }
    assert_refused(dir_as_dir, SmbError::Exists, "create DIR over Dir");
    assert_refused(dir_as_file, SmbError::Exists, "create dir over Dir");
    assert_refused(file_as_dir, SmbError::Exists, "create FILE over File");
    assert_eq!(names(backend, "").await, ["Dir", "File"]);
}

pub(super) async fn a_directory_renamed_in_case_keeps_its_entries(backend: Backend<'_>) {
    mkdir(backend, "Docs").await;
    put(backend, "Docs\\f", b"data").await;
    backend
        .rename(&path("Docs"), &path("DOCS"), false)
        .await
        .unwrap();
    assert_eq!(names(backend, "").await, ["DOCS"]);
    assert_eq!(names(backend, "DOCS").await, ["f"]);
    assert_bytes(&contents(backend, "DOCS\\f").await, b"data", "the file");
    put(backend, "DOCS\\g", b"more").await;
    assert_eq!(names(backend, "DOCS").await, ["f", "g"]);
    assert_eq!(names(backend, "").await, ["DOCS"]);
}
