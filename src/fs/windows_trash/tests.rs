use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;

use tempfile::TempDir;
use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_ATTRIBUTE_HIDDEN};

use super::*;
use crate::backend::{OpenIntent, ShareBackend};
use crate::error::SmbError;
use crate::fs::LocalFsBackend;
use crate::fs::windows_dir::SHARE_ALL;
use crate::fs::windows_dir::tests::{
    Root, host_names, junction, listed, on_each_root_async, reach, reading, symlink_dir,
};
use crate::tests::util::{dir_opts, opts, path, scratch_dir};

/// A backend on the directory `td` as `root` reaches it, which deletes as
/// on a volume that refuses POSIX deletes, as an SMB share does itself.
fn backend(td: &TempDir, root: Root) -> LocalFsBackend {
    let backend = LocalFsBackend::new(reach(td.path(), root)).unwrap();
    match root {
        Root::Local => backend.without_posix_delete(),
        Root::Unc => backend,
    }
}

/// The trash directory of the share root `td`.
fn trash(td: &TempDir) -> PathBuf {
    td.path().join(TRASH_NAME)
}

#[tokio::test]
async fn held_entries_lose_their_names_at_once() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("f.txt"), b"data").unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        let backend = backend(&td, root);
        let (file, _) = backend.open(&path("f.txt"), reading()).await.unwrap();
        let (dir, _) = backend
            .open(&path("d"), dir_opts(OpenIntent::Open))
            .await
            .unwrap();

        backend.unlink(&path("f.txt")).await.unwrap();
        backend.unlink(&path("d")).await.unwrap();
        assert_eq!(host_names(td.path()), [TRASH_NAME]);
        assert!(listed(&backend, "").await.is_empty());
        assert_eq!(host_names(&trash(&td)).len(), 2);
        let attributes = std::fs::metadata(trash(&td)).unwrap().file_attributes();
        assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN, 0);

        assert_eq!(&file.read(0, 16).await.unwrap()[..], b"data");
        assert_eq!(file.link_count().await.unwrap(), 0);
        let (made, _) = backend
            .open(&path("f.txt"), opts(OpenIntent::Create))
            .await
            .unwrap();
        made.close().await.unwrap();
        let (made, _) = backend
            .open(&path("d"), dir_opts(OpenIntent::Create))
            .await
            .unwrap();
        made.close().await.unwrap();
        assert_eq!(listed(&backend, "").await, ["d", "f.txt"]);

        file.close().await.unwrap();
        dir.close().await.unwrap();
        assert!(host_names(&trash(&td)).is_empty());
    })
    .await;
}

#[tokio::test]
async fn a_read_only_file_is_deleted() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        let at = td.path().join("ro.txt");
        std::fs::write(&at, b"x").unwrap();
        let mut permissions = std::fs::metadata(&at).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&at, permissions).unwrap();
        let backend = backend(&td, root);
        let (file, _) = backend.open(&path("ro.txt"), reading()).await.unwrap();

        backend.unlink(&path("ro.txt")).await.unwrap();
        assert_eq!(host_names(td.path()), [TRASH_NAME]);
        file.close().await.unwrap();
        assert!(host_names(&trash(&td)).is_empty());
    })
    .await;
}

#[tokio::test]
async fn a_directory_with_entries_stays_in_place() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::create_dir(td.path().join("full")).unwrap();
        std::fs::write(td.path().join("full").join("inside.txt"), b"x").unwrap();
        let backend = backend(&td, root);

        let refused = backend.unlink(&path("full")).await;
        assert!(matches!(refused, Err(SmbError::NotEmpty)), "{refused:?}");
        assert_eq!(host_names(td.path()), [TRASH_NAME, "full"]);
        assert_eq!(host_names(&td.path().join("full")), ["inside.txt"]);
        assert!(host_names(&trash(&td)).is_empty());
    })
    .await;
}

#[tokio::test]
async fn only_the_deleted_link_of_a_file_goes() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("a.txt"), b"linked").unwrap();
        std::fs::hard_link(td.path().join("a.txt"), td.path().join("b.txt")).unwrap();
        std::fs::hard_link(td.path().join("a.txt"), td.path().join("c.txt")).unwrap();
        let backend = backend(&td, root);
        let (held, _) = backend.open(&path("b.txt"), reading()).await.unwrap();

        backend.unlink(&path("a.txt")).await.unwrap();
        // A rename onto another link of the same file removes the source.
        backend
            .rename(&path("c.txt"), &path("b.txt"), true)
            .await
            .unwrap();
        assert_eq!(host_names(td.path()), [TRASH_NAME, "b.txt"]);
        assert_eq!(std::fs::read(td.path().join("b.txt")).unwrap(), b"linked");
        assert_eq!(&held.read(0, 16).await.unwrap()[..], b"linked");
        assert_eq!(held.link_count().await.unwrap(), 1);
        held.close().await.unwrap();
        assert!(host_names(&trash(&td)).is_empty());
    })
    .await;
}

#[tokio::test]
async fn clients_cannot_reach_the_trash_by_its_name() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        std::fs::create_dir(td.path().join("sub")).unwrap();
        let backend = backend(&td, root);
        backend.unlink(&path("f.txt")).await.unwrap();
        assert!(trash(&td).is_dir());

        for name in [TRASH_NAME, ".SMB-Deleted"] {
            let name = path(name);
            for (intent, refused) in [
                (OpenIntent::Open, SmbError::NotFound),
                (OpenIntent::Truncate, SmbError::NotFound),
                (OpenIntent::Create, SmbError::AccessDenied),
                (OpenIntent::OpenOrCreate, SmbError::AccessDenied),
                (OpenIntent::OverwriteOrCreate, SmbError::AccessDenied),
            ] {
                for options in [opts(intent), dir_opts(intent)] {
                    let opened = backend.open(&name, options).await.map(drop);
                    assert_eq!(
                        opened.map_err(|e| e.to_nt_status()),
                        Err(refused.to_nt_status()),
                        "{intent:?}"
                    );
                }
            }
            let unlinked = backend.unlink(&name).await;
            assert!(matches!(unlinked, Err(SmbError::NotFound)), "{unlinked:?}");
            let from = backend.rename(&name, &path("x"), false).await;
            assert!(matches!(from, Err(SmbError::NotFound)), "{from:?}");
            let to = backend.rename(&path("sub"), &name, false).await;
            assert!(matches!(to, Err(SmbError::AccessDenied)), "{to:?}");
        }
        assert_eq!(host_names(td.path()), [TRASH_NAME, "sub"]);

        // Below the share root, the name is like any other.
        let (made, _) = backend
            .open(&path("sub\\.smb-deleted"), dir_opts(OpenIntent::Create))
            .await
            .unwrap();
        made.close().await.unwrap();
        assert_eq!(listed(&backend, "sub").await, [TRASH_NAME]);
    })
    .await;
}

#[tokio::test]
async fn listings_of_the_share_root_leave_the_trash_out() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        std::fs::write(td.path().join("g.txt"), b"x").unwrap();
        let backend = backend(&td, root);
        backend.unlink(&path("f.txt")).await.unwrap();
        assert_eq!(host_names(td.path()), [TRASH_NAME, "g.txt"]);

        assert_eq!(listed(&backend, "").await, ["g.txt"]);
        let (dir, _) = backend
            .open(&path(""), dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        for pattern in [None, Some("*"), Some(".smb*"), Some(TRASH_NAME)] {
            let names: Vec<String> = dir
                .list_dir(pattern)
                .await
                .unwrap()
                .into_iter()
                .map(|entry| entry.info.name)
                .collect();
            let expected: &[&str] = if pattern.is_some_and(|p| p.starts_with('.')) {
                &[]
            } else {
                &["g.txt"]
            };
            assert_eq!(names, expected, "{pattern:?}");
        }
        dir.close().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn links_do_not_lead_into_the_trash() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        std::fs::create_dir(td.path().join("sub")).unwrap();
        let backend = backend(&td, root);
        backend.unlink(&path("f.txt")).await.unwrap();
        std::fs::write(trash(&td).join("planted.txt"), b"planted").unwrap();
        symlink_dir(&td.path().join("link"), TRASH_NAME);
        symlink_dir(
            &td.path().join("sub").join("up"),
            format!("..\\{TRASH_NAME}"),
        );

        for (name, options) in [
            ("link", dir_opts(OpenIntent::Open)),
            ("sub\\up", dir_opts(OpenIntent::Open)),
            ("link\\planted.txt", reading()),
            ("sub\\up\\planted.txt", reading()),
        ] {
            let opened = backend.open(&path(name), options).await.map(drop);
            assert!(
                matches!(opened, Err(SmbError::NotFound | SmbError::PathNotFound)),
                "{name}: {opened:?}"
            );
        }
        let renamed = backend
            .rename(&path("link\\planted.txt"), &path("out.txt"), false)
            .await;
        assert!(renamed.is_err(), "{renamed:?}");
        assert_eq!(
            std::fs::read(trash(&td).join("planted.txt")).unwrap(),
            b"planted"
        );
    })
    .await;
}

#[tokio::test]
async fn the_first_use_deletes_what_earlier_runs_left() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        let outside = scratch_dir();
        std::fs::write(outside.path().join("keep.txt"), b"keep").unwrap();
        let left = trash(&td);
        std::fs::create_dir(&left).unwrap();
        std::fs::write(left.join("file"), b"x").unwrap();
        std::fs::write(left.join("read-only"), b"x").unwrap();
        let mut permissions = std::fs::metadata(left.join("read-only"))
            .unwrap()
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(left.join("read-only"), permissions).unwrap();
        std::fs::create_dir(left.join("empty")).unwrap();
        std::fs::create_dir(left.join("full")).unwrap();
        std::fs::write(left.join("full").join("x"), b"x").unwrap();
        junction(&left.join("junction"), outside.path());
        std::fs::write(left.join("pending"), b"x").unwrap();
        let pending = std::fs::OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(SHARE_ALL)
            .open(left.join("pending"))
            .unwrap();
        delete_on_close(&pending).unwrap();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();

        let backend = backend(&td, root);
        backend.unlink(&path("f.txt")).await.unwrap();
        assert_eq!(host_names(&left), ["full", "pending"]);
        assert_eq!(host_names(&left.join("full")), ["x"]);
        assert_eq!(host_names(outside.path()), ["keep.txt"]);
        drop(pending);
        assert_eq!(host_names(&left), ["full"]);
    })
    .await;
}

#[tokio::test]
async fn a_read_only_backend_makes_no_trash() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        let backend = backend(&td, root).read_only();
        let unlinked = backend.unlink(&path("f.txt")).await;
        assert!(
            matches!(unlinked, Err(SmbError::AccessDenied)),
            "{unlinked:?}"
        );
        let renamed = backend.rename(&path("f.txt"), &path("g.txt"), false).await;
        assert!(
            matches!(renamed, Err(SmbError::AccessDenied)),
            "{renamed:?}"
        );
        assert_eq!(listed(&backend, "").await, ["f.txt"]);
        assert_eq!(host_names(td.path()), ["f.txt"]);
    })
    .await;
}

#[tokio::test]
async fn deletes_stay_in_place_when_something_else_has_the_trash_name() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(trash(&td), b"squat").unwrap();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        std::fs::write(td.path().join("g.txt"), b"x").unwrap();
        let backend = backend(&td, root);
        let (held, _) = backend.open(&path("f.txt"), reading()).await.unwrap();

        backend.unlink(&path("f.txt")).await.unwrap();
        backend.unlink(&path("g.txt")).await.unwrap();
        // The held file keeps its name until its last handle closes.
        assert_eq!(host_names(td.path()), [TRASH_NAME, "f.txt"]);
        held.close().await.unwrap();
        assert_eq!(host_names(td.path()), [TRASH_NAME]);
        assert_eq!(std::fs::read(trash(&td)).unwrap(), b"squat");
    })
    .await;
}

/// A delete of a directory with entries, under another case than the one
/// it is stored in, fails before anything moves, and the directory keeps
/// its name.
#[tokio::test]
async fn a_directory_with_entries_is_not_moved_and_keeps_its_case() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::create_dir(td.path().join("full")).unwrap();
        std::fs::write(td.path().join("full").join("inside.txt"), b"x").unwrap();
        let backend = backend(&td, root);

        let refused = backend.unlink(&path("FULL")).await;
        assert!(matches!(refused, Err(SmbError::NotEmpty)), "{refused:?}");
        assert_eq!(host_names(td.path()), [TRASH_NAME, "full"]);
        assert_eq!(host_names(&td.path().join("full")), ["inside.txt"]);
        assert!(host_names(&trash(&td)).is_empty());
    })
    .await;
}

/// A directory that gets an entry between the check that it is empty and
/// its move into the trash comes back under the name it is stored under,
/// and the delete fails. One test runs both roots, as the hook is shared.
#[tokio::test]
async fn a_directory_that_gets_an_entry_while_it_moves_comes_back_under_its_name() {
    for root in [Root::Local, Root::Unc] {
        let td = scratch_dir();
        std::fs::create_dir(td.path().join("filled")).unwrap();
        let backend = backend(&td, root);
        {
            let late = td.path().join("filled").join("late.txt");
            *BEFORE_MOVE.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Box::new(move |rel: &Path| {
                    // A failure here shows as a delete that succeeds.
                    if rel == Path::new("FILLED") {
                        let _ = std::fs::write(&late, b"x");
                    }
                }));
        }
        let refused = backend.unlink(&path("FILLED")).await;
        *BEFORE_MOVE.lock().unwrap_or_else(PoisonError::into_inner) = None;

        assert!(
            matches!(refused, Err(SmbError::NotEmpty)),
            "{root:?}: {refused:?}"
        );
        assert_eq!(host_names(td.path()), [TRASH_NAME, "filled"], "{root:?}");
        assert_eq!(
            host_names(&td.path().join("filled")),
            ["late.txt"],
            "{root:?}"
        );
        assert!(host_names(&trash(&td)).is_empty(), "{root:?}");
    }
}
