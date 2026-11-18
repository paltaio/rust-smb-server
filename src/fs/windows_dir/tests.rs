use std::io::{Read as _, Write as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::backend::{FILE_ATTRIBUTE_HIDDEN, OpenIntent, ShareBackend};
use crate::error::SmbError;
use crate::fs::LocalFsBackend;
use crate::tests::util::{dir_opts, on_admin_share, opts, path, scratch_dir};

/// How a test reaches the directory it works in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fs) enum Root {
    /// The directory's own path.
    Local,
    /// The directory on the administrative share of its drive on this
    /// host, through the SMB redirector.
    Unc,
}

/// `path` as `root` reaches it.
pub(in crate::fs) fn reach(path: &Path, root: Root) -> PathBuf {
    match root {
        Root::Local => path.to_path_buf(),
        Root::Unc => on_admin_share(path),
    }
}

/// A thread that opens each of a list of paths in turn for its
/// attributes, sharing all access, and closes it at once, as a virus
/// scanner opens new names, until it is stopped.
pub(in crate::fs) struct Opener {
    stop: Arc<AtomicBool>,
    opens: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Opener {
    /// Starts opening `paths`, and returns once 3 opens were tried.
    pub(in crate::fs) fn start(paths: Vec<PathBuf>) -> Self {
        assert!(!paths.is_empty(), "an opener needs a path");
        let stop = Arc::new(AtomicBool::new(false));
        let opens = Arc::new(AtomicUsize::new(0));
        let thread = {
            let (stop, opens) = (Arc::clone(&stop), Arc::clone(&opens));
            std::thread::spawn(move || {
                for path in paths.iter().cycle() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = std::fs::OpenOptions::new()
                        .access_mode(FILE_READ_ATTRIBUTES)
                        .share_mode(SHARE_ALL)
                        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                        .open(path);
                    opens.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        while opens.load(Ordering::Relaxed) < 3 {
            std::thread::yield_now();
        }
        Self {
            stop,
            opens,
            thread: Some(thread),
        }
    }

    /// Stops the thread, and asserts it tried at least 3 opens.
    pub(in crate::fs) fn stop(mut self) {
        self.join();
        let opens = self.opens.load(Ordering::Relaxed);
        assert!(opens >= 3, "the opener tried {opens} opens");
    }

    fn join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

impl Drop for Opener {
    fn drop(&mut self) {
        self.join();
    }
}

/// Runs `body` on each root, one after the other, and names the root a
/// failure happened on.
pub(in crate::fs) fn on_each_root(body: fn(Root)) {
    for root in [Root::Local, Root::Unc] {
        if let Err(e) = std::thread::spawn(move || body(root)).join() {
            let message = e
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("");
            panic!("failed on the {root:?} root: {message}");
        }
    }
}

/// Runs the test `body` on each root, one after the other, and names the
/// root a failure happened on.
pub(in crate::fs) async fn on_each_root_async<F>(body: fn(Root) -> F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    for root in [Root::Local, Root::Unc] {
        if let Err(e) = tokio::spawn(body(root)).await {
            panic!("failed on the {root:?} root: {e}");
        }
    }
}

fn open_dir(path: &Path) -> Dir {
    Dir::open_ambient_dir(path, ambient_authority()).unwrap()
}

/// The names `dir` lists, sorted.
fn names(dir: &Dir) -> Vec<String> {
    let mut names: Vec<String> = dir
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The names in the directory `path` of the host, sorted.
pub(in crate::fs) fn host_names(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// Makes the file `path` below `dir` with `data`.
fn create(dir: &Dir, path: &str, data: &[u8]) {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    let file = dir.open_with(path, &options).unwrap();
    (&*file).write_all(data).unwrap();
}

/// The data of the file `path` below `dir`.
fn read(dir: &Dir, path: &str) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    let file = dir.open_with(path, &options)?;
    let mut data = Vec::new();
    (&*file).read_to_end(&mut data)?;
    Ok(data)
}

/// Deletes what `path` names below `dir`, a link there itself, in place:
/// at once where the volume deletes with POSIX semantics, else when its
/// last handle closes.
fn remove(dir: &Dir, path: &str, is_dir: bool) -> io::Result<()> {
    let removal = dir.open_removal(path, is_dir)?;
    match removal.delete_posix() {
        Err(status) if refuses_posix(status) => removal.delete_on_close(),
        deleted => deleted,
    }
    .map_err(nt_error)
}

/// Makes the junction `link` to the directory `target`.
pub(in crate::fs) fn junction(link: &Path, target: &Path) {
    let made = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
}

/// Makes the file symlink `link` to `target`. Panics where this process
/// may not make symlinks.
fn symlink(link: &Path, target: impl AsRef<Path>) {
    if let Err(e) = std::os::windows::fs::symlink_file(target, link) {
        panic!("the tests need the right to make symlinks: {e}");
    }
}

/// Makes the directory symlink `link` to `target`. Panics where this
/// process may not make symlinks.
pub(in crate::fs) fn symlink_dir(link: &Path, target: impl AsRef<Path>) {
    if let Err(e) = std::os::windows::fs::symlink_dir(target, link) {
        panic!("the tests need the right to make symlinks: {e}");
    }
}

fn is_escape(result: io::Result<impl Sized>) -> bool {
    result.is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied)
}

fn is_not_found(result: io::Result<impl Sized>) -> bool {
    result.is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
}

#[test]
fn files_and_directories_are_made_opened_and_listed() {
    on_each_root(|root| {
        let td = scratch_dir();
        let dir = open_dir(&reach(td.path(), root));
        create(&dir, "a.txt", b"one");
        dir.create_dir("d").unwrap();
        create(&dir, "d\\b.txt", b"two");
        assert_eq!(names(&dir), ["a.txt", "d"]);
        assert_eq!(read(&dir, "d\\b.txt").unwrap(), b"two");
        assert_eq!(read(&dir, "d\\..\\a.txt").unwrap(), b"one");

        let file = dir.metadata("a.txt").unwrap();
        assert!(!file.is_dir());
        assert_eq!(file.len(), 3);
        assert!(file.file_index().is_some());
        assert!(dir.metadata("d").unwrap().is_dir());
        assert!(dir.metadata(".").unwrap().is_dir());

        let listed: Vec<_> = dir.entries().unwrap().map(Result::unwrap).collect();
        let entry = |name: &str| listed.iter().find(|e| e.file_name() == name).unwrap();
        assert_eq!(entry("a.txt").metadata().unwrap().len(), 3);
        assert!(entry("d").file_type().unwrap().is_dir());
        assert!(!entry("a.txt").file_type().unwrap().is_symlink());

        let exists = |e: io::Error| e.kind() == io::ErrorKind::AlreadyExists;
        assert!(dir.create_dir("d").is_err_and(exists));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        assert!(dir.open_with("a.txt", &options).is_err_and(exists));
        let missing = read(&dir, "missing.txt").unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    });
}

#[test]
fn renames_move_and_replace() {
    on_each_root(|root| {
        let td = scratch_dir();
        let dir = open_dir(&reach(td.path(), root));
        create(&dir, "a.txt", b"one");
        create(&dir, "b.txt", b"two");
        dir.create_dir("d").unwrap();

        dir.rename("a.txt", &dir, "c.txt").unwrap();
        assert_eq!(names(&dir), ["b.txt", "c.txt", "d"]);
        dir.rename("c.txt", &dir, "d\\c.txt").unwrap();
        assert_eq!(names(&dir), ["b.txt", "d"]);
        let sub = open_dir(&reach(&td.path().join("d"), root));
        assert_eq!(names(&sub), ["c.txt"]);

        sub.rename("c.txt", &dir, "b.txt").unwrap();
        assert_eq!(read(&dir, "b.txt").unwrap(), b"one");
        assert!(names(&sub).is_empty());

        // A target open elsewhere is replaced where the volume renames with
        // POSIX semantics, and the rename is refused elsewhere.
        let held = std::fs::File::open(td.path().join("b.txt")).unwrap();
        create(&dir, "e.txt", b"three");
        let replaced = dir.rename("e.txt", &dir, "b.txt");
        match root {
            Root::Local => {
                replaced.unwrap();
                assert_eq!(read(&dir, "b.txt").unwrap(), b"three");
                assert_eq!(names(&dir), ["b.txt", "d"]);
            }
            Root::Unc => {
                assert_eq!(
                    replaced.unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert_eq!(read(&dir, "b.txt").unwrap(), b"one");
                assert_eq!(names(&dir), ["b.txt", "d", "e.txt"]);
                remove(&dir, "e.txt", false).unwrap();
            }
        }
        drop(held);

        // `open_ambient_dir` does not share delete access.
        drop(sub);
        dir.rename("d", &dir, "renamed").unwrap();
        assert_eq!(names(&dir), ["b.txt", "renamed"]);
        let missing = dir.rename("missing", &dir, "x").unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    });
}

#[test]
fn deletes_remove_files_and_empty_directories() {
    on_each_root(|root| {
        let td = scratch_dir();
        let dir = open_dir(&reach(td.path(), root));
        create(&dir, "f.txt", b"x");
        dir.create_dir("empty").unwrap();
        dir.create_dir("full").unwrap();
        create(&dir, "full\\inside.txt", b"x");

        remove(&dir, "f.txt", false).unwrap();
        remove(&dir, "empty", true).unwrap();
        let full = remove(&dir, "full", true).unwrap_err();
        assert_eq!(full.kind(), io::ErrorKind::DirectoryNotEmpty);
        assert_eq!(names(&dir), ["full"]);
        let missing = remove(&dir, "f.txt", false).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);

        // The name goes at once while the file is open elsewhere where the
        // volume deletes with POSIX semantics, and with the last handle
        // elsewhere.
        create(&dir, "held.txt", b"x");
        let held = std::fs::File::open(td.path().join("held.txt")).unwrap();
        remove(&dir, "held.txt", false).unwrap();
        match root {
            Root::Local => assert_eq!(names(&dir), ["full"]),
            Root::Unc => assert_eq!(names(&dir), ["full", "held.txt"]),
        }
        drop(held);
        assert_eq!(names(&dir), ["full"]);

        create(&dir, "read-only.txt", b"x");
        let path = td.path().join("read-only.txt");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        remove(&dir, "read-only.txt", false).unwrap();
        assert_eq!(names(&dir), ["full"]);

        remove(&dir, "full\\inside.txt", false).unwrap();
        remove(&dir, "full", true).unwrap();
        assert!(names(&dir).is_empty());
    });
}

#[test]
fn paths_stay_below_the_directory() {
    on_each_root(|root| {
        let td = scratch_dir();
        let dir = open_dir(&reach(td.path(), root));
        create(&dir, "a.txt", b"one");
        dir.create_dir("sub").unwrap();
        for path in [
            "..",
            "..\\a.txt",
            "sub\\..\\..\\a.txt",
            "C:\\a.txt",
            "C:a.txt",
            "\\a.txt",
            "\\\\?\\C:\\a.txt",
        ] {
            assert!(is_escape(read(&dir, path)), "{path}");
            assert!(is_escape(dir.metadata(path)), "{path}");
            assert!(
                is_escape(dir.create_dir(Path::new(path).join("x"))),
                "{path}"
            );
        }
        let sub = open_dir(&reach(&td.path().join("sub"), root));
        assert!(is_escape(read(&sub, "..\\a.txt")));

        // A file in the middle of a path.
        let through = read(&dir, "a.txt\\x").unwrap_err();
        assert_eq!(through.raw_os_error(), Some(ERROR_DIRECTORY));
        let through = dir.create_dir("a.txt\\x").unwrap_err();
        assert_eq!(through.raw_os_error(), Some(ERROR_DIRECTORY));
    });
}

#[test]
fn junctions_are_not_followed() {
    on_each_root(|root| {
        let outside = scratch_dir();
        create(&open_dir(outside.path()), "secret.txt", b"secret");
        let td = scratch_dir();
        let dir = open_dir(&reach(td.path(), root));
        dir.create_dir("sub").unwrap();
        create(&dir, "sub\\in.txt", b"in");
        junction(&td.path().join("out"), outside.path());
        junction(&td.path().join("in"), &td.path().join("sub"));

        for link in ["out", "in"] {
            assert!(is_escape(dir.metadata(link)), "{link}");
            assert!(
                is_escape(read(&dir, &format!("{link}\\secret.txt"))),
                "{link}"
            );
            assert!(is_escape(read(&dir, &format!("{link}\\in.txt"))), "{link}");
            assert!(is_escape(dir.create_dir(format!("{link}\\x"))), "{link}");
            let itself = dir.symlink_metadata(link).unwrap();
            assert!(itself.file_type().is_symlink(), "{link}");
            assert!(!itself.is_dir(), "{link}");
        }
        let listed: Vec<_> = dir.entries().unwrap().map(Result::unwrap).collect();
        let out = listed.iter().find(|e| e.file_name() == "out").unwrap();
        assert!(out.file_type().unwrap().is_symlink());
        assert_eq!(out.ea_size(), None);

        remove(&dir, "out", true).unwrap();
        assert_eq!(names(&dir), ["in", "sub"]);
        assert_eq!(
            names(&open_dir(outside.path())),
            ["secret.txt"],
            "the target stays"
        );
    });
}

#[test]
fn symlinks_are_followed_only_to_relative_targets_inside() {
    on_each_root(|root| {
        let outside = scratch_dir();
        create(&open_dir(outside.path()), "secret.txt", b"secret");
        let outside_name = outside.path().file_name().unwrap().to_str().unwrap();
        let td = scratch_dir();
        let dir = open_dir(&reach(td.path(), root));
        create(&dir, "a.txt", b"one");
        dir.create_dir("sub").unwrap();
        symlink(&td.path().join("rel"), "a.txt");
        symlink(&td.path().join("sub").join("up"), "..\\a.txt");
        symlink(&td.path().join("sub").join("deep"), "..\\sub\\up");
        let escaping = format!("..\\{outside_name}\\secret.txt");
        symlink(&td.path().join("esc"), &escaping);
        symlink(
            &td.path().join("sub").join("esc"),
            format!("..\\{escaping}"),
        );
        symlink(&td.path().join("abs"), outside.path().join("secret.txt"));
        symlink(&td.path().join("loop"), "loop");
        assert!(td.path().join("esc").exists(), "the host follows it");

        assert_eq!(read(&dir, "rel").unwrap(), b"one");
        assert_eq!(read(&dir, "sub\\up").unwrap(), b"one");
        assert_eq!(read(&dir, "sub\\deep").unwrap(), b"one");
        assert_eq!(dir.metadata("rel").unwrap().len(), 3);
        assert!(
            dir.symlink_metadata("rel")
                .unwrap()
                .file_type()
                .is_symlink()
        );
        for link in ["esc", "sub\\esc", "abs"] {
            assert!(is_escape(read(&dir, link)), "{link}");
            assert!(is_escape(dir.metadata(link)), "{link}");
        }
        let looped = read(&dir, "loop").unwrap_err();
        assert_eq!(looped.raw_os_error(), Some(ERROR_TOO_MANY_LINKS));

        // A chain of 40 links is followed, one of 41 is not.
        for i in 1..=40 {
            let target = if i == 40 {
                "a.txt".to_string()
            } else {
                format!("l{}", i + 1)
            };
            symlink(&td.path().join(format!("l{i}")), target);
        }
        symlink(&td.path().join("l0"), "l1");
        assert_eq!(read(&dir, "l1").unwrap(), b"one");
        let long = read(&dir, "l0").unwrap_err();
        assert_eq!(long.raw_os_error(), Some(ERROR_TOO_MANY_LINKS));

        remove(&dir, "rel", false).unwrap();
        assert_eq!(read(&dir, "a.txt").unwrap(), b"one", "the target stays");
    });
}

#[test]
fn listings_of_one_open_directory_each_have_their_own_position() {
    on_each_root(|root| {
        let td = scratch_dir();
        // Long names, so a listing takes several calls.
        let count = 400;
        for i in 0..count {
            let name = format!("{i:04}{}", "x".repeat(200));
            std::fs::write(td.path().join(name), b"").unwrap();
        }
        let dir = open_dir(&reach(td.path(), root));
        let mut first = dir.entries().unwrap();
        first.next().unwrap().unwrap();
        let second = dir.entries().unwrap().count();
        let rest = first.count();
        assert_eq!(second, count);
        assert_eq!(rest + 1, count);

        let mut a = dir.entries().unwrap();
        let mut b = dir.entries().unwrap();
        let (mut from_a, mut from_b) = (0, 0);
        loop {
            let (x, y) = (a.next(), b.next());
            if x.is_none() && y.is_none() {
                break;
            }
            from_a += usize::from(x.is_some());
            from_b += usize::from(y.is_some());
        }
        assert_eq!((from_a, from_b), (count, count));
    });
}

/// Options that open a directory to look names up from, sharing all
/// access, as the backend opens a directory a client opens.
fn shared_dir_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    options
}

/// A directory a lookup has opened on its way cannot be renamed until the
/// lookup ends, so the lookup cannot be led out through a junction put in
/// its place. One test runs both roots, as the hook is shared.
#[test]
fn a_directory_a_lookup_passes_through_stays_where_it_is() {
    for root in [Root::Local, Root::Unc] {
        let outside = scratch_dir();
        std::fs::create_dir(outside.path().join("b")).unwrap();
        std::fs::write(outside.path().join("b").join("f.txt"), b"outside").unwrap();
        let td = scratch_dir();
        let name = "held-by-a-lookup";
        std::fs::create_dir_all(td.path().join(name).join("b")).unwrap();
        std::fs::write(td.path().join(name).join("b").join("f.txt"), b"inside").unwrap();
        let dir = open_dir(&reach(td.path(), root));

        let renamed: Arc<Mutex<Vec<io::Result<()>>>> = Arc::default();
        {
            let renamed = Arc::clone(&renamed);
            let (at, outside) = (td.path().to_path_buf(), outside.path().to_path_buf());
            *lock_hook() = Some(Box::new(move |opened: &OsStr| {
                if opened != name {
                    return;
                }
                let moved = std::fs::rename(at.join(name), at.join("moved"));
                if moved.is_ok() {
                    junction(&at.join(name), &outside);
                }
                renamed.lock().unwrap().push(moved);
            }));
        }
        let data = read(&dir, &format!("{name}\\b\\f.txt"));
        *lock_hook() = None;

        let renamed = std::mem::take(&mut *renamed.lock().unwrap());
        assert_eq!(renamed.len(), 1, "{root:?}");
        let refused = renamed.into_iter().next().unwrap().unwrap_err();
        assert_eq!(
            refused.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION),
            "{root:?}: {refused}"
        );
        assert_eq!(data.unwrap(), b"inside", "{root:?}");
    }
}

/// A directory renamed on the host while a client holds it, with a
/// junction to a directory outside the share put under its name, leads
/// lookups from the held handle nowhere.
#[test]
fn a_held_directory_swapped_for_a_junction_leads_nowhere() {
    on_each_root(|root| {
        let outside = scratch_dir();
        std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
        std::fs::write(outside.path().join("secret.txt:s"), b"stream").unwrap();
        let td = scratch_dir();
        std::fs::create_dir(td.path().join("a")).unwrap();
        std::fs::write(td.path().join("a").join("inside.txt"), b"inside").unwrap();
        let dir = open_dir(&reach(td.path(), root));
        let held = dir.open_dir("a", &shared_dir_options()).unwrap();
        assert_eq!(read(&held, "inside.txt").unwrap(), b"inside");

        std::fs::rename(td.path().join("a"), td.path().join("a-old")).unwrap();
        junction(&td.path().join("a"), outside.path());

        assert!(is_not_found(held.metadata("secret.txt")));
        assert!(is_not_found(read(&held, "secret.txt")));
        let stream: crate::stream::StreamName = "s".parse().unwrap();
        let peeked = crate::fs::windows_streams::peek_entries(
            &held,
            &[("secret.txt".to_string(), vec![(stream, 16)])],
        );
        assert_eq!(peeked, [vec![None]]);
        // A local handle still reaches the directory it was opened on; a
        // handle through an SMB share reaches nothing once the directory
        // has another name.
        match root {
            Root::Local => assert_eq!(read(&held, "inside.txt").unwrap(), b"inside"),
            Root::Unc => assert!(is_not_found(read(&held, "inside.txt"))),
        }
    });
}

/// Options that open an existing file to read it.
pub(in crate::fs) fn reading() -> crate::backend::OpenOptions {
    crate::backend::OpenOptions {
        read: true,
        intent: OpenIntent::Open,
        ..crate::backend::OpenOptions::default()
    }
}

/// A file and a directory a client holds, renamed on the host with others
/// made under their old names: calls through the held handles that open
/// them again reach the held ones or fail as not found, and leave the new
/// ones alone.
#[tokio::test]
async fn calls_through_held_handles_leave_new_files_under_their_names_alone() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("f.txt"), b"old").unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        let backend = LocalFsBackend::new(reach(td.path(), root)).unwrap();
        assert!(backend.capabilities().extended_attributes);
        let (file, _) = backend.open(&path("f.txt"), reading()).await.unwrap();
        let (dir, _) = backend
            .open(&path("d"), dir_opts(OpenIntent::Open))
            .await
            .unwrap();

        std::fs::rename(td.path().join("f.txt"), td.path().join("f-old.txt")).unwrap();
        std::fs::write(td.path().join("f.txt"), b"new").unwrap();
        std::fs::rename(td.path().join("d"), td.path().join("d-old")).unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        std::fs::write(td.path().join("d").join("marker"), b"").unwrap();

        let ea = crate::Ea::new("TAG", b"x".to_vec());
        let results = [
            ("file eas", file.set_eas(std::slice::from_ref(&ea)).await),
            ("dir eas", dir.set_eas(std::slice::from_ref(&ea)).await),
            (
                "file attributes",
                file.set_attributes(FILE_ATTRIBUTE_HIDDEN).await,
            ),
            (
                "dir attributes",
                dir.set_attributes(FILE_ATTRIBUTE_HIDDEN).await,
            ),
        ];
        let listed = dir.list_dir(None).await;
        for (call, result) in &results {
            match (root, result) {
                (_, Ok(())) | (Root::Unc, Err(SmbError::NotFound)) => {}
                _ => panic!("{call}: {result:?}"),
            }
        }
        match (root, &listed) {
            (_, Ok(entries)) => assert!(entries.is_empty(), "{entries:?}"),
            (Root::Unc, Err(SmbError::NotFound)) => {}
            _ => panic!("listing: {listed:?}"),
        }

        let hidden = |name: &str| {
            std::fs::metadata(td.path().join(name))
                .unwrap()
                .file_attributes()
                & FILE_ATTRIBUTE_HIDDEN
                != 0
        };
        let fresh = LocalFsBackend::new(td.path()).unwrap();
        let eas_of = async |name: &str, opts| {
            let (handle, _) = fresh.open(&path(name), opts).await.unwrap();
            let eas = handle.eas().await.unwrap();
            handle.close().await.unwrap();
            eas
        };
        assert!(eas_of("f.txt", reading()).await.is_empty());
        assert!(eas_of("d", dir_opts(OpenIntent::Open)).await.is_empty());
        assert!(!hidden("f.txt"));
        assert!(!hidden("d"));
        assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"new");

        // The held ones changed where the call went through.
        let set = |at: usize| results[at].1.is_ok();
        assert_eq!(!eas_of("f-old.txt", reading()).await.is_empty(), set(0));
        assert_eq!(
            !eas_of("d-old", dir_opts(OpenIntent::Open)).await.is_empty(),
            set(1)
        );
        assert_eq!(hidden("f-old.txt"), set(2));
        assert_eq!(hidden("d-old"), set(3));
        file.close().await.unwrap();
        dir.close().await.unwrap();
    })
    .await;
}

/// Makes `path` a reparse point of a WSL symlink to `target`, a name
/// surrogate the share does not follow.
fn lx_symlink(path: &Path, target: &str) {
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
    const IO_REPARSE_TAG_LX_SYMLINK: u32 = 0xA000_001D;

    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    // The tag, the data length, a reserved word, then the data: a version
    // of 2 and the target.
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(target.as_bytes());
    let mut buf = IO_REPARSE_TAG_LX_SYMLINK.to_le_bytes().to_vec();
    buf.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(&data);
    let mut returned = 0u32;
    // SAFETY: the handle is open for the call, `buf` is a live buffer of
    // the length passed, `returned` is a live local, and there is no
    // output buffer and no OVERLAPPED, as the handle is synchronous.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr().cast(),
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
}

#[tokio::test]
async fn a_link_of_a_kind_the_share_does_not_follow_is_a_special_file() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("a.txt"), b"one").unwrap();
        lx_symlink(&td.path().join("lx"), "a.txt");
        let backend = LocalFsBackend::new(reach(td.path(), root)).unwrap();
        for options in [reading(), opts(OpenIntent::OpenOrCreate)] {
            let opened = backend.open(&path("lx"), options).await.map(drop);
            assert!(matches!(opened, Err(SmbError::SpecialFile)), "{opened:?}");
        }
        assert_eq!(listed(&backend, "").await, ["a.txt", "lx"]);
    })
    .await;
}

/// The names `backend` lists in `dir`, sorted.
pub(in crate::fs) async fn listed(backend: &LocalFsBackend, dir: &str) -> Vec<String> {
    let (handle, _) = backend
        .open(&path(dir), dir_opts(OpenIntent::Open))
        .await
        .unwrap();
    let mut names: Vec<String> = handle
        .list_dir(None)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.info.name)
        .collect();
    handle.close().await.unwrap();
    names.sort();
    names
}

/// The backend reaches its share root through its own path, and through
/// a UNC path, the administrative share of the drive of a local directory.
#[tokio::test]
async fn a_share_root_on_a_unc_path_works_as_a_local_one() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        let backend = LocalFsBackend::new(reach(td.path(), root)).unwrap();

        let (file, _) = backend
            .open(&path("f.txt"), opts(OpenIntent::Create))
            .await
            .unwrap();
        assert_eq!(file.write(0, b"data").await.unwrap(), 4);
        file.close().await.unwrap();
        let (dir, _) = backend
            .open(&path("d"), dir_opts(OpenIntent::Create))
            .await
            .unwrap();
        dir.close().await.unwrap();
        assert_eq!(listed(&backend, "").await, ["d", "f.txt"]);

        backend
            .rename(&path("f.txt"), &path("d\\g.txt"), false)
            .await
            .unwrap();
        assert_eq!(listed(&backend, "").await, ["d"]);
        assert_eq!(listed(&backend, "d").await, ["g.txt"]);
        let (file, _) = backend.open(&path("d\\g.txt"), reading()).await.unwrap();
        assert_eq!(&file.read(0, 16).await.unwrap()[..], b"data");
        file.close().await.unwrap();
        assert_eq!(
            std::fs::read(td.path().join("d").join("g.txt")).unwrap(),
            b"data"
        );

        backend.unlink(&path("d\\g.txt")).await.unwrap();
        backend.unlink(&path("d")).await.unwrap();
        assert!(listed(&backend, "").await.is_empty());
        // Deletes through an SMB share go through a hidden directory of
        // the share root, which stays, empty.
        match root {
            Root::Local => assert!(host_names(td.path()).is_empty()),
            Root::Unc => {
                assert_eq!(host_names(td.path()), [".smb-deleted"]);
                let trash = td.path().join(".smb-deleted");
                assert!(host_names(&trash).is_empty());
                let attributes = std::fs::metadata(&trash).unwrap().file_attributes();
                assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN, 0);
            }
        }
    })
    .await;
}

/// Extended attributes set through a share root on a UNC path read back
/// through it, and are those of the file on the host.
#[tokio::test]
async fn extended_attributes_round_trip_on_a_unc_root() {
    let td = scratch_dir();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let backend = LocalFsBackend::new(on_admin_share(td.path())).unwrap();
    assert!(backend.capabilities().extended_attributes);
    let eas = [
        crate::Ea::new("TAG", b"x".to_vec()),
        crate::Ea::new("COLOR", vec![0, 1, 2, 255]),
    ];
    let (file, _) = backend
        .open(&path("f.txt"), opts(OpenIntent::Open))
        .await
        .unwrap();
    file.set_eas(&eas).await.unwrap();
    let mut read = file.eas().await.unwrap();
    file.close().await.unwrap();
    read.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(read, [eas[1].clone(), eas[0].clone()]);

    let local = LocalFsBackend::new(td.path()).unwrap();
    let (file, _) = local.open(&path("f.txt"), reading()).await.unwrap();
    let mut on_host = file.eas().await.unwrap();
    file.close().await.unwrap();
    on_host.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(on_host, read);
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
}

/// Files and directories made while another program opens their names in
/// the other case, as a virus scanner does, keep the case they were made
/// in.
#[tokio::test]
async fn names_made_while_another_program_opens_them_in_the_other_case_keep_their_case() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        let backend = LocalFsBackend::new(reach(td.path(), root)).unwrap();
        for i in 0..60 {
            let sub = format!("s{i}");
            std::fs::create_dir(td.path().join(&sub)).unwrap();
            let opener = Opener::start(vec![on_admin_share(&td.path().join(&sub)).join("F")]);
            let options = if i < 30 {
                opts(OpenIntent::Create)
            } else {
                dir_opts(OpenIntent::Create)
            };
            let (made, _) = backend
                .open(&path(&format!("{sub}\\f")), options)
                .await
                .unwrap();
            made.close().await.unwrap();
            opener.stop();
            assert_eq!(host_names(&td.path().join(&sub)), ["f"], "{sub}");
            assert_eq!(listed(&backend, &sub).await, ["f"], "{sub}");
        }
    })
    .await;
}

/// A rename that changes only the case of a file or a directory gives it
/// that case while another handle holds it under the new case, and the
/// held handle still reads the file.
#[tokio::test]
async fn a_case_only_rename_changes_the_case_while_the_new_case_is_held() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::create_dir(td.path().join("s")).unwrap();
        std::fs::write(td.path().join("s").join("d"), b"data").unwrap();
        std::fs::create_dir_all(td.path().join("t").join("d")).unwrap();
        let backend = LocalFsBackend::new(reach(td.path(), root)).unwrap();
        for sub in ["s", "t"] {
            let held = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(SHARE_ALL)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(reach(&td.path().join(sub), root).join("D"))
                .unwrap();
            backend
                .rename(
                    &path(&format!("{sub}\\d")),
                    &path(&format!("{sub}\\D")),
                    false,
                )
                .await
                .unwrap();
            assert_eq!(host_names(&td.path().join(sub)), ["D"], "{sub}");
            if sub == "s" {
                let mut data = Vec::new();
                (&held).read_to_end(&mut data).unwrap();
                assert_eq!(data, b"data");
            }
        }
    })
    .await;
}

/// A rename of a path to itself gives the entry the case of that path.
#[tokio::test]
async fn a_rename_of_a_path_to_itself_gives_the_entry_its_case() {
    on_each_root_async(|root| async move {
        let td = scratch_dir();
        std::fs::write(td.path().join("d"), b"x").unwrap();
        std::fs::create_dir(td.path().join("e")).unwrap();
        let backend = LocalFsBackend::new(reach(td.path(), root)).unwrap();
        backend.rename(&path("D"), &path("D"), false).await.unwrap();
        backend.rename(&path("E"), &path("E"), false).await.unwrap();
        assert_eq!(host_names(td.path()), ["D", "E"]);
    })
    .await;
}

/// Holds `path` open from another thread until a moment `after` the
/// returned sender sends.
fn release_after(
    path: &Path,
    after: Duration,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let held = std::fs::File::open(path).unwrap();
    let (go, signal) = std::sync::mpsc::channel::<()>();
    let releaser = std::thread::spawn(move || {
        signal.recv().unwrap();
        std::thread::sleep(after);
        drop(held);
    });
    (go, releaser)
}

/// A directory rename refused while a file below it is open succeeds once
/// the file closes, and fails with access denied after [`RENAME_WAIT`]
/// while it stays open, with nothing renamed.
#[test]
fn a_directory_rename_waits_for_a_file_open_below_it() {
    on_each_root(|root| {
        let td = scratch_dir();
        std::fs::create_dir(td.path().join("d")).unwrap();
        std::fs::write(td.path().join("d").join("f"), b"x").unwrap();
        let dir = open_dir(&reach(td.path(), root));
        let (go, releaser) =
            release_after(&td.path().join("d").join("f"), Duration::from_millis(100));
        go.send(()).unwrap();
        let started = Instant::now();
        dir.rename("d", &dir, "e").unwrap();
        let took = started.elapsed();
        releaser.join().unwrap();
        assert!(took >= Duration::from_millis(50), "{took:?}");
        assert_eq!(host_names(td.path()), ["e"]);

        let td = scratch_dir();
        std::fs::create_dir(td.path().join("d")).unwrap();
        std::fs::write(td.path().join("d").join("f"), b"x").unwrap();
        let dir = open_dir(&reach(td.path(), root));
        let held = std::fs::File::open(td.path().join("d").join("f")).unwrap();
        let started = Instant::now();
        let refused = dir.rename("d", &dir, "e").unwrap_err();
        let took = started.elapsed();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
        assert!(took >= RENAME_WAIT, "{took:?}");
        drop(held);
        assert_eq!(host_names(td.path()), ["d"]);
        assert_eq!(host_names(&td.path().join("d")), ["f"]);
    });
}

/// The same through the encryption layer, with names in the clear and
/// encrypted, over a share root on a UNC path: the layer's rename of a
/// directory waits for a file below it to close, and fails with access
/// denied while it stays open.
#[cfg(feature = "encryption")]
#[tokio::test]
async fn a_layered_directory_rename_waits_for_a_file_open_below_it() {
    use crate::encrypted::testing::{clear_over, names_over};

    for encrypted in [false, true] {
        for released in [true, false] {
            let td = scratch_dir();
            let inner = LocalFsBackend::new(on_admin_share(td.path())).unwrap();
            let backend: Box<dyn ShareBackend> = if encrypted {
                Box::new(names_over(inner).await)
            } else {
                Box::new(clear_over(inner).await)
            };
            let (made, _) = backend
                .open(&path("d"), dir_opts(OpenIntent::Create))
                .await
                .unwrap();
            made.close().await.unwrap();
            let (made, _) = backend
                .open(&path("d\\f"), opts(OpenIntent::Create))
                .await
                .unwrap();
            made.write(0, b"data").await.unwrap();
            made.close().await.unwrap();
            // The directory the layer stored, and the file in it.
            let stored: Vec<PathBuf> = std::fs::read_dir(td.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|at| at.is_dir() && !at.ends_with(".smb-deleted"))
                .collect();
            assert_eq!(stored.len(), 1, "{stored:?}");
            let stored = &stored[0];
            let child = std::fs::read_dir(stored)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|at| at.is_file())
                .unwrap();
            let names = host_names(stored);

            let what = format!("encrypted names {encrypted}, released {released}");
            let started = Instant::now();
            if released {
                let (go, releaser) = release_after(&child, Duration::from_millis(100));
                go.send(()).unwrap();
                let renamed = backend.rename(&path("d"), &path("e"), false).await;
                let took = started.elapsed();
                releaser.join().unwrap();
                assert!(renamed.is_ok(), "{what}: {renamed:?}");
                assert!(took >= Duration::from_millis(50), "{what}: {took:?}");
                assert!(!stored.exists(), "{what}");
            } else {
                let held = std::fs::File::open(&child).unwrap();
                let renamed = backend.rename(&path("d"), &path("e"), false).await;
                let took = started.elapsed();
                drop(held);
                assert!(
                    matches!(renamed, Err(SmbError::AccessDenied)),
                    "{what}: {renamed:?}"
                );
                assert!(took >= RENAME_WAIT, "{what}: {took:?}");
                assert_eq!(host_names(stored), names, "{what}");
            }
        }
    }
}

/// Makes the steps of name corrections act as `hook` says for as long as
/// it lives.
struct SettleHook;

impl SettleHook {
    fn set(hook: impl Fn(Step, &[u16]) -> Option<io::Error> + Send + 'static) -> Self {
        *SETTLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
        Self
    }

    /// Corrections of `name`, an entry of the host directory `at`, find it
    /// stored as `stored`, and each of `refused` fails: a reopen with a
    /// sharing violation, a rename with access denied.
    fn misspell(
        at: &Path,
        name: &'static str,
        stored: &'static str,
        refused: &'static [Step],
    ) -> Self {
        Self::misspell_or_take(at, name, stored, refused, false)
    }

    /// As [`SettleHook::misspell`] does; with `taken`, another file takes
    /// `name` before the rename to it.
    fn misspell_or_take(
        at: &Path,
        name: &'static str,
        stored: &'static str,
        refused: &'static [Step],
        taken: bool,
    ) -> Self {
        let at = at.to_path_buf();
        Self::set(move |step, requested| {
            if requested != name.encode_utf16().collect::<Vec<_>>() {
                return None;
            }
            // A failure here shows in what the host lists afterwards.
            let _ = match step {
                Step::Check => std::fs::rename(at.join(name), at.join(stored)),
                Step::Requested if taken => std::fs::write(at.join(name), b"theirs"),
                _ => Ok(()),
            };
            refused.contains(&step).then(|| {
                io::Error::from_raw_os_error(if step == Step::Reopen {
                    ERROR_SHARING_VIOLATION
                } else {
                    ERROR_ACCESS_DENIED
                })
            })
        })
    }
}

impl Drop for SettleHook {
    fn drop(&mut self) {
        *SETTLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// The lines of `logs` at `level`.
fn lines_at(logs: &crate::tests::logs::Logs, level: &str) -> Vec<String> {
    let marker = format!(" {level} ");
    logs.text()
        .lines()
        .filter(|line| line.contains(&marker))
        .map(str::to_string)
        .collect()
}

/// On a share root on a UNC path, a name the server stored in another case
/// that cannot be corrected is reported as the call it came from: a
/// case-only rename fails and changes nothing, a create or a move to
/// another name succeeds under the stored case with a warning, an entry
/// left under its temporary name fails the call with an error logged, and
/// a create whose name is taken meanwhile fails and leaves nothing. One
/// test runs every case, as the hook is shared.
#[tokio::test]
async fn names_that_cannot_be_corrected_are_reported_by_what_named_them() {
    use crate::tests::logs::Logs;

    let td = scratch_dir();
    let dir = open_dir(&on_admin_share(td.path()));
    let host = td.path();
    let logs = Logs::new();

    std::fs::write(host.join("cased"), b"x").unwrap();
    {
        let _hook = SettleHook::misspell(host, "CASED", "cased", &[Step::Aside]);
        let refused = dir.rename("cased", &dir, "CASED").unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
    }
    assert_eq!(host_names(host), ["cased"]);
    assert!(lines_at(&logs, "WARN").is_empty(), "{}", logs.text());
    std::fs::remove_file(host.join("cased")).unwrap();

    let expect_warning = |requested: &str, stored: &str| {
        let warnings = lines_at(&logs, "WARN");
        assert!(
            warnings
                .iter()
                .any(|line| line.contains(&format!("requested={requested}"))
                    && line.contains(&format!("stored={stored}"))),
            "{}",
            logs.text()
        );
    };

    std::fs::write(host.join("from"), b"x").unwrap();
    {
        let _hook = SettleHook::misspell(host, "moved", "MOVED", &[Step::Aside]);
        dir.rename("from", &dir, "moved").unwrap();
    }
    assert_eq!(host_names(host), ["MOVED"]);
    expect_warning("moved", "MOVED");
    std::fs::remove_file(host.join("MOVED")).unwrap();

    for (name, stored, refused) in [
        ("held", "HELD", &[Step::Reopen][..]),
        ("aside", "ASIDE", &[Step::Aside][..]),
        ("back", "BACK", &[Step::Requested][..]),
    ] {
        {
            let _hook = SettleHook::misspell(host, name, stored, refused);
            create(&dir, name, b"x");
        }
        assert_eq!(host_names(host), [stored], "{name}");
        expect_warning(name, stored);
        std::fs::remove_file(host.join(stored)).unwrap();
    }

    {
        let _hook = SettleHook::misspell(host, "lost", "LOST", &[Step::Requested, Step::Restore]);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        let refused = dir.open_with("lost", &options).map(drop).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
    }
    let left = host_names(host);
    assert_eq!(left.len(), 1, "{left:?}");
    let aside = &left[0];
    assert!(
        aside.len() == 37
            && aside.starts_with("~smb-")
            && aside[5..].bytes().all(|b| b.is_ascii_hexdigit()),
        "{aside}"
    );
    let errors = lines_at(&logs, "ERROR");
    assert!(
        errors
            .iter()
            .any(|line| line.contains("requested=lost") && line.contains(aside.as_str())),
        "{}",
        logs.text()
    );

    // A create whose name another program takes during the correction
    // fails with a sharing violation, and the entry it made is deleted.
    let td = scratch_dir();
    let backend = LocalFsBackend::new(on_admin_share(td.path())).unwrap();
    let opened = {
        let _hook = SettleHook::misspell_or_take(td.path(), "taken", "TAKEN", &[], true);
        backend
            .open(&path("taken"), opts(OpenIntent::Create))
            .await
            .map(drop)
    };
    assert!(matches!(opened, Err(SmbError::Sharing)), "{opened:?}");
    assert_eq!(host_names(td.path()), [".smb-deleted", "taken"]);
    assert_eq!(std::fs::read(td.path().join("taken")).unwrap(), b"theirs");
    assert!(host_names(&td.path().join(".smb-deleted")).is_empty());
}
