//! Path and open-option builders for tests.

use crate::backend::{OpenIntent, OpenOptions};
use crate::path::SmbPath;

/// The path `name`, backslash separated.
pub(crate) fn path(name: &str) -> SmbPath {
    name.parse().expect("a valid path")
}

/// Options for opening a file with write access and `intent`.
pub(crate) fn opts(intent: OpenIntent) -> OpenOptions {
    OpenOptions {
        write: true,
        intent,
        ..OpenOptions::default()
    }
}

/// Options for opening a directory with `intent`.
pub(crate) fn dir_opts(intent: OpenIntent) -> OpenOptions {
    OpenOptions {
        directory: true,
        intent,
        ..OpenOptions::default()
    }
}

/// A new directory for the files of a test. On Windows it is beside the test
/// binary, on the build volume, whatever the temporary directory is.
#[cfg(any(feature = "s3", all(windows, feature = "localfs")))]
pub(crate) fn scratch_dir() -> tempfile::TempDir {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().unwrap();
        tempfile::tempdir_in(exe.parent().unwrap()).unwrap()
    }
    #[cfg(not(windows))]
    {
        tempfile::tempdir().unwrap()
    }
}

/// `path`, on a local drive, as the administrative share of the drive on
/// this host: `\\localhost\C$\dir` for `C:\dir`. Panics where this host does
/// not reach that share.
#[cfg(all(windows, any(feature = "s3", feature = "localfs")))]
pub(crate) fn on_admin_share(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::{Component, PathBuf, Prefix};

    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => char::from(drive),
            other => panic!("{} is not on a drive: {other:?}", path.display()),
        },
        other => panic!("{} has no drive: {other:?}", path.display()),
    };
    let mut share = PathBuf::from(format!("\\\\localhost\\{drive}$\\"));
    share.extend(components.filter(|c| !matches!(c, Component::RootDir)));
    if let Err(e) = std::fs::read_dir(&share) {
        panic!(
            "{} is not reachable, and the tests need the administrative share of the build volume: {e}",
            share.display()
        );
    }
    share
}

/// A thread that walks a directory tree again and again, as a virus
/// scanner opens new names, until it is stopped: on each pass it opens each
/// name it lists with its case flipped, and each of a list of names with
/// its case flipped in every directory it lists, each open closed at once.
#[cfg(all(windows, feature = "localfs"))]
pub(crate) struct Contender {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    passes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(all(windows, feature = "localfs"))]
impl Contender {
    /// Starts walking the tree at `root`, opening `names` in each of its
    /// directories too.
    pub(crate) fn start(root: std::path::PathBuf, names: &[String]) -> Self {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let stop = Arc::new(AtomicBool::new(false));
        let passes = Arc::new(AtomicUsize::new(0));
        let names: Vec<String> = names.iter().map(|name| flip_case(name)).collect();
        let thread = {
            let (stop, passes) = (Arc::clone(&stop), Arc::clone(&passes));
            std::thread::spawn(move || {
                loop {
                    walk(&root, &names);
                    passes.fetch_add(1, Ordering::Relaxed);
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
            })
        };
        Self {
            stop,
            passes,
            thread: Some(thread),
        }
    }

    /// Stops the thread once the pass it is making is over, and returns
    /// how many passes it made, at least one.
    pub(crate) fn stop(mut self) -> usize {
        self.join();
        self.passes.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn join(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the contender thread ran to its end");
        }
    }
}

#[cfg(all(windows, feature = "localfs"))]
impl Drop for Contender {
    fn drop(&mut self) {
        self.join();
    }
}

/// `name` with each lowercase letter in uppercase and each other letter
/// in lowercase.
#[cfg(all(windows, feature = "localfs"))]
fn flip_case(name: &str) -> String {
    let mut flipped = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_lowercase() {
            flipped.extend(c.to_uppercase());
        } else {
            flipped.extend(c.to_lowercase());
        }
    }
    flipped
}

/// One pass of [`Contender`] over the tree at `root`, opening `names` in
/// each directory.
#[cfg(all(windows, feature = "localfs"))]
fn walk(root: &std::path::Path, names: &[String]) {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let open = |path: &std::path::Path| {
        let _ = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path);
    };
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                open(&dir.join(flip_case(name)));
            }
            if entry.file_type().is_ok_and(|ty| ty.is_dir()) {
                pending.push(entry.path());
            }
        }
        for name in names {
            open(&dir.join(name));
        }
    }
}

/// Set in the child process [`alone_in_child`] starts.
#[cfg(all(unix, feature = "s3"))]
const CHILD: &str = "SMB_SERVER_TEST_CHILD";

/// Whether to run the body of the test `name` of the module `module` (its
/// `module_path!()`) here. In the test process, runs that test alone in a child
/// process of the test binary, asserts that it passed there and returns false;
/// in that child, returns true. A child can lower its descriptor limit without
/// starving the tests that run beside it.
#[cfg(all(unix, feature = "s3"))]
pub(crate) fn alone_in_child(module: &str, name: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let module = module.split_once("::").unwrap().1;
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([&format!("{module}::{name}"), "--exact", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// How many descriptors below 4096 this process has open. It probes each
/// number, so it needs no descriptor of its own.
#[cfg(all(unix, feature = "s3"))]
pub(crate) fn open_descriptors() -> usize {
    (0..4096)
        // SAFETY: F_GETFD reads the flags of a descriptor and fails for one that
        // is not open.
        .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1)
        .count()
}

/// Opens files until the process has no descriptor left, and returns them.
/// Dropping them frees the descriptors again. The soft limit has to be low
/// already.
#[cfg(all(unix, feature = "s3"))]
pub(crate) fn exhaust_descriptors() -> Vec<std::fs::File> {
    let mut taken = Vec::new();
    while let Ok(file) = std::fs::File::open("/dev/null") {
        taken.push(file);
    }
    taken
}

/// Lowers the soft descriptor limit of this process to `headroom` above the
/// descriptors it has open.
#[cfg(all(unix, feature = "s3"))]
pub(crate) fn limit_descriptors(headroom: usize) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for both calls to read and write.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = (open_descriptors() + headroom) as libc::rlim_t;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
}
