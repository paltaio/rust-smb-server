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
