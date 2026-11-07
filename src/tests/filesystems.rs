//! Directories on two filesystems, for tests of copies between them.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use tempfile::TempDir;

/// A new directory beside the test binary, on the build's filesystem, and a
/// new one in `/dev/shm`. `None`, after a note on stderr, when `/dev/shm`
/// is not usable or is on the build's filesystem.
pub(crate) fn pair() -> Option<(TempDir, TempDir)> {
    let device = |dir: &Path| dir.metadata().unwrap().dev();
    let exe = std::env::current_exe().unwrap();
    let build = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
    let shm = tempfile::tempdir_in("/dev/shm")
        .ok()
        .filter(|shm| device(shm.path()) != device(build.path()));
    if shm.is_none() {
        eprintln!(
            "skipping: /dev/shm is not usable or is on the filesystem of {}",
            build.path().display()
        );
    }
    shm.map(|shm| (build, shm))
}
