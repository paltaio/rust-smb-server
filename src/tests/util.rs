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

/// Raises the soft limit on open files, once per process. An S3 backend keeps
/// open every file it has made until it stores the file, and a process on
/// macOS starts with room for 256.
#[cfg(feature = "s3")]
pub(crate) fn raise_file_limit() {
    #[cfg(unix)]
    {
        static RAISED: std::sync::Once = std::sync::Once::new();
        RAISED.call_once(|| {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `limit` is a valid rlimit for both calls to read and write.
            unsafe {
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                    limit.rlim_cur = limit.rlim_cur.max(limit.rlim_max.min(8192));
                    libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
                }
            }
        });
    }
}
