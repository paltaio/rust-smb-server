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
