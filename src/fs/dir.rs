//! The directory handles every name of a share is looked up from, under
//! the same names on every host: those of `cap-std` on Unix, and those of
//! `windows_dir` on Windows.

#[cfg(unix)]
pub(super) use cap_std::ambient_authority;
#[cfg(unix)]
pub(super) use cap_std::fs::{Dir, DirEntry, File, FileType, Metadata, OpenOptions};

#[cfg(windows)]
pub(super) use super::windows_dir::{
    Dir, DirEntry, File, FileType, Metadata, OpenOptions, ambient_authority,
};
