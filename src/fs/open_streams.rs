//! The named streams open through a [`LocalFsBackend`](super::LocalFsBackend)
//! that keeps them in extended attributes: per file, the stream each handle
//! is on, and the lock held over every read and change of the file's
//! streams.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use cap_std::fs::{Dir, Metadata, OpenOptions as CapOpenOptions};
use tracing::debug;

use super::local::{file_key, special_file};
use crate::path::is_valid_component;
use crate::stream::StreamName;

pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The files with named streams open through one backend, by host
/// identity.
#[derive(Default)]
pub(super) struct OpenStreams {
    files: Mutex<HashMap<(u64, u64), Weak<StreamFile>>>,
}

impl OpenStreams {
    /// The entry of the file with host identity `key`.
    pub(super) fn file(self: &Arc<Self>, key: (u64, u64)) -> Arc<StreamFile> {
        let mut files = lock(&self.files);
        if let Some(file) = files.get(&key).and_then(Weak::upgrade) {
            return file;
        }
        let file = Arc::new(StreamFile {
            key,
            owner: Arc::downgrade(self),
            open: Mutex::default(),
        });
        files.insert(key, Arc::downgrade(&file));
        file
    }
}

/// One file with named streams open or being changed. Its lock is held
/// over every read and change of the file's streams, so changes that take
/// more than one call, such as a read-modify-write of a value or a rename,
/// see each other whole. An entry lives as long as a handle on one of the
/// file's streams, which holds the file open, so its host identity stays
/// the file's.
pub(super) struct StreamFile {
    key: (u64, u64),
    owner: Weak<OpenStreams>,
    pub(super) open: Mutex<OpenNames>,
}

impl Drop for StreamFile {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            let mut files = lock(&owner.files);
            if files.get(&self.key).is_some_and(|f| f.strong_count() == 0) {
                files.remove(&self.key);
            }
        }
    }
}

/// The stream each handle of a file is on, by handle id, spelled as
/// stored.
#[derive(Default)]
pub(super) struct OpenNames {
    next: u64,
    pub(super) names: HashMap<u64, StreamName>,
}

impl OpenNames {
    pub(super) fn add(&mut self, name: StreamName) -> u64 {
        self.next += 1;
        self.names.insert(self.next, name);
        self.next
    }

    /// Moves the handles on the stream `from` to the stream `to`.
    pub(super) fn rename(&mut self, from: &StreamName, to: &StreamName) {
        for name in self.names.values_mut() {
            if name == from {
                *name = to.clone();
            }
        }
    }
}

/// Opens the file or directory at `rel` below `root` for reading, or for
/// writing too with `write`. The open does not block, so a FIFO there opens
/// or fails at once, and anything but a file or directory is refused.
pub(super) fn open_base(
    root: &Dir,
    rel: &Path,
    write: bool,
) -> io::Result<(File, Metadata, (u64, u64))> {
    use cap_std::fs::OpenOptionsExt as _;
    let mut opts = CapOpenOptions::new();
    opts.read(true)
        .write(write)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    checked(root.open_with(rel, &opts)?.into_std())
}

/// Opens the entry `name` of `dir` for reading, without following a
/// symlink there, and returns it with its host identity; a symlink is
/// followed only to a target below `dir`. Anything but a file or
/// directory is refused, as [`open_base`] refuses it. The entry is
/// opened as a path first and reopened for reading through
/// `/proc/self/fd` only once it is known to be a file or directory, so
/// nothing else is opened.
#[cfg(target_os = "linux")]
pub(super) fn open_entry(dir: &Dir, name: &str) -> io::Result<(File, (u64, u64))> {
    use cap_std::fs::OpenOptionsExt as _;
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::AsRawFd as _;
    if !is_valid_component(name) {
        return Err(io::ErrorKind::InvalidFilename.into());
    }
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut path = File::from(rustix::fs::openat(dir, name, flags, Mode::empty())?);
    let mut md = Metadata::from_file(&path)?;
    if md.file_type().is_symlink() {
        let mut opts = CapOpenOptions::new();
        opts.read(true).custom_flags(libc::O_PATH);
        path = dir.open_with(name, &opts)?.into_std();
        md = Metadata::from_file(&path)?;
    }
    if !md.is_file() && !md.is_dir() {
        return Err(special_file());
    }
    let key = file_key(&md).ok_or(io::ErrorKind::Unsupported)?;
    let file = rustix::fs::open(
        format!("/proc/self/fd/{}", path.as_raw_fd()),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok((file.into(), key))
}

/// Opens the entry `name` of `dir` for reading, as [`open_base`] does,
/// without following a symlink there, and returns it with its host
/// identity; a symlink is opened through [`open_base`], which follows it
/// only to a target below `dir`.
#[cfg(target_os = "macos")]
pub(super) fn open_entry(dir: &Dir, name: &str) -> io::Result<(File, (u64, u64))> {
    use rustix::fs::{Mode, OFlags};
    if !is_valid_component(name) {
        return Err(io::ErrorKind::InvalidFilename.into());
    }
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOFOLLOW;
    let opened = rustix::fs::openat(dir, name, flags | OFlags::CLOEXEC, Mode::empty());
    let (file, _, key) = match opened {
        Ok(fd) => checked(fd.into())?,
        Err(rustix::io::Errno::LOOP) => open_base(dir, Path::new(name), false)?,
        Err(e) => return Err(e.into()),
    };
    Ok((file, key))
}

/// `file` with its metadata and host identity, unless it is anything but a
/// file or directory.
fn checked(file: File) -> io::Result<(File, Metadata, (u64, u64))> {
    let md = Metadata::from_file(&file)?;
    if !md.is_file() && !md.is_dir() {
        return Err(special_file());
    }
    let key = file_key(&md).ok_or(io::ErrorKind::Unsupported)?;
    Ok((file, md, key))
}

/// Sets the last write time of the file `fd` is open on to now. Changes of
/// extended attributes leave it alone.
pub(super) fn touch(fd: &File) {
    use rustix::fs::{Timespec, Timestamps, UTIME_NOW, UTIME_OMIT};
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
    };
    if let Err(e) = rustix::fs::futimens(fd, &times) {
        debug!(error = %e, "last write time of a file with a changed stream not set");
    }
}
