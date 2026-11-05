//! `LocalFsBackend`: a `ShareBackend` backed by a real on-disk directory.
//!
//! The share root is opened once via `cap_std::fs::Dir::open_ambient_dir` and
//! kept as the sole authority handle. All subsequent path operations are
//! resolved relative to that handle, so a malicious symlink or `..` smuggled
//! through `SmbPath` cannot escape the sandbox; `cap-std` enforces this at
//! every step.
//!
//! - Blocking FS calls run on `tokio::task::spawn_blocking`.
//! - `read_only()` flips a flag that makes write-class opens reject early
//!   with `SmbError::AccessDenied`.
//! - `list_dir` applies the MS-FSA 2.1.4.4 wildcards (`*`, `?`, `<`, `>`,
//!   `"`) itself, since cap-std only provides raw `entries()`. Matching
//!   ignores case only where the host looks names up case-insensitively.
//!   `"*.*"` matches every name, as `"*"` does.
//! - Listings leave out names a client could not open again: names that are
//!   not valid UTF-8 or not valid `SmbPath` components.
//! - Name lookups are case-sensitive or not as the host filesystem reports
//!   for the share root.
//! - On Windows, directory handles share delete access, so a client can
//!   rename or delete a directory it or another client has open.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions as CapOpenOptions};
use tokio::task::spawn_blocking;
use tracing::debug;

use crate::backend::{
    BackendCapabilities, DirEntry as SmbDirEntry, FileInfo, FileTimes, Handle, OpenAction,
    OpenIntent, OpenOptions, ShareBackend,
};
use crate::error::{SmbError, SmbResult};
use crate::path::{SmbPath, same_path};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::stream::StreamName;
use crate::utils::{FILETIME_OFFSET, system_time_to_filetime};

use super::volume;
use crate::backend::VolumeInfo;
use crate::path::is_valid_component;
use crate::wildcard::Pattern;

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Local-filesystem backend, sandboxed at a single root directory.
///
/// Handles set access and write times on every host. The creation time is
/// set on Windows and macOS; other hosts have no call that sets it, so a
/// requested creation time is ignored there and the other times still apply.
/// The host keeps the change time.
///
/// On Unix, FIFOs, sockets and device nodes are listed, and an open of one,
/// or of a symlink to one, fails with STATUS_IO_REPARSE_TAG_NOT_HANDLED.
/// On Linux, an open that conflicts with a file lease (`F_SETLEASE`) fails
/// with STATUS_SHARING_VIOLATION instead of waiting; the kernel starts
/// breaking the lease, so a retry succeeds once the holder releases it.
///
/// On Linux, a file's or directory's named streams are its extended
/// attributes named `user.DosStream.<name>:$DATA`, each holding the
/// stream's data followed by one NUL byte. A share moves between this
/// server and Samba's `vfs_streams_xattr` with its streams. Of attributes
/// whose names differ only in case, the one that sorts first in byte order
/// is the stream; removing or replacing the stream removes them all.
///
/// A stream that outgrows its extended attribute, past 65535 bytes or past
/// the room the filesystem gives a file's extended attributes (one block
/// for all of them on ext4), moves to the stream store, and stays there
/// until it is removed or cut to zero. The store is the directory
/// `.smb-streams` in the share root, mode 0700, or the one
/// [`LocalFsBackend::stream_store`] names, made with the first request to a
/// writable share. Clients cannot open, list or rename into it under any
/// name, and cannot create its name in the share root; with a store, paths
/// are looked up one name at a time from the share root, each directory
/// opened from the one before. The store has a directory per file, named by
/// a random id that the file keeps in the extended attribute
/// `user.smb-server.streams` (its record) with its identity, so its streams
/// follow it through renames and hard links. A file that carries another
/// file's record, as a copy with its extended attributes does, reads that
/// file's streams, and gets an id of its own with a copy of them before any
/// of them changes. The identity is the file handle where the filesystem
/// gives one, else the inode number and birth time; on filesystems whose
/// inode numbers or handles change, such as some FUSE filesystems, every
/// file looks like a copy and copies its streams once more each time, and a
/// file in a snapshot reads the live file's streams in the store. A record
/// of another store is left alone, and that file's streams stay in extended
/// attributes. Removed files leave their streams in the store until
/// [`LocalFsBackend::sweep_streams`] removes them. A stream whose name
/// takes more than 126 bytes in UTF-8 cannot move to the store, and a
/// write past what its extended attribute holds fails with
/// STATUS_DISK_FULL, as does a new stream on a file with 4096. A rename
/// between the default stream and a named one copies at most 64 MiB where
/// the filesystem cannot clone the data.
///
/// Whether the share has named streams is decided once, by probing the
/// share root for user extended attributes. Below the root, a mount
/// without them lists no streams, and a stream request there fails with
/// STATUS_ACCESS_DENIED.
///
/// On macOS, a file's or directory's named streams are its extended
/// attributes, and the host's Finder shows the tags, comments, labels and
/// icons clients set. `AFP_AfpInfo` is `com.apple.FinderInfo`, in the
/// 60-byte AfpInfo layout around its 32 bytes: a write must be those 60
/// bytes at offset 0, starting with `AFP\0`, or it fails with
/// STATUS_INVALID_PARAMETER, and Finder info of all zeros, a cut to zero
/// or an overwrite removes the attribute. An `AFP_AfpInfo` stream without
/// the attribute reads as AfpInfo with Finder info of all zeros and is not
/// listed; a client can create it, and the first write stores it.
/// `AFP_Resource` is `com.apple.ResourceFork`, which holds no empty fork:
/// an `AFP_Resource` stream exists once it has data. Directories have no
/// resource fork. Any other stream is the attribute of the same name, with
/// the characters macOS clients send as U+F001 to U+F029 mapped back, so
/// `com.apple.metadata\u{F022}_kMDItemUserTags` is the attribute
/// `com.apple.metadata:_kMDItemUserTags`, and attributes list under those
/// names. A stream name holds such characters only that way: `a*b` is an
/// invalid name, and `a\u{F021}b` names the attribute `a*b`. Attribute
/// names no stream name leads to, and `com.apple.FinderInfo` and
/// `com.apple.ResourceFork` spelled in another case, are left out; a
/// stream name that maps to one of them, or to more than 127 bytes, is
/// invalid. Attributes whose names differ only in case are one stream, as
/// on Linux. A write or size change that would leave `AFP_Resource` larger
/// than 16 MiB, or another stream larger than 1 MiB, fails with
/// STATUS_DISK_FULL, as does a rename that moves more than the target
/// holds, and a read of a stream other than those two that the host made
/// larger than 1 MiB fails with STATUS_ACCESS_DENIED. Reads of a resource
/// fork stop at 4 GiB. An overwrite or supersede of a file removes every
/// attribute it lists as a stream, `com.apple.quarantine` and others the
/// host set included. A share on a volume that keeps extended attributes
/// only in `._` files, such as FAT or exFAT, has no named streams.
///
/// On Windows, a file's or directory's named streams are its NTFS
/// alternate data streams, under the names clients send, each opened
/// relative to a handle of its file inside the share without following
/// reparse points. NTFS compares stream names by the uppercase form of
/// each character and keeps the spelling a stream was made with; names
/// that differ only in a character without a one-character uppercase form,
/// such as U+00DF and U+1E9E, are two streams to NTFS and one to the
/// server's share modes and locks, while U+03C2 and U+03C3 are one stream
/// to NTFS and two to the server. A file lists at most 4096 named streams,
/// and a new stream past that fails with STATUS_DISK_FULL. Whether the
/// share has named streams is decided once, from the volume of the share
/// root: FAT and exFAT volumes have none. ReFS cannot rename streams: a
/// stream rename there fails with STATUS_INVALID_PARAMETER, and a stream
/// larger than the volume holds fails with STATUS_DISK_FULL.
///
/// On Linux, a file's or directory's extended attributes are its extended
/// attributes named `user.<name>`, the layout Samba uses, when the
/// filesystem of the share root stores user extended attributes. Names
/// compare without regard to ASCII case: a set or a removal acts on the
/// attribute as the host spells it, and a new one keeps the client's
/// spelling. Of attributes whose names differ only in case, the one that
/// sorts first in byte order is listed, and a set or removal of the name
/// replaces or removes them all. Names longer than 250 bytes fail with
/// STATUS_INVALID_EA_NAME. These host attributes are hidden, and a set of
/// one of their names fails with STATUS_ACCESS_DENIED, in any case: names
/// clients cannot send, `user.DosStream.*`, `user.smb-server.*`, and
/// Samba's `user.DOSATTRIB`, `user.SAMBA_PAI`, `user.SAMBA_STREAMS`,
/// `user.SmbReparse` and `user.org.netatalk.Metadata`. FILE_NEED_EA is not
/// kept. A set that does not fit, past the room the filesystem gives a
/// file's extended attributes (one block for all of them on ext4), fails
/// with STATUS_EA_TOO_LARGE and changes nothing. A set on a read-only file
/// fails with STATUS_ACCESS_DENIED unless the server may write the file
/// whatever its mode.
///
/// On Windows, extended attributes are the NTFS ones, on volumes that
/// store them; NTFS keeps the letters a-z of their names in uppercase.
/// macOS hosts have none: every extended attribute there is a named
/// stream.
pub struct LocalFsBackend {
    root: Arc<Dir>,
    /// Device of the share root; see `file_index`.
    root_dev: Option<u64>,
    read_only: bool,
    /// Case rule of name lookups in the share root.
    case_sensitive: bool,
    /// The share root's filesystem stores extended attributes.
    eas: bool,
    /// Watches directories for changes made outside the server.
    #[cfg(target_os = "linux")]
    hub: Option<Arc<super::inotify::Hub>>,
    /// The named streams open through the backend; `None` when the share
    /// has none.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    streams: Option<Arc<super::open_streams::OpenStreams>>,
    /// The named streams of the share root's volume; `None` when it has
    /// none.
    #[cfg(windows)]
    volume: Option<super::windows_streams::Volume>,
    /// Where streams too large for an extended attribute go; `None` when
    /// the share has no named streams.
    #[cfg(target_os = "linux")]
    store: Option<Arc<super::streams::Store>>,
    /// Runs between the lookup of a path and its open.
    #[cfg(test)]
    after_locate: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl LocalFsBackend {
    /// Open `path` as the share root. Errors if the path does not exist or is
    /// not a directory.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let dir = Dir::open_ambient_dir(path, ambient_authority())?;
        let root_dev = file_key(&dir.dir_metadata()?).map(|(dev, _)| dev);
        let case_sensitive = volume::is_case_sensitive(&dir);
        let root = Arc::new(dir);
        #[cfg(target_os = "linux")]
        let streams = super::streams::supported(&root).then(Arc::default);
        #[cfg(target_os = "macos")]
        let streams = super::macos_streams::supported(&root).then(Arc::default);
        #[cfg(windows)]
        let volume = super::windows_streams::volume(&root);
        #[cfg(target_os = "linux")]
        let eas = streams.is_some();
        #[cfg(windows)]
        let eas = super::windows_eas::supported(&root);
        #[cfg(not(any(target_os = "linux", windows)))]
        let eas = false;
        #[cfg(target_os = "linux")]
        let store = streams
            .is_some()
            .then(|| Arc::new(super::streams::Store::in_share(Arc::clone(&root))));
        Ok(Self {
            root,
            root_dev,
            read_only: false,
            case_sensitive,
            eas,
            #[cfg(target_os = "linux")]
            hub: Some(Arc::default()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            streams,
            #[cfg(windows)]
            volume,
            #[cfg(target_os = "linux")]
            store,
            #[cfg(test)]
            after_locate: None,
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn after_locate(self, f: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            after_locate: Some(Arc::new(f)),
            ..self
        }
    }

    /// Mark the backend as read-only. All write-class opens and writes return
    /// an access-denied SMB error.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Report changes made to the share's directories outside the server,
    /// by other programs on the host or through other shares, to clients
    /// that watch them. On Linux only, through inotify: only the entries
    /// directly in a watched directory are seen. The parent of each watched
    /// directory, the share root's parent included, is watched too, to see
    /// the directory deleted. The backend holds at most 4096 kernel
    /// watches; a directory past that, or one the kernel will not watch,
    /// past `fs.inotify.max_user_watches` or `fs.inotify.max_user_instances`
    /// or without `/proc`, gets only the changes made through the server,
    /// with a warning logged once. On by default.
    #[must_use]
    pub fn watch_host_changes(self, enabled: bool) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                hub: enabled.then(Arc::default),
                ..self
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = enabled;
            self
        }
    }

    /// Keep the named streams that do not fit in an extended attribute in
    /// the directory `path` instead of `.smb-streams` in the share root.
    /// The directory must exist, lie outside the share, belong to the
    /// server's user and give no access to group or others. Space taken
    /// there does not count against the share's filesystem or its quotas
    /// when it is on another filesystem. Backends that name the same
    /// directory share it, and [`LocalFsBackend::sweep_streams`] on one of
    /// them removes what none of its own files refers to, so each needs
    /// its own directory unless their shares are swept together. Linux
    /// only; elsewhere the directory is opened and not used.
    pub fn stream_store(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let dir = Dir::open_ambient_dir(path, ambient_authority())?;
        #[cfg(target_os = "linux")]
        {
            let store = self
                .streams
                .as_ref()
                .map(|_| super::streams::Store::at(dir, &self.root).map(Arc::new))
                .transpose()?;
            Ok(Self { store, ..self })
        }
        #[cfg(not(target_os = "linux"))]
        {
            drop(dir);
            Ok(self)
        }
    }

    /// Remove what the stream store keeps for files that are gone: files
    /// deleted, through the server or on the host, or replaced without
    /// their extended attributes. Returns how many files' streams went.
    ///
    /// An entry of the store goes once two sweeps in a row found no file
    /// referring to it and no request used it in between, so a file moved
    /// while one sweep walked the share keeps its streams; space a deleted
    /// file took comes back after the second sweep. The walk reads an
    /// extended attribute of every file and directory of the share and
    /// holds nothing; the pass over the store that follows makes stream
    /// requests that use the store wait until it is done, a pause that
    /// grows with the number of entries and with the size of those it
    /// removes. Any `user.smb-server.streams` attribute keeps the entry it
    /// names. A file or directory the walk cannot read fails the sweep
    /// before anything is removed; a failure in the pass over the store
    /// leaves the entries it had not reached yet. Linux only; elsewhere it
    /// removes nothing.
    pub async fn sweep_streams(&self) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            let Some(store) = self.store.clone() else {
                return Ok(0);
            };
            if self.read_only {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let root = Arc::clone(&self.root);
            spawn_blocking(move || store.sweep(&root))
                .await
                .map_err(join_to_io)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(0)
        }
    }

    /// True if `path` is the name the stream store takes in the share
    /// root, which no client may make.
    fn reserves(&self, path: &SmbPath) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(hidden) = self.store.as_ref().and_then(|store| store.hidden_name()) {
            return matches!(path.components(), [name] if is_hidden(name, hidden, self.case_sensitive));
        }
        let _ = path;
        false
    }

    /// Makes the stream store of a writable share, so it exists before a
    /// client could take its name.
    async fn prepare_store(&self) {
        #[cfg(target_os = "linux")]
        if !self.read_only
            && let Some(store) = self.store.clone()
            && !store.prepared()
        {
            let _ = spawn_blocking(move || store.prepare()).await;
        }
    }

    /// [`LocalFsBackend::locate`], once more when a directory on the way
    /// moved during the lookup; moved again, the path is not found.
    async fn locate_again(&self, path: &SmbPath, follow_last: bool) -> io::Result<Located> {
        match self.locate(path, follow_last).await {
            Err(e) if is_changed(&e) => match self.locate(path, follow_last).await {
                Err(e) if is_changed(&e) => Err(io::ErrorKind::NotFound.into()),
                located => located,
            },
            located => located,
        }
    }

    /// Where `path` is: a directory, open, and the path in it. With a
    /// stream store, the path is resolved one name at a time from the share
    /// root, each directory on the way opened from the one before, so the
    /// result is a directory that is not the store or below it, and the
    /// last name in it; a path that leads into the store fails with
    /// [`in_store`]. A symlink as the last name is followed only with
    /// `follow_last`. Without a store, it is the share root and the whole
    /// path.
    async fn locate(&self, path: &SmbPath, follow_last: bool) -> io::Result<Located> {
        #[cfg(target_os = "linux")]
        if let Some(store) = self.store.clone() {
            let root = Arc::clone(&self.root);
            let rel = to_rel_path(path);
            return spawn_blocking(move || match store.key() {
                Some(key) => resolve(&root, &rel, key, follow_last),
                None => Ok(Located {
                    base: root,
                    rel,
                    checked: false,
                }),
            })
            .await
            .map_err(join_to_io)?;
        }
        let _ = follow_last;
        Ok(Located {
            base: Arc::clone(&self.root),
            rel: to_rel_path(path),
            checked: false,
        })
    }
}

/// A path below the share root, as [`LocalFsBackend::locate`] found it.
#[derive(Clone)]
struct Located {
    /// The directory the path is in.
    base: Arc<Dir>,
    /// The path in `base`: one name, or `.` for `base` itself, when
    /// `checked`.
    rel: PathBuf,
    /// `base` was reached one name at a time, and none of it is the
    /// stream store.
    checked: bool,
}

impl Located {
    /// Fails unless the object `opened` is the one the last name of a
    /// checked path names now, without following a symlink: the name was
    /// swapped since it was resolved.
    #[cfg(target_os = "linux")]
    fn verify(&self, opened: &impl std::os::fd::AsFd) -> io::Result<()> {
        if self.checked && self.rel != Path::new(".") {
            let named = rustix::fs::statat(
                &*self.base,
                &self.rel,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
            let opened = rustix::fs::fstat(opened)?;
            if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino) {
                return Err(changed());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn verify<T>(&self, _opened: &T) -> io::Result<()> {
        Ok(())
    }
}

/// The error for a path that leads into the stream store.
#[cfg(target_os = "linux")]
fn in_store() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, InStore)
}

/// What [`special_file`] carries.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct Special;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl std::fmt::Display for Special {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a regular file or directory")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl std::error::Error for Special {}

/// The error for an open of a FIFO, a socket or a device node, which
/// [`io_to_smb`] makes [`SmbError::SpecialFile`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn special_file() -> io::Error {
    io::Error::other(Special)
}

/// The error for a name that changed between its lookup and its open.
#[cfg(unix)]
fn changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "a name changed while it was looked up",
    )
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct InStore;

#[cfg(target_os = "linux")]
impl std::fmt::Display for InStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the path leads into the stream store")
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for InStore {}

/// True if `e` says a path leads into the stream store.
fn is_in_store(e: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    {
        e.kind() == io::ErrorKind::NotFound
            && e.get_ref().is_some_and(|inner| inner.is::<InStore>())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = e;
        false
    }
}

/// True if `e` says a name changed between its lookup and its open.
fn is_changed(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::Interrupted
}

/// Resolves `rel` below `root` one name at a time, as
/// [`LocalFsBackend::locate`] says. Symlinks are followed as the share
/// follows them: relative ones within the share, absolute ones not at all;
/// with `follow_last` unset, a symlink as the last name is the result
/// itself. Only the directory reached so far is held open; a `..` opens
/// its parent again and checks it is the one it came through.
#[cfg(target_os = "linux")]
fn resolve(
    root: &Arc<Dir>,
    rel: &Path,
    store: (u64, u64),
    follow_last: bool,
) -> io::Result<Located> {
    use std::collections::VecDeque;
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let escape = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a symlink leads outside the share",
        )
    };
    let key = |fd: &dyn std::os::fd::AsFd| -> io::Result<(u64, u64)> {
        let st = rustix::fs::fstat(fd.as_fd())?;
        Ok((st.st_dev, st.st_ino))
    };
    let dir_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut top: Arc<Dir> = Arc::clone(root);
    // The device and inode of each directory from the root to `top`.
    let mut keys = vec![key(&**root)?];
    let mut pending: VecDeque<OsString> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect();
    let mut links = 0;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            if keys.len() == 1 {
                return Err(escape());
            }
            #[cfg(test)]
            if let Some(f) = lock_hook().as_ref() {
                f();
            }
            let parent = rustix::fs::openat(&*top, "..", dir_flags, Mode::empty())?;
            keys.pop();
            if Some(&key(&parent)?) != keys.last() {
                return Err(changed());
            }
            top = Arc::new(Dir::from_std_file(std::fs::File::from(parent)));
            continue;
        }
        if name == "." {
            continue;
        }
        let st = match rustix::fs::statat(&*top, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => Some(st),
            Err(rustix::io::Errno::NOENT) => None,
            Err(e) => return Err(e.into()),
        };
        let is_link = st
            .as_ref()
            .is_some_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::Symlink);
        match st {
            Some(_) if is_link && (follow_last || !pending.is_empty()) => {
                links += 1;
                if links > 40 {
                    return Err(rustix::io::Errno::LOOP.into());
                }
                let target = rustix::fs::readlinkat(&*top, &name, Vec::new())?;
                let target = Path::new(OsStr::from_bytes(target.as_bytes()));
                for c in target.components().rev() {
                    match c {
                        Component::Normal(n) => pending.push_front(n.to_os_string()),
                        Component::ParentDir => pending.push_front("..".into()),
                        Component::CurDir => {}
                        Component::RootDir | Component::Prefix(_) => return Err(escape()),
                    }
                }
            }
            Some(st) if (st.st_dev, st.st_ino) == store => return Err(in_store()),
            _ if pending.is_empty() => {
                return Ok(Located {
                    base: top,
                    rel: PathBuf::from(name),
                    checked: true,
                });
            }
            None => return Err(io::ErrorKind::NotFound.into()),
            Some(_) => {
                let fd = rustix::fs::openat(&*top, &name, dir_flags, Mode::empty())?;
                let at = key(&fd)?;
                if at == store {
                    return Err(in_store());
                }
                keys.push(at);
                top = Arc::new(Dir::from_std_file(std::fs::File::from(fd)));
            }
        }
    }
    Ok(Located {
        base: top,
        rel: PathBuf::from("."),
        checked: true,
    })
}

/// Runs in [`resolve`] before it goes up a directory.
#[cfg(all(test, target_os = "linux"))]
pub(crate) static BEFORE_PARENT: std::sync::Mutex<Option<Box<dyn Fn() + Send>>> =
    std::sync::Mutex::new(None);

#[cfg(all(test, target_os = "linux"))]
fn lock_hook() -> std::sync::MutexGuard<'static, Option<Box<dyn Fn() + Send>>> {
    BEFORE_PARENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// True if `name` is `hidden` under the case rule `case_sensitive`.
#[cfg(target_os = "linux")]
fn is_hidden(name: &str, hidden: &str, case_sensitive: bool) -> bool {
    name == hidden || (!case_sensitive && name.to_lowercase() == hidden.to_lowercase())
}

// ---------------------------------------------------------------------------
// Path translation
// ---------------------------------------------------------------------------

/// Convert a validated `SmbPath` into a relative `PathBuf` suitable for
/// `cap_std::fs::Dir` lookups.
///
/// `SmbPath` is already validated (no `..`, no forbidden chars, no doubled
/// separators), so this is purely a join. The empty `SmbPath` (root) yields
/// `PathBuf::from(".")`, which cap-std accepts for `metadata` etc.
pub(super) fn to_rel_path(path: &SmbPath) -> PathBuf {
    if path.is_root() {
        return PathBuf::from(".");
    }
    let mut out = PathBuf::new();
    for c in path.components() {
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

pub(super) fn io_to_smb(err: io::Error) -> SmbError {
    use io::ErrorKind::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if err.get_ref().is_some_and(|inner| inner.is::<Special>()) {
        return SmbError::SpecialFile;
    }
    #[cfg(windows)]
    {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        if err.raw_os_error() == Some(ERROR_SHARING_VIOLATION) {
            return SmbError::Sharing;
        }
    }
    match err.kind() {
        NotFound => SmbError::NotFound,
        PermissionDenied => SmbError::AccessDenied,
        AlreadyExists => SmbError::Exists,
        DirectoryNotEmpty => SmbError::NotEmpty,
        IsADirectory => SmbError::IsDirectory,
        NotADirectory => SmbError::NotADirectory,
        InvalidInput | InvalidFilename => SmbError::NameInvalid,
        CrossesDevices => SmbError::NotSameDevice,
        StorageFull => SmbError::DiskFull,
        QuotaExceeded => SmbError::QuotaExceeded,
        _ => SmbError::Io(err),
    }
}

/// Convert a `spawn_blocking` join error (panic or cancellation) into
/// `io::ErrorKind::Other`.
pub(super) fn join_to_io(_e: tokio::task::JoinError) -> io::Error {
    io::Error::other("blocking task panicked or was cancelled")
}

// ---------------------------------------------------------------------------
// Host-specific file access
// ---------------------------------------------------------------------------

// On Windows these also move the file cursor, which nothing here reads.

fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}

fn write_at(file: &std::fs::File, data: &[u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_at(file, data, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_write(file, data, offset)
    }
}

/// Host identity of a file: device and inode number on Unix, volume serial
/// number and file index on Windows. `None` if `md` does not carry it.
pub(super) fn file_key(md: &Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        Some((md.dev(), md.ino()))
    }
    #[cfg(windows)]
    {
        // The hidden trait returns `None` where `cap_fs_ext::MetadataExt` panics on scan metadata.
        use cap_primitives::fs::_WindowsByHandle;
        let volume = _WindowsByHandle::volume_serial_number(md)?;
        let index = _WindowsByHandle::file_index(md)?;
        Some((volume.into(), index))
    }
}

/// File id for a file with host identity `key`. Files on the share root's
/// device report the inode (file index on Windows). Files on other mounts
/// below the root have their device mixed into the id, so equal inodes on
/// different devices give different ids.
pub(super) fn file_index(root_dev: Option<u64>, key: Option<(u64, u64)>) -> u64 {
    let Some((dev, ino)) = key else {
        return 0;
    };
    if root_dev.is_none_or(|root| root == dev) {
        return ino;
    }
    // splitmix64 finalizer: spreads the device over all 64 bits.
    let mut x = dev;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ino ^ x ^ (x >> 31)
}

/// Number of hard links to a file. `None` if `md` does not carry it.
pub(super) fn link_count(md: &Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        Some(md.nlink())
    }
    #[cfg(windows)]
    {
        cap_primitives::fs::_WindowsByHandle::number_of_links(md).map(u64::from)
    }
}

/// Whether an entry, given its metadata read without following a final
/// symlink, is a directory to the host and is deleted with `remove_dir`. On
/// Unix that holds for directories only; a symlink to a directory is a plain
/// link. On Windows it holds for anything with the directory attribute,
/// which includes directory symlinks and junctions.
fn is_dir_entry(md: &Metadata) -> bool {
    #[cfg(unix)]
    {
        md.is_dir()
    }
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        cap_std::fs::MetadataExt::file_attributes(md) & FILE_ATTRIBUTE_DIRECTORY != 0
    }
}

/// Metadata for a directory listing entry, carrying the host file id. On
/// Windows, `DirEntry::metadata` comes from the directory scan and has no
/// file index, so the entry is opened for it, falling back to the scan data
/// when the open fails.
#[cfg_attr(unix, expect(unused_variables, reason = "dir is used on Windows only"))]
fn entry_metadata(dir: &Dir, entry: &cap_std::fs::DirEntry) -> io::Result<Metadata> {
    #[cfg(unix)]
    {
        entry.metadata()
    }
    #[cfg(windows)]
    {
        dir.symlink_metadata(entry.file_name())
            .or_else(|_| entry.metadata())
    }
}

/// Opens the directory `rel` below `root`. On Windows the handle shares
/// delete access, which `Dir::open_dir` leaves out, and has
/// `FILE_WRITE_ATTRIBUTES` when `write_attributes` is set.
#[cfg_attr(
    unix,
    expect(unused_variables, reason = "write_attributes is used on Windows only")
)]
fn open_dir_handle(root: &Dir, rel: &Path, write_attributes: bool) -> io::Result<Dir> {
    #[cfg(unix)]
    {
        root.open_dir(rel)
    }
    #[cfg(windows)]
    {
        use cap_primitives::fs::OpenOptionsExt as _;
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        let mut opts = CapOpenOptions::new();
        opts.read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        if write_attributes {
            opts.access_mode(GENERIC_READ | FILE_WRITE_ATTRIBUTES);
        }
        let file = root.open_with(rel, &opts)?;
        if !file.metadata()?.is_dir() {
            return Err(io::ErrorKind::NotADirectory.into());
        }
        Ok(Dir::from_std_file(file.into_std()))
    }
}

/// A `File` on the same open directory, for setting its times. On Linux a
/// `Dir` holds an `O_PATH` descriptor, which cannot change times, so the
/// directory is opened again through it.
pub(super) fn dir_as_file(dir: &Dir) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        Ok(dir.open(".")?.into_std())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;
        Ok(dir.as_handle().try_clone_to_owned()?.into())
    }
}

/// Sets or clears the read-only state of an open file: a read-only file has
/// no write permission bits, and clearing it gives the owner write
/// permission back. A file already in that state is left alone, so a file
/// the server can write but does not own takes the other attributes.
#[cfg(unix)]
fn set_read_only(file: &std::fs::File, read_only: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = file.metadata()?.permissions();
    let mode = perms.mode();
    let wanted = if read_only {
        mode & !0o222
    } else {
        mode | 0o200
    };
    if wanted == mode {
        return Ok(());
    }
    perms.set_mode(wanted);
    file.set_permissions(perms)
}

/// Gives the file or directory `file` is open on the attributes
/// `attributes` (MS-FSCC 2.6). Windows stores them as the host's
/// attributes; a handle opened without FILE_WRITE_ATTRIBUTES sets them
/// through a second handle that has only that access. Other hosts store
/// READONLY on a file and ignore the rest.
#[cfg_attr(
    windows,
    expect(unused_variables, reason = "is_dir is used on Unix only")
)]
pub(super) fn set_host_attributes(
    file: &std::fs::File,
    attributes: u32,
    is_dir: bool,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        if is_dir {
            return Ok(());
        }
        set_read_only(
            file,
            attributes & crate::backend::FILE_ATTRIBUTE_READONLY != 0,
        )
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO, FILE_WRITE_ATTRIBUTES, FileBasicInfo,
            SetFileInformationByHandle,
        };
        // 0 leaves a time unchanged, and attributes of 0 would too, so no
        // attributes are sent as FILE_ATTRIBUTE_NORMAL.
        let info = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: if attributes == 0 {
                FILE_ATTRIBUTE_NORMAL
            } else {
                attributes
            },
        };
        let set = |file: &std::fs::File| {
            // SAFETY: `info` is a live local of the size passed, and the
            // handle stays open for the call.
            let ok = unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle() as HANDLE,
                    FileBasicInfo,
                    (&raw const info).cast(),
                    std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                )
            };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        match set(file) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                set(&super::windows_eas::reopen(file, FILE_WRITE_ATTRIBUTES)?)
            }
            result => result,
        }
    }
}

/// Host times for `times`. The change time is left to the host. Hosts other
/// than Windows and macOS have no call that sets the creation time, so it is
/// ignored there, as is a time the host's clock cannot hold.
pub(super) fn host_file_times(times: FileTimes) -> std::fs::FileTimes {
    let host_time = |ft: Option<u64>| ft.and_then(filetime_to_system_time);
    let mut out = std::fs::FileTimes::new();
    if let Some(t) = host_time(times.last_write_time) {
        out = out.set_modified(t);
    }
    if let Some(t) = host_time(times.last_access_time) {
        out = out.set_accessed(t);
    }
    #[cfg(any(windows, target_os = "macos"))]
    if let Some(t) = host_time(times.creation_time) {
        out = set_created(out, t);
    }
    out
}

#[cfg(windows)]
fn set_created(times: std::fs::FileTimes, t: SystemTime) -> std::fs::FileTimes {
    use std::os::windows::fs::FileTimesExt as _;
    times.set_created(t)
}

#[cfg(target_os = "macos")]
fn set_created(times: std::fs::FileTimes, t: SystemTime) -> std::fs::FileTimes {
    use std::os::macos::fs::FileTimesExt as _;
    times.set_created(t)
}

// ---------------------------------------------------------------------------
// FILETIME conversion
// ---------------------------------------------------------------------------

/// The host time of the FILETIME `ft`, before 1970 too; `None` where the
/// host's clock cannot hold it.
fn filetime_to_system_time(ft: u64) -> Option<SystemTime> {
    let ticks = |n: u64| Duration::new(n / 10_000_000, (n % 10_000_000) as u32 * 100);
    match ft.checked_sub(FILETIME_OFFSET) {
        Some(after) => UNIX_EPOCH.checked_add(ticks(after)),
        None => UNIX_EPOCH.checked_sub(ticks(FILETIME_OFFSET - ft)),
    }
}

// ---------------------------------------------------------------------------
// FileInfo construction
// ---------------------------------------------------------------------------

pub(super) fn file_info_from_metadata(
    name: String,
    md: &Metadata,
    root_dev: Option<u64>,
) -> FileInfo {
    // Unix hosts report the size of a directory's index; clients expect 0.
    let len = if md.is_dir() { 0 } else { md.len() };
    let modified = md.modified().ok().map(|t| t.into_std());
    let accessed = md.accessed().ok().map(|t| t.into_std());
    let created = md.created().ok().map(|t| t.into_std());

    // A missing timestamp falls back to another available one, then to the
    // UNIX epoch.
    let modified = modified
        .or(created)
        .or(accessed)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let accessed = accessed.unwrap_or(modified);
    let created = created.unwrap_or(modified);

    FileInfo {
        name,
        end_of_file: len,
        allocation_size: len,
        creation_time: system_time_to_filetime(created),
        last_access_time: system_time_to_filetime(accessed),
        last_write_time: system_time_to_filetime(modified),
        change_time: system_time_to_filetime(modified),
        is_directory: md.is_dir(),
        // On Unix a directory reports no READONLY.
        read_only: (cfg!(windows) || !md.is_dir()) && md.permissions().readonly(),
        file_index: file_index(root_dev, file_key(md)),
        unix_mode: unix_mode(md),
        ea_size: 0,
        file_attributes: host_attributes(md),
    }
}

/// The attributes the host stores for the file of `md`: those of Windows,
/// none elsewhere.
fn host_attributes(md: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        let _ = md;
        0
    }
    #[cfg(windows)]
    {
        cap_std::fs::MetadataExt::file_attributes(md)
    }
}

/// The POSIX mode of `md`, on hosts that have one.
fn unix_mode(md: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        Some(md.mode())
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

// ---------------------------------------------------------------------------
// Directory listing
// ---------------------------------------------------------------------------

/// Entries of `dir` whose names match `pattern`, every entry for `None`.
/// Names a client could not open again are left out, and entries that
/// resolve to the object with the host identity `hidden`. With `eas`, each
/// entry carries the size of its extended attributes.
#[cfg_attr(
    not(any(target_os = "linux", windows)),
    expect(
        unused_variables,
        reason = "only Linux and Windows list extended attributes"
    )
)]
fn list_entries(
    dir: &Dir,
    pattern: Option<&str>,
    root_dev: Option<u64>,
    hidden: Option<(u64, u64)>,
    eas: bool,
) -> io::Result<Vec<SmbDirEntry>> {
    let pattern = pattern.filter(|p| !matches!(*p, "" | "*" | "*.*"));
    #[cfg(windows)]
    let ea_sizes = if eas {
        super::windows_eas::listing_sizes(dir, pattern).unwrap_or_else(|e| {
            debug!(error = %e, "extended attribute sizes not listed");
            Default::default()
        })
    } else {
        Default::default()
    };
    let pattern = pattern.map(|p| Pattern::new(p, !volume::is_case_sensitive(dir)));
    let mut out = Vec::new();
    for entry in dir.entries()? {
        let entry = entry?;
        let os_name = entry.file_name();
        if os_name == "." || os_name == ".." {
            continue;
        }
        let Some(name) = os_name.to_str().filter(|n| is_valid_component(n)) else {
            debug!(name = ?os_name, "listing leaves out a name clients cannot open");
            continue;
        };
        if pattern.as_ref().is_some_and(|p| !p.matches(name)) {
            continue;
        }
        let md = match listed_metadata(dir, &entry) {
            Ok(md) => md,
            // Removed since the directory was read.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if hidden.is_some() && file_key(&md) == hidden {
            continue;
        }
        #[cfg_attr(
            not(any(target_os = "linux", windows)),
            expect(unused_mut, reason = "only Linux and Windows list extended attributes")
        )]
        let mut info = file_info_from_metadata(name.to_owned(), &md, root_dev);
        #[cfg(target_os = "linux")]
        if eas {
            info.ea_size = listed_ea_size(dir, &entry, name, &md);
        }
        #[cfg(windows)]
        if eas {
            info.ea_size = match ea_sizes.get(name) {
                Some(Some(size)) => *size,
                Some(None) => super::windows_eas::entry_size(dir, name).unwrap_or_else(|e| {
                    debug!(error = %e, name, "extended attribute size not read");
                    0
                }),
                None => 0,
            };
        }
        out.push(SmbDirEntry { info });
    }
    Ok(out)
}

/// [`FileInfo::ea_size`] of a listed entry with metadata `md`, as an open
/// of its name sees it; 0 when it cannot be read.
#[cfg(target_os = "linux")]
fn listed_ea_size(dir: &Dir, entry: &cap_std::fs::DirEntry, name: &str, md: &Metadata) -> u32 {
    use super::eas::{Source, size};
    if !md.is_file() && !md.is_dir() {
        return 0;
    }
    let sized = if entry.file_type().is_ok_and(|ty| ty.is_symlink()) {
        // The target, opened without reading it, inside the share.
        use cap_std::fs::OpenOptionsExt as _;
        let mut opts = CapOpenOptions::new();
        opts.read(true).custom_flags(libc::O_PATH);
        dir.open_with(name, &opts).and_then(|target| {
            let md = target.metadata()?;
            if md.is_file() || md.is_dir() {
                size(&Source::fd(&target))
            } else {
                Ok(0)
            }
        })
    } else {
        size(&Source::entry(dir, name))
    };
    sized.unwrap_or_else(|e| {
        debug!(error = %e, name, "extended attribute size not read");
        0
    })
}

/// Metadata of a listed entry as an open of its name sees it: a symlink
/// reports its target, or itself when the target cannot be reached inside
/// the share.
fn listed_metadata(dir: &Dir, entry: &cap_std::fs::DirEntry) -> io::Result<Metadata> {
    if entry.file_type()?.is_symlink()
        && let Ok(md) = dir.metadata(entry.file_name())
    {
        return Ok(md);
    }
    entry_metadata(dir, entry)
}

/// [`FileInfo::ea_size`] of the file `file` is open on, 0 when it cannot
/// be read: a stat does not fail on it.
fn host_ea_size(file: &std::fs::File) -> u32 {
    #[cfg(target_os = "linux")]
    let size = super::eas::size(&super::eas::Source::File(file));
    #[cfg(windows)]
    let size = super::windows_eas::size(file);
    #[cfg(not(any(target_os = "linux", windows)))]
    let size: io::Result<u32> = {
        let _ = file;
        Ok(0)
    };
    best_effort(size)
}

/// [`FileInfo::ea_size`] of the directory `dir` is open on, 0 when it
/// cannot be read. On Linux it is read through the descriptor's path, so a
/// directory the server may only traverse costs no open.
fn dir_ea_size(dir: &Dir) -> u32 {
    #[cfg(target_os = "linux")]
    let size = super::eas::size(&super::eas::Source::fd(dir));
    #[cfg(windows)]
    let size = dir_as_file(dir).and_then(|file| super::windows_eas::size(&file));
    #[cfg(not(any(target_os = "linux", windows)))]
    let size: io::Result<u32> = {
        let _ = dir;
        Ok(0)
    };
    best_effort(size)
}

fn best_effort(size: io::Result<u32>) -> u32 {
    size.unwrap_or_else(|e| {
        debug!(error = %e, "extended attribute size not read");
        0
    })
}

/// The extended attributes of the file or directory `file` is open on.
fn host_eas(file: &std::fs::File) -> io::Result<Vec<crate::Ea>> {
    #[cfg(target_os = "linux")]
    {
        super::eas::list(file)
    }
    #[cfg(windows)]
    {
        super::windows_eas::list(file)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = file;
        Ok(Vec::new())
    }
}

/// Changes the extended attributes of the file or directory `file` is open
/// on, as [`Handle::set_eas`] does. On Linux, the lock of the file among
/// `open` is held throughout, as for every change of its named streams.
#[cfg_attr(
    not(target_os = "linux"),
    expect(unused_variables, reason = "only Linux shares a lock with the streams")
)]
fn host_set_eas(
    file: &std::fs::File,
    eas: &[crate::Ea],
    open: Option<&Arc<OpenStreamsOf>>,
) -> SmbResult<()> {
    #[cfg(target_os = "linux")]
    {
        let entry = match open {
            Some(open) => {
                let md = Metadata::from_file(file).map_err(io_to_smb)?;
                let key = file_key(&md).ok_or(SmbError::NotSupported)?;
                Some(open.file(key))
            }
            None => None,
        };
        let _locked = entry
            .as_ref()
            .map(|entry| super::open_streams::lock(&entry.open));
        super::eas::set(file, eas)
    }
    #[cfg(windows)]
    {
        super::windows_eas::set(file, eas)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (file, eas);
        Err(SmbError::NotSupported)
    }
}

/// The named streams open through a backend, whose per-file lock changes of
/// extended attributes take on Linux.
#[cfg(target_os = "linux")]
type OpenStreamsOf = super::open_streams::OpenStreams;
#[cfg(not(target_os = "linux"))]
type OpenStreamsOf = ();

/// What the extended attribute calls of a handle work on.
enum EaTarget {
    File(Arc<std::fs::File>),
    Dir(Arc<Dir>),
}

impl EaTarget {
    /// A file handle on it; a directory is opened again for one.
    fn file(&self) -> io::Result<Arc<std::fs::File>> {
        match self {
            EaTarget::File(file) => Ok(Arc::clone(file)),
            EaTarget::Dir(dir) => dir_as_file(dir).map(Arc::new),
        }
    }
}

/// True if `dir` has no entries besides `.` and `..`.
fn dir_is_empty(dir: &Dir) -> io::Result<bool> {
    for entry in dir.entries()? {
        let name = entry?.file_name();
        if name != "." && name != ".." {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// ShareBackend impl
// ---------------------------------------------------------------------------

impl LocalFsBackend {
    /// True if a directory on the way to `path` is missing or is not a
    /// directory.
    async fn parent_missing(&self, path: &SmbPath) -> bool {
        let Some(parent) = path.parent().filter(|p| !p.is_root()) else {
            return false;
        };
        let rel = to_rel_path(&parent);
        let root = Arc::clone(&self.root);
        spawn_blocking(move || !root.metadata(&rel).is_ok_and(|md| md.is_dir()))
            .await
            .unwrap_or(false)
    }

    async fn open_entry(
        &self,
        path: &SmbPath,
        located: Located,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        // 1. Read-only check: any open that requests creation, write access,
        //    truncation, or overwrite is rejected up front. Pure read opens
        //    pass through.
        if self.read_only && writes(&opts) {
            return Err(SmbError::AccessDenied);
        }

        let root = Arc::clone(&located.base);
        let rel = located.rel.clone();
        let read_only = self.read_only;
        let directory = opts.directory;
        let non_directory = opts.non_directory;
        let write_attributes = opts.write_attributes;

        let existing = {
            let root = Arc::clone(&root);
            let rel = rel.clone();
            spawn_blocking(move || -> io::Result<Option<cap_std::fs::FileType>> {
                match root.metadata(&rel) {
                    Ok(md) => Ok(Some(md.file_type())),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)?
        };
        if existing.is_some_and(|ty| is_special(&ty)) {
            return Err(SmbError::SpecialFile);
        }

        if directory {
            // Directory CREATE intents: Create / OpenOrCreate / OverwriteOrCreate
            // imply mkdir; Open / Truncate require existing.
            let intent = opts.intent;
            let located = located.clone();
            let (dir_handle, action) = spawn_blocking(move || -> io::Result<(Dir, OpenAction)> {
                let action = match intent {
                    OpenIntent::Open => OpenAction::Opened,
                    OpenIntent::Create => {
                        root.create_dir(&rel)?;
                        OpenAction::Created
                    }
                    OpenIntent::OpenOrCreate => match root.create_dir(&rel) {
                        Ok(()) => OpenAction::Created,
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => OpenAction::Opened,
                        Err(e) => return Err(e),
                    },
                    OpenIntent::Truncate | OpenIntent::OverwriteOrCreate => {
                        // Truncating a directory has no meaning; reject.
                        return Err(io::Error::from(io::ErrorKind::InvalidInput));
                    }
                };
                let dir = open_dir_handle(&root, &rel, write_attributes)?;
                located.verify(&dir)?;
                Ok((dir, action))
            })
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)?;

            let handle: Box<dyn Handle> = Box::new(LocalHandle::Dir {
                name: file_name_for(path),
                root_dev: self.root_dev,
                dir_handle: Arc::new(dir_handle),
                read_only,
                eas: self.eas,
                #[cfg(target_os = "linux")]
                open: self.streams.clone(),
                #[cfg(target_os = "linux")]
                hub: self.hub.clone(),
                #[cfg(target_os = "linux")]
                store: self.store.clone(),
            });
            return Ok((handle, action));
        }

        if existing.is_some_and(|ty| ty.is_dir()) {
            if non_directory {
                return Err(SmbError::IsDirectory);
            }
            match opts.intent {
                OpenIntent::Open | OpenIntent::OpenOrCreate => {
                    let root = Arc::clone(&root);
                    let rel = rel.clone();
                    let located = located.clone();
                    let dir_handle = spawn_blocking(move || {
                        let dir = open_dir_handle(&root, &rel, write_attributes)?;
                        located.verify(&dir)?;
                        Ok::<_, io::Error>(dir)
                    })
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)?;
                    let handle: Box<dyn Handle> = Box::new(LocalHandle::Dir {
                        name: file_name_for(path),
                        root_dev: self.root_dev,
                        dir_handle: Arc::new(dir_handle),
                        read_only,
                        eas: self.eas,
                        #[cfg(target_os = "linux")]
                        open: self.streams.clone(),
                        #[cfg(target_os = "linux")]
                        hub: self.hub.clone(),
                        #[cfg(target_os = "linux")]
                        store: self.store.clone(),
                    });
                    return Ok((handle, OpenAction::Opened));
                }
                OpenIntent::Create => return Err(SmbError::Exists),
                OpenIntent::Truncate | OpenIntent::OverwriteOrCreate => {
                    return Err(SmbError::IsDirectory);
                }
            }
        }

        // 2. Open the file for the intent.
        let (std_file, action) = spawn_blocking(move || {
            #[cfg(target_os = "linux")]
            if located.checked {
                let (file, action) = open_file_nofollow(&root, &rel, opts)?;
                located.verify(&file)?;
                return Ok((file, action));
            }
            let (file, action) = open_file(&root, &rel, opts)?;
            located.verify(&file)?;
            Ok::<_, io::Error>((file.into_std(), action))
        })
        .await
        .map_err(join_to_io)
        .map_err(io_to_smb)?
        .map_err(open_to_smb)?;

        let handle: Box<dyn Handle> = Box::new(LocalHandle::File {
            name: file_name_for(path),
            root_dev: self.root_dev,
            file: Arc::new(std_file),
            read_only,
            eas: self.eas,
            #[cfg(target_os = "linux")]
            open: self.streams.clone(),
            #[cfg(target_os = "linux")]
            store: self.store.clone(),
        });
        Ok((handle, action))
    }
}

/// True for a FIFO, a socket or a device node. Opening one can block or
/// act on a device, so such entries are refused before any open.
fn is_special(ty: &cap_std::fs::FileType) -> bool {
    #[cfg(unix)]
    {
        use cap_std::fs::FileTypeExt as _;
        ty.is_fifo() || ty.is_socket() || ty.is_char_device() || ty.is_block_device()
    }
    #[cfg(windows)]
    {
        let _ = ty;
        false
    }
}

/// Fails as changed unless `fd` is open on a regular file, as a name
/// replaced since it was checked may not be, then clears the O_NONBLOCK
/// the open used, so reads and writes of the file block as usual.
#[cfg(unix)]
fn check_regular_and_clear_nonblock(fd: &impl std::os::fd::AsFd) -> io::Result<()> {
    use rustix::fs::{FileType, OFlags};
    if FileType::from_raw_mode(rustix::fs::fstat(fd)?.st_mode) != FileType::RegularFile {
        return Err(changed());
    }
    let flags = rustix::fs::fcntl_getfl(fd)?;
    rustix::fs::fcntl_setfl(fd, flags.difference(OFlags::NONBLOCK))?;
    Ok(())
}

/// The error of a file open. On Linux an open that a file lease of another
/// process conflicts with fails with EWOULDBLOCK, as the open does not
/// block, after the kernel has started breaking the lease; it becomes a
/// sharing violation, which clients retry.
fn open_to_smb(e: io::Error) -> SmbError {
    #[cfg(target_os = "linux")]
    if e.kind() == io::ErrorKind::WouldBlock {
        return SmbError::Sharing;
    }
    io_to_smb(e)
}

/// Opens `rel` below `root` with `options`. On Unix an open that fails on a
/// name a FIFO, a socket or a device node took since it was checked fails
/// as changed, so the open is looked at again.
#[cfg(unix)]
fn open_with(root: &Dir, rel: &Path, options: &CapOpenOptions) -> io::Result<cap_std::fs::File> {
    root.open_with(rel, options).map_err(|e| {
        if root
            .metadata(rel)
            .is_ok_and(|md| is_special(&md.file_type()))
        {
            changed()
        } else {
            e
        }
    })
}

#[cfg(windows)]
fn open_with(root: &Dir, rel: &Path, options: &CapOpenOptions) -> io::Result<cap_std::fs::File> {
    root.open_with(rel, options)
}

/// True if `name` in `dir`, not following a final symlink, is a FIFO, a
/// socket or a device node.
#[cfg(target_os = "linux")]
fn special_at(dir: &Dir, name: &Path) -> bool {
    use rustix::fs::{AtFlags, FileType};
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|st| {
        matches!(
            FileType::from_raw_mode(st.st_mode),
            FileType::Fifo | FileType::Socket | FileType::CharacterDevice | FileType::BlockDevice
        )
    })
}

/// True if an open with `opts` may change the file: it asks for write
/// access, or its disposition may create or truncate.
fn writes(opts: &OpenOptions) -> bool {
    opts.write || opts.write_attributes || opts.intent != OpenIntent::Open
}

/// Opens the file `rel` below `root` for `opts.intent`. OPEN_IF opens an
/// existing file with the access `opts` asks for, so a read-only file opens
/// for reading.
fn open_file(
    root: &Dir,
    rel: &Path,
    opts: OpenOptions,
) -> io::Result<(cap_std::fs::File, OpenAction)> {
    let existing = existing_file_options(&opts);
    let mut created = CapOpenOptions::new();
    created.read(opts.read).write(true).create_new(true);
    let mut truncated = CapOpenOptions::new();
    truncated.read(opts.read).write(true);
    // Windows refuses to truncate a HIDDEN or SYSTEM file as it opens it;
    // the file is emptied once open instead.
    #[cfg(unix)]
    truncated.truncate(true);
    #[cfg(unix)]
    for options in [&mut created, &mut truncated] {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let not_found = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
    let exists = |e: &io::Error| e.kind() == io::ErrorKind::AlreadyExists;
    let (file, action) = match opts.intent {
        OpenIntent::Open => (open_with(root, rel, &existing)?, OpenAction::Opened),
        OpenIntent::Create => (open_with(root, rel, &created)?, OpenAction::Created),
        OpenIntent::Truncate => (open_with(root, rel, &truncated)?, OpenAction::Overwritten),
        // The file can appear or vanish between the two calls, so each pair
        // is tried a second time.
        OpenIntent::OpenOrCreate => {
            let mut attempt = 0;
            loop {
                attempt += 1;
                match open_with(root, rel, &existing) {
                    Ok(f) => break (f, OpenAction::Opened),
                    Err(e) if not_found(&e) => {}
                    Err(e) => return Err(e),
                }
                match open_with(root, rel, &created) {
                    Ok(f) => break (f, OpenAction::Created),
                    Err(e) if exists(&e) && attempt < 2 => {}
                    Err(e) => return Err(e),
                }
            }
        }
        OpenIntent::OverwriteOrCreate => {
            let mut attempt = 0;
            loop {
                attempt += 1;
                match open_with(root, rel, &created) {
                    Ok(f) => break (f, OpenAction::Created),
                    Err(e) if exists(&e) => {}
                    Err(e) => return Err(e),
                }
                match open_with(root, rel, &truncated) {
                    Ok(f) => break (f, OpenAction::Overwritten),
                    Err(e) if not_found(&e) && attempt < 2 => {}
                    Err(e) => return Err(e),
                }
            }
        }
    };
    #[cfg(unix)]
    check_regular_and_clear_nonblock(&file)?;
    #[cfg(windows)]
    if action == OpenAction::Overwritten {
        file.set_len(0)?;
    }
    Ok((file, action))
}

/// Opens the file `name` in `dir` for `opts.intent`, as [`open_file`]
/// does, without following a symlink: a name that became one since it was
/// looked up fails as changed, before anything is truncated.
#[cfg(target_os = "linux")]
fn open_file_nofollow(
    dir: &Dir,
    name: &Path,
    opts: OpenOptions,
) -> io::Result<(std::fs::File, OpenAction)> {
    use rustix::fs::{Mode, OFlags};

    let base = OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY;
    let access = |write: bool| match (opts.read, write) {
        (true, true) => OFlags::RDWR,
        (false, true) => OFlags::WRONLY,
        _ => OFlags::RDONLY,
    };
    let existing = base
        | if opts.write {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        };
    let created = base | access(true) | OFlags::CREATE | OFlags::EXCL;
    let truncated = base | access(true) | OFlags::TRUNC;
    let open = |flags: OFlags| -> io::Result<std::fs::File> {
        match rustix::fs::openat(dir, name, flags, Mode::from_raw_mode(0o666)) {
            Ok(fd) => Ok(std::fs::File::from(fd)),
            Err(rustix::io::Errno::LOOP) => Err(changed()),
            Err(_) if special_at(dir, name) => Err(changed()),
            Err(e) => Err(e.into()),
        }
    };
    let not_found = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
    let exists = |e: &io::Error| e.kind() == io::ErrorKind::AlreadyExists;
    let (file, action) = match opts.intent {
        OpenIntent::Open => (open(existing)?, OpenAction::Opened),
        OpenIntent::Create => (open(created)?, OpenAction::Created),
        OpenIntent::Truncate => (open(truncated)?, OpenAction::Overwritten),
        // The file can appear or vanish between the two calls, so each pair
        // is tried a second time.
        OpenIntent::OpenOrCreate => {
            let mut attempt = 0;
            loop {
                attempt += 1;
                match open(existing) {
                    Ok(f) => break (f, OpenAction::Opened),
                    Err(e) if not_found(&e) => {}
                    Err(e) => return Err(e),
                }
                match open(created) {
                    Ok(f) => break (f, OpenAction::Created),
                    Err(e) if exists(&e) && attempt < 2 => {}
                    Err(e) => return Err(e),
                }
            }
        }
        OpenIntent::OverwriteOrCreate => {
            let mut attempt = 0;
            loop {
                attempt += 1;
                match open(created) {
                    Ok(f) => break (f, OpenAction::Created),
                    Err(e) if exists(&e) => {}
                    Err(e) => return Err(e),
                }
                match open(truncated) {
                    Ok(f) => break (f, OpenAction::Overwritten),
                    Err(e) if not_found(&e) && attempt < 2 => {}
                    Err(e) => return Err(e),
                }
            }
        }
    };
    check_regular_and_clear_nonblock(&file)?;
    Ok((file, action))
}

/// cap-std options that open an existing file with the access `opts` asks
/// for, and on Unix without blocking.
fn existing_file_options(opts: &OpenOptions) -> CapOpenOptions {
    let mut cap_opts = CapOpenOptions::new();
    cap_opts.read(true).write(opts.write);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        cap_opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    // Unix sets times and permissions through a read-only descriptor.
    // Windows needs the access right, which a read-only file grants without
    // write access.
    #[cfg(windows)]
    if opts.write_attributes && !opts.write {
        use cap_primitives::fs::OpenOptionsExt as _;
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
        cap_opts.access_mode(GENERIC_READ | FILE_WRITE_ATTRIBUTES);
    }
    cap_opts
}

#[async_trait]
impl ShareBackend for LocalFsBackend {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let refused = match opts.intent {
            OpenIntent::Open | OpenIntent::Truncate => SmbError::NotFound,
            _ => SmbError::AccessDenied,
        };
        if self.reserves(path) {
            return Err(refused);
        }
        self.prepare_store().await;
        let mut tries = 0;
        let result = loop {
            let located = match self.locate_again(path, true).await {
                Ok(located) => located,
                Err(e) if is_in_store(&e) => return Err(refused),
                Err(e) => break Err(io_to_smb(e)),
            };
            #[cfg(test)]
            if let Some(f) = &self.after_locate {
                f();
            }
            match self.open_entry(path, located, opts).await {
                // The last name changed after it was looked up.
                Err(SmbError::Io(e)) if is_changed(&e) && tries == 0 => tries += 1,
                Err(SmbError::Io(e)) if is_changed(&e) => break Err(SmbError::NotFound),
                result => break result,
            }
        };
        if matches!(result, Err(SmbError::NotFound | SmbError::NotADirectory))
            && self.parent_missing(path).await
        {
            return Err(SmbError::PathNotFound);
        }
        result
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        if path.is_root() {
            // Refusing to delete the share root itself.
            return Err(SmbError::AccessDenied);
        }
        if self.reserves(path) {
            return Err(SmbError::NotFound);
        }
        self.prepare_store().await;
        let located = match self.locate_again(path, false).await {
            Ok(located) => located,
            Err(e) if is_in_store(&e) => return Err(SmbError::NotFound),
            Err(e) => return Err(io_to_smb(e)),
        };
        if located.checked && located.rel == Path::new(".") {
            return Err(SmbError::AccessDenied);
        }
        let Located {
            base: root, rel, ..
        } = located;

        spawn_blocking(move || -> io::Result<()> {
            // Pick the call from the entry itself: the error `remove_file`
            // returns for a directory differs between hosts. Neither call
            // follows a final symlink, so a link is removed as a link.
            if is_dir_entry(&root.symlink_metadata(&rel)?) {
                root.remove_dir(&rel)
            } else {
                root.remove_file(&rel)
            }
        })
        .await
        .map_err(join_to_io)
        .map_err(io_to_smb)?
        .map_err(io_to_smb)
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        if from.is_root() || to.is_root() {
            return Err(SmbError::NameInvalid);
        }
        if self.reserves(from) {
            return Err(SmbError::NotFound);
        }
        if self.reserves(to) {
            return Err(SmbError::AccessDenied);
        }
        self.prepare_store().await;
        let from_at = match self.locate_again(from, false).await {
            Ok(located) => located,
            Err(e) if is_in_store(&e) => return Err(SmbError::NotFound),
            Err(e) => return Err(io_to_smb(e)),
        };
        let to_at = match self.locate_again(to, false).await {
            Ok(located) => located,
            Err(e) if is_in_store(&e) => return Err(SmbError::AccessDenied),
            Err(e) if e.kind() == io::ErrorKind::NotFound && self.parent_missing(to).await => {
                return Err(SmbError::PathNotFound);
            }
            Err(e) => return Err(io_to_smb(e)),
        };
        let dot = Path::new(".");
        if (from_at.checked && from_at.rel == dot) || (to_at.checked && to_at.rel == dot) {
            return Err(SmbError::AccessDenied);
        }
        let same_name = same_path(from, to, self.capabilities().case_sensitive);
        let (root, from) = (from_at.base, from_at.rel);
        let (to_root, to_path) = (to_at.base, to_at.rel);

        let result = spawn_blocking(move || -> io::Result<()> {
            let from_md = root.symlink_metadata(&from)?;
            match to_root.symlink_metadata(&to_path) {
                Ok(to_md) => {
                    let from_key = file_key(&from_md);
                    let same_file = from_key.is_some() && from_key == file_key(&to_md);
                    // A target that is the source under the same name, such
                    // as a case-only rename on a case-insensitive host, is
                    // not a collision.
                    if !(same_file && same_name) {
                        if !replace_if_exists {
                            return Err(io::ErrorKind::AlreadyExists.into());
                        }
                        if is_dir_entry(&to_md) {
                            return Err(io::ErrorKind::PermissionDenied.into());
                        }
                    }
                    // The host leaves both names in place when renaming one
                    // hard link over another, so the source link is removed.
                    // A file with one link reached under two spellings is a
                    // single entry and goes through the rename.
                    if same_file && !same_name && link_count(&from_md) > Some(1) {
                        return root.remove_file(&from);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            root.rename(&from, &to_root, &to_path)
        })
        .await
        .map_err(join_to_io)
        .map_err(io_to_smb)?
        .map_err(io_to_smb);
        if matches!(result, Err(SmbError::NotFound | SmbError::NotADirectory))
            && self.parent_missing(to).await
        {
            return Err(SmbError::PathNotFound);
        }
        result
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: self.read_only,
            case_sensitive: self.case_sensitive,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            named_streams: self.streams.is_some(),
            #[cfg(windows)]
            named_streams: self.volume.is_some(),
            #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
            named_streams: false,
            extended_attributes: self.eas,
        }
    }

    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        let root = Arc::clone(&self.root);
        let root_dev = self.root_dev;
        spawn_blocking(move || volume::volume_info(&root, root_dev))
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    async fn open_stream(
        &self,
        file: Box<dyn Handle>,
        path: &SmbPath,
        stream: &StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let id = file.stat().await.map(|info| info.file_index);
        if let Err(e) = file.close().await {
            debug!(error = %e, path = %path, "backend close failed");
        }
        if self.read_only && writes(&opts) {
            return Err(SmbError::AccessDenied);
        }
        self.stream_place()?
            .open_stream(
                to_rel_path(path),
                file_name_for(path),
                id?,
                stream.clone(),
                opts,
            )
            .await
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    async fn remove_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        stream: &StreamName,
    ) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        self.stream_place()?
            .remove_stream(to_rel_path(path), file_index, stream.clone())
            .await
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    async fn rename_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        from: Option<&StreamName>,
        to: Option<&StreamName>,
        replace_if_exists: bool,
    ) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        self.stream_place()?
            .rename_stream(
                to_rel_path(path),
                file_index,
                from.cloned(),
                to.cloned(),
                replace_if_exists,
            )
            .await
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl LocalFsBackend {
    #[cfg(target_os = "linux")]
    fn stream_place(&self) -> SmbResult<super::streams::Place> {
        Ok(super::streams::Place {
            root: Arc::clone(&self.root),
            root_dev: self.root_dev,
            read_only: self.read_only,
            open: self.streams.clone().ok_or(SmbError::NotSupported)?,
            store: self.store.clone().ok_or(SmbError::NotSupported)?,
        })
    }

    #[cfg(target_os = "macos")]
    fn stream_place(&self) -> SmbResult<super::macos_streams::Place> {
        Ok(super::macos_streams::Place {
            root: Arc::clone(&self.root),
            root_dev: self.root_dev,
            read_only: self.read_only,
            open: self.streams.clone().ok_or(SmbError::NotSupported)?,
        })
    }

    #[cfg(windows)]
    fn stream_place(&self) -> SmbResult<super::windows_streams::Place> {
        Ok(super::windows_streams::Place {
            root: Arc::clone(&self.root),
            root_dev: self.root_dev,
            read_only: self.read_only,
            volume: self.volume.ok_or(SmbError::NotSupported)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Internal handle variant. `File` carries a `std::fs::File` (after cap-std
/// has done the safe open); `Dir` keeps the `cap_std::fs::Dir` for listing
/// and setting times.
enum LocalHandle {
    File {
        name: String,
        root_dev: Option<u64>,
        file: Arc<std::fs::File>,
        read_only: bool,
        /// The share stores extended attributes.
        eas: bool,
        /// The named streams open through the backend.
        #[cfg(target_os = "linux")]
        open: Option<Arc<super::open_streams::OpenStreams>>,
        #[cfg(target_os = "linux")]
        store: Option<Arc<super::streams::Store>>,
    },
    Dir {
        name: String,
        root_dev: Option<u64>,
        dir_handle: Arc<Dir>,
        read_only: bool,
        /// The share stores extended attributes.
        eas: bool,
        /// The named streams open through the backend.
        #[cfg(target_os = "linux")]
        open: Option<Arc<super::open_streams::OpenStreams>>,
        #[cfg(target_os = "linux")]
        hub: Option<Arc<super::inotify::Hub>>,
        #[cfg(target_os = "linux")]
        store: Option<Arc<super::streams::Store>>,
    },
}

impl LocalHandle {
    /// What the extended attribute calls work on; `NotSupported` when the
    /// share stores none.
    fn ea_target(&self) -> SmbResult<EaTarget> {
        match self {
            LocalHandle::File { eas: false, .. } | LocalHandle::Dir { eas: false, .. } => {
                Err(SmbError::NotSupported)
            }
            LocalHandle::File { file, .. } => Ok(EaTarget::File(Arc::clone(file))),
            LocalHandle::Dir { dir_handle, .. } => Ok(EaTarget::Dir(Arc::clone(dir_handle))),
        }
    }

    /// The named streams open through the backend, on Linux.
    fn open_streams(&self) -> Option<Arc<OpenStreamsOf>> {
        #[cfg(target_os = "linux")]
        {
            let (LocalHandle::File { open, .. } | LocalHandle::Dir { open, .. }) = self;
            open.clone()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// The stream store of the share, which listings leave out.
    #[cfg(target_os = "linux")]
    fn store(&self) -> Option<Arc<super::streams::Store>> {
        let (LocalHandle::File { store, .. } | LocalHandle::Dir { store, .. }) = self;
        store.clone()
    }
}

/// The changes of a watch, without those to entries named `hidden`.
#[cfg(target_os = "linux")]
struct Hiding {
    inner: Box<dyn crate::backend::DirWatch>,
    hidden: &'static str,
}

#[cfg(target_os = "linux")]
#[async_trait]
impl crate::backend::DirWatch for Hiding {
    async fn next(&mut self) -> Option<Vec<crate::backend::DirChange>> {
        use crate::backend::{DirChange, DirChangeKind};
        loop {
            let changes = self.inner.next().await?;
            let hidden = |name: &str| name == self.hidden;
            let kept: Vec<DirChange> = changes
                .into_iter()
                .filter_map(|change| match &change.kind {
                    DirChangeKind::Renamed { from } => match (hidden(from), hidden(&change.name)) {
                        (false, false) => Some(change),
                        (true, false) => Some(DirChange::new(
                            change.name,
                            DirChangeKind::Added,
                            change.is_directory,
                        )),
                        (false, true) => Some(DirChange::new(
                            from.clone(),
                            DirChangeKind::Removed,
                            change.is_directory,
                        )),
                        (true, true) => None,
                    },
                    _ if hidden(&change.name) => None,
                    _ => Some(change),
                })
                .collect();
            if !kept.is_empty() {
                return Some(kept);
            }
        }
    }
}

pub(super) fn file_name_for(path: &SmbPath) -> String {
    path.file_name().unwrap_or("").to_string()
}

#[async_trait]
impl Handle for LocalHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        match self {
            LocalHandle::File { file, .. } => {
                let file = Arc::clone(file);
                let n = len as usize;
                let bytes = spawn_blocking(move || -> io::Result<Bytes> {
                    let mut buf = vec![0u8; n];
                    let read = read_at(&file, &mut buf, offset)?;
                    buf.truncate(read);
                    Ok(Bytes::from(buf))
                })
                .await
                .map_err(join_to_io)
                .map_err(io_to_smb)?
                .map_err(io_to_smb)?;
                Ok(bytes)
            }
            LocalHandle::Dir { .. } => Err(SmbError::IsDirectory),
        }
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.write_owned(offset, data.to_vec()).await
    }

    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        match self {
            LocalHandle::File {
                file, read_only, ..
            } => {
                if *read_only {
                    return Err(SmbError::AccessDenied);
                }
                let file = Arc::clone(file);
                let written = spawn_blocking(move || write_at(&file, &data, offset))
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)?;
                Ok(u32::try_from(written).unwrap_or(u32::MAX))
            }
            LocalHandle::Dir { .. } => Err(SmbError::IsDirectory),
        }
    }

    async fn flush(&self) -> SmbResult<()> {
        match self {
            LocalHandle::File { file, .. } => {
                let file = Arc::clone(file);
                spawn_blocking(move || file.sync_data())
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)
            }
            // Flushing a directory is a no-op in SMB semantics.
            LocalHandle::Dir { .. } => Ok(()),
        }
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        match self {
            LocalHandle::File {
                file,
                name,
                root_dev,
                eas,
                ..
            } => {
                let file = Arc::clone(file);
                let name = name.clone();
                let (root_dev, eas) = (*root_dev, *eas);
                spawn_blocking(move || -> io::Result<FileInfo> {
                    let md = Metadata::from_file(&file)?;
                    let mut info = file_info_from_metadata(name, &md, root_dev);
                    if eas {
                        info.ea_size = host_ea_size(&file);
                    }
                    Ok(info)
                })
                .await
                .map_err(join_to_io)
                .map_err(io_to_smb)?
                .map_err(io_to_smb)
            }
            LocalHandle::Dir {
                dir_handle,
                name,
                root_dev,
                eas,
                ..
            } => {
                let dir_handle = Arc::clone(dir_handle);
                let name = name.clone();
                let (root_dev, eas) = (*root_dev, *eas);
                spawn_blocking(move || -> io::Result<FileInfo> {
                    let md = dir_handle.dir_metadata()?;
                    let mut info = file_info_from_metadata(name, &md, root_dev);
                    if eas {
                        info.ea_size = dir_ea_size(&dir_handle);
                    }
                    Ok(info)
                })
                .await
                .map_err(join_to_io)
                .map_err(io_to_smb)?
                .map_err(io_to_smb)
            }
        }
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        let host_times = host_file_times(times);
        match self {
            LocalHandle::File {
                file, read_only, ..
            } => {
                if *read_only {
                    return Err(SmbError::AccessDenied);
                }
                let file = Arc::clone(file);
                spawn_blocking(move || file.set_times(host_times))
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)
            }
            LocalHandle::Dir { dir_handle, .. } => {
                let dir_handle = Arc::clone(dir_handle);
                spawn_blocking(move || dir_as_file(&dir_handle)?.set_times(host_times))
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)
            }
        }
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        let set = match self {
            LocalHandle::File {
                file, read_only, ..
            } => {
                if *read_only {
                    return Err(SmbError::AccessDenied);
                }
                let file = Arc::clone(file);
                spawn_blocking(move || set_host_attributes(&file, attributes, false))
            }
            LocalHandle::Dir {
                dir_handle,
                read_only,
                ..
            } => {
                if *read_only {
                    return Err(SmbError::AccessDenied);
                }
                if cfg!(unix) {
                    return Ok(());
                }
                let dir_handle = Arc::clone(dir_handle);
                spawn_blocking(move || {
                    set_host_attributes(&dir_as_file(&dir_handle)?, attributes, true)
                })
            }
        };
        set.await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        match self {
            LocalHandle::File {
                file, read_only, ..
            } => {
                if *read_only {
                    return Err(SmbError::AccessDenied);
                }
                let file = Arc::clone(file);
                spawn_blocking(move || file.set_len(len))
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)
            }
            // Protocol layer rejects truncate on dir handles before this; if
            // it ever reaches us, surface as NotSupported.
            LocalHandle::Dir { .. } => Err(SmbError::NotSupported),
        }
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<SmbDirEntry>> {
        self.list_dir_sized(pattern, true).await
    }

    async fn list_dir_sized(
        &self,
        pattern: Option<&str>,
        ea_size: bool,
    ) -> SmbResult<Vec<SmbDirEntry>> {
        match self {
            LocalHandle::File { .. } => Err(SmbError::NotADirectory),
            LocalHandle::Dir {
                dir_handle,
                root_dev,
                eas,
                ..
            } => {
                let dir_handle = Arc::clone(dir_handle);
                let (root_dev, eas) = (*root_dev, *eas && ea_size);
                let pat = pattern.map(|s| s.to_owned());
                #[cfg(target_os = "linux")]
                let store = self.store();
                spawn_blocking(move || {
                    #[cfg(target_os = "linux")]
                    let hidden = store.and_then(|store| store.key());
                    #[cfg(not(target_os = "linux"))]
                    let hidden = None;
                    list_entries(&dir_handle, pat.as_deref(), root_dev, hidden, eas)
                })
                .await
                .map_err(join_to_io)
                .map_err(io_to_smb)?
                .map_err(io_to_smb)
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn watch(&self) -> SmbResult<Option<Box<dyn crate::backend::DirWatch>>> {
        match self {
            LocalHandle::Dir {
                dir_handle,
                hub: Some(hub),
                ..
            } => {
                let watch = hub.watch(&**dir_handle);
                let hidden = self.store().and_then(|store| store.hidden_in(dir_handle));
                Ok(match (watch, hidden) {
                    (Some(watch), Some(hidden)) => Some(Box::new(Hiding {
                        inner: watch,
                        hidden,
                    })),
                    (watch, _) => watch,
                })
            }
            _ => Ok(None),
        }
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        // Drop is sufficient: closing the underlying handle is what the OS
        // does when the last `Arc` ref goes away. No flush here: SMB CLOSE
        // does not imply fsync.
        Ok(())
    }

    /// The host link count of a file. A directory reports one link, as it
    /// has one name, or none once it has been removed.
    async fn link_count(&self) -> SmbResult<u32> {
        let md = match self {
            LocalHandle::File { file, .. } => {
                let file = Arc::clone(file);
                spawn_blocking(move || Metadata::from_file(&file)).await
            }
            LocalHandle::Dir { dir_handle, .. } => {
                let dir_handle = Arc::clone(dir_handle);
                spawn_blocking(move || dir_handle.dir_metadata()).await
            }
        }
        .map_err(join_to_io)
        .map_err(io_to_smb)?
        .map_err(io_to_smb)?;
        let links = link_count(&md).map_or(1, |n| u32::try_from(n).unwrap_or(u32::MAX));
        Ok(if md.is_dir() { links.min(1) } else { links })
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        match self {
            LocalHandle::File { .. } => Err(SmbError::NotADirectory),
            LocalHandle::Dir { dir_handle, .. } => {
                let dir_handle = Arc::clone(dir_handle);
                spawn_blocking(move || dir_is_empty(&dir_handle))
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)
            }
        }
    }

    async fn eas(&self) -> SmbResult<Vec<crate::Ea>> {
        let target = self.ea_target()?;
        spawn_blocking(move || host_eas(&*target.file()?))
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)
    }

    async fn set_eas(&self, eas: &[crate::Ea]) -> SmbResult<()> {
        let (LocalHandle::File { read_only, .. } | LocalHandle::Dir { read_only, .. }) = self;
        if *read_only {
            return Err(SmbError::AccessDenied);
        }
        let target = self.ea_target()?;
        let open = self.open_streams();
        let eas = eas.to_vec();
        spawn_blocking(move || {
            let file = target.file().map_err(io_to_smb)?;
            host_set_eas(&file, &eas, open.as_ref())
        })
        .await
        .map_err(join_to_io)
        .map_err(io_to_smb)?
    }

    #[cfg(target_os = "linux")]
    async fn streams(&self) -> SmbResult<Vec<crate::stream::StreamInfo>> {
        let listed = match self {
            LocalHandle::File {
                file,
                store: Some(store),
                ..
            } => {
                let (file, store) = (Arc::clone(file), Arc::clone(store));
                spawn_blocking(move || super::streams::list_smb(&file, &store)).await
            }
            LocalHandle::Dir {
                dir_handle,
                store: Some(store),
                ..
            } => {
                let (dir_handle, store) = (Arc::clone(dir_handle), Arc::clone(store));
                spawn_blocking(move || {
                    let fd = dir_as_file(&dir_handle).map_err(io_to_smb)?;
                    super::streams::list_smb(&fd, &store)
                })
                .await
            }
            _ => return Ok(Vec::new()),
        };
        listed.map_err(join_to_io).map_err(io_to_smb)?
    }

    #[cfg(any(target_os = "macos", windows))]
    async fn streams(&self) -> SmbResult<Vec<crate::stream::StreamInfo>> {
        #[cfg(target_os = "macos")]
        use super::macos_streams::list_smb;
        #[cfg(windows)]
        use super::windows_streams::list_smb;
        match self {
            LocalHandle::File { file, .. } => {
                let file = Arc::clone(file);
                spawn_blocking(move || list_smb(&file)).await
            }
            LocalHandle::Dir { dir_handle, .. } => {
                let dir_handle = Arc::clone(dir_handle);
                spawn_blocking(move || {
                    let fd = dir_as_file(&dir_handle).map_err(io_to_smb)?;
                    list_smb(&fd)
                })
                .await
            }
        }
        .map_err(join_to_io)
        .map_err(io_to_smb)?
    }

    /// Each entry is opened from this directory, a symlink followed only
    /// to a target below it, and its streams are read on that descriptor.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    async fn peek_streams(
        &self,
        entries: &[(&str, &[(StreamName, u32)])],
    ) -> SmbResult<Vec<Vec<Option<(u64, Bytes)>>>> {
        let LocalHandle::Dir { dir_handle, .. } = self else {
            return Err(SmbError::NotADirectory);
        };
        let dir = Arc::clone(dir_handle);
        let entries: Vec<_> = entries
            .iter()
            .map(|&(name, streams)| (name.to_owned(), streams.to_vec()))
            .collect();
        #[cfg(target_os = "linux")]
        let peek = {
            let (open, store) = self
                .open_streams()
                .zip(self.store())
                .ok_or(SmbError::NotSupported)?;
            move || super::streams::peek_entries(&dir, &open, &store, &entries)
        };
        #[cfg(target_os = "macos")]
        let peek = move || super::macos_streams::peek_entries(&dir, &entries);
        #[cfg(windows)]
        let peek = move || super::windows_streams::peek_entries(&dir, &entries);
        spawn_blocking(peek)
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::backend::{OpenIntent, OpenOptions};
    use crate::path::SmbPath;
    use tempfile::tempdir;

    fn p(s: &str) -> SmbPath {
        s.parse::<SmbPath>().unwrap()
    }

    fn opts_create() -> OpenOptions {
        OpenOptions {
            read: true,
            write: true,
            write_attributes: true,
            intent: OpenIntent::Create,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        }
    }

    fn opts_open_rw() -> OpenOptions {
        OpenOptions {
            read: true,
            write: true,
            write_attributes: true,
            intent: OpenIntent::Open,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        }
    }

    fn opts_open_ro() -> OpenOptions {
        OpenOptions {
            read: true,
            write: false,
            write_attributes: false,
            intent: OpenIntent::Open,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        }
    }

    fn opts_open_dir() -> OpenOptions {
        OpenOptions {
            read: true,
            write: false,
            write_attributes: false,
            intent: OpenIntent::Open,
            directory: true,
            non_directory: false,
            delete_on_close: false,
        }
    }

    #[tokio::test]
    async fn create_write_read_stat_close() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();

        // Create
        let h = backend
            .open(&p("hello.txt"), opts_create())
            .await
            .unwrap()
            .0;
        let n = h.write(0, b"hello world").await.unwrap();
        assert_eq!(n, 11);
        h.flush().await.unwrap();

        // Stat
        let info = h.stat().await.unwrap();
        assert_eq!(info.name, "hello.txt");
        assert_eq!(info.end_of_file, 11);
        assert!(!info.is_directory);
        assert!(info.last_write_time > 0);
        h.close().await.unwrap();

        // Reopen for read
        let h2 = backend
            .open(&p("hello.txt"), opts_open_ro())
            .await
            .unwrap()
            .0;
        let bytes = h2.read(0, 1024).await.unwrap();
        assert_eq!(&bytes[..], b"hello world");

        // Short-read past EOF returns truncated
        let bytes = h2.read(6, 1024).await.unwrap();
        assert_eq!(&bytes[..], b"world");

        // Read past EOF returns empty
        let bytes = h2.read(100, 1024).await.unwrap();
        assert!(bytes.is_empty());
        h2.close().await.unwrap();
    }

    #[tokio::test]
    async fn list_dir_finds_created_file() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let h = backend.open(&p("a.txt"), opts_create()).await.unwrap().0;
        h.close().await.unwrap();

        let dir_h = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap()
            .0;
        let entries = dir_h.list_dir(None).await.unwrap();
        assert!(entries.iter().any(|e| e.info.name == "a.txt"));
        dir_h.close().await.unwrap();
    }

    #[tokio::test]
    async fn read_only_rejects_writes() {
        let td = tempdir().unwrap();
        // Pre-create a file via a writable backend so we have something to
        // attempt to open RW.
        {
            let writable = LocalFsBackend::new(td.path()).unwrap();
            let h = writable.open(&p("x.txt"), opts_create()).await.unwrap().0;
            h.close().await.unwrap();
        }

        let backend = LocalFsBackend::new(td.path()).unwrap().read_only();
        assert!(backend.capabilities().is_read_only);

        // RW open should be rejected.
        let err = backend
            .open(&p("x.txt"), opts_open_rw())
            .await
            .err()
            .unwrap();
        assert!(matches!(err, SmbError::AccessDenied));

        // Create should be rejected.
        let err = backend
            .open(&p("y.txt"), opts_create())
            .await
            .err()
            .unwrap();
        assert!(matches!(err, SmbError::AccessDenied));

        // Pure read open is fine; writes through it are rejected.
        let h = backend.open(&p("x.txt"), opts_open_ro()).await.unwrap().0;
        assert!(matches!(
            h.write(0, b"x").await,
            Err(SmbError::AccessDenied)
        ));
        h.close().await.unwrap();

        // unlink rejected.
        let err = backend.unlink(&p("x.txt")).await.err().unwrap();
        assert!(matches!(err, SmbError::AccessDenied));
    }

    #[tokio::test]
    async fn unlink_file_then_nonempty_dir_errors() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();

        // Create & remove a file.
        let h = backend
            .open(&p("doomed.txt"), opts_create())
            .await
            .unwrap()
            .0;
        h.close().await.unwrap();
        backend.unlink(&p("doomed.txt")).await.unwrap();
        assert!(matches!(
            backend.unlink(&p("doomed.txt")).await.err().unwrap(),
            SmbError::NotFound
        ));

        // Create a non-empty directory; unlink should fail with NotEmpty.
        std::fs::create_dir(td.path().join("dir1")).unwrap();
        std::fs::write(td.path().join("dir1").join("inside"), b"x").unwrap();

        let err = backend.unlink(&p("dir1")).await.err().unwrap();
        assert!(
            matches!(err, SmbError::NotEmpty),
            "expected NotEmpty, got {err:?}"
        );

        // Empty it and retry.
        std::fs::remove_file(td.path().join("dir1").join("inside")).unwrap();
        backend.unlink(&p("dir1")).await.unwrap();
    }

    #[tokio::test]
    async fn rename_within_root() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();

        let h = backend.open(&p("old.txt"), opts_create()).await.unwrap().0;
        h.write(0, b"data").await.unwrap();
        h.close().await.unwrap();

        backend
            .rename(&p("old.txt"), &p("new.txt"), false)
            .await
            .unwrap();
        assert!(td.path().join("new.txt").exists());
        assert!(!td.path().join("old.txt").exists());

        // Renaming over an existing target should fail.
        let h = backend
            .open(&p("other.txt"), opts_create())
            .await
            .unwrap()
            .0;
        h.close().await.unwrap();
        let err = backend
            .rename(&p("other.txt"), &p("new.txt"), false)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, SmbError::Exists), "got {err:?}");
    }

    #[tokio::test]
    async fn rename_onto_itself_is_not_a_collision() {
        let td = tempdir().unwrap();
        std::fs::write(td.path().join("doc.txt"), b"old").unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        backend
            .rename(&p("doc.txt"), &p("doc.txt"), false)
            .await
            .unwrap();
        assert_eq!(std::fs::read(td.path().join("doc.txt")).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rename_between_hard_links_follows_collision_rules() {
        let td = tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("a.txt"), b"data").unwrap();
        std::fs::hard_link(root.join("a.txt"), root.join("b.txt")).unwrap();
        let backend = LocalFsBackend::new(root).unwrap();

        let err = backend
            .rename(&p("a.txt"), &p("b.txt"), false)
            .await
            .unwrap_err();
        assert!(matches!(err, SmbError::Exists), "got {err:?}");
        assert!(root.join("a.txt").exists());

        backend
            .rename(&p("a.txt"), &p("b.txt"), true)
            .await
            .unwrap();
        assert!(!root.join("a.txt").exists());
        assert_eq!(std::fs::read(root.join("b.txt")).unwrap(), b"data");
    }

    #[tokio::test]
    async fn directory_file_index_is_the_same_for_every_open_and_listing() {
        let td = tempdir().unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();

        let root = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap()
            .0;
        let listed = root.list_dir(None).await.unwrap();
        let first = backend.open(&p("d"), opts_open_dir()).await.unwrap().0;
        let second = backend.open(&p("d"), opts_open_dir()).await.unwrap().0;
        let id = first.stat().await.unwrap().file_index;
        assert_ne!(id, 0);
        assert_eq!(second.stat().await.unwrap().file_index, id);
        let entry = listed.iter().find(|e| e.info.name == "d").unwrap();
        assert_eq!(entry.info.file_index, id);
    }

    #[test]
    fn file_index_keeps_root_device_inodes_and_separates_other_devices() {
        let root = Some(0x803);
        assert_eq!(file_index(root, Some((0x803, 42))), 42);
        assert_eq!(file_index(None, Some((0x803, 42))), 42);
        assert_eq!(file_index(root, None), 0);
        assert_ne!(
            file_index(root, Some((0x803, 1))),
            file_index(root, Some((0x2b, 1)))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_index_is_the_inode_on_the_root_device() {
        use std::os::unix::fs::MetadataExt as _;

        let td = tempdir().unwrap();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let h = backend.open(&p("f.txt"), opts_open_ro()).await.unwrap().0;
        let ino = std::fs::metadata(td.path().join("f.txt")).unwrap().ino();
        assert_eq!(h.stat().await.unwrap().file_index, ino);
    }

    #[tokio::test]
    async fn stat_and_listings_report_the_host_mode() {
        let td = tempdir().unwrap();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |name: &str, mode| {
                let perms = std::fs::Permissions::from_mode(mode);
                std::fs::set_permissions(td.path().join(name), perms).unwrap();
            };
            mode("f.txt", 0o751);
            mode("d", 0o710);
        }
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let root = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap()
            .0;
        let listed = root.list_dir(None).await.unwrap();
        let listed_mode = |name: &str| {
            listed
                .iter()
                .find(|e| e.info.name == name)
                .expect(name)
                .info
                .unix_mode
        };
        let h = backend.open(&p("f.txt"), opts_open_ro()).await.unwrap().0;
        let stat = h.stat().await.unwrap().unix_mode;
        let (file, dir) = if cfg!(unix) {
            (Some(0o100_751), Some(0o040_710))
        } else {
            (None, None)
        };
        assert_eq!(stat, file);
        assert_eq!(listed_mode("f.txt"), file);
        assert_eq!(listed_mode("d"), dir);
    }

    /// Needs mounts below `/` whose roots share an inode number, as procfs,
    /// sysfs and tmpfs roots do on Linux.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn file_index_differs_across_mounts_with_equal_inodes() {
        use std::os::unix::fs::MetadataExt as _;

        let mounts: Vec<_> = ["proc", "sys", "dev", "tmp"]
            .into_iter()
            .filter_map(|name| {
                let md = std::fs::metadata(Path::new("/").join(name)).ok()?;
                Some((name, md.dev(), md.ino()))
            })
            .collect();
        let pair = mounts.iter().enumerate().find_map(|(i, a)| {
            mounts[i + 1..]
                .iter()
                .find(|b| a.1 != b.1 && a.2 == b.2)
                .map(|b| (a.0, b.0))
        });
        let Some((a, b)) = pair else {
            eprintln!("no two mounts below / share an inode number; skipping");
            return;
        };
        let backend = LocalFsBackend::new("/").unwrap();
        let root = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap()
            .0;
        let listed = root.list_dir(None).await.unwrap();
        let mut ids = Vec::new();
        for name in [a, b] {
            let h = backend.open(&p(name), opts_open_dir()).await.unwrap().0;
            let id = h.stat().await.unwrap().file_index;
            let entry = listed.iter().find(|e| e.info.name == name).unwrap();
            assert_eq!(entry.info.file_index, id, "{name}");
            ids.push(id);
        }
        assert_ne!(ids[0], ids[1], "{a} and {b}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unlink_removes_empty_dirs_and_symlinks_as_links() {
        use std::os::unix::fs::symlink;

        let td = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("keep.txt"), b"x").unwrap();
        let root = td.path();
        std::fs::create_dir(root.join("empty")).unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::write(root.join("target").join("inside.txt"), b"x").unwrap();
        symlink(root.join("target"), root.join("link_in")).unwrap();
        symlink(outside.path(), root.join("link_out")).unwrap();
        symlink(root.join("missing"), root.join("dangling")).unwrap();
        let backend = LocalFsBackend::new(root).unwrap();

        backend.unlink(&p("empty")).await.unwrap();
        assert!(!root.join("empty").exists());

        for link in ["link_in", "link_out", "dangling"] {
            backend.unlink(&p(link)).await.unwrap();
            assert!(root.join(link).symlink_metadata().is_err(), "{link}");
        }
        assert!(root.join("target").join("inside.txt").exists());
        assert!(outside.path().join("keep.txt").exists());
    }

    #[test]
    fn cross_device_error_maps_to_not_same_device() {
        assert!(matches!(
            io_to_smb(io::ErrorKind::CrossesDevices.into()),
            SmbError::NotSameDevice
        ));
    }

    #[tokio::test]
    async fn list_dir_pattern_matching() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();

        for name in ["a.txt", "b.txt", "c.log", "README"] {
            let h = backend.open(&p(name), opts_create()).await.unwrap().0;
            h.close().await.unwrap();
        }

        let dir_h = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap()
            .0;

        let txts = dir_h.list_dir(Some("*.txt")).await.unwrap();
        let names: Vec<_> = txts.iter().map(|e| e.info.name.as_str()).collect();
        assert_eq!(names.len(), 2, "expected 2 .txt files, got {names:?}");
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));

        // Single-char wildcard.
        let one = dir_h.list_dir(Some("?.log")).await.unwrap();
        let names: Vec<_> = one.iter().map(|e| e.info.name.as_str()).collect();
        assert_eq!(names, vec!["c.log"]);

        // Case follows the host's lookup rule.
        let any_txt = dir_h.list_dir(Some("*.TXT")).await.unwrap();
        let expected = if backend.capabilities().case_sensitive {
            0
        } else {
            2
        };
        assert_eq!(any_txt.len(), expected);

        // "*" matches everything.
        let all = dir_h.list_dir(Some("*")).await.unwrap();
        assert_eq!(all.len(), 4);

        dir_h.close().await.unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn sharing_violation_maps_to_sharing() {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        assert!(matches!(
            io_to_smb(io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION)),
            SmbError::Sharing
        ));
    }

    #[tokio::test]
    async fn directory_unlinks_while_open() {
        let td = tempdir().unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let h = backend.open(&p("d"), opts_open_dir()).await.unwrap().0;
        backend.unlink(&p("d")).await.unwrap();
        assert!(!td.path().join("d").exists());
        h.close().await.unwrap();
    }

    fn filetime(secs: u64) -> u64 {
        system_time_to_filetime(UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[tokio::test]
    async fn creation_time_is_set_where_the_host_can() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let h = backend.open(&p("f.txt"), opts_create()).await.unwrap().0;
        let before = h.stat().await.unwrap();
        let t = filetime(1_557_126_489);
        h.set_times(FileTimes {
            creation_time: Some(t),
            ..FileTimes::default()
        })
        .await
        .unwrap();
        let after = h.stat().await.unwrap();
        if cfg!(any(windows, target_os = "macos")) {
            assert_eq!(after.creation_time, t);
        } else {
            assert_eq!(after.creation_time, before.creation_time);
        }
        assert_eq!(after.last_write_time, before.last_write_time);
        h.close().await.unwrap();
    }

    #[tokio::test]
    async fn creation_time_does_not_block_the_other_times() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let h = backend.open(&p("f.txt"), opts_create()).await.unwrap().0;
        let created = filetime(1_557_126_489);
        let written = filetime(1_577_934_245);
        h.set_times(FileTimes {
            creation_time: Some(created),
            last_access_time: Some(written),
            last_write_time: Some(written),
            ..FileTimes::default()
        })
        .await
        .unwrap();
        let info = h.stat().await.unwrap();
        assert_eq!(info.last_write_time, written);
        assert_eq!(info.last_access_time, written);
        if cfg!(any(windows, target_os = "macos")) {
            assert_eq!(info.creation_time, created);
        }
        h.close().await.unwrap();
    }

    #[tokio::test]
    async fn attributes_are_stored_where_the_host_keeps_them() {
        use crate::backend::{
            FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
            FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
        };
        let td = tempdir().unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        std::fs::write(td.path().join("f.txt"), b"x").unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        async fn listed(backend: &LocalFsBackend, name: &str) -> u32 {
            let root = backend
                .open(&SmbPath::root(), opts_open_dir())
                .await
                .unwrap()
                .0;
            let entries = root.list_dir(None).await.unwrap();
            root.close().await.unwrap();
            let entry = entries.into_iter().find(|e| e.info.name == name).unwrap();
            entry.info.attributes()
        }

        // A handle opened without attribute access sets them too.
        let others = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE;
        let h = backend.open(&p("f.txt"), opts_open_ro()).await.unwrap().0;
        for (set, windows, unix) in [
            (others, others, FILE_ATTRIBUTE_NORMAL),
            (
                FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
                FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
                FILE_ATTRIBUTE_READONLY,
            ),
            (0, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NORMAL),
        ] {
            h.set_attributes(set).await.unwrap();
            let expected = if cfg!(windows) { windows } else { unix };
            assert_eq!(h.stat().await.unwrap().attributes(), expected, "{set:#x}");
            assert_eq!(listed(&backend, "f.txt").await, expected, "{set:#x} listed");
        }
        h.close().await.unwrap();

        let dir = backend.open(&p("d"), opts_open_dir()).await.unwrap().0;
        let set = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN;
        dir.set_attributes(set).await.unwrap();
        let expected = if cfg!(windows) {
            FILE_ATTRIBUTE_DIRECTORY | set
        } else {
            FILE_ATTRIBUTE_DIRECTORY
        };
        assert_eq!(dir.stat().await.unwrap().attributes(), expected);
        assert_eq!(listed(&backend, "d").await, expected);
        dir.set_attributes(0).await.unwrap();
        assert_eq!(
            dir.stat().await.unwrap().attributes(),
            FILE_ATTRIBUTE_DIRECTORY
        );
        dir.close().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_set_that_keeps_the_read_only_state_leaves_the_mode_alone() {
        use std::os::unix::fs::MetadataExt as _;
        let td = tempdir().unwrap();
        let path = td.path().join("f.txt");
        std::fs::write(&path, b"x").unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let h = backend.open(&p("f.txt"), opts_open_ro()).await.unwrap().0;
        let changed = || {
            let md = std::fs::metadata(&path).unwrap();
            (md.ctime(), md.ctime_nsec())
        };
        let before = changed();
        std::thread::sleep(Duration::from_millis(20));
        h.set_attributes(crate::backend::FILE_ATTRIBUTE_HIDDEN)
            .await
            .unwrap();
        assert_eq!(changed(), before);
        h.close().await.unwrap();
    }

    #[test]
    fn filetimes_before_1970_reach_the_host_clock() {
        for ft in [
            0,
            95_616_288_000_000_000,
            FILETIME_OFFSET - 1,
            FILETIME_OFFSET,
        ] {
            let t = filetime_to_system_time(ft).unwrap();
            assert_eq!(system_time_to_filetime(t), ft);
        }
        assert_eq!(
            filetime_to_system_time(95_616_288_000_000_000),
            UNIX_EPOCH.checked_sub(Duration::from_secs(2_082_844_800))
        );
    }

    #[test]
    fn filetime_round_trip() {
        let now = SystemTime::now();
        let ft = system_time_to_filetime(now);
        let back = filetime_to_system_time(ft).unwrap();
        let delta = now
            .duration_since(back)
            .or_else(|e| Ok::<_, std::time::SystemTimeError>(e.duration()))
            .unwrap();
        // 100ns granularity: round-trip should be sub-microsecond.
        assert!(delta < Duration::from_micros(1), "delta = {delta:?}");
    }

    #[test]
    fn full_disk_and_quota_map_to_their_statuses() {
        let full = io_to_smb(io::ErrorKind::StorageFull.into());
        assert_eq!(full.to_nt_status(), crate::ntstatus::STATUS_DISK_FULL);
        let quota = io_to_smb(io::ErrorKind::QuotaExceeded.into());
        assert_eq!(
            quota.to_nt_status(),
            crate::ntstatus::STATUS_DISK_QUOTA_EXCEEDED
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn volume_info_reports_the_host_volume() {
        let td = tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let info = backend.volume_info().await.unwrap();
        let st = rustix::fs::statvfs(td.path()).unwrap();
        assert_eq!(info.total_allocation_units, st.f_blocks);
        let unit = u64::from(info.sectors_per_allocation_unit) * u64::from(info.bytes_per_sector);
        assert_eq!(unit, st.f_frsize);
        // Free space moves with other activity on the volume.
        let free_bytes = info.actual_available_allocation_units * unit;
        let host_free = st.f_bfree * st.f_frsize;
        assert!(
            free_bytes.abs_diff(host_free) <= 64 << 20,
            "{free_bytes} vs {host_free}"
        );
        assert!(info.caller_available_allocation_units <= info.actual_available_allocation_units);
        assert_ne!(info, VolumeInfo::default());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn listing_leaves_out_names_clients_cannot_open() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let td = tempdir().unwrap();
        for name in [
            OsStr::new("ok.txt"),
            OsStr::new("a:b"),
            OsStr::new("star*"),
            OsStr::from_bytes(b"bad\xffutf8"),
        ] {
            std::fs::write(td.path().join(name), b"x").unwrap();
        }
        let long = "x".repeat(200) + "\u{e9}"; // 202 bytes, 201 UTF-16 units
        std::fs::write(td.path().join(&long), b"x").unwrap();

        let backend = LocalFsBackend::new(td.path()).unwrap();
        let dir = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap()
            .0;
        let mut names: Vec<String> = dir
            .list_dir(None)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.info.name)
            .collect();
        names.sort();
        let mut expected = vec!["ok.txt".to_string(), long];
        expected.sort();
        assert_eq!(names, expected);
        // Every listed name opens again.
        for name in &names {
            backend
                .open(&p(name), opts_open_ro())
                .await
                .unwrap()
                .0
                .close()
                .await
                .unwrap();
        }
        dir.close().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dir_is_empty_counts_unlisted_names() {
        let td = tempdir().unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let dir = backend.open(&p("d"), opts_open_dir()).await.unwrap().0;
        assert!(dir.dir_is_empty().await.unwrap());
        std::fs::write(td.path().join("d").join("a:b"), b"x").unwrap();
        assert!(dir.list_dir(None).await.unwrap().is_empty());
        assert!(!dir.dir_is_empty().await.unwrap());
        dir.close().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn link_count_reports_hard_links() {
        let td = tempdir().unwrap();
        std::fs::write(td.path().join("a"), b"x").unwrap();
        std::fs::hard_link(td.path().join("a"), td.path().join("b")).unwrap();
        std::fs::create_dir_all(td.path().join("d").join("sub")).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();

        let file = backend.open(&p("a"), opts_open_ro()).await.unwrap().0;
        assert_eq!(file.link_count().await.unwrap(), 2);
        std::fs::remove_file(td.path().join("a")).unwrap();
        std::fs::remove_file(td.path().join("b")).unwrap();
        assert_eq!(file.link_count().await.unwrap(), 0);
        file.close().await.unwrap();

        let dir = backend.open(&p("d"), opts_open_dir()).await.unwrap().0;
        assert_eq!(dir.link_count().await.unwrap(), 1);
        dir.close().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn listing_reports_symlinks_as_their_targets() {
        let td = tempdir().unwrap();
        std::fs::create_dir(td.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", td.path().join("link")).unwrap();
        std::os::unix::fs::symlink("missing", td.path().join("dangling")).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();

        let root = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap()
            .0;
        let entries = root.list_dir(None).await.unwrap();
        let get = |name: &str| {
            entries
                .iter()
                .find(|e| e.info.name == name)
                .unwrap_or_else(|| panic!("{name} listed"))
                .info
                .clone()
        };
        let link = get("link");
        let opened = backend.open(&p("link"), opts_open_ro()).await.unwrap().0;
        let stat = opened.stat().await.unwrap();
        assert!(link.is_directory);
        assert_eq!(link.is_directory, stat.is_directory);
        assert_eq!(link.file_index, stat.file_index);
        assert!(!get("dangling").is_directory);
        opened.close().await.unwrap();
        root.close().await.unwrap();
    }

    /// Makes a FIFO at `path`.
    #[cfg(unix)]
    pub(in crate::fs) fn mkfifo(path: &Path) {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
    }

    /// Opens the FIFO at `path` for reading and for writing without
    /// blocking, and writes to it, so a thread stuck opening, reading or
    /// writing it returns.
    #[cfg(unix)]
    pub(in crate::fs) fn release(path: &Path) {
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::OpenOptionsExt as _;
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path);
        if let Ok(mut fifo) = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            let _ = fifo.write_all(b"x");
        }
        if let Ok(mut reader) = reader {
            let _ = reader.read(&mut [0; 64]);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_or_socket_in_place_of_a_checked_file_fails_as_changed_at_once() {
        let td = tempdir().unwrap();
        let fifo = td.path().join("fifo");
        mkfifo(&fifo);
        // A socket fails to open at all; a FIFO opens and is no file.
        let _socket = std::os::unix::net::UnixListener::bind(td.path().join("sock")).unwrap();
        let root = Arc::new(Dir::open_ambient_dir(td.path(), ambient_authority()).unwrap());
        for (name, opts) in [
            ("fifo", opts_open_ro()),
            ("fifo", opts_open_rw()),
            ("sock", opts_open_ro()),
        ] {
            let dir = Arc::clone(&root);
            let opened = spawn_blocking(move || {
                let name = Path::new(name);
                #[cfg_attr(not(target_os = "linux"), expect(unused_mut))]
                let mut results = vec![open_file(&dir, name, opts).map(|_| ())];
                #[cfg(target_os = "linux")]
                results.push(open_file_nofollow(&dir, name, opts).map(|_| ()));
                results
            });
            let Ok(opened) = tokio::time::timeout(Duration::from_secs(10), opened).await else {
                release(&fifo);
                panic!("the open of a FIFO blocked");
            };
            for result in opened.unwrap() {
                assert!(result.is_err_and(|e| is_changed(&e)), "{name}");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_opened_file_is_left_in_blocking_mode() {
        let td = tempdir().unwrap();
        std::fs::write(td.path().join("f"), b"x").unwrap();
        let root = Dir::open_ambient_dir(td.path(), ambient_authority()).unwrap();
        let (file, _) = open_file(&root, Path::new("f"), opts_open_rw()).unwrap();
        let flags = rustix::fs::fcntl_getfl(&file).unwrap();
        assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK));
        #[cfg(target_os = "linux")]
        {
            let (file, _) = open_file_nofollow(&root, Path::new("f"), opts_open_rw()).unwrap();
            let flags = rustix::fs::fcntl_getfl(&file).unwrap();
            assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifos_and_sockets_are_refused_for_every_intent() {
        let td = tempdir().unwrap();
        let fifo = td.path().join("fifo");
        mkfifo(&fifo);
        let _socket = std::os::unix::net::UnixListener::bind(td.path().join("sock")).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        for name in ["fifo", "sock"] {
            for intent in [
                OpenIntent::Open,
                OpenIntent::OpenOrCreate,
                OpenIntent::Truncate,
                OpenIntent::OverwriteOrCreate,
            ] {
                for opts in [opts_open_ro(), opts_open_rw()] {
                    let (path, opts) = (p(name), OpenOptions { intent, ..opts });
                    let open = backend.open(&path, opts);
                    let Ok(opened) = tokio::time::timeout(Duration::from_secs(10), open).await
                    else {
                        release(&fifo);
                        panic!("the open of {name} blocked");
                    };
                    assert!(
                        matches!(opened, Err(SmbError::SpecialFile)),
                        "{name} {intent:?}"
                    );
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_open_against_a_file_lease_fails_as_shared_and_breaks_the_lease() {
        use libc::{F_GETLEASE, F_SETLEASE};
        let td = tempdir().unwrap();
        std::fs::write(td.path().join("f"), b"x").unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        for (lease, opts, breaks_to) in [
            (libc::F_WRLCK, opts_open_ro(), libc::F_RDLCK),
            (libc::F_RDLCK, opts_open_rw(), libc::F_UNLCK),
            (
                libc::F_RDLCK,
                OpenOptions {
                    intent: OpenIntent::Truncate,
                    ..opts_open_rw()
                },
                libc::F_UNLCK,
            ),
        ] {
            let holder = std::fs::File::open(td.path().join("f")).unwrap();
            let fd = std::os::fd::AsRawFd::as_raw_fd(&holder);
            // SAFETY: `fd` is open for the whole block; F_SETOWN 0 sends the
            // break signal to no process.
            unsafe {
                if libc::fcntl(fd, F_SETLEASE, lease) != 0 {
                    eprintln!("skipping: no file lease: {}", io::Error::last_os_error());
                    return;
                }
                assert_eq!(libc::fcntl(fd, libc::F_SETOWN, 0), 0);
            }
            let opened = backend.open(&p("f"), opts).await;
            assert!(matches!(opened, Err(SmbError::Sharing)), "{lease}");
            // SAFETY: as above.
            assert_eq!(
                unsafe { libc::fcntl(fd, F_GETLEASE) },
                breaks_to,
                "breaking"
            );
            // SAFETY: as above.
            assert_eq!(unsafe { libc::fcntl(fd, F_SETLEASE, libc::F_UNLCK) }, 0);
            let (file, _) = backend.open(&p("f"), opts).await.unwrap();
            file.close().await.unwrap();
            drop(holder);
        }
    }
}
