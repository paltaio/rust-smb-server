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
//!   `"`) itself, folding ASCII case only, since cap-std only provides raw
//!   `entries()`. `"*.*"` matches every name, as `"*"` does.
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

use crate::backend::{
    BackendCapabilities, DirEntry as SmbDirEntry, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_READONLY,
    FileInfo, FileTimes, Handle, OpenIntent, OpenOptions, ShareBackend,
};
use crate::error::{SmbError, SmbResult};
use crate::path::{SmbPath, same_path};
use crate::utils::{FILETIME_OFFSET, system_time_to_filetime};

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Local-filesystem backend, sandboxed at a single root directory.
///
/// Handles set access and write times on every host. The creation time is
/// set on Windows and macOS; other hosts have no call that sets it, so a
/// requested creation time is ignored there and the other times still apply.
/// The host keeps the change time.
pub struct LocalFsBackend {
    root: Arc<Dir>,
    /// Device of the share root; see `file_index`.
    root_dev: Option<u64>,
    read_only: bool,
}

impl LocalFsBackend {
    /// Open `path` as the share root. Errors if the path does not exist or is
    /// not a directory.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let dir = Dir::open_ambient_dir(path, ambient_authority())?;
        let root_dev = file_key(&dir.dir_metadata()?).map(|(dev, _)| dev);
        Ok(Self {
            root: Arc::new(dir),
            root_dev,
            read_only: false,
        })
    }

    /// Mark the backend as read-only. All write-class opens and writes return
    /// an access-denied SMB error.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }
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
fn to_rel_path(path: &SmbPath) -> PathBuf {
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

fn io_to_smb(err: io::Error) -> SmbError {
    use io::ErrorKind::*;
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
        _ => SmbError::Io(err),
    }
}

/// Convert a `spawn_blocking` join error (panic or cancellation) into
/// `io::ErrorKind::Other`.
fn join_to_io(_e: tokio::task::JoinError) -> io::Error {
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
fn file_key(md: &Metadata) -> Option<(u64, u64)> {
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
fn file_index(root_dev: Option<u64>, key: Option<(u64, u64)>) -> u64 {
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
fn link_count(md: &Metadata) -> Option<u64> {
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
fn dir_as_file(dir: &Dir) -> io::Result<std::fs::File> {
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

/// Sets or clears the read-only state of an open file. On Unix a read-only
/// file has no write permission bits, and clearing it gives the owner write
/// permission back.
fn set_read_only(file: &std::fs::File, read_only: bool) -> io::Result<()> {
    let mut perms = file.metadata()?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = perms.mode();
        perms.set_mode(if read_only {
            mode & !0o222
        } else {
            mode | 0o200
        });
    }
    #[cfg(windows)]
    {
        perms.set_readonly(read_only);
    }
    file.set_permissions(perms)
}

/// Host times for `times`. The change time is left to the host. Hosts other
/// than Windows and macOS have no call that sets the creation time, so it is
/// ignored there.
fn host_file_times(times: FileTimes) -> SmbResult<std::fs::FileTimes> {
    let host_time = |ft| filetime_to_system_time(ft).ok_or(SmbError::NotSupported);
    let mut out = std::fs::FileTimes::new();
    if let Some(ft) = times.last_write_time {
        out = out.set_modified(host_time(ft)?);
    }
    if let Some(ft) = times.last_access_time {
        out = out.set_accessed(host_time(ft)?);
    }
    #[cfg(any(windows, target_os = "macos"))]
    if let Some(ft) = times.creation_time {
        out = set_created(out, host_time(ft)?);
    }
    Ok(out)
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

fn filetime_to_system_time(ft: u64) -> Option<SystemTime> {
    if ft < FILETIME_OFFSET {
        return None;
    }
    let unix_100ns = ft - FILETIME_OFFSET;
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
}

// ---------------------------------------------------------------------------
// FileInfo construction
// ---------------------------------------------------------------------------

fn file_info_from_metadata(name: String, md: &Metadata, root_dev: Option<u64>) -> FileInfo {
    let len = md.len();
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
        read_only: !md.is_dir() && md.permissions().readonly(),
        file_index: file_index(root_dev, file_key(md)),
    }
}

// ---------------------------------------------------------------------------
// DOS glob matching
// ---------------------------------------------------------------------------

/// Match `name` against a pattern with the wildcards of MS-FSA 2.1.4.4.
/// Comparison folds ASCII case only.
///
/// - `*` matches any sequence, `?` any single character.
/// - `<` (DOS_STAR) matches any sequence that does not contain the last `.`
///   of the name.
/// - `>` (DOS_QM) matches any single character other than `.`, and matches
///   nothing at a `.` or at the end of the name.
/// - `"` (DOS_DOT) matches a `.`, or nothing at the end of the name.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let last_dot = n.iter().rposition(|&c| c == '.');

    // matches[j]: the pattern consumed so far matches the first j characters
    // of the name. One row per pattern character.
    let mut matches = vec![false; n.len() + 1];
    matches[0] = true;
    for &pc in &p {
        let mut next = vec![false; n.len() + 1];
        for j in 0..=n.len() {
            let here = j < n.len();
            next[j] = match pc {
                '*' => matches[j] || (j > 0 && next[j - 1]),
                '<' => matches[j] || (j > 0 && next[j - 1] && Some(j - 1) != last_dot),
                '?' => j > 0 && matches[j - 1],
                '>' => {
                    (j > 0 && matches[j - 1] && n[j - 1] != '.')
                        || (matches[j] && (!here || n[j] == '.'))
                }
                '"' => (j > 0 && matches[j - 1] && n[j - 1] == '.') || (matches[j] && !here),
                c => j > 0 && matches[j - 1] && c.eq_ignore_ascii_case(&n[j - 1]),
            };
        }
        matches = next;
    }
    matches[n.len()]
}

// ---------------------------------------------------------------------------
// ShareBackend impl
// ---------------------------------------------------------------------------

#[async_trait]
impl ShareBackend for LocalFsBackend {
    async fn open(&self, path: &SmbPath, opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        // 1. Read-only check: any open that requests creation, write access,
        //    truncation, or overwrite is rejected up front. Pure read opens
        //    pass through.
        let writes = opts.write
            || opts.write_attributes
            || matches!(
                opts.intent,
                OpenIntent::Create
                    | OpenIntent::OpenOrCreate
                    | OpenIntent::OverwriteOrCreate
                    | OpenIntent::Truncate
            );
        if self.read_only && writes {
            return Err(SmbError::AccessDenied);
        }

        let rel = to_rel_path(path);
        let root = Arc::clone(&self.root);
        let read_only = self.read_only;
        let directory = opts.directory;
        let non_directory = opts.non_directory;
        let write_attributes = opts.write_attributes;

        if directory {
            // Directory CREATE intents: Create / OpenOrCreate / OverwriteOrCreate
            // imply mkdir; Open / Truncate require existing.
            let intent = opts.intent;
            let dir_handle = spawn_blocking(move || -> io::Result<Dir> {
                match intent {
                    OpenIntent::Open => open_dir_handle(&root, &rel, write_attributes),
                    OpenIntent::Create => {
                        root.create_dir(&rel)?;
                        open_dir_handle(&root, &rel, write_attributes)
                    }
                    OpenIntent::OpenOrCreate => {
                        if !root.exists(&rel) {
                            root.create_dir(&rel)?;
                        }
                        open_dir_handle(&root, &rel, write_attributes)
                    }
                    OpenIntent::Truncate | OpenIntent::OverwriteOrCreate => {
                        // Truncating a directory has no meaning; reject.
                        Err(io::Error::from(io::ErrorKind::InvalidInput))
                    }
                }
            })
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)?;

            return Ok(Box::new(LocalHandle::Dir {
                name: file_name_for(path),
                root_dev: self.root_dev,
                dir_handle: Arc::new(dir_handle),
            }));
        }

        let existing_is_dir = {
            let root = Arc::clone(&self.root);
            let rel = rel.clone();
            spawn_blocking(move || -> io::Result<bool> {
                match root.metadata(&rel) {
                    Ok(md) => Ok(md.is_dir()),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)?
        };
        if existing_is_dir {
            if non_directory {
                return Err(SmbError::IsDirectory);
            }
            match opts.intent {
                OpenIntent::Open | OpenIntent::OpenOrCreate => {
                    let root = Arc::clone(&self.root);
                    let rel = rel.clone();
                    let dir_handle =
                        spawn_blocking(move || open_dir_handle(&root, &rel, write_attributes))
                            .await
                            .map_err(join_to_io)
                            .map_err(io_to_smb)?
                            .map_err(io_to_smb)?;
                    return Ok(Box::new(LocalHandle::Dir {
                        name: file_name_for(path),
                        root_dev: self.root_dev,
                        dir_handle: Arc::new(dir_handle),
                    }));
                }
                OpenIntent::Create => return Err(SmbError::Exists),
                OpenIntent::Truncate | OpenIntent::OverwriteOrCreate => {
                    return Err(SmbError::IsDirectory);
                }
            }
        }

        // 2. Translate OpenIntent -> cap-std OpenOptions.
        let mut cap_opts = CapOpenOptions::new();
        match opts.intent {
            OpenIntent::Open => {
                cap_opts.read(true).write(opts.write);
                // Unix sets times and permissions through a read-only
                // descriptor. Windows needs the access right, which a
                // read-only file grants without write access.
                #[cfg(windows)]
                if opts.write_attributes && !opts.write {
                    use cap_primitives::fs::OpenOptionsExt as _;
                    const GENERIC_READ: u32 = 0x8000_0000;
                    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
                    cap_opts.access_mode(GENERIC_READ | FILE_WRITE_ATTRIBUTES);
                }
            }
            OpenIntent::Create => {
                cap_opts.read(opts.read).write(true).create_new(true);
            }
            OpenIntent::Truncate => {
                cap_opts.read(opts.read).write(true).truncate(true);
            }
            OpenIntent::OpenOrCreate => {
                cap_opts.read(opts.read).write(true).create(true);
            }
            OpenIntent::OverwriteOrCreate => {
                cap_opts
                    .read(opts.read)
                    .write(true)
                    .create(true)
                    .truncate(true);
            }
        }

        let cap_file = spawn_blocking(move || root.open_with(&rel, &cap_opts))
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)?;

        // Convert to a `std::fs::File`. We only need cap-std for the safe
        // *open*; once we hold a verified file handle, std's API gives us
        // `set_times`, `set_len`, `sync_data`, and `FileExt::{read,write}_at`.
        let std_file: std::fs::File = cap_file.into_std();

        Ok(Box::new(LocalHandle::File {
            name: file_name_for(path),
            root_dev: self.root_dev,
            file: Arc::new(std_file),
            read_only,
        }))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        if path.is_root() {
            // Refusing to delete the share root itself.
            return Err(SmbError::AccessDenied);
        }
        let rel = to_rel_path(path);
        let root = Arc::clone(&self.root);

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
        let same_name = same_path(from, to, self.capabilities().case_sensitive);
        let from = to_rel_path(from);
        let to_path = to_rel_path(to);
        let root = Arc::clone(&self.root);

        spawn_blocking(move || -> io::Result<()> {
            let from_md = root.symlink_metadata(&from)?;
            match root.symlink_metadata(&to_path) {
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
            root.rename(&from, &root, &to_path)
        })
        .await
        .map_err(join_to_io)
        .map_err(io_to_smb)?
        .map_err(io_to_smb)
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: self.read_only,
            // Case rule of the platform's usual filesystem; lookups go to the host.
            case_sensitive: cfg!(any(target_os = "linux", target_os = "freebsd")),
        }
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
    },
    Dir {
        name: String,
        root_dev: Option<u64>,
        dir_handle: Arc<Dir>,
    },
}

fn file_name_for(path: &SmbPath) -> String {
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
                ..
            } => {
                let file = Arc::clone(file);
                let name = name.clone();
                let root_dev = *root_dev;
                spawn_blocking(move || -> io::Result<FileInfo> {
                    let md = Metadata::from_file(&file)?;
                    Ok(file_info_from_metadata(name, &md, root_dev))
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
            } => {
                let dir_handle = Arc::clone(dir_handle);
                let name = name.clone();
                let root_dev = *root_dev;
                spawn_blocking(move || -> io::Result<FileInfo> {
                    let md = dir_handle.dir_metadata()?;
                    Ok(file_info_from_metadata(name, &md, root_dev))
                })
                .await
                .map_err(join_to_io)
                .map_err(io_to_smb)?
                .map_err(io_to_smb)
            }
        }
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        let host_times = host_file_times(times)?;
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
        if attributes & !(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE) != 0 {
            return Err(SmbError::NotSupported);
        }
        let read_only = attributes & FILE_ATTRIBUTE_READONLY != 0;
        match self {
            LocalHandle::File {
                file,
                read_only: backend_read_only,
                ..
            } => {
                if *backend_read_only {
                    return Err(SmbError::AccessDenied);
                }
                let file = Arc::clone(file);
                spawn_blocking(move || set_read_only(&file, read_only))
                    .await
                    .map_err(join_to_io)
                    .map_err(io_to_smb)?
                    .map_err(io_to_smb)
            }
            LocalHandle::Dir { .. } if read_only => Err(SmbError::NotSupported),
            LocalHandle::Dir { .. } => Ok(()),
        }
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
        match self {
            LocalHandle::File { .. } => Err(SmbError::NotADirectory),
            LocalHandle::Dir {
                dir_handle,
                root_dev,
                ..
            } => {
                let dir_handle = Arc::clone(dir_handle);
                let root_dev = *root_dev;
                let pat = pattern.map(|s| s.to_owned());
                spawn_blocking(move || -> io::Result<Vec<SmbDirEntry>> {
                    let mut out = Vec::new();
                    for entry in dir_handle.entries()? {
                        let entry = entry?;
                        let os_name = entry.file_name();
                        let Some(name) = os_name.to_str().map(str::to_owned) else {
                            // Skip non-UTF-8 names; SMB wire format is UTF-16
                            // and we never want to emit invalid Unicode here.
                            continue;
                        };
                        if let Some(p) = pat.as_deref() {
                            // Empty / "*" / "*.*" all mean "match everything"
                            // in DOS-speak.
                            if !(p.is_empty() || p == "*" || p == "*.*" || glob_match(p, &name)) {
                                continue;
                            }
                        }
                        let md = entry_metadata(&dir_handle, &entry)?;
                        let info = file_info_from_metadata(name, &md, root_dev);
                        out.push(SmbDirEntry { info });
                    }
                    Ok(out)
                })
                .await
                .map_err(join_to_io)
                .map_err(io_to_smb)?
                .map_err(io_to_smb)
            }
        }
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        // Drop is sufficient: closing the underlying handle is what the OS
        // does when the last `Arc` ref goes away. No flush here: SMB CLOSE
        // does not imply fsync.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
        let h = backend.open(&p("hello.txt"), opts_create()).await.unwrap();
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
        let h2 = backend.open(&p("hello.txt"), opts_open_ro()).await.unwrap();
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
        let h = backend.open(&p("a.txt"), opts_create()).await.unwrap();
        h.close().await.unwrap();

        let dir_h = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap();
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
            let h = writable.open(&p("x.txt"), opts_create()).await.unwrap();
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
        let h = backend.open(&p("x.txt"), opts_open_ro()).await.unwrap();
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
        let h = backend.open(&p("doomed.txt"), opts_create()).await.unwrap();
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

        let h = backend.open(&p("old.txt"), opts_create()).await.unwrap();
        h.write(0, b"data").await.unwrap();
        h.close().await.unwrap();

        backend
            .rename(&p("old.txt"), &p("new.txt"), false)
            .await
            .unwrap();
        assert!(td.path().join("new.txt").exists());
        assert!(!td.path().join("old.txt").exists());

        // Renaming over an existing target should fail.
        let h = backend.open(&p("other.txt"), opts_create()).await.unwrap();
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
            .unwrap();
        let listed = root.list_dir(None).await.unwrap();
        let first = backend.open(&p("d"), opts_open_dir()).await.unwrap();
        let second = backend.open(&p("d"), opts_open_dir()).await.unwrap();
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
        let h = backend.open(&p("f.txt"), opts_open_ro()).await.unwrap();
        let ino = std::fs::metadata(td.path().join("f.txt")).unwrap().ino();
        assert_eq!(h.stat().await.unwrap().file_index, ino);
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
            .unwrap();
        let listed = root.list_dir(None).await.unwrap();
        let mut ids = Vec::new();
        for name in [a, b] {
            let h = backend.open(&p(name), opts_open_dir()).await.unwrap();
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
            let h = backend.open(&p(name), opts_create()).await.unwrap();
            h.close().await.unwrap();
        }

        let dir_h = backend
            .open(&SmbPath::root(), opts_open_dir())
            .await
            .unwrap();

        let txts = dir_h.list_dir(Some("*.txt")).await.unwrap();
        let names: Vec<_> = txts.iter().map(|e| e.info.name.as_str()).collect();
        assert_eq!(names.len(), 2, "expected 2 .txt files, got {names:?}");
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));

        // Single-char wildcard.
        let one = dir_h.list_dir(Some("?.log")).await.unwrap();
        let names: Vec<_> = one.iter().map(|e| e.info.name.as_str()).collect();
        assert_eq!(names, vec!["c.log"]);

        // Case-insensitive.
        let any_txt = dir_h.list_dir(Some("*.TXT")).await.unwrap();
        assert_eq!(any_txt.len(), 2);

        // "*" matches everything.
        let all = dir_h.list_dir(Some("*")).await.unwrap();
        assert_eq!(all.len(), 4);

        dir_h.close().await.unwrap();
    }

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.txt", "foo.txt"));
        assert!(!glob_match("*.txt", "foo.log"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("a*b*c", "axxxbxxxc"));
        assert!(glob_match("FOO", "foo"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
    }

    #[test]
    fn glob_match_dos_wildcards() {
        // DOS_STAR stops before the last dot.
        assert!(glob_match("<.txt", "ow.txt"));
        assert!(glob_match("<.txt", "a.b.txt"));
        assert!(glob_match("<.TXT", "ow.txt"));
        assert!(!glob_match("<.txt", "ow.log"));
        assert!(!glob_match("<", "a.b"));
        assert!(glob_match("<", "noext"));
        assert!(glob_match("<.<", "a.b"));
        // DOS_QM takes one character, or none at a dot or the end.
        assert!(glob_match(">w.txt", "ow.txt"));
        assert!(!glob_match(">w.txt", "w.txt"));
        assert!(glob_match(">>>.txt", "ab.txt"));
        assert!(glob_match("a>>", "a"));
        assert!(!glob_match("a>", "abc"));
        // DOS_DOT matches a dot, or nothing at the end.
        assert!(glob_match("a\"txt", "a.txt"));
        assert!(glob_match("abc\"", "abc"));
        assert!(!glob_match("a\"txt", "aXtxt"));
        assert!(glob_match("<\"<", "a.b"));
        assert!(glob_match("<\"<", "noext"));
        assert!(glob_match("<\"", "noext"));
        assert!(!glob_match("<\"", "a.b"));
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
        let h = backend.open(&p("d"), opts_open_dir()).await.unwrap();
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
        let h = backend.open(&p("f.txt"), opts_create()).await.unwrap();
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
        let h = backend.open(&p("f.txt"), opts_create()).await.unwrap();
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
    async fn unsupported_attributes_are_rejected() {
        let td = tempdir().unwrap();
        std::fs::create_dir(td.path().join("d")).unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let h = backend.open(&p("f.txt"), opts_create()).await.unwrap();
        assert!(matches!(
            h.set_attributes(0x2).await,
            Err(SmbError::NotSupported)
        ));
        h.close().await.unwrap();

        let dir = backend.open(&p("d"), opts_open_dir()).await.unwrap();
        assert!(matches!(
            dir.set_attributes(FILE_ATTRIBUTE_READONLY).await,
            Err(SmbError::NotSupported)
        ));
        dir.set_attributes(0).await.unwrap();
        dir.close().await.unwrap();
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
}
