//! `ShareBackend` and `Handle` traits: the storage abstraction.
//!
//! Implementors of these traits plug into `Share::new(name, backend)`. The
//! protocol layer never exposes raw FS types to backends; everything goes
//! through validated `SmbPath`s and the small structs below.

use async_trait::async_trait;
use std::time::SystemTime;

use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

// ---------------------------------------------------------------------------
// OpenOptions
// ---------------------------------------------------------------------------

/// SMB CREATE disposition as seen by a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenIntent {
    /// `FILE_OPEN`: open existing only; fail if missing.
    Open,
    /// `FILE_CREATE`: create new only; fail if exists.
    Create,
    /// `FILE_OPEN_IF`: open existing or create new.
    OpenOrCreate,
    /// `FILE_OVERWRITE_IF`: open existing (truncating) or create new.
    OverwriteOrCreate,
    /// `FILE_OVERWRITE`: open existing and truncate; fail if missing.
    Truncate,
}

/// Options passed to `ShareBackend::open`.
#[derive(Debug, Clone, Copy)]
pub struct OpenOptions {
    /// The open was granted `FILE_READ_DATA`, or has no data write access.
    /// At least one of `read` and `write` is set.
    pub read: bool,
    /// The open was granted `FILE_WRITE_DATA` or `FILE_APPEND_DATA`.
    pub write: bool,
    /// The open was granted `FILE_WRITE_ATTRIBUTES`: the handle must be able
    /// to change times and attributes, including on a read-only file.
    pub write_attributes: bool,
    /// CREATE disposition.
    pub intent: OpenIntent,
    /// `FILE_DIRECTORY_FILE` was set on CREATE: open or create a directory.
    pub directory: bool,
    /// `FILE_NON_DIRECTORY_FILE` was set on CREATE: fail if the target is a directory.
    pub non_directory: bool,
    /// `FILE_DELETE_ON_CLOSE` was set on CREATE.
    pub delete_on_close: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            read: true,
            write: false,
            write_attributes: false,
            intent: OpenIntent::Open,
            directory: false,
            non_directory: false,
            delete_on_close: false,
        }
    }
}

/// What `ShareBackend::open` did to the file (MS-SMB2 2.2.14 CreateAction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAction {
    /// An existing file or directory was opened.
    Opened,
    /// A new file or directory was created.
    Created,
    /// An existing file was truncated to zero length, as
    /// [`OpenIntent::Truncate`] and [`OpenIntent::OverwriteOrCreate`] do.
    Overwritten,
}

// ---------------------------------------------------------------------------
// FileInfo / DirEntry / FileTimes
// ---------------------------------------------------------------------------

/// Filesystem-style metadata for a single file or directory. Built with
/// [`FileInfo::new`]; every field is public.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FileInfo {
    /// Display name (last component). For QUERY_INFO at the share root this
    /// is the share name.
    pub name: String,
    /// File size in bytes.
    pub end_of_file: u64,
    /// Allocation size, usually `end_of_file` rounded up to a cluster.
    /// Backends may return `end_of_file`.
    pub allocation_size: u64,
    /// FILETIME (100ns ticks since 1601).
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    /// True if this is a directory.
    pub is_directory: bool,
    /// The file has `FILE_ATTRIBUTE_READONLY`.
    pub read_only: bool,
    /// Stable id of the file, unique within the share including any mounts
    /// below the share root, reported as the file id by QUERY_INFO and
    /// QUERY_DIRECTORY. Backends return the same value from `Handle::stat`
    /// and `Handle::list_dir` for the same file, across opens and renames.
    /// `0` if the backend has none; the server then tells files apart by
    /// path, so a file reached through two hard links counts as two files:
    /// share modes, byte-range locks and leases taken through one name do
    /// not see opens through the other, and clients on the two names can
    /// both cache writes to it.
    pub file_index: u64,
}

// File attributes (MS-FSCC 2.6).
pub(crate) const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub(crate) const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub(crate) const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub(crate) const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub(crate) const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub(crate) const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
pub(crate) const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
pub(crate) const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;

/// Attributes FileBasicInformation can set (MS-FSA 2.1.5.15.2).
pub(crate) const VALID_SET_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_TEMPORARY
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

impl FileInfo {
    /// A zero-length, writable file named `name` with no times and no file
    /// id. Set the fields the backend knows.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            end_of_file: 0,
            allocation_size: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            is_directory: false,
            read_only: false,
            file_index: 0,
        }
    }

    /// SMB2 file attributes (MS-FSCC 2.6) for this file:
    /// `FILE_ATTRIBUTE_DIRECTORY` for directories and
    /// `FILE_ATTRIBUTE_READONLY` for read-only files.
    /// `FILE_ATTRIBUTE_NORMAL` stands alone when neither applies.
    pub fn attributes(&self) -> u32 {
        let mut attributes = 0;
        if self.is_directory {
            attributes |= FILE_ATTRIBUTE_DIRECTORY;
        }
        if self.read_only {
            attributes |= FILE_ATTRIBUTE_READONLY;
        }
        if attributes == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            attributes
        }
    }
}

/// One entry of a directory listing.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub info: FileInfo,
}

/// Optional FILETIME values for `set_times`. `None` means "leave unchanged".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileTimes {
    pub creation_time: Option<u64>,
    pub last_access_time: Option<u64>,
    pub last_write_time: Option<u64>,
    pub change_time: Option<u64>,
}

impl FileTimes {
    /// `FileTimes` with all four fields set to `t`.
    pub fn all(t: SystemTime) -> Self {
        let ft = crate::utils::system_time_to_filetime(t);
        Self {
            creation_time: Some(ft),
            last_access_time: Some(ft),
            last_write_time: Some(ft),
            change_time: Some(ft),
        }
    }
}

// ---------------------------------------------------------------------------
// BackendCapabilities
// ---------------------------------------------------------------------------

/// Static, advertised capabilities of a backend. Built from
/// [`BackendCapabilities::default`]; every field is public.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct BackendCapabilities {
    /// If true, all write-class operations are denied at the protocol layer
    /// before reaching the backend (matches `LocalFsBackend::read_only()`).
    pub is_read_only: bool,
    /// True iff the backend treats names case-sensitively.
    pub case_sensitive: bool,
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Pluggable storage backend mounted as a share.
///
/// Implementors must be `Send + Sync + 'static` so the server can spawn
/// per-request handlers freely.
#[async_trait]
pub trait ShareBackend: Send + Sync + 'static {
    /// Open or create a file or directory. Returns a fresh handle and what
    /// the open did to the file.
    ///
    /// Fail with [`SmbError::PathNotFound`] when a directory on the way to
    /// `path` is missing and [`SmbError::NotFound`] when only the last
    /// component is.
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)>;

    /// Delete a file or an empty directory.
    async fn unlink(&self, path: &SmbPath) -> SmbResult<()>;

    /// Rename `from` to `to`.
    ///
    /// If `to` names an existing file other than `from`, including another
    /// hard link to the same file, fail with [`SmbError::Exists`] unless
    /// `replace_if_exists` is set, in which case the existing file is
    /// replaced. An existing directory at `to` is never
    /// replaced: fail with [`SmbError::AccessDenied`].
    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()>;

    /// Static capabilities. TREE_CONNECT clamps access to read-only when
    /// `is_read_only` is set.
    fn capabilities(&self) -> BackendCapabilities;

    /// Size, free space and identity of the volume behind the share, for the
    /// filesystem QUERY_INFO classes. The default returns
    /// [`VolumeInfo::default`].
    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        Ok(VolumeInfo::default())
    }
}

/// A live open file or directory handle.
///
/// One handle per `CREATE`. `close` runs when CLOSE arrives, and when the
/// tree, session or connection the open belongs to ends.
#[async_trait]
pub trait Handle: Send + Sync {
    /// Read up to `len` bytes at `offset`. May return fewer.
    async fn read(&self, offset: u64, len: u32) -> SmbResult<bytes::Bytes>;

    /// Write `data` at `offset`. Returns bytes written.
    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32>;

    /// Write owned `data` at `offset`. Backends that need ownership across a
    /// blocking boundary can override this to avoid an extra copy.
    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        self.write(offset, &data).await
    }

    /// Flush buffered writes. May be a no-op on backends that always flush.
    async fn flush(&self) -> SmbResult<()>;

    /// Stat: current file info.
    async fn stat(&self) -> SmbResult<FileInfo>;

    /// Set timestamps on a file or directory. `None` fields leave the
    /// corresponding time alone.
    ///
    /// Return [`SmbError::NotSupported`] for an access or write time the
    /// backend cannot store. A backend that cannot store a creation time
    /// ignores it and applies the other fields; a request with only a
    /// creation time then succeeds and changes nothing.
    /// `change_time` is the time of the last change: a backend whose
    /// storage moves it to the current time on every change, as POSIX ctime
    /// does, may keep doing so and not store the requested value.
    ///
    /// `LocalFsBackend` sets access and write times on every host and
    /// creation time on Windows and macOS. Elsewhere it ignores the creation
    /// time. The host keeps the change time.
    async fn set_times(&self, times: FileTimes) -> SmbResult<()>;

    /// Set the attributes (MS-FSCC 2.6) of a file or directory to
    /// `attributes`, a combination of `FILE_ATTRIBUTE_READONLY` (0x1),
    /// `HIDDEN` (0x2), `SYSTEM` (0x4), `ARCHIVE` (0x20), `TEMPORARY`
    /// (0x100), `OFFLINE` (0x1000) and `NOT_CONTENT_INDEXED` (0x2000).
    /// Flags left out are cleared. The protocol layer calls this only when
    /// the request differs from the attributes [`Handle::stat`] reports.
    ///
    /// Return [`SmbError::NotSupported`] if a flag cannot be stored.
    ///
    /// `LocalFsBackend` stores `READONLY` on files: on Unix as the absence
    /// of write permission bits, on Windows as the host attribute. It
    /// accepts `ARCHIVE` without storing it and never reports it. Every
    /// other flag, and `READONLY` on a directory, returns `NotSupported`.
    async fn set_attributes(&self, attributes: u32) -> SmbResult<()>;

    /// Truncate (or extend) to `len` bytes. For directories: the protocol
    /// layer rejects this before reaching the backend.
    async fn truncate(&self, len: u64) -> SmbResult<()>;

    /// List directory entries matching the optional pattern. The pattern
    /// uses the wildcards of MS-FSA 2.1.4.4: `*` and `?`, and the DOS forms
    /// `<` (DOS_STAR), `>` (DOS_QM) and `"` (DOS_DOT).
    /// QUERY_DIRECTORY returns the result as is, so the backend applies the
    /// pattern. The `.` and `..` entries are left out; QUERY_DIRECTORY adds
    /// them.
    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>>;

    /// Close the handle. Boxed self lets implementors consume internal state.
    async fn close(self: Box<Self>) -> SmbResult<()>;

    /// Number of hard links to the file, reported as NumberOfLinks by
    /// FileStandardInformation. `0` means the file has been deleted while
    /// open. The default reports `1`.
    async fn link_count(&self) -> SmbResult<u32> {
        Ok(1)
    }

    /// True if this directory has no entries other than `.` and `..`,
    /// including entries [`Handle::list_dir`] leaves out. The default checks
    /// `list_dir(None)`, so a backend whose listing hides entries overrides
    /// it.
    async fn dir_is_empty(&self) -> SmbResult<bool> {
        Ok(self.list_dir(None).await?.is_empty())
    }
}

/// Backend for the synthetic IPC$ share. `open`, `unlink` and `rename`
/// return [`SmbError::NotSupported`].
pub(crate) struct NotSupportedBackend;

#[async_trait]
impl ShareBackend for NotSupportedBackend {
    async fn open(
        &self,
        _path: &SmbPath,
        _opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        Err(SmbError::NotSupported)
    }
    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }
    async fn rename(&self, _from: &SmbPath, _to: &SmbPath, _replace: bool) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: true,
            case_sensitive: false,
        }
    }
}

// ---------------------------------------------------------------------------
// VolumeInfo
// ---------------------------------------------------------------------------

/// Volume behind a share, as reported by FileFsVolumeInformation,
/// FileFsSizeInformation, FileFsFullSizeInformation,
/// FileFsAttributeInformation and FileFsSectorSizeInformation (MS-FSCC 2.5).
///
/// Sizes count allocation units of `sectors_per_allocation_unit *
/// bytes_per_sector` bytes. Built from [`VolumeInfo::default`]; every
/// field is public.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeInfo {
    /// Total allocation units on the volume.
    pub total_allocation_units: u64,
    /// Free allocation units available to the share's users, after quotas
    /// and reserved space.
    pub caller_available_allocation_units: u64,
    /// Free allocation units on the volume.
    pub actual_available_allocation_units: u64,
    /// Sectors in one allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// Bytes in one sector.
    pub bytes_per_sector: u32,
    /// Volume serial number.
    pub serial_number: u32,
    /// Volume label. `None` reports the share name.
    pub label: Option<String>,
    /// Longest file name the volume stores, in characters.
    pub max_name_length: u32,
}

impl Default for VolumeInfo {
    /// A 4 PiB volume with 2 PiB free, in 4 KiB allocation units.
    fn default() -> Self {
        Self {
            total_allocation_units: 1 << 40,
            caller_available_allocation_units: 1 << 39,
            actual_available_allocation_units: 1 << 39,
            sectors_per_allocation_unit: 1,
            bytes_per_sector: 4096,
            serial_number: crate::info_class::VOLUME_SERIAL_NUMBER,
            label: None,
            max_name_length: 255,
        }
    }
}
