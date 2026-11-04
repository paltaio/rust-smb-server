//! The store for named streams that do not fit in an extended attribute.
//!
//! The store is a directory, `.smb-streams` in the share root unless the
//! embedder names one outside the share, with a file `store-id` holding a
//! random id. It holds one entry per file with spilled streams: a
//! directory named by a random 128-bit id in hex, with one file per
//! stream, named by the hex of the stream name's UTF-8, and a file `owner`
//! holding the entry's record. The file keeps the same record in its
//! extended attribute `user.smb-server.streams`: the entry id, the store
//! id, and the identity of the file the entry was made for, its file
//! handle where the filesystem gives one, else its inode number and birth
//! time.
//!
//! A record whose identity is not the file's own makes the file a copy of
//! that file, or a file put in its place: it reads that file's spilled
//! streams, and gets an entry of its own, with a copy of them, before any
//! of its spilled streams change. A file whose identity changes, as after
//! a restore from backup, copies its streams once that way; a file in a
//! snapshot reads the spilled streams of the live file until it changes
//! them. A record of another store, or one naming an entry whose `owner`
//! file holds another record, is left alone, and the file keeps its
//! streams in extended attributes only. A record of this store naming an
//! entry it no longer has gets a new entry when a stream spills.
//!
//! The store, its entries and their files are opened one name at a time
//! without following symlinks, and used only when they belong to the
//! server's user and give no access to group or others; a stream file
//! with more than one link is refused.
//!
//! [`Store::sweep`] removes an entry only once two sweeps in a row found no
//! record naming it and nothing used it in between, so a file that was
//! moved while a sweep walked the share keeps its streams. Requests that
//! use the store wait while the second part of a sweep goes over the
//! store's entries, for as long as that pass takes.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, PoisonError, Weak};

use cap_std::fs::Dir;
use rustix::fs::{AtFlags, Mode, OFlags, StatxFlags, XattrFlags};
use rustix::io::Errno;
use tracing::{debug, warn};

use crate::stream::StreamName;

/// Name of the store in the share root.
pub(in crate::fs) const STORE_NAME: &str = ".smb-streams";

/// The extended attribute that holds a file's record.
const RECORD_ATTR: &str = "user.smb-server.streams";

/// The file in an entry that holds its record.
const OWNER_FILE: &str = "owner";

/// The file in an entry that a sweep leaves when it finds no record naming
/// the entry; the next sweep removes the entry if the file is still there.
const UNREFERENCED: &str = "unreferenced";

/// The file in the store that holds its random id, which records made for
/// it carry.
const STORE_ID_FILE: &str = "store-id";

/// Version of the record layout.
const RECORD_VERSION: u8 = 1;

/// Prefix of a stream file while it is written, and of one a rename set
/// aside.
const ASIDE: char = '~';

/// Longest name in a directory (NAME_MAX).
const MAX_FILE_NAME: usize = 255;

/// Longest stream a rename to or from the default stream copies when the
/// filesystem cannot clone it.
pub(in crate::fs) const MAX_COPY: u64 = 64 << 20;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The effective user id of the server.
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// A store, entry or stream file that is not private to the server's user,
/// or not what this server makes.
#[derive(Debug)]
struct NotPrivate;

impl std::fmt::Display for NotPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not private to the server's user")
    }
}

impl std::error::Error for NotPrivate {}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, NotPrivate)
}

/// True if `e` is a refusal of something not private to the server, or
/// not a directory or file where one should be: not something this server
/// made.
fn not_ours(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<NotPrivate>())
        || matches!(
            e.raw_os_error().map(Errno::from_raw_os_error),
            Some(Errno::LOOP | Errno::NOTDIR | Errno::ISDIR)
        )
}

/// The error for a file whose record belongs to someone else: its
/// streams cannot move to this store.
fn foreign() -> io::Error {
    io::ErrorKind::StorageFull.into()
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// What a record says identifies a file: kind 1 is a file handle (type,
/// then handle bytes), kind 0 an inode number and birth time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity(Vec<u8>);

/// A record: the entry id, the id of the store it is in, the layout
/// version, then the identity of the file it was made for. A sweep reads
/// the first 16 bytes of any record as the id of an entry it keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    id: [u8; 16],
    store: [u8; 16],
    of: Identity,
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut out = self.id.to_vec();
        out.extend_from_slice(&self.store);
        out.push(RECORD_VERSION);
        out.extend_from_slice(&self.of.0);
        out
    }

    fn decode(value: &[u8]) -> Option<Self> {
        let (id, rest) = value.split_at_checked(16)?;
        let (store, rest) = rest.split_at_checked(16)?;
        let (&version, of) = rest.split_first()?;
        if version != RECORD_VERSION {
            return None;
        }
        let valid = match of.first()? {
            0 => of.len() == 1 + 8 + 8 + 4,
            1 => of.len() > 1 + 4 && of.len() <= 1 + 4 + 128,
            _ => false,
        };
        valid.then(|| Self {
            id: id.try_into().unwrap(),
            store: store.try_into().unwrap(),
            of: Identity(of.to_vec()),
        })
    }

    fn dir_name(&self) -> String {
        hex(&self.id)
    }
}

/// The identity of the file `fd` is open on.
fn identity_of(fd: &impl AsFd) -> io::Result<Identity> {
    if let Some(handle) = file_handle(fd) {
        return Ok(handle);
    }
    let st = rustix::fs::statx(
        fd,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::INO | StatxFlags::BTIME,
    )?;
    let (secs, nanos) = if st.stx_mask & StatxFlags::BTIME.bits() != 0 {
        (st.stx_btime.tv_sec, st.stx_btime.tv_nsec)
    } else {
        (0, 0)
    };
    let mut out = vec![0];
    out.extend_from_slice(&st.stx_ino.to_le_bytes());
    out.extend_from_slice(&secs.to_le_bytes());
    out.extend_from_slice(&nanos.to_le_bytes());
    Ok(Identity(out))
}

/// The file handle of the file `fd` is open on, which tells files apart
/// across inode reuse and snapshots where the filesystem gives one.
fn file_handle(fd: &impl AsFd) -> Option<Identity> {
    use std::os::fd::AsRawFd as _;

    #[repr(C)]
    struct Handle {
        bytes: u32,
        kind: i32,
        data: [u8; 128],
    }
    let mut handle = Handle {
        bytes: 128,
        kind: 0,
        data: [0; 128],
    };
    let mut mount_id = 0;
    // SAFETY: `handle` starts with the header of `struct file_handle` and
    // has room for MAX_HANDLE_SZ bytes after it, as `bytes` says; the path
    // is a NUL-terminated empty string.
    let rc = unsafe {
        libc::name_to_handle_at(
            fd.as_fd().as_raw_fd(),
            c"".as_ptr(),
            (&raw mut handle).cast(),
            &mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    let len = handle.bytes as usize;
    if rc != 0 || len == 0 || len > handle.data.len() {
        return None;
    }
    let mut out = vec![1];
    out.extend_from_slice(&handle.kind.to_le_bytes());
    out.extend_from_slice(&handle.data[..len]);
    Some(Identity(out))
}

/// The record of the file `fd` is open on.
enum Found {
    None,
    /// A record this server cannot read.
    Unreadable,
    Record(Record),
}

fn read_record(fd: &impl AsFd) -> io::Result<Found> {
    let mut buf = [0u8; 256];
    match rustix::fs::fgetxattr(fd, RECORD_ATTR, &mut buf[..]) {
        Ok(len) => Ok(Record::decode(&buf[..len]).map_or(Found::Unreadable, Found::Record)),
        Err(Errno::NODATA | Errno::NOTSUP) => Ok(Found::None),
        Err(Errno::RANGE) => Ok(Found::Unreadable),
        Err(e) => Err(e.into()),
    }
}

/// The entry id at the start of the record of the file `fd` is open on,
/// whatever layout the rest has.
fn record_id(fd: &impl AsFd) -> io::Result<Option<[u8; 16]>> {
    let mut buf = [0u8; 256];
    match rustix::fs::fgetxattr(fd, RECORD_ATTR, &mut buf[..]) {
        Ok(len) if len >= 16 => Ok(Some(buf[..16].try_into().unwrap())),
        Ok(_) | Err(Errno::NODATA | Errno::NOTSUP) => Ok(None),
        Err(Errno::RANGE) => {
            let mut value = vec![0u8; 65536];
            let len = rustix::fs::fgetxattr(fd, RECORD_ATTR, &mut value[..])?;
            Ok((len >= 16).then(|| value[..16].try_into().unwrap()))
        }
        Err(e) => Err(e.into()),
    }
}

fn write_record(fd: &File, record: &Record, flags: XattrFlags) -> io::Result<()> {
    Ok(rustix::fs::fsetxattr(
        fd,
        RECORD_ATTR,
        &record.encode(),
        flags,
    )?)
}

fn new_id() -> io::Result<[u8; 16]> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty()
        || !s.len().is_multiple_of(2)
        || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&s[at..at + 2], 16).ok())
        .collect()
}

/// The name of the file that holds the stream `stream`. A name too long
/// for one cannot be spilled, which stops the stream from growing.
fn file_name(stream: &StreamName) -> io::Result<String> {
    let name = hex(stream.as_str().as_bytes());
    // Room for the prefixes of a file being written or set aside.
    if name.len() + 2 > MAX_FILE_NAME {
        return Err(io::ErrorKind::StorageFull.into());
    }
    Ok(name)
}

/// The stream a file in a store entry holds, if its name is one.
fn stream_of(file_name: &str) -> Option<StreamName> {
    String::from_utf8(unhex(file_name)?).ok()?.parse().ok()
}

// ---------------------------------------------------------------------------
// Checked opens
// ---------------------------------------------------------------------------

/// Fails unless what `fd` is open on belongs to the server's user and
/// gives no access to group or others.
fn check_private(fd: &impl AsFd) -> io::Result<()> {
    let st = rustix::fs::fstat(fd)?;
    if st.st_uid != euid() || st.st_mode & 0o077 != 0 {
        return Err(refused());
    }
    Ok(())
}

/// Opens the directory `name` in `parent` without following a symlink,
/// made with mode 0700 first with `create`. `None` if it is missing.
fn open_dir(parent: &impl AsFd, name: impl AsRef<OsStr>, create: bool) -> io::Result<Option<Dir>> {
    let name = name.as_ref();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let open = || rustix::fs::openat(parent, name, flags, Mode::empty());
    let fd = match open() {
        Ok(fd) => fd,
        Err(Errno::NOENT) if create => {
            match rustix::fs::mkdirat(parent, name, Mode::RWXU) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
            open()?
        }
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(Dir::from_std_file(File::from(fd))))
}

/// Opens the private directory `name` in `parent`, as [`open_dir`] does.
fn open_private_dir(parent: &impl AsFd, name: &str, create: bool) -> io::Result<Option<Dir>> {
    let Some(dir) = open_dir(parent, name, create)? else {
        return Ok(None);
    };
    check_private(&dir)?;
    Ok(Some(dir))
}

/// Opens the file `name` in the entry `dir` without following a symlink,
/// and fails unless it is a private regular file with one link.
fn open_file(dir: &Dir, name: &str, flags: OFlags) -> io::Result<File> {
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = File::from(rustix::fs::openat(
        dir,
        name,
        flags,
        Mode::RUSR | Mode::WUSR,
    )?);
    let md = file.metadata()?;
    if !md.is_file() || md.nlink() != 1 {
        return Err(refused());
    }
    check_private(&file)?;
    Ok(file)
}

fn exists(dir: &impl AsFd, name: &str) -> bool {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).is_ok()
}

/// Removes the file `name` in `dir`, if it is there.
fn remove_if_there(dir: &impl AsFd, name: &str) -> io::Result<()> {
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Fills `to` from `from`: a clone where the filesystem can make one,
/// else a copy, of at most `limit` bytes when given.
pub(in crate::fs) fn fill(to: &File, from: &File, limit: Option<u64>) -> io::Result<u64> {
    let len = from.metadata()?.len();
    if rustix::fs::ioctl_ficlone(to, from).is_ok() {
        return Ok(len);
    }
    if limit.is_some_and(|limit| len > limit) {
        return Err(io::ErrorKind::StorageFull.into());
    }
    to.set_len(0)?;
    let mut buf = vec![0; 1 << 16];
    let mut at = 0u64;
    loop {
        let n = from.read_at(&mut buf, at)?;
        if n == 0 {
            to.set_len(at)?;
            return Ok(at);
        }
        to.write_all_at(&buf[..n], at)?;
        at += n as u64;
    }
}

/// The streams the entry `dir` holds, at most `max`.
fn names(dir: &Dir, max: usize) -> io::Result<Vec<StreamName>> {
    let mut out = Vec::new();
    for entry in dir.entries()? {
        if out.len() == max {
            break;
        }
        if let Some(stream) = entry?.file_name().to_str().and_then(stream_of) {
            out.push(stream);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The sweep lock
// ---------------------------------------------------------------------------

/// Held shared by every use of a store, and exclusively by a sweep while
/// it removes entries. One per store directory in the process, so backends
/// sharing a store share it.
#[derive(Default)]
struct SweepLock {
    state: Mutex<(usize, bool)>,
    changed: Condvar,
}

/// The sweep locks of the stores in use, by device and inode.
type SweepLocks = Mutex<HashMap<(u64, u64), Weak<SweepLock>>>;

static SWEEP_LOCKS: LazyLock<SweepLocks> = LazyLock::new(Mutex::default);

fn sweep_lock(key: (u64, u64)) -> Arc<SweepLock> {
    let mut locks = lock(&SWEEP_LOCKS);
    locks.retain(|_, l| l.strong_count() > 0);
    if let Some(found) = locks.get(&key).and_then(Weak::upgrade) {
        return found;
    }
    let made = Arc::new(SweepLock::default());
    locks.insert(key, Arc::downgrade(&made));
    made
}

struct Shared(Arc<SweepLock>);

impl Shared {
    fn take(lock: Arc<SweepLock>) -> Self {
        let mut state = self::lock(&lock.state);
        while state.1 {
            state = lock
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.0 += 1;
        drop(state);
        Self(lock)
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        let mut state = lock(&self.0.state);
        state.0 -= 1;
        drop(state);
        self.0.changed.notify_all();
    }
}

struct Exclusive(Arc<SweepLock>);

impl Exclusive {
    fn take(lock: Arc<SweepLock>) -> Self {
        let mut state = self::lock(&lock.state);
        while state.1 {
            state = lock
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        // New users wait from here on, so the ones in flight finish.
        state.1 = true;
        while state.0 > 0 {
            state = lock
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(state);
        Self(lock)
    }
}

impl Drop for Exclusive {
    fn drop(&mut self) {
        lock(&self.0.state).1 = false;
        self.0.changed.notify_all();
    }
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// The stream store of one backend.
pub(in crate::fs) struct Store {
    at: At,
    /// Device and inode of the store directory, once it exists.
    key: Mutex<Option<(u64, u64)>>,
    /// The store and its id exist.
    prepared: std::sync::atomic::AtomicBool,
}

enum At {
    /// `.smb-streams` in the share root.
    Share(Arc<Dir>),
    /// A directory the embedder named.
    Dir(Dir),
}

/// The store directory, open and in use: entries are not removed while it
/// is held.
pub(in crate::fs) struct Held {
    dir: Dir,
    /// The store's id, which its records carry.
    id: [u8; 16],
    _shared: Shared,
}

/// The spilled streams of one file: the store entry they are in and their
/// names, spelled as stored. Valid while the [`Held`] it came from is.
pub(in crate::fs) struct Spilled {
    pub(in crate::fs) dir: Dir,
    pub(in crate::fs) names: Vec<StreamName>,
}

/// What the record of a file means to this store.
enum Standing {
    /// No record.
    None,
    /// A record for another store or one this server cannot use.
    Foreign,
    /// A record of this store naming an entry it no longer has.
    Lost,
    /// A record naming an entry of this store, given to this file
    /// (`owned`) or to the file it is a copy of.
    Entry { dir: Dir, owned: bool },
}

/// The id of the store `dir`. A store without one takes the id its
/// entries' records carry, or a new one when it has no entries; a store
/// whose id file cannot be read, or whose entries disagree, is not used.
fn store_id(dir: &Dir) -> io::Result<[u8; 16]> {
    for _ in 0..2 {
        let mut id = [0; 16];
        let short = match open_file(dir, STORE_ID_FILE, OFlags::RDONLY) {
            Ok(file) => match file.read_at(&mut id, 0) {
                Ok(16) => return Ok(id),
                Ok(_) => true,
                Err(_) => return Err(refused()),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(refused()),
        };
        let from_entries = id_of_entries(dir)?;
        if short {
            // A store id left short, by a crash or a write still under way,
            // is made again only in a store that no record refers to yet.
            if from_entries.is_some() {
                return Err(refused());
            }
            remove_if_there(dir, STORE_ID_FILE)?;
        }
        let id = match from_entries {
            Some(id) => id,
            None => new_id()?,
        };
        publish_store_id(dir, &id)?;
    }
    Err(refused())
}

/// Writes `id` as the id of the store `dir`, unless another backend did
/// first: through a temporary file renamed into place without replacing
/// one, or, on a filesystem without that rename, by creating the file.
fn publish_store_id(dir: &Dir, id: &[u8; 16]) -> io::Result<()> {
    let temp = format!("{ASIDE}{STORE_ID_FILE}");
    remove_if_there(dir, &temp)?;
    let file = open_file(dir, &temp, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
    file.write_all_at(id, 0)?;
    file.sync_all()?;
    #[cfg(test)]
    let forced = NO_RENAME_NOREPLACE.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(test))]
    let forced = false;
    let renamed = if forced {
        Err(Errno::INVAL)
    } else {
        rustix::fs::renameat_with(
            dir,
            &temp,
            dir,
            STORE_ID_FILE,
            rustix::fs::RenameFlags::NOREPLACE,
        )
    };
    match renamed {
        Ok(()) => return Ok(rustix::fs::fsync(dir)?),
        Err(Errno::EXIST) => return remove_if_there(dir, &temp),
        Err(_) => remove_if_there(dir, &temp)?,
    }
    match open_file(
        dir,
        STORE_ID_FILE,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
    ) {
        Ok(file) => {
            file.write_all_at(id, 0)?;
            file.sync_all()?;
            Ok(rustix::fs::fsync(dir)?)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Makes [`publish_store_id`] act as on a filesystem without
/// RENAME_NOREPLACE.
#[cfg(test)]
pub(in crate::fs) static NO_RENAME_NOREPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The store id the records of the entries of the store `dir` carry, if
/// it has any; they must all carry the same. An entry with no `owner` and
/// no streams, as a crash while it was made leaves one, is left out.
fn id_of_entries(dir: &Dir) -> io::Result<Option<[u8; 16]>> {
    let mut found = None;
    for entry in dir.entries()? {
        let name = entry?.file_name();
        let Some(name) = name
            .to_str()
            .filter(|n| unhex(n).is_some_and(|id| id.len() == 16))
        else {
            continue;
        };
        let Some(entry) = open_private_dir(dir, name, false).map_err(|_| refused())? else {
            continue;
        };
        let mut stored = Vec::new();
        match open_file(&entry, OWNER_FILE, OFlags::RDONLY) {
            Ok(mut owner) => {
                io::Read::read_to_end(&mut owner, &mut stored).map_err(|_| refused())?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if names(&entry, 1).map_err(|_| refused())?.is_empty() {
                    continue;
                }
                return Err(refused());
            }
            Err(_) => return Err(refused()),
        }
        let store = Record::decode(&stored).ok_or_else(refused)?.store;
        if found.is_some_and(|found| found != store) {
            return Err(refused());
        }
        found = Some(store);
    }
    Ok(found)
}

fn dir_key(dir: &impl AsFd) -> io::Result<(u64, u64)> {
    let st = rustix::fs::fstat(dir)?;
    Ok((st.st_dev, st.st_ino))
}

impl Store {
    pub(in crate::fs) fn in_share(root: Arc<Dir>) -> Self {
        let store = Self {
            at: At::Share(root),
            key: Mutex::new(None),
            prepared: Default::default(),
        };
        let _ = store.key();
        store
    }

    /// The store in `dir`, which must be private to the server's user and
    /// lie outside `root`, the share root.
    pub(in crate::fs) fn at(dir: Dir, root: &Dir) -> io::Result<Self> {
        let dir = open_dir(&dir, ".", false)?.ok_or(io::ErrorKind::NotFound)?;
        check_private(&dir)?;
        let root_key = dir_key(root)?;
        let mut at = dir_key(&dir)?;
        let mut up = File::from(dir.as_fd().try_clone_to_owned()?);
        loop {
            if at == root_key {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the stream store lies in the share",
                ));
            }
            let parent = File::from(rustix::fs::openat(
                &up,
                "..",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let parent_key = dir_key(&parent)?;
            if parent_key == at {
                break;
            }
            (up, at) = (parent, parent_key);
        }
        let key = dir_key(&dir)?;
        Ok(Self {
            at: At::Dir(dir),
            key: Mutex::new(Some(key)),
            prepared: Default::default(),
        })
    }

    /// True once [`Store::prepare`] made the store.
    pub(in crate::fs) fn prepared(&self) -> bool {
        self.prepared.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Makes the store and its id, if they are missing.
    pub(in crate::fs) fn prepare(&self) {
        match self.hold(true) {
            Ok(_) => self
                .prepared
                .store(true, std::sync::atomic::Ordering::Release),
            Err(e) => warn_unusable(&e),
        }
    }

    /// The name the store takes in the share root, if it is there.
    pub(in crate::fs) fn hidden_name(&self) -> Option<&'static str> {
        matches!(self.at, At::Share(_)).then_some(STORE_NAME)
    }

    /// The name the store takes in `dir` when `dir` is the share root it
    /// lies in.
    pub(in crate::fs) fn hidden_in(&self, dir: &impl AsFd) -> Option<&'static str> {
        let At::Share(root) = &self.at else {
            return None;
        };
        (dir_key(dir).ok()? == dir_key(&**root).ok()?).then_some(STORE_NAME)
    }

    /// The store directory, made with `create`, checked private. `None`
    /// if it is missing.
    fn dir(&self, create: bool) -> io::Result<Option<Dir>> {
        let dir = match &self.at {
            // Anything but a directory there is no store this server uses.
            At::Share(root) => match self.share_dir(root, create) {
                Err(e)
                    if matches!(
                        e.raw_os_error().map(Errno::from_raw_os_error),
                        Some(Errno::LOOP | Errno::NOTDIR)
                    ) =>
                {
                    return Err(refused());
                }
                dir => dir?,
            },
            At::Dir(dir) => {
                let dir = dir.try_clone()?;
                check_private(&dir)?;
                Some(dir)
            }
        };
        if let Some(dir) = &dir {
            *lock(&self.key) = Some(dir_key(dir)?);
        }
        Ok(dir)
    }

    /// The store in the share root `root`, made on disk, the root's entry
    /// for it included, with `create`.
    fn share_dir(&self, root: &Dir, create: bool) -> io::Result<Option<Dir>> {
        if let Some(dir) = open_private_dir(root, STORE_NAME, false)? {
            return Ok(Some(dir));
        }
        if !create {
            return Ok(None);
        }
        let dir = open_private_dir(root, STORE_NAME, true)?;
        rustix::fs::fsync(super::super::local::dir_as_file(root)?)?;
        Ok(dir)
    }

    /// Device and inode of the store directory, if it exists.
    pub(in crate::fs) fn key(&self) -> Option<(u64, u64)> {
        if let Some(key) = *lock(&self.key) {
            return Some(key);
        }
        self.dir(false).ok().flatten()?;
        *lock(&self.key)
    }

    /// The store directory, made with `create` and held. `None` if it is
    /// missing.
    pub(in crate::fs) fn hold(&self, create: bool) -> io::Result<Option<Held>> {
        let Some(dir) = self.dir(create)? else {
            return Ok(None);
        };
        let shared = Shared::take(sweep_lock(dir_key(&dir)?));
        let id = store_id(&dir).map_err(|e| {
            if !not_ours(&e) {
                debug!(error = %e, "stream store id not made");
            }
            refused()
        })?;
        Ok(Some(Held {
            dir,
            id,
            _shared: shared,
        }))
    }

    /// What the record of the file `fd` is open on means here.
    fn standing(&self, held: &Held, fd: &File) -> io::Result<Standing> {
        let record = match read_record(fd)? {
            Found::None => return Ok(Standing::None),
            Found::Unreadable => return Ok(Standing::Foreign),
            Found::Record(record) if record.store != held.id => return Ok(Standing::Foreign),
            Found::Record(record) => record,
        };
        let dir = match open_private_dir(&held.dir, &record.dir_name(), false) {
            Ok(Some(dir)) => dir,
            Ok(None) => return Ok(Standing::Lost),
            Err(e) if not_ours(&e) => return Ok(Standing::Foreign),
            Err(e) => return Err(e),
        };
        let mut owner = match open_file(&dir, OWNER_FILE, OFlags::RDONLY) {
            Ok(owner) => owner,
            Err(e) if not_ours(&e) || e.kind() == io::ErrorKind::NotFound => {
                return Ok(Standing::Foreign);
            }
            Err(e) => return Err(e),
        };
        let mut stored = Vec::new();
        io::Read::read_to_end(&mut owner, &mut stored)?;
        if stored != record.encode() {
            return Ok(Standing::Foreign);
        }
        if let Err(e) = remove_if_there(&dir, UNREFERENCED) {
            debug!(error = %e, "store entry in use left marked unreferenced");
        }
        let owned = record.of == identity_of(fd)?;
        Ok(Standing::Entry { dir, owned })
    }

    /// The spilled streams of the file `fd` is open on, at most `max`,
    /// where its record points, also when the file is a copy that has no
    /// entry of its own yet.
    pub(in crate::fs) fn find(
        &self,
        held: &Held,
        fd: &File,
        max: usize,
    ) -> io::Result<Option<Spilled>> {
        match self.standing(held, fd)? {
            Standing::Entry { dir, .. } => {
                let names = names(&dir, max)?;
                Ok(Some(Spilled { dir, names }))
            }
            _ => Ok(None),
        }
    }

    /// Makes an entry for the file `fd` is open on, with the identity
    /// `of`, and returns it with its record, which the file does not carry
    /// yet.
    fn make_entry(&self, held: &Held, of: Identity) -> io::Result<(Record, Dir)> {
        loop {
            let record = Record {
                id: new_id()?,
                store: held.id,
                of: of.clone(),
            };
            let name = record.dir_name();
            match rustix::fs::mkdirat(&held.dir, &name, Mode::RWXU) {
                Ok(()) => {}
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(e.into()),
            }
            let made = (|| {
                let dir =
                    open_private_dir(&held.dir, &name, false)?.ok_or(io::ErrorKind::NotFound)?;
                let owner = open_file(
                    &dir,
                    OWNER_FILE,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                );
                let owner = owner?;
                owner.write_all_at(&record.encode(), 0)?;
                owner.sync_all()?;
                rustix::fs::fsync(&dir)?;
                rustix::fs::fsync(&held.dir)?;
                Ok(dir)
            })();
            return match made {
                Ok(dir) => Ok((record, dir)),
                Err(e) => {
                    let _ = held.dir.remove_dir_all(&name);
                    Err(e)
                }
            };
        }
    }

    /// Gives the file `fd` is open on an entry of its own when it reads
    /// another file's: a new id, with a copy of the streams there. Called
    /// before any of the file's spilled streams change.
    fn claim(&self, held: &Held, fd: &File) -> io::Result<()> {
        let Standing::Entry {
            dir: source,
            owned: false,
            ..
        } = self.standing(held, fd)?
        else {
            return Ok(());
        };
        let (mine, dir) = self.make_entry(held, identity_of(fd)?)?;
        let copied = (|| {
            let spilled = Spilled {
                dir,
                names: Vec::new(),
            };
            for stream in names(&source, usize::MAX)? {
                let from = open_file(&source, &file_name(&stream)?, OFlags::RDONLY)?;
                spilled.put(&stream, |to| fill(to, &from, None).map(drop))?;
            }
            write_record(fd, &mine, XattrFlags::REPLACE)
        })();
        if copied.is_err() {
            let _ = held.dir.remove_dir_all(mine.dir_name());
        }
        copied
    }

    /// The spilled streams of the file `fd` is open on, in an entry of its
    /// own: a copy claims one first.
    pub(in crate::fs) fn find_own(
        &self,
        held: &Held,
        fd: &File,
        max: usize,
    ) -> io::Result<Option<Spilled>> {
        self.claim(held, fd)?;
        self.find(held, fd, max)
    }

    /// The entry of the file `fd` is open on, its own, made when it has
    /// none. Fails for a file whose record belongs to someone else.
    pub(in crate::fs) fn own(&self, held: &Held, fd: &File, max: usize) -> io::Result<Spilled> {
        self.claim(held, fd)?;
        let flags = match self.standing(held, fd)? {
            Standing::Entry {
                dir, owned: true, ..
            } => {
                let names = names(&dir, max)?;
                return Ok(Spilled { dir, names });
            }
            Standing::Entry { .. } | Standing::Foreign => return Err(foreign()),
            Standing::None => XattrFlags::CREATE,
            Standing::Lost => XattrFlags::REPLACE,
        };
        let (record, dir) = self.make_entry(held, identity_of(fd)?)?;
        if let Err(e) = write_record(fd, &record, flags) {
            let _ = held.dir.remove_dir_all(record.dir_name());
            return Err(match e.raw_os_error().map(Errno::from_raw_os_error) {
                Some(Errno::EXIST | Errno::NODATA) => foreign(),
                _ => e,
            });
        }
        Ok(Spilled {
            dir,
            names: Vec::new(),
        })
    }

    /// Removes the store entries that no record names, two sweeps in a row
    /// and with no use in between, and the leftovers of writes that did
    /// not finish. Returns how many entries went.
    ///
    /// The walk of the share holds nothing; only the pass over the store
    /// holds it, and stream requests that use the store wait for it. A
    /// file whose record cannot be read stops the sweep before it changes
    /// anything; a failure in the pass over the store leaves the entries
    /// it did not reach.
    pub(in crate::fs) fn sweep(&self, root: &Dir) -> io::Result<usize> {
        let Some(store) = self.dir(false)? else {
            return Ok(0);
        };
        let store_key = dir_key(&store)?;
        let used = referenced(root, store_key)?;
        let _all = Exclusive::take(sweep_lock(store_key));
        let mut removed = 0;
        for entry in store.entries()? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = unhex(name).filter(|id| id.len() == 16) else {
                continue;
            };
            let Some(dir) = open_private_dir(&store, name, false)? else {
                continue;
            };
            if used.contains(id.as_slice()) {
                remove_if_there(&dir, UNREFERENCED)?;
                drop_leftovers(&dir)?;
            } else if exists(&dir, UNREFERENCED) {
                store.remove_dir_all(name)?;
                removed += 1;
            } else {
                drop(open_file(
                    &dir,
                    UNREFERENCED,
                    OFlags::WRONLY | OFlags::CREATE,
                )?);
            }
        }
        Ok(removed)
    }
}

/// The ids the records of the files and directories below `root` name.
/// Directories are walked by path, each opened one name at a time without
/// following symlinks, so the walk holds two descriptors at most.
fn referenced(root: &Dir, store_key: (u64, u64)) -> io::Result<HashSet<Vec<u8>>> {
    let mut used = HashSet::new();
    let mut note = |fd: &dyn AsFd| -> io::Result<()> {
        if let Some(id) = record_id(&fd.as_fd())? {
            used.insert(id.to_vec());
        }
        Ok(())
    };
    note(&super::super::local::dir_as_file(root)?)?;
    let mut pending: Vec<Vec<OsString>> = vec![Vec::new()];
    while let Some(path) = pending.pop() {
        let Some(dir) = open_path(root, &path)? else {
            continue;
        };
        if dir_key(&dir)? == store_key {
            continue;
        }
        if !path.is_empty() {
            note(&dir)?;
        }
        for entry in dir.entries()? {
            let entry = entry?;
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let name = entry.file_name();
            if file_type.is_dir() {
                let mut sub = path.clone();
                sub.push(name);
                pending.push(sub);
            } else if file_type.is_file() {
                let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
                match rustix::fs::openat(&dir, &name, flags, Mode::empty()) {
                    Ok(fd) => note(&fd)?,
                    Err(Errno::NOENT | Errno::LOOP) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(used)
}

/// Opens the directory `path` below `root` one name at a time without
/// following symlinks. `None` if it is gone or is no longer a directory.
fn open_path(root: &Dir, path: &[OsString]) -> io::Result<Option<Dir>> {
    let mut dir = root.try_clone()?;
    for name in path {
        dir = match open_dir(&dir, name, false) {
            Ok(Some(next)) => next,
            Ok(None) => return Ok(None),
            Err(e)
                if matches!(
                    e.raw_os_error().map(Errno::from_raw_os_error),
                    Some(Errno::LOOP | Errno::NOTDIR)
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
    }
    Ok(Some(dir))
}

/// Removes the files in a store entry that writes and renames left there.
fn drop_leftovers(dir: &Dir) -> io::Result<()> {
    for entry in dir.entries()? {
        let name = entry?.file_name();
        if name.to_str().is_some_and(|n| n.starts_with(ASIDE)) {
            rustix::fs::unlinkat(dir, &*name, AtFlags::empty())?;
        }
    }
    Ok(())
}

impl Spilled {
    /// Opens the file of the stream `stream` for reading, and for writing
    /// too with `write`.
    pub(in crate::fs) fn open(&self, stream: &StreamName, write: bool) -> io::Result<File> {
        let flags = if write { OFlags::RDWR } else { OFlags::RDONLY };
        open_file(&self.dir, &file_name(stream)?, flags)
    }

    /// Removes the stream `stream`.
    pub(in crate::fs) fn remove(&self, stream: &StreamName) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(
            &self.dir,
            file_name(stream)?,
            AtFlags::empty(),
        )?)
    }

    /// Renames the stream `from` to `to`, replacing a stream `to`.
    pub(in crate::fs) fn rename(&self, from: &StreamName, to: &StreamName) -> io::Result<()> {
        rustix::fs::renameat(&self.dir, file_name(from)?, &self.dir, file_name(to)?)?;
        Ok(rustix::fs::fsync(&self.dir)?)
    }

    /// Sets the stream `stream` aside under another name, from where
    /// [`Spilled::restore`] puts it back.
    pub(in crate::fs) fn set_aside(&self, stream: &StreamName) -> io::Result<()> {
        let name = file_name(stream)?;
        Ok(rustix::fs::renameat(
            &self.dir,
            &name,
            &self.dir,
            format!("{ASIDE}{name}"),
        )?)
    }

    pub(in crate::fs) fn restore(&self, stream: &StreamName) -> io::Result<()> {
        let name = file_name(stream)?;
        Ok(rustix::fs::renameat(
            &self.dir,
            format!("{ASIDE}{name}"),
            &self.dir,
            &name,
        )?)
    }

    /// Removes the stream `stream` that was set aside.
    pub(in crate::fs) fn drop_aside(&self, stream: &StreamName) -> io::Result<()> {
        let name = format!("{ASIDE}{}", file_name(stream)?);
        Ok(rustix::fs::unlinkat(&self.dir, name, AtFlags::empty())?)
    }

    /// Makes the stream `stream` with the data `write` puts in its file,
    /// replacing a stream of that name only once the data is all written
    /// and on disk, the entry included.
    pub(in crate::fs) fn put(
        &self,
        stream: &StreamName,
        write: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<File> {
        let name = file_name(stream)?;
        let temp = format!("{ASIDE}{ASIDE}{name}");
        remove_if_there(&self.dir, &temp)?;
        let written = (|| {
            let file = open_file(
                &self.dir,
                &temp,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            )?;
            write(&file)?;
            file.sync_all()?;
            rustix::fs::renameat(&self.dir, &temp, &self.dir, &name)?;
            rustix::fs::fsync(&self.dir)?;
            Ok(file)
        })();
        if written.is_err() {
            let _ = rustix::fs::unlinkat(&self.dir, &temp, AtFlags::empty());
        }
        written
    }
}

/// Logs once that the store of a share is not used.
pub(in crate::fs) fn warn_unusable(e: &io::Error) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| warn!(error = %e, "stream store not used"));
}
