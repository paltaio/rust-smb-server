//! Changes made to watched directories of a [`LocalFsBackend`] by anyone,
//! read from one inotify instance per backend.
//!
//! A directory is watched through its open handle: the watch is added on
//! `/proc/self/fd/N` of the directory descriptor cap-std opened, which the
//! kernel resolves to that inode, so no path is looked up again and no
//! symlink in the share is followed. Only the directory's own entries are
//! watched; inotify does not reach below them.
//!
//! The kernel reports a directory's own deletion only once every
//! descriptor of it is closed, and the server keeps one open for each
//! watch. So the parent of each watched directory is watched too, the
//! share root's parent included, and a directory whose link count dropped
//! to zero when an entry of its parent was removed or replaced is reported
//! deleted. Events of a parent go to no one unless the parent is watched
//! itself.
//!
//! [`LocalFsBackend`]: super::LocalFsBackend

use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use async_trait::async_trait;
use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tracing::{debug, warn};

use crate::backend::{DirChange, DirChangeKind, DirWatch};

/// What a watch asks the kernel for.
const EVENTS: WatchFlags = WatchFlags::CREATE
    .union(WatchFlags::DELETE)
    .union(WatchFlags::MOVED_FROM)
    .union(WatchFlags::MOVED_TO)
    .union(WatchFlags::ATTRIB)
    .union(WatchFlags::CLOSE_WRITE)
    .union(WatchFlags::DELETE_SELF)
    .union(WatchFlags::MOVE_SELF)
    .union(WatchFlags::ONLYDIR);

/// How long a move out waits for its move in from the next read.
const PAIR_WAIT: Duration = Duration::from_millis(50);

/// Batches of changes one subscriber may have waiting. Past it, changes
/// are dropped and the subscriber is told it lost some.
const QUEUED_BATCHES: usize = 64;

/// Most kernel watches one instance holds, parents included. Past it, a
/// directory gets only the changes made through the server.
const MAX_KERNEL_WATCHES: usize = 4096;

/// Most events taken from the instance before other tasks get to run.
const EVENTS_PER_WAKEUP: usize = 4096;

/// Set once a failure to watch has been logged.
static FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

/// Set once a failure to read an instance has been logged.
static READ_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The inotify instance of one backend, made with its first watch and
/// closed with its last. An instance whose reader stopped is replaced by
/// the next watch.
#[derive(Default)]
pub(super) struct Hub {
    instance: Mutex<Weak<Instance>>,
}

impl Hub {
    /// Watches the directory open as `dir`. `None`, logged once, when the
    /// kernel refuses another instance or watch, or the instance holds
    /// [`MAX_KERNEL_WATCHES`]: the server then reports only its own changes
    /// for it.
    pub(super) fn watch(&self, dir: &impl AsFd) -> Option<Box<dyn DirWatch>> {
        match self.subscribe(dir.as_fd()) {
            Ok(watch) => Some(Box::new(watch)),
            Err(e) => {
                if !FAILURE_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(error = %e, "cannot watch a directory for changes made outside the server");
                } else {
                    debug!(error = %e, "cannot watch a directory");
                }
                None
            }
        }
    }

    fn subscribe(&self, dir: BorrowedFd<'_>) -> io::Result<Subscription> {
        let mut instance = self.instance()?;
        let mut watches = lock(&instance.shared.watches);
        // A reader that stopped since cleared the watches or is about to.
        if instance.shared.ended.load(Ordering::Acquire) {
            drop(watches);
            instance = self.instance()?;
            watches = lock(&instance.shared.watches);
            if instance.shared.ended.load(Ordering::Acquire) {
                return Err(io::Error::other("the instance stopped"));
            }
        }
        let inotify = instance.fd.get_ref().as_fd();
        let wd = add_watch(inotify, dir)?;
        if !watches.dirs.contains_key(&wd) {
            let too_many = || io::Error::other("too many directories watched");
            if !watches.has_room(wd) {
                watches.release(inotify, wd);
                return Err(too_many());
            }
            let dir = match dir.try_clone_to_owned() {
                Ok(dir) => dir,
                Err(e) => {
                    watches.release(inotify, wd);
                    return Err(e);
                }
            };
            let watched = Watched {
                subscribers: Vec::new(),
                dir,
                parent: None,
            };
            watches.dirs.insert(wd, watched);
            if !watches.watch_parent(inotify, wd) {
                watches.remove(inotify, wd);
                return Err(too_many());
            }
        }
        let id = instance.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(QUEUED_BATCHES);
        let flags = Arc::new(Flags::default());
        let subscriber = Subscriber {
            id,
            tx,
            flags: Arc::clone(&flags),
        };
        if let Some(watched) = watches.dirs.get_mut(&wd) {
            watched.subscribers.push(subscriber);
        }
        // Deleted before its parent was watched, the directory is reported
        // deleted now.
        if watches.dirs.get(&wd).is_some_and(|w| is_deleted(&w.dir)) {
            watches.deleted(inotify, wd);
        }
        drop(watches);
        Ok(Subscription {
            instance,
            wd,
            id,
            rx,
            flags,
            done: false,
        })
    }

    /// The live instance, made if there is none.
    fn instance(&self) -> io::Result<Arc<Instance>> {
        let mut slot = lock(&self.instance);
        match slot.upgrade() {
            Some(instance) if !instance.shared.ended.load(Ordering::Acquire) => Ok(instance),
            _ => {
                let instance = Instance::new()?;
                *slot = Arc::downgrade(&instance);
                Ok(instance)
            }
        }
    }
}

/// Adds the instance's watch of the directory open as `dir`.
fn add_watch(inotify: BorrowedFd<'_>, dir: BorrowedFd<'_>) -> io::Result<i32> {
    let path = format!("/proc/self/fd/{}", dir.as_raw_fd());
    Ok(inotify::add_watch(inotify, path, EVENTS)?)
}

/// Whether the directory open as `dir` was deleted.
fn is_deleted(dir: &OwnedFd) -> bool {
    rustix::fs::fstat(dir).is_ok_and(|stat| stat.st_nlink == 0)
}

struct Subscriber {
    id: u64,
    tx: mpsc::Sender<Vec<DirChange>>,
    flags: Arc<Flags>,
}

/// What a subscriber's stream reports besides its batches.
#[derive(Default)]
struct Flags {
    /// Batches were dropped since the last one taken.
    lost: AtomicBool,
    /// The directory was deleted; the stream says so as it ends.
    deleted: AtomicBool,
}

/// One watched directory. The kernel gives every watch of one inode the
/// same descriptor.
struct Watched {
    subscribers: Vec<Subscriber>,
    /// The directory, to tell whether it was deleted.
    dir: OwnedFd,
    /// The kernel watch of the directory's parent.
    parent: Option<i32>,
}

/// The kernel watches of an instance, by watch descriptor.
#[derive(Default)]
struct Watches {
    dirs: HashMap<i32, Watched>,
    /// Watched directories by the watch of their parent.
    children: HashMap<i32, Vec<i32>>,
}

impl Watches {
    /// Watches the parent of the directory watched as `wd`. False when
    /// that would take the instance past [`MAX_KERNEL_WATCHES`].
    fn watch_parent(&mut self, inotify: BorrowedFd<'_>, wd: i32) -> bool {
        let Some(watched) = self.dirs.get(&wd) else {
            return true;
        };
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let parent = rustix::fs::openat(&watched.dir, "..", flags, Mode::empty())
            .map_err(io::Error::from)
            .and_then(|parent| add_watch(inotify, parent.as_fd()));
        match parent {
            Ok(parent) if !self.has_room(parent) => {
                self.release(inotify, parent);
                debug!("too many kernel watches to watch the parent of a watched directory");
                return false;
            }
            Ok(parent) => {
                if let Some(watched) = self.dirs.get_mut(&wd) {
                    watched.parent = Some(parent);
                }
                self.children.entry(parent).or_default().push(wd);
            }
            Err(e) => debug!(error = %e, "cannot watch the parent of a watched directory"),
        }
        true
    }

    /// Whether the kernel watch `wd` is held already or one more fits.
    fn has_room(&self, wd: i32) -> bool {
        self.dirs.contains_key(&wd)
            || self.children.contains_key(&wd)
            || self.kernel_watches() < MAX_KERNEL_WATCHES
    }

    /// Stops watching the parent of the directory watched as `wd`.
    fn unwatch_parent(&mut self, inotify: BorrowedFd<'_>, wd: i32) {
        let Some(parent) = self.dirs.get_mut(&wd).and_then(|w| w.parent.take()) else {
            return;
        };
        if let Some(children) = self.children.get_mut(&parent) {
            children.retain(|&child| child != wd);
            if children.is_empty() {
                self.children.remove(&parent);
            }
        }
        self.release(inotify, parent);
    }

    /// Removes the kernel watch `wd` once nothing needs it.
    fn release(&self, inotify: BorrowedFd<'_>, wd: i32) {
        if !self.dirs.contains_key(&wd) && !self.children.contains_key(&wd) {
            let _ = inotify::remove_watch(inotify, wd);
        }
    }

    /// Stops watching the directory watched as `wd`, which ends its
    /// subscribers' streams.
    fn remove(&mut self, inotify: BorrowedFd<'_>, wd: i32) {
        self.unwatch_parent(inotify, wd);
        if self.dirs.remove(&wd).is_some() {
            self.release(inotify, wd);
        }
    }

    /// Forgets the kernel watch `wd`, which the kernel dropped.
    fn dropped(&mut self, inotify: BorrowedFd<'_>, wd: i32) {
        self.unwatch_parent(inotify, wd);
        self.dirs.remove(&wd);
        for child in self.children.remove(&wd).unwrap_or_default() {
            if let Some(watched) = self.dirs.get_mut(&child) {
                watched.parent = None;
            }
        }
    }

    /// The directory watched as `wd` was deleted: its subscribers' streams
    /// say so and end.
    fn deleted(&mut self, inotify: BorrowedFd<'_>, wd: i32) {
        for subscriber in self.dirs.get(&wd).into_iter().flat_map(|w| &w.subscribers) {
            subscriber.flags.deleted.store(true, Ordering::Release);
        }
        self.remove(inotify, wd);
    }

    /// Kernel watches held, parents included.
    fn kernel_watches(&self) -> usize {
        let parents_only = self
            .children
            .keys()
            .filter(|wd| !self.dirs.contains_key(wd))
            .count();
        self.dirs.len() + parents_only
    }

    fn send(&self, wd: i32, batch: &[DirChange]) {
        if batch.is_empty() {
            return;
        }
        for subscriber in self.dirs.get(&wd).into_iter().flat_map(|w| &w.subscribers) {
            if subscriber.tx.try_send(batch.to_vec()).is_err() {
                subscriber.flags.lost.store(true, Ordering::Release);
            }
        }
    }
}

/// What an instance's reader shares with the watches.
#[derive(Default)]
struct Shared {
    watches: Mutex<Watches>,
    /// The reader stopped; the instance takes no more watches.
    ended: AtomicBool,
}

struct Instance {
    fd: Arc<AsyncFd<OwnedFd>>,
    shared: Arc<Shared>,
    next_id: AtomicU64,
    reader: AbortHandle,
}

impl Instance {
    fn new() -> io::Result<Arc<Self>> {
        let fd = inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)?;
        // An `OwnedFd` keeps its descriptor open, and the same, for as long
        // as the `AsyncFd` holds it, which is what registering needs.
        #[allow(deprecated)]
        let fd = Arc::new(AsyncFd::new(fd)?);
        let shared: Arc<Shared> = Arc::default();
        let reader = tokio::spawn(read_events(Arc::clone(&fd), Arc::clone(&shared)));
        Ok(Arc::new(Self {
            fd,
            shared,
            next_id: AtomicU64::new(0),
            reader: reader.abort_handle(),
        }))
    }
}

impl Drop for Instance {
    /// Stops the reader, which closes the instance and every kernel watch.
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// One directory watch. Dropping it removes the kernel watch once no
/// other subscriber of the directory is left.
struct Subscription {
    instance: Arc<Instance>,
    wd: i32,
    id: u64,
    rx: mpsc::Receiver<Vec<DirChange>>,
    flags: Arc<Flags>,
    /// The stream ended.
    done: bool,
}

#[async_trait]
impl DirWatch for Subscription {
    async fn next(&mut self) -> Option<Vec<DirChange>> {
        if self.done {
            return None;
        }
        let Some(mut batch) = self.rx.recv().await else {
            self.done = true;
            let deleted = self.flags.deleted.load(Ordering::Acquire);
            return deleted.then(|| vec![DirChange::new("", DirChangeKind::Deleted, true)]);
        };
        if self.flags.lost.swap(false, Ordering::AcqRel) {
            batch.insert(0, DirChange::new("", DirChangeKind::Lost, false));
        }
        Some(batch)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let mut watches = lock(&self.instance.shared.watches);
        let Some(watched) = watches.dirs.get_mut(&self.wd) else {
            return;
        };
        watched.subscribers.retain(|s| s.id != self.id);
        if watched.subscribers.is_empty() {
            watches.remove(self.instance.fd.get_ref().as_fd(), self.wd);
        }
    }
}

/// One event as read from the instance.
#[derive(Debug, Clone)]
struct RawEvent {
    wd: i32,
    mask: ReadFlags,
    cookie: u32,
    name: Option<String>,
}

/// Marks the instance ended and ends every subscriber's stream when its
/// reader stops, however it stops.
struct ReaderGone(Arc<Shared>);

impl Drop for ReaderGone {
    fn drop(&mut self) {
        let mut watches = lock(&self.0.watches);
        self.0.ended.store(true, Ordering::Release);
        *watches = Watches::default();
    }
}

/// Reads events until the instance goes away or reading fails, and hands
/// each directory's changes to its subscribers.
fn read_events(
    fd: Arc<AsyncFd<OwnedFd>>,
    shared: Arc<Shared>,
) -> impl Future<Output = ()> + Send + 'static {
    // Held by the future itself, so it also runs for a reader stopped
    // before it started.
    let gone = ReaderGone(Arc::clone(&shared));
    async move {
        let _gone = gone;
        if let Err(e) = read(&fd, &shared).await {
            if !READ_FAILURE_LOGGED.swap(true, Ordering::Relaxed) {
                warn!(error = %e, "reading directory changes failed; watches start over");
            } else {
                debug!(error = %e, "reading directory changes failed");
            }
        }
    }
}

/// A move out that ends a read waits up to [`PAIR_WAIT`] for a move in
/// with its cookie, which the kernel may put in the next read, before it
/// counts as a removal; the later events of its directory wait with it.
async fn read(fd: &AsyncFd<OwnedFd>, shared: &Shared) -> io::Result<()> {
    let inotify = fd.get_ref().as_fd();
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 16 * 1024];
    let mut held: Vec<RawEvent> = Vec::new();
    loop {
        let ready = if held.is_empty() {
            Some(fd.readable().await)
        } else {
            tokio::time::timeout(PAIR_WAIT, fd.readable()).await.ok()
        };
        let mut events = std::mem::take(&mut held);
        let Some(ready) = ready else {
            dispatch(inotify, &events, &mut lock(&shared.watches));
            continue;
        };
        let mut ready = ready?;
        let carried = events.len();
        let mut reader = inotify::Reader::new(inotify, &mut buf);
        // Past the cap the instance stays ready, and the rest is read after
        // other tasks ran.
        let mut capped = false;
        loop {
            if events.len() - carried >= EVENTS_PER_WAKEUP {
                capped = true;
                break;
            }
            match reader.next() {
                Ok(event) => events.push(RawEvent {
                    wd: event.wd(),
                    mask: event.events(),
                    cookie: event.cookie(),
                    name: event
                        .file_name()
                        .and_then(|name| name.to_str().ok())
                        .map(str::to_string),
                }),
                Err(Errno::AGAIN) => {
                    ready.clear_ready();
                    break;
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        held = unpaired_moves(&mut events, carried);
        dispatch(inotify, &events, &mut lock(&shared.watches));
        if capped {
            tokio::task::yield_now().await;
        }
    }
}

/// Takes out of `events` each move out, from `from` on, that no move in of
/// the same directory and cookie follows, with every later event of its
/// directory, so they keep their order. Those already waited are left.
fn unpaired_moves(events: &mut Vec<RawEvent>, from: usize) -> Vec<RawEvent> {
    let unpaired = |at: usize, e: &RawEvent| {
        e.mask.contains(ReadFlags::MOVED_FROM)
            && !events[at + 1..].iter().any(|to| {
                to.wd == e.wd && to.cookie == e.cookie && to.mask.contains(ReadFlags::MOVED_TO)
            })
    };
    let mut waiting: Vec<i32> = Vec::new();
    let mut hold = vec![false; events.len()];
    for at in from..events.len() {
        let event = &events[at];
        if !waiting.contains(&event.wd) && unpaired(at, event) {
            waiting.push(event.wd);
        }
        hold[at] = waiting.contains(&event.wd);
    }
    let mut held = Vec::new();
    let mut at = 0;
    events.retain(|event| {
        let keep = !hold[at];
        at += 1;
        if !keep {
            held.push(event.clone());
        }
        keep
    });
    held
}

/// Sends the changes in `events` to the subscribers of their directories.
/// A lost event queue reaches everyone. A directory deleted or dropped by
/// the kernel loses its subscribers, which ends their streams.
fn dispatch(inotify: BorrowedFd<'_>, events: &[RawEvent], watches: &mut Watches) {
    let mut deleted: Vec<i32> = Vec::new();
    if events
        .iter()
        .any(|e| e.mask.contains(ReadFlags::QUEUE_OVERFLOW))
    {
        let lost = [DirChange::new("", DirChangeKind::Lost, false)];
        for (&wd, watched) in &watches.dirs {
            watches.send(wd, &lost);
            if is_deleted(&watched.dir) {
                deleted.push(wd);
            }
        }
    }
    let mut wds: Vec<i32> = events.iter().map(|e| e.wd).filter(|&wd| wd >= 0).collect();
    wds.sort_unstable();
    wds.dedup();
    for wd in wds {
        let of_wd: Vec<RawEvent> = events.iter().filter(|e| e.wd == wd).cloned().collect();
        let mut batch = changes(&of_wd);
        // A moved directory's new parent is watched before anyone hears of
        // the move.
        if batch.iter().any(|c| c.kind == DirChangeKind::Moved) {
            watches.unwatch_parent(inotify, wd);
            let _ = watches.watch_parent(inotify, wd);
        }
        // The deletion ends the stream, after what came before it.
        if let Some(at) = batch.iter().position(|c| c.kind == DirChangeKind::Deleted) {
            batch.truncate(at);
            deleted.push(wd);
        }
        watches.send(wd, &batch);
        // An entry of the parent removed, or replaced by a rename, may have
        // been a watched directory.
        let gone_below = of_wd.iter().any(|e| {
            e.mask.contains(ReadFlags::ISDIR)
                && e.mask.intersects(ReadFlags::DELETE | ReadFlags::MOVED_TO)
        });
        if gone_below {
            for child in watches.children.get(&wd).into_iter().flatten() {
                if watches.dirs.get(child).is_some_and(|w| is_deleted(&w.dir)) {
                    deleted.push(*child);
                }
            }
        }
        if of_wd.iter().any(|e| e.mask.contains(ReadFlags::IGNORED)) {
            watches.dropped(inotify, wd);
        }
    }
    deleted.sort_unstable();
    deleted.dedup();
    for wd in deleted {
        watches.deleted(inotify, wd);
    }
}

/// The changes the events of one directory describe, in order. A move out
/// and a move in with the same cookie are a rename within the directory;
/// alone they are a removal and an addition. Names that are not UTF-8 are
/// left out.
fn changes(events: &[RawEvent]) -> Vec<DirChange> {
    let mut out = Vec::new();
    let mut paired = vec![false; events.len()];
    for (at, event) in events.iter().enumerate() {
        if paired[at] {
            continue;
        }
        let Some(name) = &event.name else {
            let kind = if event.mask.contains(ReadFlags::DELETE_SELF) {
                DirChangeKind::Deleted
            } else if event.mask.contains(ReadFlags::MOVE_SELF) {
                DirChangeKind::Moved
            } else if event.mask.contains(ReadFlags::UNMOUNT) {
                DirChangeKind::Lost
            } else {
                continue;
            };
            out.push(DirChange::new("", kind, true));
            continue;
        };
        let is_directory = event.mask.contains(ReadFlags::ISDIR);
        let kind = if event.mask.contains(ReadFlags::CREATE) {
            DirChangeKind::Added
        } else if event.mask.contains(ReadFlags::DELETE) {
            DirChangeKind::Removed
        } else if event.mask.contains(ReadFlags::MOVED_FROM) {
            let to = events.iter().enumerate().skip(at + 1).find(|(i, e)| {
                !paired[*i]
                    && e.wd == event.wd
                    && e.cookie == event.cookie
                    && e.mask.contains(ReadFlags::MOVED_TO)
            });
            match to {
                Some((i, to)) => {
                    paired[i] = true;
                    let Some(to_name) = &to.name else {
                        out.push(DirChange::new(name, DirChangeKind::Removed, is_directory));
                        continue;
                    };
                    out.push(DirChange::new(
                        to_name,
                        DirChangeKind::Renamed { from: name.clone() },
                        is_directory,
                    ));
                    continue;
                }
                None => DirChangeKind::Removed,
            }
        } else if event.mask.contains(ReadFlags::MOVED_TO) {
            DirChangeKind::Added
        } else if event.mask.contains(ReadFlags::CLOSE_WRITE) {
            DirChangeKind::Modified
        } else if event.mask.contains(ReadFlags::ATTRIB) {
            DirChangeKind::AttributesChanged
        } else {
            continue;
        };
        out.push(DirChange::new(name, kind, is_directory));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(mask: ReadFlags, cookie: u32, name: &str) -> RawEvent {
        on(1, mask, cookie, name)
    }

    fn on(wd: i32, mask: ReadFlags, cookie: u32, name: &str) -> RawEvent {
        RawEvent {
            wd,
            mask,
            cookie,
            name: Some(name.to_string()),
        }
    }

    fn nameless(wd: i32, mask: ReadFlags) -> RawEvent {
        RawEvent {
            wd,
            mask,
            cookie: 0,
            name: None,
        }
    }

    fn names(events: &[RawEvent]) -> Vec<String> {
        events.iter().map(|e| e.name.clone().unwrap()).collect()
    }

    async fn next(watch: &mut Box<dyn DirWatch>) -> Option<Vec<DirChange>> {
        tokio::time::timeout(Duration::from_secs(5), watch.next())
            .await
            .expect("a batch or the end in time")
    }

    #[test]
    fn moves_pair_by_cookie_and_stand_alone_otherwise() {
        let events = [
            event(ReadFlags::CREATE | ReadFlags::ISDIR, 0, "dir"),
            event(ReadFlags::MOVED_FROM, 7, "a"),
            event(ReadFlags::MOVED_FROM, 8, "gone"),
            event(ReadFlags::MOVED_TO, 7, "b"),
            event(ReadFlags::MOVED_TO, 9, "came"),
            event(ReadFlags::CLOSE_WRITE, 0, "b"),
            event(ReadFlags::ATTRIB, 0, "b"),
            event(ReadFlags::DELETE, 0, "x"),
        ];
        let renamed = DirChangeKind::Renamed {
            from: "a".to_string(),
        };
        assert_eq!(
            changes(&events),
            [
                DirChange::new("dir", DirChangeKind::Added, true),
                DirChange::new("b", renamed, false),
                DirChange::new("gone", DirChangeKind::Removed, false),
                DirChange::new("came", DirChangeKind::Added, false),
                DirChange::new("b", DirChangeKind::Modified, false),
                DirChange::new("b", DirChangeKind::AttributesChanged, false),
                DirChange::new("x", DirChangeKind::Removed, false),
            ]
        );
    }

    #[test]
    fn a_move_out_waits_for_its_move_in_once() {
        let mut events = vec![
            event(ReadFlags::MOVED_FROM, 1, "carried"),
            event(ReadFlags::CREATE, 0, "x"),
            event(ReadFlags::MOVED_FROM, 2, "paired"),
            event(ReadFlags::MOVED_TO, 2, "after"),
            event(ReadFlags::MOVED_FROM, 3, "alone"),
        ];
        let held = unpaired_moves(&mut events, 1);
        assert_eq!(names(&held), ["alone"]);
        assert_eq!(names(&events), ["carried", "x", "paired", "after"]);

        // Held over, it pairs with the move in of the next read.
        let mut next = held;
        next.push(event(ReadFlags::MOVED_TO, 3, "back"));
        assert!(unpaired_moves(&mut next, 1).is_empty());
        let renamed = DirChangeKind::Renamed {
            from: "alone".to_string(),
        };
        assert_eq!(changes(&next), [DirChange::new("back", renamed, false)]);
    }

    #[test]
    fn later_events_of_a_directory_wait_with_its_move_out() {
        // mv d/a d2/a; mv d2/a d/a, with d watched as 1 and d2 as 2.
        let mut events = vec![
            on(1, ReadFlags::MOVED_FROM, 4, "a"),
            on(2, ReadFlags::MOVED_TO, 4, "a"),
            on(2, ReadFlags::MOVED_FROM, 5, "a"),
            on(1, ReadFlags::MOVED_TO, 5, "a"),
        ];
        let held = unpaired_moves(&mut events, 0);
        let wds = |events: &[RawEvent]| events.iter().map(|e| e.wd).collect::<Vec<_>>();
        assert_eq!(wds(&held), [1, 2, 1]);
        assert_eq!(wds(&events), [2]);
        let of_d: Vec<RawEvent> = held.into_iter().filter(|e| e.wd == 1).collect();
        assert_eq!(
            changes(&of_d),
            [
                DirChange::new("a", DirChangeKind::Removed, false),
                DirChange::new("a", DirChangeKind::Added, false),
            ]
        );

        // A move out followed by a create of the name, read together.
        let mut events = vec![
            event(ReadFlags::MOVED_FROM, 6, "f"),
            event(ReadFlags::CREATE, 0, "f"),
        ];
        let mut next = unpaired_moves(&mut events, 0);
        assert!(events.is_empty());
        let carried = next.len();
        next.push(event(ReadFlags::CLOSE_WRITE, 0, "f"));
        assert!(unpaired_moves(&mut next, carried).is_empty());
        assert_eq!(
            changes(&next),
            [
                DirChange::new("f", DirChangeKind::Removed, false),
                DirChange::new("f", DirChangeKind::Added, false),
                DirChange::new("f", DirChangeKind::Modified, false),
            ]
        );
    }

    #[test]
    fn events_about_the_directory_itself_report_it() {
        let events = [
            nameless(1, ReadFlags::MOVE_SELF),
            nameless(1, ReadFlags::UNMOUNT),
            nameless(1, ReadFlags::DELETE_SELF),
            nameless(1, ReadFlags::IGNORED),
        ];
        let kinds: Vec<DirChangeKind> = changes(&events).into_iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [
                DirChangeKind::Moved,
                DirChangeKind::Lost,
                DirChangeKind::Deleted
            ]
        );
    }

    #[test]
    fn a_lost_queue_reaches_every_subscriber_and_a_dropped_watch_ends_its_own() {
        let inotify = inotify::init(CreateFlags::CLOEXEC).unwrap();
        let td = tempfile::tempdir().unwrap();
        let mut watches = Watches::default();
        let mut receivers = Vec::new();
        for wd in [1, 2] {
            let (tx, rx) = mpsc::channel(QUEUED_BATCHES);
            let flags = Arc::default();
            let dir: OwnedFd = std::fs::File::open(td.path()).unwrap().into();
            let watched = Watched {
                subscribers: vec![Subscriber { id: 0, tx, flags }],
                dir,
                parent: None,
            };
            watches.dirs.insert(wd, watched);
            receivers.push(rx);
        }
        let overflow = nameless(-1, ReadFlags::QUEUE_OVERFLOW);
        let ignored = nameless(2, ReadFlags::IGNORED);
        dispatch(inotify.as_fd(), &[overflow, ignored], &mut watches);
        for rx in &mut receivers {
            let batch = rx.try_recv().expect("a batch");
            assert_eq!(batch[0].kind, DirChangeKind::Lost);
        }
        assert!(watches.dirs.contains_key(&1));
        assert!(!watches.dirs.contains_key(&2));
        assert!(receivers[1].try_recv().is_err(), "the stream of 2 ended");
    }

    #[tokio::test]
    async fn a_directory_watch_sees_changes_and_goes_with_its_last_subscriber() {
        let td = tempfile::tempdir().unwrap();
        let dir = std::fs::File::open(td.path()).unwrap();
        let hub = Hub::default();
        let mut first = hub.watch(&dir).expect("watched");
        let second = hub.watch(&dir).expect("watched");
        std::fs::write(td.path().join("f"), b"x").unwrap();
        let batch = next(&mut first).await.expect("changes");
        assert_eq!(batch[0], DirChange::new("f", DirChangeKind::Added, false));
        drop(second);
        let instance = lock(&hub.instance).upgrade().expect("instance");
        let left: usize = lock(&instance.shared.watches)
            .dirs
            .values()
            .map(|w| w.subscribers.len())
            .sum();
        assert_eq!(left, 1);
        drop(instance);
        drop(first);
        assert!(lock(&hub.instance).upgrade().is_none());
    }

    #[tokio::test]
    async fn a_directory_deleted_while_open_is_seen_from_its_parent() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("d");
        std::fs::create_dir(&path).unwrap();
        let dir = std::fs::File::open(&path).unwrap();
        let hub = Hub::default();
        let mut watch = hub.watch(&dir).expect("watched");
        std::fs::remove_dir(&path).unwrap();
        let batch = next(&mut watch).await.expect("changes");
        assert_eq!(batch, [DirChange::new("", DirChangeKind::Deleted, true)]);
        assert!(next(&mut watch).await.is_none(), "the stream ends");
        let instance = lock(&hub.instance).upgrade().expect("instance");
        let watches = lock(&instance.shared.watches);
        assert!(watches.dirs.is_empty() && watches.children.is_empty());
    }

    #[tokio::test]
    async fn a_moved_directory_is_seen_deleted_from_its_new_parent() {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(td.path().join("a/d")).unwrap();
        std::fs::create_dir(td.path().join("b")).unwrap();
        let dir = std::fs::File::open(td.path().join("a/d")).unwrap();
        let hub = Hub::default();
        let mut watch = hub.watch(&dir).expect("watched");
        std::fs::rename(td.path().join("a/d"), td.path().join("b/d")).unwrap();
        let batch = next(&mut watch).await.expect("changes");
        assert_eq!(batch, [DirChange::new("", DirChangeKind::Moved, true)]);
        std::fs::remove_dir(td.path().join("b/d")).unwrap();
        let batch = next(&mut watch).await.expect("changes");
        assert_eq!(batch, [DirChange::new("", DirChangeKind::Deleted, true)]);
    }

    #[tokio::test]
    async fn a_stopped_reader_ends_its_watches_and_the_next_watch_starts_over() {
        let td = tempfile::tempdir().unwrap();
        let dir = std::fs::File::open(td.path()).unwrap();
        let hub = Hub::default();
        let mut watch = hub.watch(&dir).expect("watched");
        let stopped = lock(&hub.instance).upgrade().expect("instance");
        stopped.reader.abort();
        assert!(next(&mut watch).await.is_none(), "the stream ends");
        let mut again = hub.watch(&dir).expect("watched");
        let fresh = lock(&hub.instance).upgrade().expect("instance");
        assert!(!Arc::ptr_eq(&stopped, &fresh));
        std::fs::write(td.path().join("f"), b"x").unwrap();
        let batch = next(&mut again).await.expect("changes");
        assert_eq!(batch[0], DirChange::new("f", DirChangeKind::Added, false));
    }

    #[tokio::test]
    async fn a_directory_deleted_before_it_is_watched_is_reported_deleted() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("d");
        std::fs::create_dir(&path).unwrap();
        let dir = std::fs::File::open(&path).unwrap();
        std::fs::remove_dir(&path).unwrap();
        let hub = Hub::default();
        let mut watch = hub.watch(&dir).expect("watched");
        let batch = next(&mut watch).await.expect("changes");
        assert_eq!(batch, [DirChange::new("", DirChangeKind::Deleted, true)]);
        assert!(next(&mut watch).await.is_none(), "the stream ends");
    }

    #[tokio::test]
    async fn a_directory_replaced_by_a_rename_is_reported_deleted() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("d");
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(td.path().join("other")).unwrap();
        let dir = std::fs::File::open(&path).unwrap();
        let hub = Hub::default();
        let mut watch = hub.watch(&dir).expect("watched");
        std::fs::rename(td.path().join("other"), &path).unwrap();
        let batch = next(&mut watch).await.expect("changes");
        assert_eq!(batch, [DirChange::new("", DirChangeKind::Deleted, true)]);
    }

    #[tokio::test]
    async fn a_deletion_reaches_a_subscriber_whose_queue_is_full() {
        let instance = Instance::new().unwrap();
        let inotify = instance.fd.get_ref().as_fd();
        let td = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(vec![DirChange::new("a", DirChangeKind::Added, false)])
            .unwrap();
        let flags: Arc<Flags> = Arc::default();
        let subscriber = Subscriber {
            id: 0,
            tx,
            flags: Arc::clone(&flags),
        };
        let dir: OwnedFd = std::fs::File::open(td.path()).unwrap().into();
        {
            let mut watches = lock(&instance.shared.watches);
            let watched = Watched {
                subscribers: vec![subscriber],
                dir,
                parent: None,
            };
            watches.dirs.insert(1, watched);
            watches.send(1, &[DirChange::new("b", DirChangeKind::Added, false)]);
            watches.deleted(inotify, 1);
        }
        let mut watch: Box<dyn DirWatch> = Box::new(Subscription {
            instance: Arc::clone(&instance),
            wd: 1,
            id: 0,
            rx,
            flags,
            done: false,
        });
        let batch = next(&mut watch).await.expect("the queued batch");
        assert_eq!(batch[0].kind, DirChangeKind::Lost);
        assert_eq!(
            next(&mut watch).await.expect("the deletion"),
            [DirChange::new("", DirChangeKind::Deleted, true)]
        );
        assert!(next(&mut watch).await.is_none());
    }

    #[tokio::test]
    async fn changes_in_a_watched_directorys_parent_reach_no_one() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("d");
        std::fs::create_dir(&path).unwrap();
        let dir = std::fs::File::open(&path).unwrap();
        let hub = Hub::default();
        let mut watch = hub.watch(&dir).expect("watched");
        std::fs::create_dir(td.path().join("beside")).unwrap();
        std::fs::remove_dir(td.path().join("beside")).unwrap();
        std::fs::write(td.path().join("f"), b"x").unwrap();
        std::fs::create_dir(path.join("inside")).unwrap();
        let batch = next(&mut watch).await.expect("changes");
        assert_eq!(
            batch,
            [DirChange::new("inside", DirChangeKind::Added, true)]
        );
    }

    #[test]
    fn a_dropped_parent_watch_is_released_with_its_last_child() {
        let inotify = inotify::init(CreateFlags::CLOEXEC).unwrap();
        let td = tempfile::tempdir().unwrap();
        let mut watches = Watches::default();
        for (wd, parent) in [(1, 9), (2, 9)] {
            let dir: OwnedFd = std::fs::File::open(td.path()).unwrap().into();
            let watched = Watched {
                subscribers: Vec::new(),
                dir,
                parent: Some(parent),
            };
            watches.dirs.insert(wd, watched);
            watches.children.entry(parent).or_default().push(wd);
        }
        watches.dropped(inotify.as_fd(), 1);
        assert_eq!(watches.children[&9], [2]);
        watches.dropped(inotify.as_fd(), 2);
        assert!(watches.children.is_empty());
        assert_eq!(watches.kernel_watches(), 0);
    }

    #[test]
    fn only_new_kernel_watches_count_against_the_cap() {
        let mut watches = Watches::default();
        for wd in 0..MAX_KERNEL_WATCHES as i32 {
            watches.children.insert(wd, Vec::new());
        }
        assert!(watches.has_room(7), "a watch already held");
        assert!(!watches.has_room(-7), "a new one");
        watches.children.remove(&0);
        assert!(watches.has_room(-7));
    }
}
