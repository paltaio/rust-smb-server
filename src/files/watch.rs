//! Change notification on a share (MS-FSA 2.1.5.11, 2.1.4.1): the
//! directories clients watch, the changes buffered for each watch between
//! requests, and the requests waiting for them.
//!
//! A watch belongs to one open and lives until that open closes. The first
//! CHANGE_NOTIFY on the open fixes its filter, whether it covers the whole
//! tree below the directory and how much it buffers (MS-SMB2 3.3.1.3).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use tokio::task::AbortHandle;

use crate::backend::{DirChange, DirChangeKind, DirWatch, Handle};
use crate::ntstatus;
use crate::path::{SmbPath, is_valid_component, rebase};
use crate::proto::messages::change_notify::{
    FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME,
    FILE_ACTION_RENAMED_OLD_NAME, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    entries_len, push_entry,
};
use crate::server::ShareBindings;

/// Most bytes one watch buffers, whatever OutputBufferLength asked for.
pub(crate) const MAX_NOTIFY_BUFFER: u32 = 64 * 1024;

/// Most bytes the watches of one connection buffer together. Past it, the
/// watch that would cross it drops what it holds and answers
/// STATUS_NOTIFY_ENUM_DIR next.
pub(crate) const MAX_NOTIFY_BYTES: usize = 8 << 20;

/// Most watches one connection may hold.
pub(crate) const MAX_WATCHES_PER_CONNECTION: usize = 4096;

/// Filter of a change to a file's contents: a write, a size change, an
/// overwrite. Windows reports a write or a truncation to watchers asking
/// for LAST_WRITE, and not to watchers asking for ATTRIBUTES without it.
/// ATTRIBUTES is set here on purpose, so watchers that ask for attributes
/// but not for times, as macOS clients do, hear about new contents too.
pub(crate) const CONTENT_CHANGED: u32 =
    FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES;

/// One change to report: `action` (FILE_ACTION_*) happened at `path`, and
/// it matches the FILE_NOTIFY_CHANGE_* bits `filter`.
pub(crate) struct Change<'a> {
    pub path: &'a SmbPath,
    pub action: u32,
    pub filter: u32,
    /// A backend that reports changes sees this addition, removal or rename
    /// itself. The removal of an entry a rename replaced is not seen: the
    /// backend sees only the rename.
    pub seen: bool,
}

/// How a CHANGE_NOTIFY is answered.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// FILE_NOTIFY_INFORMATION entries.
    Changes(Vec<u8>),
    /// Changes were lost or do not fit: STATUS_NOTIFY_ENUM_DIR.
    EnumDir,
    /// The watch is gone; every request on it ends with this status.
    Ended(u32),
}

/// What the watches of one connection hold.
#[derive(Default)]
pub(crate) struct NotifyBudget {
    watches: AtomicUsize,
    bytes: AtomicUsize,
}

impl NotifyBudget {
    fn take_watch(&self) -> bool {
        self.watches
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_WATCHES_PER_CONNECTION).then_some(n + 1)
            })
            .is_ok()
    }

    fn charge(&self, bytes: usize) -> bool {
        self.bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held + bytes <= MAX_NOTIFY_BYTES).then_some(held + bytes)
            })
            .is_ok()
    }

    fn refund(&self, bytes: usize) {
        self.bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// Watches held now.
    #[cfg(test)]
    pub(crate) fn watches(&self) -> usize {
        self.watches.load(Ordering::Acquire)
    }

    /// Bytes buffered now.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

/// Entries for one watch: each change's action and its name relative to
/// the watched directory.
type Batch = Vec<(u32, Vec<u16>)>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Key of the directory made of `components`: backslash-joined, lowercased
/// unless the backend is case-sensitive, empty for the root.
fn dir_key(components: &[String], case_sensitive: bool) -> String {
    let joined = components.join("\\");
    if case_sensitive {
        joined
    } else {
        joined.to_lowercase()
    }
}

/// One open's watch (MS-FSA ChangeNotifyEntry).
pub(crate) struct Watch {
    /// CompletionFilter of the first request, invalid bits dropped.
    filter: u32,
    /// SMB2_WATCH_TREE was set on the first request.
    tree: bool,
    /// Most bytes buffered: the first request's OutputBufferLength, up to
    /// [`MAX_NOTIFY_BUFFER`].
    limit: u32,
    state: Mutex<WatchState>,
    /// Counts changes to `state` a waiting request may act on.
    changed: tokio::sync::watch::Sender<u64>,
    /// The connection whose open armed the watch.
    budget: Arc<NotifyBudget>,
}

/// How long the server's own change to an entry hides the backend's
/// report of the same change.
const ECHO_TIME: Duration = Duration::from_secs(5);

/// Most changes of the server one watched directory remembers.
const ECHO_LIMIT: usize = 1024;

/// How long a backend report waits before it is compared with what the
/// server did: the server reports its own change right after making it.
const HOST_GRACE: Duration = Duration::from_millis(200);

/// Batches of backend reports one watched directory holds while they wait.
const HOST_QUEUE: usize = 64;

/// Marks the server's rename of a watched directory itself in its
/// [`Echo`], under an empty name.
const RENAMED_SELF: u32 = 0;

async fn sleep_until_due(due: Option<tokio::time::Instant>) {
    if let Some(due) = due {
        tokio::time::sleep_until(due).await;
    }
}

/// The server's recent changes to the entries of a watched directory, by
/// name as the table compares names.
#[derive(Default)]
struct Echo {
    /// Changes the server reported, each hiding one backend report:
    /// additions, removals and renames, and as MODIFIED the close of a file
    /// that could be written and was not.
    reported: VecDeque<(Instant, u32, String)>,
    /// Entries the server changed, hiding modifications.
    touched: VecDeque<(Instant, String)>,
}

impl Echo {
    fn prune(&mut self, now: Instant) {
        let fresh = |at: &Instant| now.duration_since(*at) < ECHO_TIME;
        while self.reported.front().is_some_and(|(at, ..)| !fresh(at)) {
            self.reported.pop_front();
        }
        while self.touched.front().is_some_and(|(at, _)| !fresh(at)) {
            self.touched.pop_front();
        }
    }

    fn report(&mut self, action: u32, name: String) {
        let now = Instant::now();
        self.prune(now);
        if self.reported.len() == ECHO_LIMIT {
            self.reported.pop_front();
        }
        self.reported.push_back((now, action, name));
    }

    fn closed(&mut self, name: String) {
        self.report(FILE_ACTION_MODIFIED, name);
    }

    fn touch(&mut self, name: String) {
        if self.touched.len() == ECHO_LIMIT {
            self.touched.pop_front();
        }
        self.touched.push_back((Instant::now(), name));
    }

    /// Takes the server's report of `action` on `name`, if there is one.
    fn take(&mut self, action: u32, name: &str) -> bool {
        self.prune(Instant::now());
        let found = self
            .reported
            .iter()
            .position(|(_, a, n)| *a == action && n == name);
        found.map(|at| self.reported.remove(at)).is_some()
    }

    /// Takes the server's report of any of `actions` on `name`, the first
    /// that matches.
    fn take_any(&mut self, actions: &[u32], name: &str) -> bool {
        actions.iter().any(|&action| self.take(action, name))
    }

    fn touched(&mut self, name: &str) -> bool {
        self.prune(Instant::now());
        self.touched.iter().any(|(_, n)| n == name)
    }

    /// Takes back the latest record of a change the server made to `name`.
    fn untouch(&mut self, name: &str) {
        if let Some(at) = self.touched.iter().rposition(|(_, n)| n == name) {
            self.touched.remove(at);
        }
    }

    fn clear(&mut self) {
        self.reported.clear();
        self.touched.clear();
    }
}

/// The backend's reports of changes to one watched directory's entries,
/// shared by every watch of the directory.
struct Host {
    /// The directory, moved by renames as its watches are.
    dir: Mutex<SmbPath>,
    share: Weak<ShareBindings>,
    /// What the server itself did to the directory's entries lately, to
    /// tell the backend's reports of it from other changes.
    echo: Mutex<Echo>,
    /// Reports waiting for [`HOST_GRACE`] from their arrival. Its lock is
    /// held while they are passed on, so they go out in order.
    waiting: Mutex<VecDeque<(tokio::time::Instant, Vec<DirChange>)>>,
    /// The task that takes the backend's reports.
    task: Mutex<Option<AbortHandle>>,
    stopped: AtomicBool,
    /// The backend gives no reports for the directory, so nothing is
    /// recorded in `echo`.
    idle: AtomicBool,
}

impl Host {
    fn new(dir: SmbPath, share: &Arc<ShareBindings>) -> Self {
        Self {
            dir: Mutex::new(dir),
            share: Arc::downgrade(share),
            echo: Mutex::default(),
            waiting: Mutex::default(),
            task: Mutex::new(None),
            stopped: AtomicBool::new(false),
            idle: AtomicBool::new(false),
        }
    }

    /// Takes the backend's reports from `source` until the host stops, the
    /// reports end or the share goes away. Each batch waits [`HOST_GRACE`]
    /// from its arrival, unless a change the server reports in the
    /// directory sends it on first.
    fn start(self: &Arc<Self>, source: Box<dyn DirWatch>) {
        let host = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut source = source;
            let mut open = true;
            loop {
                let (due, full) = {
                    let waiting = lock(&host.waiting);
                    let due = waiting.front().map(|(at, _)| *at + HOST_GRACE);
                    (due, waiting.len() >= HOST_QUEUE)
                };
                if !open && due.is_none() {
                    break;
                }
                tokio::select! {
                    changes = source.next(), if open && !full => match changes {
                        Some(changes) => {
                            let now = tokio::time::Instant::now();
                            lock(&host.waiting).push_back((now, changes));
                        }
                        None => open = false,
                    },
                    () = sleep_until_due(due), if due.is_some() => {
                        if !host.pass_on(Some(tokio::time::Instant::now())) {
                            return;
                        }
                    }
                }
            }
            if let Some(share) = host.share.upgrade() {
                share.watches.host_ended(&host);
            }
        });
        *lock(&self.task) = Some(task.abort_handle());
        if self.stopped.load(Ordering::Acquire) {
            task.abort();
        }
    }

    /// Passes on the waiting reports that arrived by `now`, or all of them.
    /// False once the share is gone.
    fn pass_on(self: &Arc<Self>, now: Option<tokio::time::Instant>) -> bool {
        let Some(share) = self.share.upgrade() else {
            return false;
        };
        let mut waiting = lock(&self.waiting);
        while let Some((at, _)) = waiting.front() {
            if now.is_some_and(|now| *at + HOST_GRACE > now) {
                break;
            }
            let Some((_, changes)) = waiting.pop_front() else {
                break;
            };
            share.watches.take_host_changes(&share, self, changes);
        }
        true
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(task) = lock(&self.task).take() {
            task.abort();
        }
    }
}

/// Changes the server is about to make, noted in the echoes of the watched
/// directories they happen in before the backend can report them. Dropped
/// without [`Expected::report`], as when the change failed, the notes are
/// taken back; a note a backend report already took stood for a change
/// someone else made, which is then reported as theirs.
pub(crate) struct Expected {
    marks: Vec<Mark>,
}

/// One change noted in a host's echo.
struct Mark {
    host: Arc<Host>,
    /// Index of the change among those expected; `None` for the rename of
    /// the watched directory itself.
    change: Option<usize>,
    /// The action noted to hide one backend report, if any.
    action: Option<u32>,
    /// The entry's name as the table compares names.
    key: String,
    /// The entry's name as spelled, and the change's filter.
    name: String,
    filter: u32,
}

impl Expected {
    /// Reports `changes`, the changes this expected, now made. A directory
    /// that started hearing its backend since gets them noted now.
    pub(crate) fn report(mut self, table: &WatchTable, changes: &[Change<'_>]) {
        let marks = std::mem::take(&mut self.marks);
        table.deliver(changes, |at, host| {
            marks
                .iter()
                .any(|mark| mark.change == Some(at) && Arc::ptr_eq(&mark.host, host))
        });
    }
}

impl Drop for Expected {
    fn drop(&mut self) {
        for mark in self.marks.drain(..) {
            let taken = {
                let mut echo = lock(&mark.host.echo);
                echo.untouch(&mark.key);
                mark.action
                    .is_some_and(|action| !echo.take(action, &mark.key))
            };
            let Some(share) = mark.host.share.upgrade() else {
                continue;
            };
            if taken {
                let _order = lock(&mark.host.waiting);
                let heard = [(
                    mark.action.unwrap_or_default(),
                    mark.name.as_str(),
                    mark.filter,
                )];
                match mark.change {
                    Some(_) => share.watches.hear(&mark.host, &heard, false),
                    None => share.watches.hear(&mark.host, &[], true),
                }
            }
        }
    }
}

/// The watches of one directory, and the backend's reports for them.
#[derive(Default)]
struct Watched {
    watches: Vec<Arc<Watch>>,
    host: Option<Arc<Host>>,
}

impl Drop for Watched {
    /// The backend's reports stop with the last watch of the directory.
    fn drop(&mut self) {
        if let Some(host) = &self.host {
            host.stop();
        }
    }
}

struct WatchState {
    /// The watched directory.
    dir: SmbPath,
    /// Encoded entries, each padded to 4 bytes.
    entries: Vec<u8>,
    /// Offset of the last entry in `entries`.
    last: Option<usize>,
    /// A name in `entries` lies below a subdirectory.
    nested: bool,
    /// Changes were dropped; the next answer is STATUS_NOTIFY_ENUM_DIR.
    overflow: bool,
    /// Set once the watch is removed.
    end: Option<u32>,
    /// The directory was deleted outside the server, which ended the watch
    /// for good.
    gone: bool,
    /// Tickets of the waiting requests, oldest first.
    queue: VecDeque<u64>,
    next_ticket: u64,
}

impl Watch {
    /// A watch of `dir` with the first request's `filter`, `tree` flag and
    /// OutputBufferLength `len`, counted against `budget`. `None` when the
    /// connection already holds [`MAX_WATCHES_PER_CONNECTION`].
    fn new(
        dir: SmbPath,
        filter: u32,
        tree: bool,
        len: u32,
        budget: &Arc<NotifyBudget>,
    ) -> Option<Arc<Self>> {
        if !budget.take_watch() {
            return None;
        }
        Some(Arc::new(Self {
            filter,
            tree,
            limit: len.min(MAX_NOTIFY_BUFFER),
            state: Mutex::new(WatchState {
                dir,
                entries: Vec::new(),
                last: None,
                nested: false,
                overflow: false,
                end: None,
                gone: false,
                queue: VecDeque::new(),
                next_ticket: 0,
            }),
            changed: tokio::sync::watch::Sender::new(0),
            budget: Arc::clone(budget),
        }))
    }

    /// Drops what the watch buffered: its next answer is
    /// STATUS_NOTIFY_ENUM_DIR.
    fn lose(&self) {
        let mut state = self.state();
        if state.end.is_some() || state.overflow {
            return;
        }
        self.budget.refund(state.entries.len());
        state.entries = Vec::new();
        state.last = None;
        state.nested = false;
        state.overflow = true;
        drop(state);
        self.bump();
    }

    fn state(&self) -> MutexGuard<'_, WatchState> {
        lock(&self.state)
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n += 1);
    }

    /// Puts a request with OutputBufferLength `len`, and SMB2_WATCH_TREE
    /// when `tree`, at the end of the queue of waiting requests.
    pub(crate) fn enqueue(self: &Arc<Self>, len: u32, tree: bool) -> Ticket {
        let mut state = self.state();
        let id = state.next_ticket;
        state.next_ticket += 1;
        state.queue.push_back(id);
        Ticket {
            watch: Arc::clone(self),
            id,
            len,
            tree,
        }
    }

    /// A receiver that sees every later change a waiting request may act
    /// on. Subscribe before the first [`Watch::take`], so no change falls
    /// between the two.
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// The answer to the request holding `ticket`, once it has one: the
    /// buffered changes when this request is the oldest waiting and they fit
    /// both its OutputBufferLength and the watch's limit (MS-FSA
    /// 2.1.5.11.1). A request without SMB2_WATCH_TREE gets
    /// STATUS_NOTIFY_ENUM_DIR instead of names below a subdirectory, which
    /// clients refuse in an answer to such a request (MS-SMB2 3.2.5.16).
    /// Taking empties the buffer either way.
    pub(crate) fn take(&self, ticket: &Ticket) -> Option<Answer> {
        let mut state = self.state();
        if let Some(status) = state.end {
            state.queue.retain(|&id| id != ticket.id);
            return Some(Answer::Ended(status));
        }
        if state.queue.front() != Some(&ticket.id) {
            return None;
        }
        let answer = if state.overflow {
            state.overflow = false;
            Answer::EnumDir
        } else if state.entries.is_empty() {
            return None;
        } else {
            let carried = entries_len(&state.entries, state.last);
            let answer = if carried > ticket.len.min(self.limit) as usize
                || (state.nested && !ticket.tree)
            {
                Answer::EnumDir
            } else {
                Answer::Changes(state.entries[..carried].to_vec())
            };
            self.budget.refund(state.entries.len());
            state.entries.clear();
            state.last = None;
            state.nested = false;
            answer
        };
        state.queue.pop_front();
        drop(state);
        self.bump();
        Some(answer)
    }

    /// Buffers `entries` (action, name relative to the watched directory),
    /// the changes of one report, all or none of them. When they do not fit
    /// the watch's limit or the connection's budget, everything buffered is
    /// dropped and the next answer is STATUS_NOTIFY_ENUM_DIR. An ended
    /// watch takes nothing.
    fn push(&self, entries: &[(u32, Vec<u16>)]) {
        let mut state = self.state();
        if state.end.is_some() || state.overflow {
            return;
        }
        let held = state.entries.len();
        let mut last = state.last;
        for (action, name) in entries {
            push_entry(&mut state.entries, &mut last, *action, name);
        }
        let added = state.entries.len() - held;
        if added == 0 {
            return;
        }
        if entries_len(&state.entries, last) <= self.limit as usize && self.budget.charge(added) {
            state.last = last;
            state.nested |= entries
                .iter()
                .any(|(_, name)| name.contains(&u16::from(b'\\')));
        } else {
            self.budget.refund(held);
            state.entries = Vec::new();
            state.last = None;
            state.nested = false;
            state.overflow = true;
        }
        drop(state);
        self.bump();
    }

    /// Ends the watch with `status` for every request on it, and gives back
    /// what it held.
    fn end(&self, status: u32) {
        let mut state = self.state();
        if state.end.is_some() {
            return;
        }
        state.end = Some(status);
        self.budget.refund(state.entries.len());
        state.entries = Vec::new();
        state.last = None;
        self.budget.watches.fetch_sub(1, Ordering::AcqRel);
        drop(state);
        self.bump();
    }
}

/// One waiting request's place in its watch's queue. Dropping it leaves
/// the queue.
pub(crate) struct Ticket {
    watch: Arc<Watch>,
    id: u64,
    /// The request's OutputBufferLength.
    len: u32,
    /// The request has SMB2_WATCH_TREE.
    tree: bool,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut state = self.watch.state();
        let Some(at) = state.queue.iter().position(|&id| id == self.id) else {
            return;
        };
        state.queue.remove(at);
        drop(state);
        self.watch.bump();
    }
}

/// The watches on one share, by watched directory (MS-FSA
/// Volume.ChangeNotifyList).
///
/// Lock order: a host's waiting reports, then `dirs`, then a watch's state
/// or a host's directory, echo or task, a host's directory before its
/// echo. A report passes on the waiting reports of the directories it
/// changed, then pushes into the watches it matched, after letting go of
/// `dirs`. Only a host's waiting reports are held while taking a lock of
/// the file table, and none of these is taken while holding a lock of the
/// file, lease or durable tables.
pub(crate) struct WatchTable {
    case_sensitive: bool,
    /// Watches in the table; with none, a report costs one load.
    count: AtomicUsize,
    /// Watches with SMB2_WATCH_TREE; with none, only the parent of a change
    /// is looked up.
    tree_count: AtomicUsize,
    dirs: Mutex<HashMap<String, Watched>>,
    /// Batches pushed into watches.
    #[cfg(test)]
    pushes: AtomicUsize,
}

impl WatchTable {
    pub(crate) fn new(case_sensitive: bool) -> Self {
        Self {
            case_sensitive,
            count: AtomicUsize::new(0),
            tree_count: AtomicUsize::new(0),
            dirs: Mutex::default(),
            #[cfg(test)]
            pushes: AtomicUsize::new(0),
        }
    }

    fn insert(&self, watch: &Arc<Watch>) {
        let mut dirs = lock(&self.dirs);
        let key = dir_key(watch.state().dir.components(), self.case_sensitive);
        dirs.entry(key).or_default().watches.push(Arc::clone(watch));
        self.count.fetch_add(1, Ordering::AcqRel);
        if watch.tree {
            self.tree_count.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn remove(&self, watch: &Arc<Watch>) {
        let mut dirs = lock(&self.dirs);
        let key = dir_key(watch.state().dir.components(), self.case_sensitive);
        let Some(watched) = dirs.get_mut(&key) else {
            return;
        };
        let Some(at) = watched.watches.iter().position(|w| Arc::ptr_eq(w, watch)) else {
            return;
        };
        watched.watches.swap_remove(at);
        if watched.watches.is_empty() {
            dirs.remove(&key);
        }
        self.count.fetch_sub(1, Ordering::AcqRel);
        if watch.tree {
            self.tree_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Buffers `changes` in every watch they match and wakes the requests
    /// waiting on those watches (MS-FSA 2.1.4.1). A change matches a watch
    /// of its parent directory, or of any directory above it when the watch
    /// covers the tree, whose filter shares a bit with the change's. The
    /// watched directory itself is never reported. Names are relative to
    /// the watched directory, as spelled in `path`: the spelling of the
    /// client that made the change, which on a backend that ignores case can
    /// differ from the name on disk. Watches are matched by path, so a
    /// change made through a symlink inside the share reaches the watchers
    /// of the path it was made through, not of the directory the symlink
    /// leads to. Each watch takes the changes of one call together, in
    /// order, after the backend's reports of the same directories that
    /// arrived before.
    pub(crate) fn report(&self, changes: &[Change<'_>]) {
        self.deliver(changes, |_, _| false);
    }

    /// Notes `changes`, which the server is about to make, so the backend's
    /// reports of them are left out whenever they arrive; with
    /// `renamed_dir`, also the rename of that watched directory itself.
    /// The changes are reported through the returned [`Expected`].
    pub(crate) fn expect(&self, changes: &[Change<'_>], renamed_dir: Option<&SmbPath>) -> Expected {
        let mut marks = Vec::new();
        if self.is_empty() {
            return Expected { marks };
        }
        let dirs = lock(&self.dirs);
        for (at, change) in changes.iter().enumerate() {
            if let Some((host, key)) = self.host_of(&dirs, change.path) {
                let action = self.note(&host, change, &key);
                let name = change.path.file_name().unwrap_or_default().to_string();
                marks.push(Mark {
                    host,
                    change: Some(at),
                    action,
                    key,
                    name,
                    filter: change.filter,
                });
            }
        }
        let renamed = renamed_dir.and_then(|dir| {
            dirs.get(&dir_key(dir.components(), self.case_sensitive))?
                .host
                .clone()
                .filter(|host| !host.idle.load(Ordering::Acquire))
        });
        if let Some(host) = renamed {
            lock(&host.echo).report(RENAMED_SELF, String::new());
            marks.push(Mark {
                host,
                change: None,
                action: Some(RENAMED_SELF),
                key: String::new(),
                name: String::new(),
                filter: 0,
            });
        }
        Expected { marks }
    }

    /// The listening host of the directory `path` is in, and the name of
    /// `path` in it as the table compares names.
    fn host_of(
        &self,
        dirs: &HashMap<String, Watched>,
        path: &SmbPath,
    ) -> Option<(Arc<Host>, String)> {
        let components = path.components();
        let parent = components.len().checked_sub(1)?;
        let host = dirs
            .get(&dir_key(&components[..parent], self.case_sensitive))?
            .host
            .clone()
            .filter(|host| !host.idle.load(Ordering::Acquire))?;
        Some((host, self.name_key(&components[parent])))
    }

    /// Notes `change` to the entry `name` in `host`'s echo. Returns the
    /// action noted to hide one backend report, if any.
    fn note(&self, host: &Host, change: &Change<'_>, name: &str) -> Option<u32> {
        let named = matches!(
            change.action,
            FILE_ACTION_ADDED
                | FILE_ACTION_REMOVED
                | FILE_ACTION_RENAMED_OLD_NAME
                | FILE_ACTION_RENAMED_NEW_NAME
        );
        let mut echo = lock(&host.echo);
        echo.touch(name.to_string());
        if named && change.seen {
            echo.report(change.action, name.to_string());
            return Some(change.action);
        }
        None
    }

    /// Pushes `changes` into the watches they reach, noting each in the echo
    /// of its directory first unless `noted` says it is, by its index.
    fn deliver(&self, changes: &[Change<'_>], noted: impl Fn(usize, &Arc<Host>) -> bool) {
        if self.count.load(Ordering::Acquire) == 0 {
            return;
        }
        let deep = self.tree_count.load(Ordering::Acquire) > 0;
        let dirs = lock(&self.dirs);
        let mut batches: Vec<(Arc<Watch>, Batch)> = Vec::new();
        let mut slots: HashMap<*const Watch, usize> = HashMap::new();
        let mut hosts: Vec<Arc<Host>> = Vec::new();
        for (at, change) in changes.iter().enumerate() {
            let components = change.path.components();
            let Some(parent) = components.len().checked_sub(1) else {
                continue;
            };
            if let Some((host, name)) = self.host_of(&dirs, change.path)
                && !noted(at, &host)
            {
                self.note(&host, change, &name);
            }
            let top = if deep { 0 } else { parent };
            for depth in (top..=parent).rev() {
                let Some(watched) = dirs.get(&dir_key(&components[..depth], self.case_sensitive))
                else {
                    continue;
                };
                // What the backend reported earlier in this directory or a
                // directory above, which a tree watch hears too, goes first.
                if let Some(host) = &watched.host
                    && !host.idle.load(Ordering::Acquire)
                    && !hosts.iter().any(|h| Arc::ptr_eq(h, host))
                {
                    hosts.push(Arc::clone(host));
                }
                let mut name = None;
                for watch in &watched.watches {
                    if watch.filter & change.filter == 0 || (depth < parent && !watch.tree) {
                        continue;
                    }
                    let name = name
                        .get_or_insert_with(|| {
                            components[depth..]
                                .join("\\")
                                .encode_utf16()
                                .collect::<Vec<u16>>()
                        })
                        .clone();
                    let slot = *slots.entry(Arc::as_ptr(watch)).or_insert_with(|| {
                        batches.push((Arc::clone(watch), Vec::new()));
                        batches.len() - 1
                    });
                    batches[slot].1.push((change.action, name));
                }
            }
        }
        // A watch removed from here on ends before or after it takes the
        // batch; either way the end gives back what it holds.
        drop(dirs);
        for host in hosts {
            host.pass_on(None);
        }
        for (watch, entries) in batches {
            #[cfg(test)]
            self.pushes.fetch_add(1, Ordering::AcqRel);
            watch.push(&entries);
        }
    }

    /// Ends every watch of the directory `dir`, on any connection, with
    /// `status` and takes them out of the table (MS-FSA 2.1.5.15.3).
    /// Watches of directories above or below it stay.
    pub(crate) fn end_at(&self, dir: &SmbPath, status: u32) {
        if self.is_empty() {
            return;
        }
        let key = dir_key(dir.components(), self.case_sensitive);
        let ended = self.take_entry(&mut lock(&self.dirs), &key);
        for watch in ended {
            watch.end(status);
        }
    }

    /// Takes the watches of the directory keyed `key` out of the table.
    fn take_entry(&self, dirs: &mut HashMap<String, Watched>, key: &str) -> Vec<Arc<Watch>> {
        let Some(mut watched) = dirs.remove(key) else {
            return Vec::new();
        };
        for watch in &watched.watches {
            self.count.fetch_sub(1, Ordering::AcqRel);
            if watch.tree {
                self.tree_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
        std::mem::take(&mut watched.watches)
    }

    /// `name` as the table compares names.
    fn name_key(&self, name: &str) -> String {
        if self.case_sensitive {
            name.to_string()
        } else {
            name.to_lowercase()
        }
    }

    /// Notes that the server changed the entry at `path`, or is about to
    /// close it after changing it, so the backend's reports of that
    /// entry's modification are dropped for [`ECHO_TIME`].
    pub(crate) fn touch(&self, path: &SmbPath) {
        self.echo_at(path, Echo::touch);
    }

    /// Notes that the server is about to close the entry at `path`, open
    /// to write, created or overwritten, without having written it, so the
    /// backend's next report of its modification is dropped.
    pub(crate) fn closed(&self, path: &SmbPath) {
        self.echo_at(path, Echo::closed);
    }

    /// Records the server's change to the entry at `path` with `record`,
    /// when its directory hears the backend.
    fn echo_at(&self, path: &SmbPath, record: fn(&mut Echo, String)) {
        if self.is_empty() {
            return;
        }
        let components = path.components();
        let Some(parent) = components.len().checked_sub(1) else {
            return;
        };
        let dirs = lock(&self.dirs);
        let host = dirs
            .get(&dir_key(&components[..parent], self.case_sensitive))
            .and_then(|watched| watched.host.as_ref())
            .filter(|host| !host.idle.load(Ordering::Acquire));
        if let Some(host) = host {
            record(&mut lock(&host.echo), self.name_key(&components[parent]));
        }
    }

    /// Whether a change at `path` would reach a watch, whatever its
    /// filter.
    pub(crate) fn watching(&self, path: &SmbPath) -> bool {
        if self.count.load(Ordering::Acquire) == 0 {
            return false;
        }
        let components = path.components();
        let Some(parent) = components.len().checked_sub(1) else {
            return false;
        };
        let top = if self.tree_count.load(Ordering::Acquire) > 0 {
            0
        } else {
            parent
        };
        let dirs = lock(&self.dirs);
        (top..=parent).any(|depth| {
            dirs.get(&dir_key(&components[..depth], self.case_sensitive))
                .is_some_and(|watched| depth == parent || watched.watches.iter().any(|w| w.tree))
        })
    }

    /// Moves every watch of `from`, or of a directory below it, to the
    /// matching directory under `to`, which `from` was renamed to, with the
    /// backend's reports for it. What the watches buffered stays.
    pub(crate) fn rename(&self, from: &SmbPath, to: &SmbPath) {
        if self.count.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut dirs = lock(&self.dirs);
        let keys: Vec<String> = dirs.keys().cloned().collect();
        let mut moved = Vec::new();
        for key in keys {
            let Some(watched) = dirs.get(&key) else {
                continue;
            };
            let mut new_key = None;
            for watch in &watched.watches {
                let mut state = watch.state();
                if let Some(dir) = rebase(&state.dir, from, to, self.case_sensitive) {
                    new_key = Some(dir_key(dir.components(), self.case_sensitive));
                    state.dir = dir;
                }
            }
            if let Some(host) = &watched.host {
                let mut dir = lock(&host.dir);
                if let Some(rebased) = rebase(&dir, from, to, self.case_sensitive) {
                    new_key
                        .get_or_insert_with(|| dir_key(rebased.components(), self.case_sensitive));
                    *dir = rebased;
                }
            }
            if let Some(new_key) = new_key
                && let Some(watched) = dirs.remove(&key)
            {
                moved.push((new_key, watched));
            }
        }
        for (key, mut watched) in moved {
            match dirs.get_mut(&key) {
                // What was watched under the new name is gone; the reports
                // of the moved directory are kept.
                Some(existing) => {
                    existing.watches.append(&mut watched.watches);
                    if let Some(old) = std::mem::replace(&mut existing.host, watched.host.take()) {
                        old.stop();
                    }
                }
                None => {
                    dirs.insert(key, watched);
                }
            }
        }
    }

    /// Asks `handle`, an open of the directory `watch` watches, for the
    /// backend's reports of changes to the directory's entries, unless the
    /// directory has them already or the backend gave none. They go to
    /// every watch of the directory until its last watch ends or they stop.
    pub(crate) async fn listen(
        &self,
        share: &Arc<ShareBindings>,
        watch: &Arc<Watch>,
        handle: &dyn Handle,
    ) {
        // The server's own changes are recorded before the backend can see
        // any.
        let host = {
            let mut dirs = lock(&self.dirs);
            let dir = watch.state().dir.clone();
            let Some(watched) = dirs.get_mut(&dir_key(dir.components(), self.case_sensitive))
            else {
                return;
            };
            if watched.host.is_some() || !watched.watches.iter().any(|w| Arc::ptr_eq(w, watch)) {
                return;
            }
            let host = Arc::new(Host::new(dir, share));
            watched.host = Some(Arc::clone(&host));
            host
        };
        match handle.watch().await {
            Ok(Some(source)) => host.start(source),
            _ => {
                host.idle.store(true, Ordering::Release);
                lock(&host.echo).clear();
            }
        }
    }

    /// Takes `host` away from its directory, which can listen again.
    fn detach(&self, host: &Arc<Host>) {
        let mut dirs = lock(&self.dirs);
        let key = dir_key(lock(&host.dir).components(), self.case_sensitive);
        if let Some(watched) = dirs.get_mut(&key)
            && watched.host.as_ref().is_some_and(|h| Arc::ptr_eq(h, host))
        {
            watched.host = None;
        }
    }

    /// The watches of the directory `host` reports for.
    fn watches_of(&self, host: &Arc<Host>) -> Vec<Arc<Watch>> {
        let dirs = lock(&self.dirs);
        let key = dir_key(lock(&host.dir).components(), self.case_sensitive);
        dirs.get(&key)
            .filter(|watched| watched.host.as_ref().is_some_and(|h| Arc::ptr_eq(h, host)))
            .map(|watched| watched.watches.clone())
            .unwrap_or_default()
    }

    /// The backend's reports ended without the directory being deleted:
    /// changes may have been lost, so every watch of it answers
    /// STATUS_NOTIFY_ENUM_DIR next, and the directory can listen again.
    fn host_ended(&self, host: &Arc<Host>) {
        for watch in self.watches_of(host) {
            watch.lose();
        }
        self.detach(host);
    }

    /// The directory `host` reports for was deleted outside the server: its
    /// watches end with STATUS_DELETE_PENDING, as when it is marked for
    /// deletion through the server, and stay ended.
    fn host_deleted(&self, host: &Arc<Host>) {
        let ended = {
            let mut dirs = lock(&self.dirs);
            let key = dir_key(lock(&host.dir).components(), self.case_sensitive);
            let ours = dirs
                .get(&key)
                .is_some_and(|watched| watched.host.as_ref().is_some_and(|h| Arc::ptr_eq(h, host)));
            if !ours {
                return;
            }
            self.take_entry(&mut dirs, &key)
        };
        for watch in ended {
            watch.state().gone = true;
            watch.end(ntstatus::STATUS_DELETE_PENDING);
        }
    }

    /// Buffers the backend's `changes` to the directory `host` reports for
    /// in each of its watches whose filter asks for them, but those the
    /// server made.
    fn take_host_changes(&self, share: &ShareBindings, host: &Arc<Host>, changes: Vec<DirChange>) {
        let dir = lock(&host.dir).clone();
        let names = |directory: bool| {
            if directory {
                FILE_NOTIFY_CHANGE_DIR_NAME
            } else {
                FILE_NOTIFY_CHANGE_FILE_NAME
            }
        };
        let case_sensitive = share.backend.capabilities().case_sensitive;
        // (action, name, filter) of what the watches hear.
        let mut heard: Vec<(u32, &str, u32)> = Vec::new();
        // Modifications heard, by index in `heard`, unless an open through
        // the server may be making them, with their paths.
        let mut unless_open: Vec<(usize, SmbPath)> = Vec::new();
        let mut lost = false;
        for change in &changes {
            let valid = is_valid_component(&change.name);
            let filter = names(change.is_directory);
            // A rename to or from a name the server cannot use is the
            // removal or addition of the other name.
            let kind = match &change.kind {
                DirChangeKind::Renamed { from } => match (is_valid_component(from), valid) {
                    (true, true) => change.kind.clone(),
                    (true, false) => {
                        let key = self.name_key(from);
                        if !lock(&host.echo)
                            .take_any(&[FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_OLD_NAME], &key)
                        {
                            heard.push((FILE_ACTION_REMOVED, from, filter));
                        }
                        continue;
                    }
                    (false, true) => DirChangeKind::Added,
                    (false, false) => continue,
                },
                kind => kind.clone(),
            };
            match kind {
                DirChangeKind::Deleted => {
                    self.host_deleted(host);
                    return;
                }
                DirChangeKind::Lost => {
                    lost = true;
                    continue;
                }
                // Moved outside the server, the directory keeps its watches
                // under its old name, where the server's changes below it
                // no longer reach them.
                DirChangeKind::Moved => {
                    lost |= !lock(&host.echo).take(RENAMED_SELF, "");
                    continue;
                }
                _ if !valid => continue,
                _ => {}
            }
            let key = self.name_key(&change.name);
            match kind {
                // A rename the kernel split in two matches the server's
                // rename too.
                DirChangeKind::Added | DirChangeKind::Removed => {
                    let (action, half) = if kind == DirChangeKind::Added {
                        (FILE_ACTION_ADDED, FILE_ACTION_RENAMED_NEW_NAME)
                    } else {
                        (FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_OLD_NAME)
                    };
                    if !lock(&host.echo).take_any(&[action, half], &key) {
                        heard.push((action, &change.name, filter));
                    }
                }
                DirChangeKind::Renamed { .. } => {
                    let DirChangeKind::Renamed { from } = &change.kind else {
                        continue;
                    };
                    let from_key = self.name_key(from);
                    let mut echo = lock(&host.echo);
                    let echoed = echo.take(FILE_ACTION_RENAMED_OLD_NAME, &from_key)
                        & echo.take(FILE_ACTION_RENAMED_NEW_NAME, &key);
                    drop(echo);
                    if !echoed {
                        heard.push((FILE_ACTION_RENAMED_OLD_NAME, from, filter));
                        heard.push((FILE_ACTION_RENAMED_NEW_NAME, &change.name, filter));
                    }
                }
                DirChangeKind::Modified | DirChangeKind::AttributesChanged => {
                    let Ok(path) = dir.join(&change.name) else {
                        continue;
                    };
                    let echoed = {
                        let mut echo = lock(&host.echo);
                        (kind == DirChangeKind::Modified && echo.take(FILE_ACTION_MODIFIED, &key))
                            || echo.touched(&key)
                    };
                    if echoed {
                        continue;
                    }
                    let filter = match kind {
                        DirChangeKind::Modified => CONTENT_CHANGED,
                        _ => FILE_NOTIFY_CHANGE_ATTRIBUTES,
                    };
                    unless_open.push((heard.len(), path));
                    heard.push((FILE_ACTION_MODIFIED, &change.name, filter));
                }
                _ => {}
            }
        }
        let paths: Vec<SmbPath> = unless_open.iter().map(|(_, path)| path.clone()).collect();
        let open = share.files.open_to_change(&paths, case_sensitive);
        let mut dropped = vec![false; heard.len()];
        for ((at, _), open) in unless_open.iter().zip(open) {
            dropped[*at] = open;
        }
        let mut at = 0;
        heard.retain(|_| {
            at += 1;
            !dropped[at - 1]
        });
        self.hear(host, &heard, lost);
    }

    /// Pushes `heard`, (action, name, filter) of changes the backend
    /// reported, into each watch of `host`'s directory whose filter asks
    /// for them, after STATUS_NOTIFY_ENUM_DIR when `lost`.
    fn hear(&self, host: &Arc<Host>, heard: &[(u32, &str, u32)], lost: bool) {
        for watch in self.watches_of(host) {
            if lost {
                watch.lose();
            }
            let batch: Batch = heard
                .iter()
                .filter(|(_, _, filter)| watch.filter & filter != 0)
                .map(|(action, name, _)| (*action, name.encode_utf16().collect()))
                .collect();
            if !batch.is_empty() {
                watch.push(&batch);
            }
        }
    }

    /// True when the share has no watch, so no change reaches anyone.
    pub(crate) fn is_empty(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    /// Batches pushed into watches so far.
    #[cfg(test)]
    pub(crate) fn pushes(&self) -> usize {
        self.pushes.load(Ordering::Acquire)
    }

    /// Watches on the share.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

/// An open's watch, in its share's table. Dropping it removes the watch
/// and ends the requests waiting on it with STATUS_NOTIFY_CLEANUP.
pub(crate) struct WatchReg {
    share: Arc<ShareBindings>,
    watch: Arc<Watch>,
}

impl WatchReg {
    /// Arms a watch of the directory `dir` on `share` for a first
    /// CHANGE_NOTIFY with `filter`, `tree` and OutputBufferLength `len`.
    /// `None` when the connection behind `budget` holds
    /// [`MAX_WATCHES_PER_CONNECTION`] watches.
    pub(crate) fn arm(
        share: &Arc<ShareBindings>,
        dir: SmbPath,
        filter: u32,
        tree: bool,
        len: u32,
        budget: &Arc<NotifyBudget>,
    ) -> Option<Self> {
        let watch = Watch::new(dir, filter, tree, len, budget)?;
        share.watches.insert(&watch);
        Some(Self {
            share: Arc::clone(share),
            watch,
        })
    }

    pub(crate) fn watch(&self) -> &Arc<Watch> {
        &self.watch
    }

    /// Whether the watch has ended while its open stays.
    pub(crate) fn ended(&self) -> bool {
        self.watch.state().end.is_some()
    }

    /// Whether the watch ended because its directory was deleted outside
    /// the server.
    pub(crate) fn gone(&self) -> bool {
        self.watch.state().gone
    }

    /// Takes the watch out of the table, so no change reaches it; dropping
    /// the registration ends it.
    pub(crate) fn leave_table(&self) {
        self.share.watches.remove(&self.watch);
    }
}

impl Drop for WatchReg {
    fn drop(&mut self) {
        self.share.watches.remove(&self.watch);
        self.watch.end(ntstatus::STATUS_NOTIFY_CLEANUP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::messages::change_notify::{
        FILE_ACTION_ADDED, FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME,
        FILE_ACTION_RENAMED_OLD_NAME, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    };
    use crate::server::ShareMode;
    use crate::tests::memfs::MemFsBackend;

    const NAMES: u32 = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME;

    fn p(s: &str) -> SmbPath {
        s.parse().unwrap()
    }

    fn watch_on(
        table: &WatchTable,
        dir: &str,
        filter: u32,
        tree: bool,
        len: u32,
        budget: &Arc<NotifyBudget>,
    ) -> Arc<Watch> {
        let watch = Watch::new(p(dir), filter, tree, len, budget).expect("under the cap");
        table.insert(&watch);
        watch
    }

    fn added(table: &WatchTable, path: &str) {
        table.report(&[Change {
            path: &p(path),
            action: FILE_ACTION_ADDED,
            filter: FILE_NOTIFY_CHANGE_FILE_NAME,
            seen: true,
        }]);
    }

    /// (action, name) of each entry in a response buffer.
    fn decode(buf: &[u8]) -> Vec<(u32, String)> {
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let field = |o: usize| u32::from_le_bytes(buf[at + o..at + o + 4].try_into().unwrap());
            let len = field(8) as usize;
            let name: Vec<u16> = buf[at + 12..at + 12 + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push((field(4), String::from_utf16(&name).unwrap()));
            match field(0) {
                0 => return out,
                next => at += next as usize,
            }
        }
    }

    /// The names a request on `watch` gets now, or `None` when it would
    /// wait.
    fn names(watch: &Arc<Watch>) -> Option<Vec<String>> {
        let ticket = watch.enqueue(MAX_NOTIFY_BUFFER, true);
        match watch.take(&ticket)? {
            Answer::Changes(buf) => Some(decode(&buf).into_iter().map(|(_, n)| n).collect()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_change_reaches_its_parent_and_tree_watches_above() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        let root = watch_on(&table, "", NAMES, false, 4096, &budget);
        let root_tree = watch_on(&table, "", NAMES, true, 4096, &budget);
        let a = watch_on(&table, "a", NAMES, false, 4096, &budget);
        let a_tree = watch_on(&table, "a", NAMES, true, 4096, &budget);
        let abc = watch_on(&table, "a\\b\\c", NAMES, true, 4096, &budget);
        let other = watch_on(
            &table,
            "a\\b",
            FILE_NOTIFY_CHANGE_DIR_NAME,
            false,
            4096,
            &budget,
        );

        added(&table, "a\\b\\c\\f");
        assert_eq!(names(&root), None);
        assert_eq!(names(&root_tree).unwrap(), ["a\\b\\c\\f"]);
        assert_eq!(names(&a), None);
        assert_eq!(names(&a_tree).unwrap(), ["b\\c\\f"]);
        assert_eq!(names(&abc).unwrap(), ["f"]);

        // The filters share no bit.
        added(&table, "a\\b\\g");
        assert_eq!(names(&other), None);
        assert_eq!(names(&a_tree).unwrap(), ["b\\g"]);

        // A change to the watched directory itself goes to its parent.
        added(&table, "a");
        assert_eq!(names(&a), None);
        assert_eq!(names(&a_tree), None);
        assert_eq!(names(&root).unwrap(), ["a"]);
        assert_eq!(names(&root_tree).unwrap(), ["a\\b\\g", "a"]);
    }

    #[test]
    fn keys_ignore_case_unless_the_backend_is_case_sensitive() {
        let budget = Arc::default();
        let insensitive = WatchTable::new(false);
        let sensitive = WatchTable::new(true);
        let a = watch_on(&insensitive, "sub", NAMES, false, 4096, &budget);
        let b = watch_on(&sensitive, "sub", NAMES, false, 4096, &budget);
        added(&insensitive, "Sub\\X.txt");
        added(&sensitive, "Sub\\X.txt");
        assert_eq!(names(&a).unwrap(), ["X.txt"]);
        assert_eq!(names(&b), None);
    }

    #[test]
    fn a_full_buffer_answers_enum_dir_once_then_buffers_again() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        // Each entry for a one-letter name is 14 bytes, 16 padded.
        let watch = watch_on(&table, "", NAMES, false, 30, &budget);
        added(&table, "a");
        added(&table, "b");
        added(&table, "c");
        let ticket = watch.enqueue(4096, true);
        assert_eq!(watch.take(&ticket), Some(Answer::EnumDir));
        drop(ticket);
        assert_eq!(names(&watch), None);
        added(&table, "d");
        added(&table, "e");
        assert_eq!(names(&watch).unwrap(), ["d", "e"]);

        // A buffer of 0 holds nothing: every change is an ENUM_DIR.
        let none = watch_on(&table, "z", NAMES, false, 0, &budget);
        added(&table, "z\\f");
        let ticket = none.enqueue(4096, true);
        assert_eq!(none.take(&ticket), Some(Answer::EnumDir));
    }

    #[test]
    fn the_first_requests_length_sticks_and_each_request_caps_it() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        let small = watch_on(&table, "", NAMES, false, 1, &budget);
        added(&table, "a");
        let ticket = small.enqueue(4096, true);
        assert_eq!(small.take(&ticket), Some(Answer::EnumDir));

        let big = watch_on(&table, "d", NAMES, false, 4096, &budget);
        added(&table, "d\\a");
        let ticket = big.enqueue(13, true);
        assert_eq!(big.take(&ticket), Some(Answer::EnumDir));
        drop(ticket);
        // The entries went with that answer.
        assert_eq!(names(&big), None);
        assert_eq!(budget.bytes(), 0);
    }

    #[test]
    fn buffers_are_capped_at_64_kib() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        let watch = watch_on(&table, "", NAMES, false, u32::MAX, &budget);
        let name = "n".repeat(255);
        // 524 bytes per entry; 125 entries fit in 64 KiB, 126 do not.
        for i in 0..126 {
            added(&table, &format!("{}{i:03}", &name[..252]));
        }
        let ticket = watch.enqueue(u32::MAX, true);
        assert_eq!(watch.take(&ticket), Some(Answer::EnumDir));
    }

    #[test]
    fn bytes_are_charged_to_the_connection_and_given_back() {
        let budget: Arc<NotifyBudget> = Arc::default();
        let share = ShareBindings::new(
            "s".to_string(),
            Arc::new(MemFsBackend::new()),
            ShareMode::Public,
            HashMap::new(),
            false,
            true,
            true,
        );
        let reg = WatchReg::arm(&share, p("d"), NAMES, false, 4096, &budget).unwrap();
        let watch = Arc::clone(reg.watch());
        share.watches.report(&[Change {
            path: &p("d\\ab"),
            action: FILE_ACTION_REMOVED,
            filter: FILE_NOTIFY_CHANGE_FILE_NAME,
            seen: true,
        }]);
        assert_eq!(budget.bytes(), 16);
        assert_eq!(names(&watch).unwrap(), ["ab"]);
        assert_eq!(budget.bytes(), 0);
        share.watches.report(&[Change {
            path: &p("d\\ab"),
            action: FILE_ACTION_ADDED,
            filter: FILE_NOTIFY_CHANGE_FILE_NAME,
            seen: true,
        }]);
        assert_eq!((budget.watches(), budget.bytes()), (1, 16));
        drop(reg);
        assert_eq!((budget.watches(), budget.bytes()), (0, 0));
        assert_eq!(share.watches.len(), 0);

        // The watch that would cross the connection's budget overflows.
        let first = Watch::new(p(""), NAMES, false, 64, &budget).unwrap();
        let second = Watch::new(p(""), NAMES, false, 64, &budget).unwrap();
        budget.charge(MAX_NOTIFY_BYTES - 20);
        first.push(&[(FILE_ACTION_ADDED, vec![0x61])]);
        second.push(&[(FILE_ACTION_ADDED, vec![0x61])]);
        assert_eq!(budget.bytes(), MAX_NOTIFY_BYTES - 4);
        let ticket = second.enqueue(64, true);
        assert_eq!(second.take(&ticket), Some(Answer::EnumDir));
        assert!(matches!(
            first.take(&first.enqueue(64, true)),
            Some(Answer::Changes(_))
        ));
        assert_eq!(budget.bytes(), MAX_NOTIFY_BYTES - 20);
    }

    #[test]
    fn watches_stop_at_the_connection_cap() {
        let budget = Arc::default();
        let held: Vec<_> = (0..MAX_WATCHES_PER_CONNECTION)
            .map(|_| Watch::new(p(""), NAMES, false, 0, &budget).expect("under the cap"))
            .collect();
        assert!(Watch::new(p(""), NAMES, false, 0, &budget).is_none());
        held[0].end(ntstatus::STATUS_NOTIFY_CLEANUP);
        assert!(Watch::new(p(""), NAMES, false, 0, &budget).is_some());
    }

    #[test]
    fn waiting_requests_take_in_order_and_an_end_answers_them_all() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        let watch = watch_on(&table, "", NAMES, false, 4096, &budget);
        let first = watch.enqueue(4096, true);
        let second = watch.enqueue(4096, true);
        let third = watch.enqueue(4096, true);
        added(&table, "a");
        assert_eq!(watch.take(&second), None);
        assert!(matches!(watch.take(&first), Some(Answer::Changes(_))));
        added(&table, "b");
        // A request that leaves the queue lets the next one take.
        drop(second);
        let Some(Answer::Changes(buf)) = watch.take(&third) else {
            panic!("third takes after second left");
        };
        assert_eq!(decode(&buf), [(FILE_ACTION_ADDED, "b".to_string())]);

        let a = watch.enqueue(4096, true);
        let b = watch.enqueue(4096, true);
        watch.end(ntstatus::STATUS_NOTIFY_CLEANUP);
        for ticket in [&b, &a] {
            assert_eq!(
                watch.take(ticket),
                Some(Answer::Ended(ntstatus::STATUS_NOTIFY_CLEANUP))
            );
        }
    }

    #[test]
    fn a_request_without_watch_tree_gets_no_nested_names() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        let watch = watch_on(&table, "", NAMES, true, 4096, &budget);
        added(&table, "a\\b");
        let flat = watch.enqueue(4096, false);
        assert_eq!(watch.take(&flat), Some(Answer::EnumDir));
        drop(flat);
        added(&table, "c");
        let flat = watch.enqueue(4096, false);
        assert!(matches!(watch.take(&flat), Some(Answer::Changes(_))));
        drop(flat);
        added(&table, "a\\d");
        assert_eq!(names(&watch).unwrap(), ["a\\d"]);
    }

    #[test]
    fn a_watch_ended_around_a_push_gives_back_its_bytes() {
        let budget: Arc<NotifyBudget> = Arc::default();
        let share = ShareBindings::new(
            "s".to_string(),
            Arc::new(MemFsBackend::new()),
            ShareMode::Public,
            HashMap::new(),
            false,
            true,
            true,
        );
        let entry = [(FILE_ACTION_ADDED, vec![0x61])];
        // A report that matched the watch before it left the table pushes
        // after the end: nothing is kept.
        let reg = WatchReg::arm(&share, p(""), NAMES, false, 4096, &budget).unwrap();
        let watch = Arc::clone(reg.watch());
        drop(reg);
        watch.push(&entry);
        assert_eq!(budget.bytes(), 0);
        let ticket = watch.enqueue(4096, true);
        assert_eq!(
            watch.take(&ticket),
            Some(Answer::Ended(ntstatus::STATUS_NOTIFY_CLEANUP))
        );
        // One that pushes first has its bytes given back by the end.
        let reg = WatchReg::arm(&share, p(""), NAMES, false, 4096, &budget).unwrap();
        reg.watch().push(&entry);
        assert_eq!(budget.bytes(), 16);
        drop(reg);
        assert_eq!((budget.watches(), budget.bytes()), (0, 0));
    }

    #[test]
    fn renames_move_watches_at_and_below_the_renamed_directory() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        let renamed = watch_on(&table, "a", NAMES, false, 4096, &budget);
        let below = watch_on(&table, "a\\b", NAMES, true, 4096, &budget);
        let sibling = watch_on(&table, "ab", NAMES, false, 4096, &budget);
        added(&table, "a\\early");
        table.rename(&p("A"), &p("z"));
        added(&table, "z\\late");
        added(&table, "z\\b\\c\\deep");
        added(&table, "ab\\s");
        assert_eq!(names(&renamed).unwrap(), ["early", "late"]);
        assert_eq!(names(&below).unwrap(), ["c\\deep"]);
        assert_eq!(names(&sibling).unwrap(), ["s"]);
        // The old names match nothing.
        added(&table, "a\\gone");
        added(&table, "a\\b\\gone");
        assert_eq!(names(&renamed), None);
        assert_eq!(names(&below), None);
        assert_eq!(renamed.state().dir, p("z"));
        assert_eq!(below.state().dir, p("z\\b"));
    }

    #[test]
    fn watching_looks_at_the_parent_and_tree_watches_above() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        assert!(!table.watching(&p("a\\b\\c")));
        let _plain = watch_on(&table, "a\\b", 0, false, 4096, &budget);
        assert!(table.watching(&p("A\\b\\c")));
        assert!(!table.watching(&p("a\\b\\c\\d")));
        let _tree = watch_on(&table, "a", 0, true, 4096, &budget);
        assert!(table.watching(&p("a\\b\\c\\d")));
        assert!(!table.watching(&p("a")));
    }

    #[test]
    fn a_rename_pair_is_buffered_whole_or_not_at_all() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        // Each one-letter entry is 14 bytes, 16 padded: the pair takes 30,
        // the first half alone 14.
        let fits = watch_on(&table, "", NAMES, false, 30, &budget);
        let half = watch_on(&table, "", NAMES, false, 16, &budget);
        let mut fits_changed = fits.subscribe();
        let mut half_changed = half.subscribe();
        let (from, to) = (p("c"), p("e"));
        table.report(&[
            Change {
                path: &from,
                action: FILE_ACTION_RENAMED_OLD_NAME,
                filter: FILE_NOTIFY_CHANGE_FILE_NAME,
                seen: true,
            },
            Change {
                path: &to,
                action: FILE_ACTION_RENAMED_NEW_NAME,
                filter: FILE_NOTIFY_CHANGE_FILE_NAME,
                seen: true,
            },
        ]);
        // One push each: a request woken in between could not take half.
        assert_eq!(*fits_changed.borrow_and_update(), 1);
        assert_eq!(*half_changed.borrow_and_update(), 1);
        assert_eq!(names(&fits).unwrap(), ["c", "e"]);
        let ticket = half.enqueue(4096, true);
        assert_eq!(half.take(&ticket), Some(Answer::EnumDir));
    }

    /// The (action, name) of each change a request on `watch` gets now, or
    /// `None` when it would wait.
    fn actions(watch: &Arc<Watch>) -> Option<Vec<(u32, String)>> {
        let ticket = watch.enqueue(MAX_NOTIFY_BUFFER, true);
        match watch.take(&ticket)? {
            Answer::Changes(buf) => Some(decode(&buf)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn host_changes_leave_out_what_the_server_did() {
        use crate::backend::{DirChange, DirChangeKind};
        let budget: Arc<NotifyBudget> = Arc::default();
        let share = ShareBindings::new(
            "s".to_string(),
            Arc::new(MemFsBackend::new()),
            ShareMode::Public,
            HashMap::new(),
            false,
            true,
            true,
        );
        let all = NAMES | CONTENT_CHANGED;
        let reg = WatchReg::arm(&share, p("d"), all, false, 4096, &budget).unwrap();
        let names_reg = WatchReg::arm(&share, p("d"), NAMES, false, 4096, &budget).unwrap();
        let watch = Arc::clone(reg.watch());
        let names_only = Arc::clone(names_reg.watch());
        let host = Arc::new(Host::new(p("d"), &share));
        lock(&share.watches.dirs)
            .get_mut(&dir_key(p("d").components(), false))
            .unwrap()
            .host = Some(Arc::clone(&host));
        let take = |changes| share.watches.take_host_changes(&share, &host, changes);
        let server = |action, path: &str, seen| {
            share.watches.report(&[Change {
                path: &p(path),
                action,
                filter: FILE_NOTIFY_CHANGE_FILE_NAME,
                seen,
            }]);
        };
        let both = || (names(&watch), names(&names_only));
        server(FILE_ACTION_ADDED, "d\\X", true);
        server(FILE_ACTION_RENAMED_OLD_NAME, "d\\X", true);
        server(FILE_ACTION_RENAMED_NEW_NAME, "d\\y", true);
        share.watches.touch(&p("d\\w"));
        assert_eq!(names(&watch).unwrap(), ["X", "X", "y"]);
        assert_eq!(names(&names_only).unwrap(), ["X", "X", "y"]);

        let host_change = |name: &str, kind| DirChange::new(name, kind, false);
        let renamed = |from: &str| DirChangeKind::Renamed {
            from: from.to_string(),
        };
        // One backend report reaches each watch whose filter asks for it.
        take(vec![
            host_change("x", DirChangeKind::Added),
            host_change("y", renamed("x")),
            host_change("w", DirChangeKind::Modified),
            host_change("v", DirChangeKind::Modified),
            host_change("b", renamed("a")),
            host_change("bad:name", DirChangeKind::Added),
        ]);
        assert_eq!(names(&watch).unwrap(), ["v", "a", "b"]);
        assert_eq!(names(&names_only).unwrap(), ["a", "b"]);

        // Each server report hides one backend report, for every watch.
        take(vec![host_change("x", DirChangeKind::Added)]);
        assert_eq!(both(), (Some(vec!["x".into()]), Some(vec!["x".into()])));

        // A rename the kernel split into a removal and an addition.
        server(FILE_ACTION_RENAMED_OLD_NAME, "d\\m", true);
        server(FILE_ACTION_RENAMED_NEW_NAME, "d\\n", true);
        both();
        take(vec![host_change("m", DirChangeKind::Removed)]);
        take(vec![host_change("n", DirChangeKind::Added)]);
        assert_eq!(both(), (None, None));

        // The removal of an entry a rename replaced is not seen by the
        // backend, so it hides nothing: a later removal is reported.
        server(FILE_ACTION_REMOVED, "d\\t", false);
        server(FILE_ACTION_RENAMED_OLD_NAME, "d\\s", true);
        server(FILE_ACTION_RENAMED_NEW_NAME, "d\\t", true);
        both();
        take(vec![host_change("t", renamed("s"))]);
        take(vec![host_change("t", DirChangeKind::Removed)]);
        assert_eq!(
            actions(&watch).unwrap(),
            [(FILE_ACTION_REMOVED, "t".to_string())]
        );
        names(&names_only);

        // A rename to or from a name the server cannot use.
        take(vec![
            host_change("bad:1", renamed("c")),
            host_change("e", renamed("bad:2")),
            host_change("bad:4", renamed("bad:3")),
        ]);
        let expected = vec![
            (FILE_ACTION_REMOVED, "c".to_string()),
            (FILE_ACTION_ADDED, "e".to_string()),
        ];
        assert_eq!(actions(&watch).unwrap(), expected);
        assert_eq!(actions(&names_only).unwrap(), expected);

        // A close of a file opened to write hides one modification.
        share.watches.closed(&p("d\\u"));
        take(vec![host_change("u", DirChangeKind::Modified)]);
        assert_eq!(names(&watch), None);
        take(vec![host_change("u", DirChangeKind::Modified)]);
        assert_eq!(names(&watch).unwrap(), ["u"]);
        // An open that may change the file hides its changes; one that
        // only reads does not.
        let file = |access| {
            let sharing = crate::files::Sharing { access, share: 7 };
            let info = crate::backend::FileInfo::new("");
            crate::files::FileRef::register(&share, &info, &p("d\\r"), sharing.into())
                .unwrap()
                .0
        };
        let reader = file(crate::access_mask::FILE_READ_DATA);
        take(vec![host_change("r", DirChangeKind::AttributesChanged)]);
        assert_eq!(names(&watch).unwrap(), ["r"]);
        let writer = file(crate::access_mask::FILE_WRITE_ATTRIBUTES);
        take(vec![host_change("r", DirChangeKind::AttributesChanged)]);
        assert_eq!(names(&watch), None);
        drop((reader, writer));

        // A lost queue, or a move of the directory the server did not
        // make, is an ENUM_DIR.
        take(vec![host_change("", DirChangeKind::Lost)]);
        for watch in [&watch, &names_only] {
            let ticket = watch.enqueue(4096, true);
            assert_eq!(watch.take(&ticket), Some(Answer::EnumDir));
        }
        let expected = share.watches.expect(&[], Some(&p("d")));
        share.watches.rename(&p("d"), &p("e"));
        expected.report(&share.watches, &[]);
        take(vec![host_change("", DirChangeKind::Moved)]);
        assert_eq!(both(), (None, None));
        take(vec![host_change("", DirChangeKind::Moved)]);
        let ticket = watch.enqueue(4096, true);
        assert_eq!(watch.take(&ticket), Some(Answer::EnumDir));

        // A deleted directory ends its watches for good.
        take(vec![host_change("", DirChangeKind::Deleted)]);
        let ticket = watch.enqueue(4096, true);
        assert_eq!(
            watch.take(&ticket),
            Some(Answer::Ended(ntstatus::STATUS_DELETE_PENDING))
        );
        assert!(reg.gone() && names_reg.gone());
        assert!(share.watches.is_empty());
    }

    #[test]
    fn watches_renamed_onto_watched_name_keep_their_own_reports() {
        let budget: Arc<NotifyBudget> = Arc::default();
        let share = ShareBindings::new(
            "s".to_string(),
            Arc::new(MemFsBackend::new()),
            ShareMode::Public,
            HashMap::new(),
            false,
            true,
            true,
        );
        let _old = WatchReg::arm(&share, p("e"), NAMES, false, 4096, &budget).unwrap();
        let _moved = WatchReg::arm(&share, p("d"), NAMES, false, 4096, &budget).unwrap();
        let attach = |dir: &str| {
            let host = Arc::new(Host::new(p(dir), &share));
            lock(&share.watches.dirs)
                .get_mut(&dir_key(p(dir).components(), false))
                .unwrap()
                .host = Some(Arc::clone(&host));
            host
        };
        let old = attach("e");
        let moved = attach("d");
        share.watches.rename(&p("d"), &p("e"));
        let dirs = lock(&share.watches.dirs);
        let kept = dirs[&dir_key(p("e").components(), false)].host.as_ref();
        assert!(kept.is_some_and(|host| Arc::ptr_eq(host, &moved)));
        assert!(old.stopped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn a_change_wakes_a_subscriber() {
        let budget = Arc::default();
        let table = WatchTable::new(false);
        let watch = watch_on(&table, "", NAMES, false, 4096, &budget);
        let mut changed = watch.subscribe();
        added(&table, "a");
        changed.changed().await.unwrap();
        assert_eq!(names(&watch).unwrap(), ["a"]);
    }
}
