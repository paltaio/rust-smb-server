//! Change notification on a share (MS-FSA 2.1.5.11, 2.1.4.1): the
//! directories clients watch, the changes buffered for each watch between
//! requests, and the requests waiting for them.
//!
//! A watch belongs to one open and lives until that open closes. The first
//! CHANGE_NOTIFY on the open fixes its filter, whether it covers the whole
//! tree below the directory and how much it buffers (MS-SMB2 3.3.1.3).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::ntstatus;
use crate::path::{SmbPath, rebase};
use crate::proto::messages::change_notify::{entries_len, push_entry};
use crate::server::ShareBindings;

/// Most bytes one watch buffers, whatever OutputBufferLength asked for.
pub(crate) const MAX_NOTIFY_BUFFER: u32 = 64 * 1024;

/// Most bytes the watches of one connection buffer together. Past it, the
/// watch that would cross it drops what it holds and answers
/// STATUS_NOTIFY_ENUM_DIR next.
pub(crate) const MAX_NOTIFY_BYTES: usize = 8 << 20;

/// Most watches one connection may hold.
pub(crate) const MAX_WATCHES_PER_CONNECTION: usize = 4096;

/// One change to report: `action` (FILE_ACTION_*) happened at `path`, and
/// it matches the FILE_NOTIFY_CHANGE_* bits `filter`.
pub(crate) struct Change<'a> {
    pub path: &'a SmbPath,
    pub action: u32,
    pub filter: u32,
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
                queue: VecDeque::new(),
                next_ticket: 0,
            }),
            changed: tokio::sync::watch::Sender::new(0),
            budget: Arc::clone(budget),
        }))
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
/// Lock order: `dirs`, then a watch's state. A report pushes into the
/// watches it matched after letting go of `dirs`. Neither is held while taking a
/// lock of the file, lease or durable tables, and neither is taken while
/// holding one of those.
pub(crate) struct WatchTable {
    case_sensitive: bool,
    /// Watches in the table; with none, a report costs one load.
    count: AtomicUsize,
    /// Watches with SMB2_WATCH_TREE; with none, only the parent of a change
    /// is looked up.
    tree_count: AtomicUsize,
    dirs: Mutex<HashMap<String, Vec<Arc<Watch>>>>,
}

impl WatchTable {
    pub(crate) fn new(case_sensitive: bool) -> Self {
        Self {
            case_sensitive,
            count: AtomicUsize::new(0),
            tree_count: AtomicUsize::new(0),
            dirs: Mutex::default(),
        }
    }

    fn insert(&self, watch: &Arc<Watch>) {
        let mut dirs = lock(&self.dirs);
        let key = dir_key(watch.state().dir.components(), self.case_sensitive);
        dirs.entry(key).or_default().push(Arc::clone(watch));
        self.count.fetch_add(1, Ordering::AcqRel);
        if watch.tree {
            self.tree_count.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn remove(&self, watch: &Arc<Watch>) {
        let mut dirs = lock(&self.dirs);
        let key = dir_key(watch.state().dir.components(), self.case_sensitive);
        let Some(watches) = dirs.get_mut(&key) else {
            return;
        };
        let Some(at) = watches.iter().position(|w| Arc::ptr_eq(w, watch)) else {
            return;
        };
        watches.swap_remove(at);
        if watches.is_empty() {
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
    /// order.
    pub(crate) fn report(&self, changes: &[Change<'_>]) {
        if self.count.load(Ordering::Acquire) == 0 {
            return;
        }
        let deep = self.tree_count.load(Ordering::Acquire) > 0;
        let dirs = lock(&self.dirs);
        let mut batches: Vec<(Arc<Watch>, Batch)> = Vec::new();
        let mut slots: HashMap<*const Watch, usize> = HashMap::new();
        for change in changes {
            let components = change.path.components();
            let Some(parent) = components.len().checked_sub(1) else {
                continue;
            };
            let top = if deep { 0 } else { parent };
            for depth in (top..=parent).rev() {
                let Some(watches) = dirs.get(&dir_key(&components[..depth], self.case_sensitive))
                else {
                    continue;
                };
                let mut name = None;
                for watch in watches {
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
        for (watch, entries) in batches {
            watch.push(&entries);
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
                .is_some_and(|watches| depth == parent || watches.iter().any(|w| w.tree))
        })
    }

    /// Moves every watch of `from`, or of a directory below it, to the
    /// matching directory under `to`, which `from` was renamed to. What the
    /// watches buffered stays.
    pub(crate) fn rename(&self, from: &SmbPath, to: &SmbPath) {
        if self.count.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut dirs = lock(&self.dirs);
        let mut moved = Vec::new();
        dirs.retain(|_, watches| {
            watches.retain(|watch| {
                let mut state = watch.state();
                match rebase(&state.dir, from, to, self.case_sensitive) {
                    Some(dir) => {
                        state.dir = dir;
                        moved.push(Arc::clone(watch));
                        false
                    }
                    None => true,
                }
            });
            !watches.is_empty()
        });
        for watch in moved {
            let key = dir_key(watch.state().dir.components(), self.case_sensitive);
            dirs.entry(key).or_default().push(watch);
        }
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
        }]);
        assert_eq!(budget.bytes(), 16);
        assert_eq!(names(&watch).unwrap(), ["ab"]);
        assert_eq!(budget.bytes(), 0);
        share.watches.report(&[Change {
            path: &p("d\\ab"),
            action: FILE_ACTION_ADDED,
            filter: FILE_NOTIFY_CHANGE_FILE_NAME,
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
            },
            Change {
                path: &to,
                action: FILE_ACTION_RENAMED_NEW_NAME,
                filter: FILE_NOTIFY_CHANGE_FILE_NAME,
            },
        ]);
        // One push each: a request woken in between could not take half.
        assert_eq!(*fits_changed.borrow_and_update(), 1);
        assert_eq!(*half_changed.borrow_and_update(), 1);
        assert_eq!(names(&fits).unwrap(), ["c", "e"]);
        let ticket = half.enqueue(4096, true);
        assert_eq!(half.take(&ticket), Some(Answer::EnumDir));
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
