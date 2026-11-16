//! The state of the files and directories that handles of the backend have
//! open. Every handle holds the node of its file, and every handle of one
//! file holds the same node.

use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::RwLock;

use super::block::FileCipher;
use super::header::Header;
use super::locks::lock;
use crate::path::{SmbPath, rebase, same_path};

/// What identifies a file in the table: the inner backend's file id when it
/// reports one, else the path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum NodeKey {
    Index(u64),
    Path(String),
}

/// How the inner backend compares names.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NameMatch {
    Exact,
    Folded,
}

impl NameMatch {
    fn is_exact(self) -> bool {
        self == Self::Exact
    }
}

/// Whether an open created its entry or found it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    Opened,
    Created,
}

/// The path as a table key: its components joined with `\`, and folded with
/// `str::to_lowercase` unless names compare exactly.
pub(super) fn path_key(path: &SmbPath, names: NameMatch) -> String {
    let joined = path.display_backslash();
    if names.is_exact() {
        joined
    } else {
        joined.to_lowercase()
    }
}

/// True if the directory with the key `key` is the one with the key `dir` or
/// lies below it. Keys are made by `path_key` with exact names.
pub(super) fn is_at_or_below(key: &str, dir: &str) -> bool {
    dir.is_empty()
        || key
            .strip_prefix(dir)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
}

/// What the backend knows of the header of a stored file.
pub(super) enum HeaderState {
    /// The file may have a header that is not read yet.
    Unknown,
    /// The file has no header: it is new or truncated to zero.
    Absent,
    /// The header read from the file, and the cipher of its key.
    Present(Header, Box<FileCipher>),
}

/// Which state a header is in.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum HeaderKind {
    Unknown,
    Absent,
    Present,
}

#[cfg(test)]
impl HeaderState {
    pub(super) fn kind(&self) -> HeaderKind {
        match self {
            Self::Unknown => HeaderKind::Unknown,
            Self::Absent => HeaderKind::Absent,
            Self::Present(..) => HeaderKind::Present,
        }
    }
}

/// The state of a file behind its lock.
pub(super) struct FileMeta {
    pub(super) header: HeaderState,
}

enum NodeKind {
    Directory,
    File(RwLock<FileMeta>),
}

/// A file or directory with open handles.
pub(super) struct Node {
    table: Arc<NodeTable>,
    /// The inner file id, 0 when the inner backend reports none.
    file_index: u64,
    /// The stored path as of the last rename through the backend.
    path: Mutex<SmbPath>,
    /// Path keys are folded unless names compare exactly.
    names: NameMatch,
    kind: NodeKind,
    /// The file was unlinked or replaced; the node is out of the table.
    detached: AtomicBool,
}

/// The file or directory an open reached.
pub(super) struct Found<'a> {
    pub(super) path: &'a SmbPath,
    pub(super) file_index: u64,
    pub(super) directory: bool,
    pub(super) origin: Origin,
    pub(super) names: NameMatch,
}

/// The nodes of the open files, by key. An entry does not keep its node
/// alive.
pub(super) struct NodeTable {
    entries: Mutex<HashMap<NodeKey, Weak<Node>>>,
}

impl NodeTable {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// The node of the file `found` describes: the one at its key, or a new
    /// one. A create takes the key over from a node that is already there. So
    /// does a directory where a file was, or a file where a directory was.
    pub(super) fn attach(self: &Arc<Self>, found: &Found<'_>) -> Arc<Node> {
        let key = NodeKey::new(found.file_index, found.path, found.names);
        let (node, replaced) = {
            let mut entries = lock(&self.entries);
            let live = entries.get(&key).and_then(Weak::upgrade);
            match live {
                Some(node)
                    if found.origin == Origin::Opened && node.is_directory() == found.directory =>
                {
                    (node, None)
                }
                replaced => {
                    let node = Arc::new(Node::new(self, found));
                    entries.insert(key, Arc::downgrade(&node));
                    (node, replaced)
                }
            }
        };
        if let Some(replaced) = replaced {
            replaced.detached.store(true, Ordering::Release);
        }
        node
    }

    /// Detaches the nodes of the file at `path` after it is unlinked.
    pub(super) fn unlinked(&self, path: &SmbPath, names: NameMatch) {
        for node in self.live() {
            if same_path(&node.path(), path, names.is_exact()) {
                node.detach();
            }
        }
    }

    /// Moves the nodes at or below `from` to `to` after a rename, and detaches
    /// the nodes of the file it replaced.
    pub(super) fn renamed(&self, from: &SmbPath, to: &SmbPath, names: NameMatch) {
        let exact = names.is_exact();
        let same_entry = same_path(from, to, exact);
        let mut moves = Vec::new();
        for node in self.live() {
            let at = node.path();
            if let Some(new_path) = rebase(&at, from, to, exact) {
                if node.file_index != 0 {
                    node.set_path(new_path);
                } else {
                    let old_key = node.key();
                    node.set_path(new_path);
                    moves.push((old_key, node.key(), node));
                }
            } else if !same_entry && same_path(&at, to, exact) {
                node.detach();
            }
        }
        let mut entries = lock(&self.entries);
        for (old_key, _, node) in &moves {
            if entries
                .get(old_key)
                .is_some_and(|entry| ptr::eq(entry.as_ptr(), Arc::as_ptr(node)))
            {
                entries.remove(old_key);
            }
        }
        for (_, new_key, node) in &moves {
            entries.insert(new_key.clone(), Arc::downgrade(node));
        }
    }

    /// The nodes in the table.
    fn live(&self) -> Vec<Arc<Node>> {
        lock(&self.entries)
            .values()
            .filter_map(Weak::upgrade)
            .collect()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        lock(&self.entries).len()
    }
}

impl NodeKey {
    fn new(file_index: u64, path: &SmbPath, names: NameMatch) -> Self {
        if file_index != 0 {
            Self::Index(file_index)
        } else {
            Self::Path(path_key(path, names))
        }
    }
}

impl Node {
    fn new(table: &Arc<NodeTable>, found: &Found<'_>) -> Self {
        let kind = if found.directory {
            NodeKind::Directory
        } else {
            let header = match found.origin {
                Origin::Created => HeaderState::Absent,
                Origin::Opened => HeaderState::Unknown,
            };
            NodeKind::File(RwLock::new(FileMeta { header }))
        };
        Self {
            table: Arc::clone(table),
            file_index: found.file_index,
            path: Mutex::new(found.path.clone()),
            names: found.names,
            kind,
            detached: AtomicBool::new(false),
        }
    }

    pub(super) fn is_directory(&self) -> bool {
        matches!(self.kind, NodeKind::Directory)
    }

    /// The lock and state of a file; `None` for a directory.
    pub(super) fn file(&self) -> Option<&RwLock<FileMeta>> {
        match &self.kind {
            NodeKind::File(file) => Some(file),
            NodeKind::Directory => None,
        }
    }

    /// The header of the file is gone: truncated to zero, or replaced by an
    /// open that created the file.
    pub(super) async fn forget_header(&self) {
        if let Some(file) = self.file() {
            file.write().await.header = HeaderState::Absent;
        }
    }

    pub(super) fn path(&self) -> SmbPath {
        lock(&self.path).clone()
    }

    fn set_path(&self, path: SmbPath) {
        *lock(&self.path) = path;
    }

    fn key(&self) -> NodeKey {
        NodeKey::new(self.file_index, &lock(&self.path), self.names)
    }

    /// Takes the node out of the table, for a file that was unlinked or
    /// replaced. Handles that hold it keep working on it.
    fn detach(&self) {
        self.detached.store(true, Ordering::Release);
        self.unlist();
    }

    /// Removes the entry of this node, if the entry is still this node's.
    fn unlist(&self) {
        let key = self.key();
        let mut entries = lock(&self.table.entries);
        if entries
            .get(&key)
            .is_some_and(|entry| ptr::eq(entry.as_ptr(), self))
        {
            entries.remove(&key);
        }
    }

    /// The node left the table, because its file was unlinked or replaced.
    #[cfg(test)]
    pub(super) fn is_detached(&self) -> bool {
        self.detached.load(Ordering::Acquire)
    }

    /// The header state of a file; `None` for a directory.
    #[cfg(test)]
    pub(super) async fn header(&self) -> Option<HeaderKind> {
        Some(self.file()?.read().await.header.kind())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.unlist();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::util::path;

    fn found(at: &SmbPath, file_index: u64) -> Found<'_> {
        Found {
            path: at,
            file_index,
            directory: false,
            origin: Origin::Opened,
            names: NameMatch::Folded,
        }
    }

    fn open(table: &Arc<NodeTable>, name: &str, file_index: u64) -> Arc<Node> {
        table.attach(&found(&path(name), file_index))
    }

    #[test]
    fn path_keys_fold_unless_names_compare_exactly() {
        let at = path("Dir\\File.TXT");
        assert_eq!(path_key(&at, NameMatch::Exact), "Dir\\File.TXT");
        assert_eq!(path_key(&at, NameMatch::Folded), "dir\\file.txt");
        assert_eq!(path_key(&SmbPath::root(), NameMatch::Folded), "");
    }

    #[test]
    fn paths_that_differ_in_case_are_one_file_when_names_fold() {
        let table = NodeTable::new();
        let first = open(&table, "a", 0);
        let again = open(&table, "A", 0);
        let other = open(&table, "b", 0);
        assert!(Arc::ptr_eq(&first, &again), "paths fold");
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn exact_names_are_not_folded() {
        let table = NodeTable::new();
        let exact = |name: &str| {
            let at = path(name);
            table.attach(&Found {
                names: NameMatch::Exact,
                ..found(&at, 0)
            })
        };
        assert!(!Arc::ptr_eq(&exact("a"), &exact("A")));
    }

    #[test]
    fn a_file_id_names_the_file_whatever_its_path() {
        let table = NodeTable::new();
        let first = open(&table, "a", 7);
        let linked = open(&table, "b", 7);
        let other = open(&table, "a", 8);
        assert!(Arc::ptr_eq(&first, &linked));
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(table.len(), 2);
    }

    #[tokio::test]
    async fn a_new_node_starts_with_its_header_unknown_and_a_created_one_without() {
        let table = NodeTable::new();
        let at = path("f");
        let opened = table.attach(&found(&at, 0));
        assert_eq!(opened.header().await, Some(HeaderKind::Unknown));
        let created = table.attach(&Found {
            origin: Origin::Created,
            ..found(&at, 0)
        });
        assert_eq!(created.header().await, Some(HeaderKind::Absent));
        let dir = table.attach(&Found {
            directory: true,
            ..found(&path("d"), 0)
        });
        assert_eq!(dir.header().await, None);
        assert!(dir.is_directory() && dir.file().is_none());
    }

    #[test]
    fn a_create_replaces_the_node_it_finds_and_detaches_it() {
        for file_index in [0, 7] {
            let table = NodeTable::new();
            let old = open(&table, "f", file_index);
            let at = path("f");
            let new = table.attach(&Found {
                origin: Origin::Created,
                ..found(&at, file_index)
            });
            assert!(!Arc::ptr_eq(&old, &new));
            assert!(old.is_detached() && !new.is_detached());
            assert!(Arc::ptr_eq(&open(&table, "f", file_index), &new));
            assert_eq!(table.len(), 1);
        }
    }

    #[test]
    fn a_directory_where_a_file_was_gets_a_node_of_its_own() {
        let table = NodeTable::new();
        let file = open(&table, "x", 0);
        let at = path("x");
        let dir = table.attach(&Found {
            directory: true,
            ..found(&at, 0)
        });
        assert!(!Arc::ptr_eq(&file, &dir));
        assert!(file.is_detached() && dir.is_directory());
    }

    #[test]
    fn a_dropped_node_leaves_the_table() {
        let table = NodeTable::new();
        let by_path = open(&table, "a", 0);
        let by_index = open(&table, "b", 5);
        assert_eq!(table.len(), 2);
        drop(by_path);
        assert_eq!(table.len(), 1);
        drop(by_index);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn a_node_that_was_replaced_leaves_the_entry_of_its_successor() {
        let table = NodeTable::new();
        let old = open(&table, "f", 0);
        let at = path("f");
        let new = table.attach(&Found {
            origin: Origin::Created,
            ..found(&at, 0)
        });
        drop(old);
        assert_eq!(table.len(), 1);
        assert!(Arc::ptr_eq(&open(&table, "f", 0), &new));
    }

    #[test]
    fn an_unlink_detaches_the_nodes_at_the_path() {
        let table = NodeTable::new();
        let by_path = open(&table, "f", 0);
        let by_index = open(&table, "g", 9);
        let kept = open(&table, "h", 0);
        table.unlinked(&path("F"), NameMatch::Folded);
        table.unlinked(&path("g"), NameMatch::Exact);
        assert!(by_path.is_detached() && by_index.is_detached());
        assert!(!kept.is_detached());
        assert_eq!(table.len(), 1);
        assert!(!Arc::ptr_eq(&open(&table, "f", 0), &by_path));
    }

    #[test]
    fn exact_names_unlink_only_the_exact_path() {
        let table = NodeTable::new();
        let node = open(&table, "f", 0);
        table.unlinked(&path("F"), NameMatch::Exact);
        assert!(!node.is_detached());
    }

    #[test]
    fn a_rename_moves_the_nodes_at_and_below_the_source() {
        let table = NodeTable::new();
        let dir = open(&table, "d", 0);
        let below = open(&table, "d\\x\\f", 0);
        let indexed = open(&table, "d\\g", 4);
        let outside = open(&table, "e\\f", 0);
        table.renamed(&path("d"), &path("n"), NameMatch::Folded);
        assert_eq!(dir.path(), path("n"));
        assert_eq!(below.path(), path("n\\x\\f"));
        assert_eq!(indexed.path(), path("n\\g"));
        assert_eq!(outside.path(), path("e\\f"));
        assert!(Arc::ptr_eq(&open(&table, "n", 0), &dir));
        assert!(Arc::ptr_eq(&open(&table, "N\\X\\F", 0), &below));
        assert!(Arc::ptr_eq(&open(&table, "anything", 4), &indexed));
        assert!(Arc::ptr_eq(&open(&table, "e\\f", 0), &outside));
        assert_eq!(table.len(), 4);
        assert!(
            ![&dir, &below, &indexed, &outside]
                .iter()
                .any(|node| node.is_detached())
        );
    }

    #[test]
    fn a_rename_leaves_the_nodes_of_names_that_only_start_like_the_source() {
        let table = NodeTable::new();
        let below = open(&table, "d\\f", 0);
        let near = open(&table, "dx\\f", 0);
        table.renamed(&path("d"), &path("n"), NameMatch::Folded);
        assert_eq!(below.path(), path("n\\f"));
        assert_eq!(near.path(), path("dx\\f"));
        assert!(Arc::ptr_eq(&open(&table, "dx\\f", 0), &near));
    }

    #[test]
    fn a_rename_detaches_the_nodes_of_the_file_it_replaces() {
        for (file_index_source, file_index_target) in [(0, 0), (1, 2)] {
            let table = NodeTable::new();
            let source = open(&table, "a", file_index_source);
            let target = open(&table, "b", file_index_target);
            table.renamed(&path("a"), &path("b"), NameMatch::Folded);
            assert!(target.is_detached());
            assert!(!source.is_detached());
            assert_eq!(source.path(), path("b"));
            assert!(Arc::ptr_eq(&open(&table, "b", file_index_source), &source));
            assert_eq!(table.len(), 1);
        }
    }

    #[test]
    fn a_rename_that_only_changes_case_keeps_the_node_and_takes_the_new_spelling() {
        let table = NodeTable::new();
        let node = open(&table, "report", 0);
        table.renamed(&path("report"), &path("REPORT"), NameMatch::Folded);
        assert!(!node.is_detached());
        assert_eq!(node.path(), path("REPORT"));
        assert!(Arc::ptr_eq(&open(&table, "Report", 0), &node));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn exact_names_that_differ_in_case_are_two_files_in_a_rename() {
        let table = NodeTable::new();
        let exact = |name: &str| {
            let at = path(name);
            table.attach(&Found {
                names: NameMatch::Exact,
                ..found(&at, 0)
            })
        };
        let lower = exact("a");
        let upper = exact("A");
        table.renamed(&path("a"), &path("A"), NameMatch::Exact);
        assert!(upper.is_detached());
        assert!(!lower.is_detached());
        assert_eq!(lower.path(), path("A"));
    }

    #[test]
    fn a_node_dropped_after_a_rename_removes_its_new_entry() {
        let table = NodeTable::new();
        let node = open(&table, "a", 0);
        table.renamed(&path("a"), &path("b"), NameMatch::Folded);
        drop(node);
        assert_eq!(table.len(), 0);
    }
}
