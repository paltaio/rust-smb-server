//! A long random run of creates, deletes and renames, checked against a model
//! of the names after every step.
//!
//! The model keeps entries under their names folded by the backend's case
//! rule. A call that the model says succeeds must succeed, and one it says
//! fails must fail with some error; the contract names the errors of only some
//! of those. After each step every directory is listed, and every 25 steps
//! every file is read.

use std::collections::BTreeMap;

use super::helpers::{Backend, assert_bytes, contents, open_dir, shown};
use crate::backend::OpenIntent;
use crate::error::SmbResult;
use crate::tests::data::xorshift;
use crate::tests::util::{dir_opts, opts, path};

enum Node {
    File(Vec<u8>),
    Dir(Tree),
}

/// Entries by folded name.
type Tree = BTreeMap<String, Entry>;

struct Entry {
    /// The spellings the listing may show. More than one after a rename that
    /// replaced a name of another case, which keeps either.
    spellings: Vec<String>,
    node: Node,
}

enum Op {
    Put(Vec<String>, Vec<u8>),
    Mkdir(Vec<String>),
    Unlink(Vec<String>),
    Rename(Vec<String>, Vec<String>, bool),
}

impl Op {
    fn describe(&self) -> String {
        let at = |parts: &[String]| {
            parts
                .iter()
                .map(|part| shown(part))
                .collect::<Vec<_>>()
                .join("\\")
        };
        match self {
            Op::Put(parts, data) => format!("put {} ({} bytes)", at(parts), data.len()),
            Op::Mkdir(parts) => format!("mkdir {}", at(parts)),
            Op::Unlink(parts) => format!("unlink {}", at(parts)),
            Op::Rename(from, to, replace) => {
                format!("rename {} to {} (replace {replace})", at(from), at(to))
            }
        }
    }
}

/// The key of `name` in a tree.
fn fold_name(sensitive: bool, name: &str) -> String {
    if sensitive {
        name.to_string()
    } else {
        name.to_lowercase()
    }
}

struct Model {
    sensitive: bool,
    root: Tree,
}

impl Model {
    fn fold(&self, name: &str) -> String {
        fold_name(self.sensitive, name)
    }

    fn dir(&self, parts: &[String]) -> Option<&Tree> {
        let mut tree = &self.root;
        for part in parts {
            match &tree.get(&self.fold(part))?.node {
                Node::Dir(sub) => tree = sub,
                Node::File(_) => return None,
            }
        }
        Some(tree)
    }

    fn dir_mut(&mut self, parts: &[String]) -> Option<&mut Tree> {
        let sensitive = self.sensitive;
        let mut tree = &mut self.root;
        for part in parts {
            match &mut tree.get_mut(&fold_name(sensitive, part))?.node {
                Node::Dir(sub) => tree = sub,
                Node::File(_) => return None,
            }
        }
        Some(tree)
    }

    fn entry(&self, parts: &[String]) -> Option<&Entry> {
        let (name, parent) = parts.split_last()?;
        self.dir(parent)?.get(&self.fold(name))
    }

    /// Every path in the model, as the listings last showed it, and whether
    /// it is a directory.
    fn paths(&self) -> Vec<(Vec<String>, bool)> {
        fn walk(tree: &Tree, at: &mut Vec<String>, out: &mut Vec<(Vec<String>, bool)>) {
            for entry in tree.values() {
                at.push(entry.spellings[0].clone());
                match &entry.node {
                    Node::Dir(sub) => {
                        out.push((at.clone(), true));
                        walk(sub, at, out);
                    }
                    Node::File(_) => out.push((at.clone(), false)),
                }
                at.pop();
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut Vec::new(), &mut out);
        out
    }

    /// True if the call cannot be judged: a directory moved below itself or
    /// onto a file.
    fn unjudged(&self, op: &Op) -> bool {
        let Op::Rename(from, to, _) = op else {
            return false;
        };
        let Some(source) = self.entry(from) else {
            return false;
        };
        if !matches!(source.node, Node::Dir(_)) {
            return false;
        }
        let below = to.len() > from.len()
            && from
                .iter()
                .zip(to)
                .all(|(a, b)| self.fold(a) == self.fold(b));
        let onto_file = matches!(self.entry(to).map(|entry| &entry.node), Some(Node::File(_)));
        below || onto_file
    }

    /// Applies `op` if it succeeds, and says whether it does.
    fn apply(&mut self, op: &Op) -> bool {
        match op {
            Op::Put(parts, data) => self.add(parts, Node::File(data.clone())),
            Op::Mkdir(parts) => self.add(parts, Node::Dir(Tree::new())),
            Op::Unlink(parts) => {
                let (name, parent) = parts.split_last().expect("a name");
                let key = self.fold(name);
                let removable = match self.dir(parent).and_then(|tree| tree.get(&key)) {
                    Some(Entry {
                        node: Node::Dir(sub),
                        ..
                    }) => sub.is_empty(),
                    Some(_) => true,
                    None => false,
                };
                if removable {
                    self.dir_mut(parent).expect("a directory").remove(&key);
                }
                removable
            }
            Op::Rename(from, to, replace) => self.rename(from, to, *replace),
        }
    }

    fn add(&mut self, parts: &[String], node: Node) -> bool {
        let (name, parent) = parts.split_last().expect("a name");
        let key = self.fold(name);
        let Some(tree) = self.dir_mut(parent) else {
            return false;
        };
        if tree.contains_key(&key) {
            return false;
        }
        tree.insert(
            key,
            Entry {
                spellings: vec![name.clone()],
                node,
            },
        );
        true
    }

    fn rename(&mut self, from: &[String], to: &[String], replace: bool) -> bool {
        let (from_name, from_parent) = from.split_last().expect("a name");
        let (to_name, to_parent) = to.split_last().expect("a name");
        let (from_key, to_key) = (self.fold(from_name), self.fold(to_name));
        if self.entry(from).is_none() || self.dir(to_parent).is_none() {
            return false;
        }
        let same_directory = from_parent.len() == to_parent.len()
            && from_parent
                .iter()
                .zip(to_parent)
                .all(|(a, b)| self.fold(a) == self.fold(b));
        if same_directory && from_key == to_key {
            let tree = self.dir_mut(from_parent).expect("a directory");
            let entry = tree.get_mut(&from_key).expect("the entry");
            // Renaming a name to its own spelling may keep the old spelling,
            // so the listing may show either.
            if from_name == to_name {
                entry.spellings.push(to_name.clone());
            } else {
                entry.spellings = vec![to_name.clone()];
            }
            return true;
        }
        match self.entry(to) {
            Some(Entry {
                node: Node::Dir(_), ..
            }) => return false,
            Some(_) if !replace => return false,
            _ => {}
        }
        let replaced = self
            .dir(to_parent)
            .and_then(|tree| tree.get(&to_key))
            .map(|entry| entry.spellings.clone());
        let mut moved = self
            .dir_mut(from_parent)
            .expect("a directory")
            .remove(&from_key)
            .expect("the entry");
        moved.spellings = vec![to_name.clone()];
        moved.spellings.extend(replaced.into_iter().flatten());
        self.dir_mut(to_parent)
            .expect("a directory")
            .insert(to_key, moved);
        true
    }
}

async fn run(backend: Backend<'_>, op: &Op) -> SmbResult<()> {
    let at = |parts: &[String]| path(&parts.join("\\"));
    match op {
        Op::Put(parts, data) => {
            let (handle, _) = backend.open(&at(parts), opts(OpenIntent::Create)).await?;
            let written = handle.write(0, data).await;
            handle.close().await?;
            assert_eq!(usize::try_from(written?).unwrap(), data.len());
            Ok(())
        }
        Op::Mkdir(parts) => {
            let (handle, _) = backend
                .open(&at(parts), dir_opts(OpenIntent::Create))
                .await?;
            handle.close().await
        }
        Op::Unlink(parts) => backend.unlink(&at(parts)).await,
        Op::Rename(from, to, replace) => backend.rename(&at(from), &at(to), *replace).await,
    }
}

/// Lists every directory of the backend and checks that the names, kinds and
/// sizes are what the model holds; with `read`, reads every file too. A
/// spelling the listing shows settles the model's.
async fn check(backend: Backend<'_>, model: &mut Model, after: &str, read: bool) {
    let mut pending = vec![Vec::<String>::new()];
    while let Some(dir) = pending.pop() {
        let handle = open_dir(backend, &dir.join("\\")).await;
        let entries = handle.list_dir(None).await.unwrap();
        handle.close().await.unwrap();

        let sensitive = model.sensitive;
        let fold = |name: &str| fold_name(sensitive, name);
        let tree = model.dir_mut(&dir).expect("a directory of the model");
        let mut listed: Vec<_> = entries.iter().map(|e| fold(&e.info.name)).collect();
        listed.sort();
        let expected: Vec<_> = tree.keys().cloned().collect();
        assert!(
            listed == expected,
            "{after}: the directory {:?} lists {:?}, the model has {:?}",
            shown(&dir.join("\\")),
            listed.iter().map(|n| shown(n)).collect::<Vec<_>>(),
            expected.iter().map(|n| shown(n)).collect::<Vec<_>>()
        );
        for listing in entries {
            let name = listing.info.name;
            let modeled = tree.get_mut(&fold(&name)).expect("a listed entry");
            assert!(
                modeled.spellings.contains(&name),
                "{after}: {} is listed as {}",
                shown(&modeled.spellings[0]),
                shown(&name)
            );
            modeled.spellings = vec![name.clone()];
            let mut child = dir.clone();
            child.push(name);
            match &modeled.node {
                Node::Dir(_) => {
                    assert!(listing.info.is_directory, "{after}: {child:?}");
                    pending.push(child);
                }
                Node::File(bytes) => {
                    let at = child.join("\\");
                    assert!(!listing.info.is_directory, "{after}: {}", shown(&at));
                    assert_eq!(
                        listing.info.end_of_file,
                        bytes.len() as u64,
                        "{after}: size of {}",
                        shown(&at)
                    );
                    if read {
                        let held = contents(backend, &at).await;
                        assert_bytes(&held, bytes, &format!("{after}: {at}"));
                    }
                }
            }
        }
    }
}

/// `parts` with the case of the last name swapped.
fn flipped(mut parts: Vec<String>) -> Vec<String> {
    if let Some(last) = parts.last_mut() {
        *last = last
            .chars()
            .map(|c| {
                if c.is_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
    }
    parts
}

const NAMES: [&str; 7] = ["f", "F", "g.txt", "G.TXT", "d", "D", "e"];

pub(super) async fn namespace_changes_match_a_model(backend: Backend<'_>) {
    let long = ["x".repeat(150), "X".repeat(150)];
    let pool: Vec<String> = NAMES
        .iter()
        .map(|name| (*name).to_string())
        .chain(long)
        .collect();
    let mut next = xorshift(0x9e37_79b9_7f4a_7c15);
    let mut pick = |len: usize| usize::try_from(next() % len as u64).unwrap();
    let mut model = Model {
        sensitive: backend.capabilities().case_sensitive,
        root: Tree::new(),
    };
    let mut succeeded = 0;
    let mut refused = 0;

    for step in 0..500_u32 {
        let known = model.paths();
        let dirs: Vec<Vec<String>> = std::iter::once(Vec::new())
            .chain(
                known
                    .iter()
                    .filter(|(_, dir)| *dir)
                    .map(|(at, _)| at.clone()),
            )
            .collect();
        let anywhere = |pick: &mut dyn FnMut(usize) -> usize| {
            let mut parent = dirs[pick(dirs.len())].clone();
            if pick(10) == 0 {
                parent.push(pool[pick(pool.len())].clone());
            }
            parent.push(pool[pick(pool.len())].clone());
            parent
        };
        let existing = |pick: &mut dyn FnMut(usize) -> usize| {
            if known.is_empty() || pick(10) == 0 {
                anywhere(pick)
            } else {
                known[pick(known.len())].0.clone()
            }
        };
        let op = match pick(20) {
            0..=6 => {
                let len = [0, 7, 100, 3_000, 3_000, 70_000][pick(6)];
                let tag = u8::try_from(step % 250).unwrap() + 1;
                Op::Put(anywhere(&mut pick), vec![tag; len])
            }
            7..=8 => Op::Mkdir(anywhere(&mut pick)),
            9..=11 => Op::Unlink(existing(&mut pick)),
            _ => {
                let from = existing(&mut pick);
                let to = match pick(10) {
                    0..=1 => flipped(from.clone()),
                    2..=5 => flipped(existing(&mut pick)),
                    _ => anywhere(&mut pick),
                };
                Op::Rename(from, to, pick(4) != 0)
            }
        };
        if model.unjudged(&op) {
            continue;
        }

        let what = format!("step {step}, {}", op.describe());
        let result = run(backend, &op).await;
        let succeeds = model.apply(&op);
        assert_eq!(
            result.is_ok(),
            succeeds,
            "{what}: the model says it {}, the backend answered {result:?}",
            if succeeds { "succeeds" } else { "fails" }
        );
        if succeeds {
            succeeded += 1;
        } else {
            refused += 1;
        }
        check(backend, &mut model, &what, step % 25 == 24).await;
        let written = match &op {
            Op::Put(at, _) | Op::Rename(_, at, _) if succeeds => Some(at),
            _ => None,
        };
        if let Some(at) = written
            && let Some(Entry {
                node: Node::File(bytes),
                ..
            }) = model.entry(at)
        {
            let at = at.join("\\");
            assert_bytes(
                &contents(backend, &at).await,
                bytes,
                &format!("{what}: {at}"),
            );
        }
    }
    check(backend, &mut model, "the end", true).await;
    assert!(
        succeeded > 100 && refused > 50,
        "the run needs over 100 successes and over 50 refusals: {succeeded} and {refused}"
    );
}
