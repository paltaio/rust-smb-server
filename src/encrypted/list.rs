//! Listings, emptiness checks and watches of a directory in a share with
//! encrypted names.
//!
//! The inner backend lists and reports stored names. Clients get the names
//! they spell. The marker, side objects and names that are not the share's
//! stay out of what they see.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use super::backend::{EncryptedBackend, Shared};
use super::handle::{EncryptedHandle, next_mapped};
use super::names::{StoredKind, classify};
use super::node::{NameMatch, path_key};
use super::scan::{Began, Decoded, Hold, Name};
use crate::backend::{DirChange, DirChangeKind, DirEntry, DirWatch, FileInfo, ShareBackend};
use crate::error::SmbResult;
use crate::path::SmbPath;
use crate::wildcard::{Pattern, has_wildcard, without_match_all};

impl<B: ShareBackend> EncryptedHandle<B> {
    /// The backend this handle belongs to.
    fn layer(&self) -> EncryptedBackend<B> {
        EncryptedBackend {
            shared: Arc::clone(&self.shared),
        }
    }

    /// The entries of the directory that `pattern` selects, under the names
    /// clients spell. `None`, an empty pattern, `*` and `*.*` select all.
    pub(super) async fn list_names(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        let dir = self.node.path();
        match without_match_all(pattern) {
            Some(name) if !has_wildcard(name) => self.list_one(&dir, name).await,
            pattern => self.list_all(&dir, pattern).await,
        }
    }

    /// Lists the whole directory and keeps the entries whose names match
    /// `pattern`. Two stored names for one name leave the canonical one, else
    /// the smaller. With case-insensitive names, the names go to the name
    /// cache when no change was counted since the listing began and every
    /// side object was read.
    ///
    /// A directory that has moved by the time the names are decoded is listed
    /// again at its new path, and the first listing is kept by nobody. If it
    /// moves again, the second listing is the result and is not kept either.
    ///
    /// Holds the lock entry of the directory but not its lock. Creates
    /// proceed during a listing, and the entry keeps the change count from
    /// resetting until the listing ends.
    async fn list_all(&self, dir: &SmbPath, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        let layer = self.layer();
        let shared = &self.shared;
        let mut dir = dir.clone();
        let mut moved = false;
        let decoded = loop {
            let lock = shared.locks.directory(path_key(&dir, NameMatch::Exact));
            let began = Began::of(&lock);
            // The inner handle may not follow the move, so the second
            // listing opens the directory at its new path.
            let listed = if moved {
                layer.list_stored(&dir).await?.unwrap_or_default()
            } else {
                self.inner.list_dir_sized(None, false).await?
            };
            let listing = layer.decode(&dir, listed).await?;
            let decoded = without_duplicates(&dir, listing.names, |plain| {
                layer.stored_form(plain).ok().map(|form| form.entry)
            });
            let now = self.node.path();
            if now == dir {
                if shared.settings.case_insensitive {
                    let entries = decoded.iter().map(|decoded| decoded.entry.clone());
                    shared.keep_names(&lock, began, Hold::Nothing, listing.complete, entries);
                }
                break decoded;
            }
            if moved {
                break decoded;
            }
            moved = true;
            dir = now;
        };
        let matcher = pattern.map(|p| Pattern::new(p, shared.settings.case_insensitive));
        Ok(decoded
            .into_iter()
            .filter(|decoded| {
                matcher
                    .as_ref()
                    .is_none_or(|matcher| matcher.matches(&decoded.entry.plain))
            })
            .map(|decoded| self.shown(decoded.entry.plain, decoded.info))
            .collect())
    }

    /// The entry that `name`, a pattern without wildcards, stands for: the one
    /// stored as `name`, else with case-insensitive names the one that differs
    /// in case.
    ///
    /// A directory that has moved by the time the lookup ends is searched
    /// again at its new path, and that answer is the result.
    async fn list_one(&self, dir: &SmbPath, name: &str) -> SmbResult<Vec<DirEntry>> {
        let found = self.find_one(dir, name, false).await?;
        let now = self.node.path();
        if now == *dir {
            return Ok(found);
        }
        self.find_one(&now, name, true).await
    }

    /// `list_one` for the directory at the stored path `dir`. With `by_path`
    /// the entries come from a listing of `dir` itself, not from the handle.
    async fn find_one(&self, dir: &SmbPath, name: &str, by_path: bool) -> SmbResult<Vec<DirEntry>> {
        let layer = self.layer();
        let Ok(form) = layer.stored_form(name) else {
            return Ok(Vec::new());
        };
        let at = by_path.then_some(dir);
        let mut plain = name.to_string();
        let mut found = self.list_stored(at, &form.entry).await?;
        if found.is_none() && self.shared.settings.case_insensitive {
            let variant = {
                let Some(names) = layer.names_of(dir, Hold::Nothing).await? else {
                    return Ok(Vec::new());
                };
                names.entry(name, &form.entry)
            };
            if let Some(variant) = variant
                && variant.stored != form.entry
            {
                found = self.list_stored(at, &variant.stored).await?;
                plain = variant.plain;
            }
        }
        Ok(found
            .map(|info| self.shown(plain, info))
            .into_iter()
            .collect())
    }

    /// The entry stored as `stored`, from a listing the inner backend narrows
    /// to that name, or from a listing of the stored directory `at` when that
    /// is given. Other entries it returns are ignored.
    async fn list_stored(&self, at: Option<&SmbPath>, stored: &str) -> SmbResult<Option<FileInfo>> {
        let listed = match at {
            Some(dir) => self.layer().list_stored(dir).await?.unwrap_or_default(),
            None => self.inner.list_dir_sized(Some(stored), false).await?,
        };
        Ok(listed
            .into_iter()
            .map(|entry| entry.info)
            .find(|info| info.name == stored))
    }

    /// `info` from the inner backend as the share reports it, named `plain`.
    fn shown(&self, plain: String, mut info: FileInfo) -> DirEntry {
        info.name = plain;
        self.report(&mut info);
        DirEntry { info }
    }

    /// True if the inner backend lists nothing, or only the marker (in the
    /// root) and side objects. Any other name, including one the share does
    /// not know, makes it non-empty.
    pub(super) async fn names_dir_is_empty(&self) -> SmbResult<bool> {
        if self.inner.dir_is_empty().await? {
            return Ok(true);
        }
        let listed = self.inner.list_dir_sized(None, false).await?;
        let in_root = self.on_root();
        // A listing with nothing in it, for a directory the inner backend
        // says has entries, hides them.
        Ok(!listed.is_empty()
            && listed.iter().all(|entry| {
                matches!(
                    classify(&entry.info.name, in_root),
                    StoredKind::Marker | StoredKind::SideObject
                )
            }))
    }

    /// The watch of the inner backend, reporting the names clients spell.
    pub(super) async fn names_watch(&self) -> SmbResult<Option<Box<dyn DirWatch>>> {
        let Some(inner) = self.inner.watch().await? else {
            return Ok(None);
        };
        Ok(Some(Box::new(NamesWatch {
            inner,
            shared: Arc::clone(&self.shared),
            in_root: self.on_root(),
        })))
    }
}

/// `decoded` with one entry for each name. Of several stored names for one
/// name, such as its short and its long form, the one that `canonical` gives
/// stays, else the smaller. Each entry left out is logged.
fn without_duplicates(
    dir: &SmbPath,
    decoded: Vec<Decoded>,
    canonical: impl Fn(&str) -> Option<String>,
) -> Vec<Decoded> {
    let mut at: HashMap<String, usize> = HashMap::with_capacity(decoded.len());
    let mut kept: Vec<Decoded> = Vec::with_capacity(decoded.len());
    for next in decoded {
        let Some(&held) = at.get(&next.entry.plain) else {
            at.insert(next.entry.plain.clone(), kept.len());
            kept.push(next);
            continue;
        };
        let canonical = canonical(&next.entry.plain);
        let replaces = prefers(
            &next.entry.stored,
            &kept[held].entry.stored,
            canonical.as_deref(),
        );
        let (stays, goes) = if replaces {
            (&next, &kept[held])
        } else {
            (&kept[held], &next)
        };
        warn!(
            dir = %dir,
            name = %next.entry.plain,
            kept = ?stays.entry.stored,
            dropped = ?goes.entry.stored,
            "two stored names for one name"
        );
        if replaces {
            kept[held] = next;
        }
    }
    kept
}

/// True if the stored name `new` replaces `held` as the entry of one name:
/// `new` is the canonical name, or `held` is not and `new` is smaller.
fn prefers(new: &str, held: &str, canonical: Option<&str>) -> bool {
    match canonical {
        Some(canonical) if held == canonical => false,
        Some(canonical) if new == canonical => true,
        _ => new < held,
    }
}

/// The watch of a directory with encrypted names: the changes of the inner
/// watch, under the names clients spell.
struct NamesWatch<B> {
    inner: Box<dyn DirWatch>,
    shared: Arc<Shared<B>>,
    in_root: bool,
}

/// What a change of the inner watch becomes.
enum Mapped {
    Keep(DirChange),
    Drop,
    /// The change names a long entry that is not in the long-name cache.
    Lost,
}

/// `batch` as clients see it, with at most one `Lost`. A change that names a
/// long entry the long-name cache does not hold becomes a `Lost`. Of all the
/// `Lost` changes, those of the inner watch included, the first stays.
fn map_batch<B>(shared: &Shared<B>, in_root: bool, batch: Vec<DirChange>) -> Vec<DirChange> {
    let mut mapped = Vec::with_capacity(batch.len());
    let mut lost = false;
    for change in batch {
        let change = match map_change(shared, in_root, change) {
            Mapped::Keep(change) => change,
            Mapped::Drop => continue,
            Mapped::Lost => DirChange::new("", DirChangeKind::Lost, false),
        };
        if change.kind == DirChangeKind::Lost {
            if lost {
                continue;
            }
            lost = true;
        }
        mapped.push(change);
    }
    mapped
}

/// A rename with one side that is not a name of the share is the addition or
/// the removal of the other.
fn map_change<B>(shared: &Shared<B>, in_root: bool, change: DirChange) -> Mapped {
    let DirChange {
        name,
        kind,
        is_directory,
    } = change;
    let read = |stored: &str| shared.read_name(stored, in_root);
    let keep =
        |name: String, kind: DirChangeKind| Mapped::Keep(DirChange::new(name, kind, is_directory));
    match kind {
        DirChangeKind::Lost | DirChangeKind::Moved | DirChangeKind::Deleted => keep(name, kind),
        DirChangeKind::Renamed { from } => match (read(&name), read(&from)) {
            (Name::Long, _) | (_, Name::Long) => Mapped::Lost,
            (Name::Plain(to), Name::Plain(from)) => keep(to, DirChangeKind::Renamed { from }),
            (Name::Plain(to), Name::Hidden) => keep(to, DirChangeKind::Added),
            (Name::Hidden, Name::Plain(from)) => keep(from, DirChangeKind::Removed),
            (Name::Hidden, Name::Hidden) => Mapped::Drop,
        },
        DirChangeKind::Added
        | DirChangeKind::Removed
        | DirChangeKind::Modified
        | DirChangeKind::AttributesChanged => match read(&name) {
            Name::Plain(plain) => keep(plain, kind),
            Name::Long => Mapped::Lost,
            Name::Hidden => Mapped::Drop,
        },
    }
}

#[async_trait]
impl<B: ShareBackend> DirWatch for NamesWatch<B> {
    async fn next(&mut self) -> Option<Vec<DirChange>> {
        let (shared, in_root) = (&self.shared, self.in_root);
        next_mapped(&mut *self.inner, |batch| map_batch(shared, in_root, batch)).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::task::JoinHandle;

    use super::super::cache::Entry;
    use super::super::format::MARKER_NAME;
    use super::super::names::{StoredName, encode_name};
    use super::super::node::{Found, Origin};
    use super::super::testing::{
        Hiding, PRIVATE_WORD, Script, change, drop_at, fail_open_of, injected, key_schedule, layer,
        names, names_over, names_settings, names_with, open, open_dir, open_file,
        other_key_schedule, parked, read_all, renamed, sealed_invalid_names, seed_dir, seed_file,
        seed_hidden_names, seed_orphan, stored_at, stored_bytes, stored_form, stored_name, summary,
    };
    use super::*;
    use crate::backend::{Handle, OpenAction, OpenIntent};
    use crate::ea::Ea;
    use crate::error::SmbError;
    use crate::tests::faulty::Faulty;
    use crate::tests::file_ids::FileIds;
    use crate::tests::gated::Gated;
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::recorder::Recorder;
    use crate::tests::util::{dir_opts, path};

    /// `names`, sorted.
    fn sorted(names: &[&str]) -> Vec<String> {
        let mut names: Vec<_> = names.iter().map(|name| (*name).to_string()).collect();
        names.sort();
        names
    }

    /// The names `dir` lists for `pattern`, sorted.
    async fn listed<B: ShareBackend>(
        dir: &EncryptedHandle<B>,
        pattern: Option<&str>,
    ) -> Vec<String> {
        names(&dir.list_dir(pattern).await.unwrap())
    }

    /// The debug lines about names that are not the share's.
    fn foreign_lines(logs: &Logs) -> Vec<String> {
        logs.debugs()
            .into_iter()
            .filter(|line| line.contains("not an encrypted name"))
            .collect()
    }

    // Listings

    #[tokio::test]
    async fn a_root_listing_leaves_out_the_marker_side_objects_and_foreign_names() {
        let logs = Logs::at(tracing::Level::DEBUG);
        let (files, layer) = layer().await;
        let long = "l".repeat(150);
        seed_dir(&files, "Docs");
        seed_file(&files, "a.txt", b"");
        seed_file(&files, &long, b"");
        let foreign = seed_hidden_names(&files);
        assert!(files.contents(MARKER_NAME).is_some());

        let root = open_dir(&layer, "").await;
        assert_eq!(listed(&root, None).await, sorted(&["Docs", "a.txt", &long]));
        assert!(logs.warnings().is_empty(), "{:?}", logs.warnings());
        let lines = foreign_lines(&logs);
        assert_eq!(lines.len(), foreign.len(), "{lines:?}");
        for name in &foreign {
            assert!(lines.iter().any(|line| line.contains(name)), "{name}");
        }
        assert!(!logs.text().contains(PRIVATE_WORD));
        assert_eq!(files.open_handles(), 1, "only the root handle is open");
    }

    #[tokio::test]
    async fn below_the_root_the_marker_name_is_a_foreign_name() {
        let logs = Logs::at(tracing::Level::DEBUG);
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\a", b"");
        let below = format!("{}\\{MARKER_NAME}", stored_at("Docs"));
        files.clone().with_file(&below, b"");

        let docs = open_dir(&layer, "Docs").await;
        assert_eq!(listed(&docs, None).await, ["a"]);
        let lines = foreign_lines(&logs);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(MARKER_NAME));
    }

    #[tokio::test]
    async fn a_subdirectory_lists_its_entries_under_their_names() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\Sub\\deep.txt", b"");
        seed_file(&files, "Docs\\b.md", &stored_bytes(b"xy"));
        seed_file(&files, "other\\c", b"");

        for dir in ["Docs", "docs", "DOCS"] {
            let handle = open_dir(&layer, dir).await;
            let entries = handle.list_dir(None).await.unwrap();
            assert_eq!(names(&entries), ["Sub", "b.md"], "{dir}");
            let by_name = |name: &str| entries.iter().find(|entry| entry.info.name == name);
            assert!(by_name("Sub").unwrap().info.is_directory);
            assert!(!by_name("b.md").unwrap().info.is_directory);
        }
        let sub = open_dir(&layer, "docs\\sub").await;
        assert_eq!(listed(&sub, None).await, ["deep.txt"]);
        let root = open_dir(&layer, "").await;
        assert_eq!(listed(&root, None).await, ["Docs", "other"]);
    }

    #[tokio::test]
    async fn a_subdirectory_listing_keeps_its_names_under_its_stored_path() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\Sub\\deep.txt", b"");
        seed_file(&files, "top.txt", b"");
        let sub = open_dir(&layer, "Docs\\Sub").await;
        assert_eq!(listed(&sub, None).await, ["deep.txt"]);

        let key = stored_at("Docs\\Sub");
        let kept = layer.shared.names.fresh(&key).expect("the names are kept");
        assert!(kept.entry("deep.txt", &stored_name("deep.txt")).is_some());
        assert!(layer.shared.names.fresh("").is_none());
        assert_eq!(layer.shared.names.keys(), [key]);
    }

    #[tokio::test]
    async fn match_all_patterns_list_everything_and_wildcards_filter_by_name() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let all = [
            "Makefile", "a.txt", "B.TXT", "c.md", "abc", "AbC", "ac", "abcd",
        ];
        for name in all {
            seed_file(&files, name, b"");
        }
        let root = open_dir(&layer, "").await;
        let before = faulty.list_calls().len();

        let patterns = [None, Some(""), Some("*"), Some("*.*")];
        for pattern in patterns {
            assert_eq!(listed(&root, pattern).await, sorted(&all), "{pattern:?}");
        }
        let wildcards = [
            ("*.TXT", &["a.txt", "B.TXT"][..]),
            ("*.txt", &["a.txt", "B.TXT"]),
            ("a?c", &["abc", "AbC"]),
            ("a<", &["abc", "AbC", "ac", "abcd"]),
            ("a\"txt", &["a.txt"]),
            ("AB>", &["abc", "AbC"]),
            ("*x*", &["a.txt", "B.TXT"]),
            ("nothing*", &[]),
        ];
        for (pattern, expected) in wildcards {
            assert_eq!(
                listed(&root, Some(pattern)).await,
                sorted(expected),
                "{pattern}"
            );
        }
        let calls = faulty.list_calls().split_off(before);
        assert_eq!(calls.len(), patterns.len() + wildcards.len());
        assert!(
            calls.iter().all(|call| *call == (None, false)),
            "the inner backend lists the whole directory: {calls:?}"
        );
        assert!(faulty.reads().is_empty(), "no file is read");
    }

    #[tokio::test]
    async fn wildcards_match_exactly_when_names_are_case_sensitive() {
        let files = MemFsBackend::new();
        let layer = names_with(files.clone(), |builder| builder.case_insensitive(false)).await;
        for name in ["a.txt", "B.TXT", "abc", "AbC", "ac"] {
            seed_file(&files, name, b"");
        }
        let root = open_dir(&layer, "").await;
        assert_eq!(listed(&root, Some("*.TXT")).await, ["B.TXT"]);
        assert_eq!(listed(&root, Some("*.txt")).await, ["a.txt"]);
        assert_eq!(listed(&root, Some("a?c")).await, ["abc"]);
        assert_eq!(listed(&root, Some("A*")).await, ["AbC"]);
    }

    #[tokio::test]
    async fn a_full_listing_keeps_no_names_when_names_are_case_sensitive() {
        let files = MemFsBackend::new();
        let layer = names_with(files.clone(), |builder| builder.case_insensitive(false)).await;
        seed_file(&files, "a.txt", b"");
        let root = open_dir(&layer, "").await;
        assert_eq!(listed(&root, None).await, ["a.txt"]);
        assert_eq!(listed(&root, Some("*.txt")).await, ["a.txt"]);
        assert!(layer.shared.names.keys().is_empty());
    }

    #[tokio::test]
    async fn list_dir_sized_never_asks_the_inner_backend_for_ea_sizes() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "a.txt", b"");
        seed_file(&files, "b.md", b"");
        let root = open_dir(&layer, "").await;
        let before = faulty.list_calls().len();

        let sized = root.list_dir_sized(Some("*.txt"), true).await.unwrap();
        assert_eq!(names(&sized), ["a.txt"]);
        let sized = root.list_dir_sized(None, true).await.unwrap();
        assert_eq!(names(&sized), ["a.txt", "b.md"]);
        assert_eq!(
            faulty.list_calls().split_off(before),
            [(None, false), (None, false)]
        );
    }

    #[tokio::test]
    async fn a_failed_listing_returns_the_error_and_keeps_no_names() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "a.txt", b"");
        let root = open_dir(&layer, "").await;

        faulty.fail_listing(1, injected());
        assert!(matches!(root.list_dir(None).await, Err(SmbError::Io(_))));
        faulty.fail_listing(1, injected());
        assert!(matches!(
            root.list_dir(Some("a.txt")).await,
            Err(SmbError::Io(_))
        ));
        assert!(layer.shared.names.keys().is_empty());
        assert_eq!(listed(&root, None).await, ["a.txt"]);
    }

    #[tokio::test]
    async fn a_listing_without_a_name_cache_still_lists() {
        let files = MemFsBackend::new();
        let layer = names_with(files.clone(), |builder| {
            builder.name_cache_ttl(Duration::ZERO)
        })
        .await;
        seed_file(&files, "a.txt", b"");
        let root = open_dir(&layer, "").await;
        assert_eq!(listed(&root, None).await, ["a.txt"]);
        assert_eq!(listed(&root, Some("A.TXT")).await, ["a.txt"]);
        assert!(layer.shared.names.keys().is_empty());
    }

    // Two stored names for one name

    /// The stored forms of the name `name` of 30 bytes, whose short form has
    /// 74 characters: the short one, and the long one of a share with a
    /// threshold of 62. Both are in the store of `files`, holding 5 and 2
    /// bytes.
    fn seed_both_forms(files: &MemFsBackend, name: &str) -> (StoredName, StoredName) {
        let short = encode_name(&key_schedule(), name, 255).unwrap();
        let long = encode_name(&key_schedule(), name, 62).unwrap();
        let side = long.side_object.as_ref().unwrap();
        assert!(short.side_object.is_none());
        files
            .clone()
            .with_file(&short.entry, &stored_bytes(b"short"))
            .with_file(&long.entry, &stored_bytes(b"lo"))
            .with_file(&side.name, &side.content);
        (short, long)
    }

    #[tokio::test]
    async fn two_stored_names_for_one_name_list_the_canonical_one_with_a_warning() {
        let logs = Logs::new();
        let name = "d".repeat(30);
        let (files, layer) = layer().await;
        let (short, long) = seed_both_forms(&files, &name);
        let root = open_dir(&layer, "").await;

        let entries = root.list_dir(None).await.unwrap();
        assert_eq!(names(&entries), [name.as_str()]);
        assert_eq!(entries[0].info.end_of_file, 5, "the short form");
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&short.entry) && warnings[0].contains(&long.entry));

        let kept = layer.shared.names.fresh("").expect("the names are kept");
        assert_eq!(kept.entry(&name, &short.entry).unwrap().stored, short.entry);
    }

    #[tokio::test]
    async fn the_canonical_form_follows_the_threshold() {
        let logs = Logs::new();
        let name = "d".repeat(30);
        let files = MemFsBackend::new();
        let layer = names_with(files.clone(), |builder| builder.long_name_threshold(62)).await;
        seed_both_forms(&files, &name);
        let root = open_dir(&layer, "").await;

        let entries = root.list_dir(None).await.unwrap();
        assert_eq!(names(&entries), [name.as_str()]);
        assert_eq!(entries[0].info.end_of_file, 2, "the long form");
        assert_eq!(logs.warnings().len(), 1);
    }

    fn decoded(plain: &str, stored: &str) -> Decoded {
        Decoded {
            entry: Entry {
                plain: plain.to_string(),
                stored: stored.to_string(),
                directory: false,
            },
            info: FileInfo::new(stored),
        }
    }

    fn stored_names(entries: &[Decoded]) -> Vec<&str> {
        entries
            .iter()
            .map(|decoded| decoded.entry.stored.as_str())
            .collect()
    }

    #[test]
    fn with_no_canonical_name_among_them_the_smallest_stays() {
        let logs = Logs::new();
        let entries = vec![
            decoded("a", "s2"),
            decoded("b", "s7"),
            decoded("a", "s1"),
            decoded("a", "s3"),
        ];
        let kept = without_duplicates(&SmbPath::root(), entries, |_| Some("s9".to_string()));
        assert_eq!(stored_names(&kept), ["s1", "s7"]);
        assert_eq!(logs.warnings().len(), 2);

        let entries = vec![decoded("a", "s2"), decoded("a", "s1")];
        let kept = without_duplicates(&SmbPath::root(), entries, |_| None);
        assert_eq!(stored_names(&kept), ["s1"]);
    }

    #[test]
    fn of_several_stored_names_the_canonical_one_stays_whatever_the_order() {
        for order in [["s1", "s9", "s0"], ["s9", "s0", "s1"], ["s0", "s1", "s9"]] {
            let entries = order.iter().map(|stored| decoded("a", stored)).collect();
            let kept = without_duplicates(&SmbPath::root(), entries, |_| Some("s9".to_string()));
            assert_eq!(stored_names(&kept), ["s9"], "{order:?}");
        }
    }

    // Literal patterns

    #[tokio::test]
    async fn a_literal_pattern_asks_the_inner_backend_for_the_one_stored_name() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let long = "x".repeat(150);
        for name in ["Foo", "Bar", "Baz.txt", long.as_str()] {
            seed_file(&files, name, &stored_bytes(b"x"));
        }
        let root = open_dir(&layer, "").await;
        let before = faulty.list_calls().len();

        // The inner backend ignores the pattern and returns every entry.
        for name in ["Foo", "Bar", "Baz.txt", long.as_str()] {
            let found = root.list_dir(Some(name)).await.unwrap();
            assert_eq!(names(&found), [name]);
            assert_eq!(found[0].info.end_of_file, 1, "{name}");
        }
        let wanted =
            ["Foo", "Bar", "Baz.txt", long.as_str()].map(|name| (Some(stored_name(name)), false));
        assert_eq!(faulty.list_calls().split_off(before), wanted);
        assert!(layer.shared.names.keys().is_empty(), "no listing, no cache");
        assert!(faulty.reads().is_empty(), "no object is read");
    }

    #[tokio::test]
    async fn a_literal_in_another_case_gives_the_stored_spelling() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Report.TXT", &stored_bytes(b"quarterly"));
        seed_file(&files, "other", b"");
        let root = open_dir(&layer, "").await;
        let before = faulty.list_calls().len();
        let calls = || faulty.list_calls().split_off(before);
        let stored = |name: &str| (Some(stored_name(name)), false);

        let found = root.list_dir(Some("report.txt")).await.unwrap();
        assert_eq!(names(&found), ["Report.TXT"]);
        assert_eq!(found[0].info.end_of_file, 9);
        assert_eq!(
            calls(),
            [stored("report.txt"), (None, false), stored("Report.TXT")],
            "the exact name, the names of the directory, the stored name"
        );

        let found = root.list_dir(Some("REPORT.txt")).await.unwrap();
        assert_eq!(names(&found), ["Report.TXT"]);
        assert_eq!(calls().len(), 5, "the cached names give the spelling");

        let found = root.list_dir(Some("missing")).await.unwrap();
        assert!(found.is_empty());
        assert_eq!(calls().len(), 6, "a name the cached names lack is one call");
    }

    #[tokio::test]
    async fn the_exact_spelling_comes_before_a_variant() {
        let (files, layer) = layer().await;
        seed_file(&files, "foo", &stored_bytes(b"lower"));
        seed_file(&files, "Foo", &stored_bytes(b"upper"));
        let root = open_dir(&layer, "").await;
        for asked in ["foo", "Foo"] {
            let found = root.list_dir(Some(asked)).await.unwrap();
            assert_eq!(names(&found), [asked]);
        }
        let found = root.list_dir(Some("FOO")).await.unwrap();
        let (_, smallest) = ["foo", "Foo"]
            .into_iter()
            .map(|name| (stored_name(name), name))
            .min()
            .unwrap();
        assert_eq!(names(&found), [smallest]);
    }

    #[tokio::test]
    async fn a_literal_finds_nothing_in_another_case_when_names_are_case_sensitive() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_with(faulty.clone(), |builder| builder.case_insensitive(false)).await;
        seed_file(&files, "Report.TXT", b"");
        let root = open_dir(&layer, "").await;
        let before = faulty.list_calls().len();

        assert!(root.list_dir(Some("report.txt")).await.unwrap().is_empty());
        assert_eq!(
            faulty.list_calls().split_off(before),
            [(Some(stored_name("report.txt")), false)]
        );
        assert_eq!(listed(&root, Some("Report.TXT")).await, ["Report.TXT"]);
    }

    #[tokio::test]
    async fn a_literal_that_is_no_name_finds_nothing_and_asks_nothing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let root = open_dir(&layer, "").await;
        let before = faulty.list_calls().len();
        for pattern in [".", "..", "a:b", &"n".repeat(300)] {
            assert!(root.list_dir(Some(pattern)).await.unwrap().is_empty());
        }
        assert_eq!(faulty.list_calls().len(), before);
    }

    #[tokio::test]
    async fn a_literal_in_a_subdirectory_asks_that_directory() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\Notes.md", &stored_bytes(b"abc"));
        seed_file(&files, "Notes.md", &stored_bytes(b"root"));
        let docs = open_dir(&layer, "docs").await;
        let found = docs.list_dir(Some("notes.MD")).await.unwrap();
        assert_eq!(names(&found), ["Notes.md"]);
        assert_eq!(found[0].info.end_of_file, 3);
    }

    // Long entries without a side object

    #[tokio::test]
    async fn a_long_entry_without_its_side_object_is_left_out_of_listings_but_opens_by_name() {
        let logs = Logs::new();
        let (files, layer) = layer().await;
        let long = "x".repeat(150);
        seed_file(&files, "a.txt", b"");
        seed_file(&files, &long, &stored_bytes(b"data"));
        let form = stored_form(&long);
        files.remove(&form.side_object.unwrap().name);
        let root = open_dir(&layer, "").await;

        assert_eq!(listed(&root, None).await, ["a.txt"]);
        assert_eq!(listed(&root, Some("*")).await, ["a.txt"]);
        assert!(listed(&root, Some("x*")).await.is_empty());
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 3, "one for each listing: {warnings:?}");
        assert!(warnings.iter().all(|line| line.contains(&form.entry)));

        let handle = open_file(&layer, &long).await;
        assert_eq!(read_all(&handle).await, b"data");
        assert_eq!(handle.stat().await.unwrap().name, long);
        assert_eq!(
            listed(&root, Some(&long)).await,
            sorted(&[&long]),
            "a lookup by the exact name finds what opens by it"
        );
    }

    #[tokio::test]
    async fn a_side_object_that_cannot_be_read_leaves_out_its_entry_and_the_names_are_not_kept() {
        let logs = Logs::new();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let long = "b".repeat(150);
        seed_file(&files, "a.txt", b"");
        seed_file(&files, &long, b"");
        let side = stored_form(&long).side_object.unwrap().name;
        fail_open_of(&faulty, &side);
        let root = open_dir(&layer, "").await;

        assert_eq!(listed(&root, None).await, ["a.txt"]);
        assert_eq!(logs.warnings().len(), 1, "{:?}", logs.warnings());
        assert!(layer.shared.names.fresh("").is_none());

        assert_eq!(listed(&root, None).await, sorted(&["a.txt", &long]));
        let kept = layer.shared.names.fresh("").expect("the names are kept");
        assert!(kept.entry(&long, &stored_name(&long)).is_some());
    }

    // Info

    #[tokio::test]
    async fn sizes_are_mapped_ea_sizes_are_zero_and_the_rest_comes_from_the_inner_backend() {
        let files = MemFsBackend::new();
        let layer = names_over(FileIds::new(files.clone())).await;
        seed_file(&files, "f", &stored_bytes(b"hello"));
        seed_dir(&files, "d");
        files.clone().with_dir_size(4096);
        files
            .clone()
            .with_ea(&stored_name("f"), Ea::new("note", b"value".to_vec()));
        let root = open_dir(&layer, "").await;

        let all = root.list_dir(None).await.unwrap();
        assert_eq!(
            summary(&all),
            [("d".to_string(), 4096, 4096, 0), ("f".to_string(), 5, 5, 0)]
        );
        let one = root.list_dir(Some("f")).await.unwrap();
        assert_eq!(summary(&one), [("f".to_string(), 5, 5, 0)]);

        let (inner_root, _) = layer
            .shared
            .inner
            .open(&SmbPath::root(), dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        let inner = inner_root.list_dir(None).await.unwrap();
        assert_eq!(inner.len(), 2 + 1, "the marker is listed there");
        assert_ne!(
            inner
                .iter()
                .find(|entry| entry.info.name == stored_name("f"))
                .unwrap()
                .info
                .ea_size,
            0
        );
        let by_open = open_file(&layer, "f").await.stat().await.unwrap();
        let listed_f = all.iter().find(|entry| entry.info.name == "f").unwrap();
        assert_ne!(by_open.file_index, 0);
        assert_eq!(listed_f.info.file_index, by_open.file_index);
    }

    // Keeping the names

    /// Lists the root in a task, which parks at the gate.
    fn list_in_task(
        root: &Arc<EncryptedHandle<Gated<MemFsBackend>>>,
    ) -> JoinHandle<SmbResult<Vec<DirEntry>>> {
        let root = Arc::clone(root);
        tokio::spawn(async move { root.list_dir(None).await })
    }

    #[tokio::test]
    async fn a_create_during_a_listing_is_not_held_up_and_its_names_stay() {
        let (_, layer, gate) = parked().await;
        let root = Arc::new(open_dir(&layer, "").await);
        let listing = list_in_task(&root);
        gate.reached().await;

        let (_created, action) = open(&layer, "new", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        gate.release();
        assert_eq!(names(&listing.await.unwrap().unwrap()), ["a.txt"]);

        let kept = layer
            .shared
            .names
            .fresh("")
            .expect("the create's names stay");
        assert!(kept.entry("new", &stored_name("new")).is_some());
    }

    #[tokio::test]
    async fn a_dropped_listing_leaves_no_lock_entry_and_no_names() {
        let (_, layer, gate) = parked().await;
        let root = open_dir(&layer, "").await;
        drop_at(&gate, root.list_dir(None)).await;
        assert_eq!(layer.shared.locks.directory_count(), 0);
        assert!(layer.shared.names.fresh("").is_none());
    }

    #[tokio::test]
    async fn a_second_listing_reads_no_side_objects() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        for n in 0..3 {
            seed_file(&files, &format!("{n:0>150}"), b"");
        }
        let root = open_dir(&layer, "").await;
        let side_reads = || {
            let opens = faulty.open_calls();
            opens.iter().filter(|(at, _)| at.ends_with(".n")).count()
        };

        assert_eq!(root.list_dir(None).await.unwrap().len(), 3);
        assert_eq!(side_reads(), 3);
        assert_eq!(root.list_dir(None).await.unwrap().len(), 3);
        assert_eq!(side_reads(), 3);
    }

    // Empty directories

    #[tokio::test]
    async fn a_directory_with_only_orphan_side_objects_is_empty() {
        let (files, layer) = layer().await;
        seed_dir(&files, "Docs");
        let docs = open_dir(&layer, "Docs").await;
        let at = stored_at("Docs");
        assert!(docs.dir_is_empty().await.unwrap(), "nothing in it");

        seed_orphan(&files, &at, &"a".repeat(150));
        assert!(docs.dir_is_empty().await.unwrap());
        assert_eq!(listed(&docs, None).await, Vec::<String>::new());
    }

    #[tokio::test]
    async fn the_root_with_the_marker_and_orphan_side_objects_is_empty() {
        let (files, layer) = layer().await;
        let root = open_dir(&layer, "").await;
        assert!(files.contents(MARKER_NAME).is_some());
        assert!(root.dir_is_empty().await.unwrap(), "the marker only");
        seed_orphan(&files, "", &"a".repeat(150));
        assert!(root.dir_is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn one_real_entry_makes_a_directory_not_empty() {
        let (files, layer) = layer().await;
        seed_dir(&files, "Docs");
        let at = stored_at("Docs");
        let docs = open_dir(&layer, "Docs").await;
        let root = open_dir(&layer, "").await;
        assert!(!root.dir_is_empty().await.unwrap(), "it holds Docs");

        let inside = |name: &str| format!("{at}\\{name}");
        let long = "l".repeat(150);
        let long_form = stored_form(&long);
        let side = long_form.side_object.as_ref().unwrap();
        let entries = [
            (stored_name("a.txt"), None),
            ("junk".to_string(), None),
            (MARKER_NAME.to_string(), None),
            (long_form.entry.clone(), None),
            (long_form.entry.clone(), Some(side)),
        ];
        for (stored, side) in entries {
            let entry = inside(&stored);
            files.clone().with_file(&entry, b"");
            if let Some(side) = side {
                files.clone().with_file(&inside(&side.name), &side.content);
            }
            assert!(!docs.dir_is_empty().await.unwrap(), "{stored}");
            files.remove(&entry);
        }
        assert!(docs.dir_is_empty().await.unwrap(), "back to orphans only");
    }

    #[tokio::test]
    async fn a_directory_the_inner_backend_calls_empty_is_not_listed() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_dir(&files, "Docs");
        let docs = open_dir(&layer, "Docs").await;
        let before = faulty.list_calls().len();
        assert!(docs.dir_is_empty().await.unwrap());
        assert_eq!(faulty.list_calls().len(), before);

        seed_orphan(&files, &stored_at("Docs"), &"a".repeat(150));
        assert!(docs.dir_is_empty().await.unwrap());
        assert_eq!(faulty.list_calls().len(), before + 1, "listed once");
    }

    #[tokio::test]
    async fn a_directory_with_entries_that_the_inner_listing_hides_is_not_empty() {
        let layer = names_over(MemFsBackend::new()).await;
        let node = layer.shared.nodes.attach(&Found {
            path: &SmbPath::root(),
            file_index: 0,
            directory: true,
            origin: Origin::Opened,
            names: NameMatch::Exact,
        });
        let root = EncryptedHandle::new(Box::new(Hiding), node, Arc::clone(&layer.shared));
        assert!(!root.dir_is_empty().await.unwrap());
    }

    // Watches

    fn watch_over<B: ShareBackend>(
        layer: &EncryptedBackend<B>,
        in_root: bool,
        batches: Vec<Vec<DirChange>>,
    ) -> NamesWatch<B> {
        NamesWatch {
            inner: Box::new(Script::new(batches)),
            shared: Arc::clone(&layer.shared),
            in_root,
        }
    }

    fn lost() -> DirChange {
        change("", DirChangeKind::Lost)
    }

    #[tokio::test]
    async fn changes_to_short_names_arrive_under_the_names_clients_spell() {
        let layer = names_over(MemFsBackend::new()).await;
        let [a, dir, c] = ["a.txt", "Dir", "c"].map(stored_name);
        let mut watch = watch_over(
            &layer,
            false,
            vec![vec![
                change(&a, DirChangeKind::Added),
                DirChange::new(&dir, DirChangeKind::Removed, true),
                change(&c, DirChangeKind::Modified),
                change(&a, DirChangeKind::AttributesChanged),
                renamed(&a, &c),
                DirChange::new(&dir, DirChangeKind::Renamed { from: c.clone() }, true),
            ]],
        );
        assert_eq!(
            watch.next().await,
            Some(vec![
                change("a.txt", DirChangeKind::Added),
                DirChange::new("Dir", DirChangeKind::Removed, true),
                change("c", DirChangeKind::Modified),
                change("a.txt", DirChangeKind::AttributesChanged),
                renamed("a.txt", "c"),
                DirChange::new(
                    "Dir",
                    DirChangeKind::Renamed {
                        from: "c".to_string()
                    },
                    true
                ),
            ])
        );
        assert_eq!(watch.next().await, None);
    }

    #[tokio::test]
    async fn the_marker_side_objects_and_foreign_names_are_dropped() {
        let logs = Logs::at(tracing::Level::DEBUG);
        let layer = names_over(MemFsBackend::new()).await;
        let long = "x".repeat(150);
        let side = stored_form(&long).side_object.unwrap().name;
        let other_key = encode_name(&other_key_schedule(), "other", 255)
            .unwrap()
            .entry;
        let invalid = sealed_invalid_names();
        let mut batch = vec![
            change(MARKER_NAME, DirChangeKind::Modified),
            change(&side, DirChangeKind::Added),
            change("junk", DirChangeKind::Removed),
            change(&other_key, DirChangeKind::Added),
        ];
        batch.extend(
            invalid
                .iter()
                .map(|name| change(name, DirChangeKind::Modified)),
        );
        batch.push(change(&stored_name("kept"), DirChangeKind::Added));
        let mut watch = watch_over(&layer, true, vec![batch]);
        assert_eq!(
            watch.next().await,
            Some(vec![change("kept", DirChangeKind::Added)])
        );
        assert_eq!(watch.next().await, None);

        let lines = foreign_lines(&logs);
        assert_eq!(lines.len(), 2 + invalid.len(), "{lines:?}");
        let seen = invalid.iter().map(String::as_str);
        for name in seen.chain(["junk", other_key.as_str()]) {
            assert!(lines.iter().any(|line| line.contains(name)), "{name}");
        }
        assert!(!logs.text().contains(PRIVATE_WORD));
    }

    #[tokio::test]
    async fn below_the_root_the_marker_name_is_a_foreign_name_in_a_watch() {
        let logs = Logs::at(tracing::Level::DEBUG);
        let layer = names_over(MemFsBackend::new()).await;
        let mut watch = watch_over(
            &layer,
            false,
            vec![vec![change(MARKER_NAME, DirChangeKind::Added)]],
        );
        assert_eq!(watch.next().await, None);
        assert_eq!(foreign_lines(&logs).len(), 1);
    }

    #[tokio::test]
    async fn long_names_arrive_through_the_cache_and_an_unknown_one_is_one_lost() {
        let recorder = Recorder::default();
        let layer = EncryptedBackend::new(recorder.clone(), key_schedule(), names_settings());
        let [known, unknown, other] = ["k", "u", "o"].map(|c| c.repeat(150));
        let known_entry = stored_form(&known).entry;
        let unknown_entry = stored_form(&unknown).entry;
        layer.shared.long_names.insert(known_entry.clone(), &known);
        let a = stored_name("a");
        let mut watch = watch_over(
            &layer,
            false,
            vec![
                vec![
                    change(&unknown_entry, DirChangeKind::Added),
                    change(&known_entry, DirChangeKind::Modified),
                    change(&a, DirChangeKind::Added),
                    change(&stored_form(&other).entry, DirChangeKind::Removed),
                    change(&unknown_entry, DirChangeKind::Modified),
                ],
                vec![change(&unknown_entry, DirChangeKind::Added)],
            ],
        );
        assert_eq!(
            watch.next().await,
            Some(vec![
                lost(),
                change(&known, DirChangeKind::Modified),
                change("a", DirChangeKind::Added),
            ]),
            "one lost, where the first unknown name was"
        );

        layer
            .shared
            .long_names
            .insert(unknown_entry.clone(), &unknown);
        assert_eq!(
            watch.next().await,
            Some(vec![change(&unknown, DirChangeKind::Added)]),
            "a name the cache got since is known"
        );
        assert_eq!(recorder.calls(), Vec::<String>::new(), "no inner calls");
    }

    #[tokio::test]
    async fn a_lost_of_the_inner_watch_counts_as_the_one_lost_of_a_batch() {
        let layer = names_over(MemFsBackend::new()).await;
        let unknown = stored_form(&"u".repeat(150)).entry;
        let a = stored_name("a");
        let mut watch = watch_over(
            &layer,
            false,
            vec![
                vec![lost(), change(&unknown, DirChangeKind::Added)],
                vec![
                    change(&unknown, DirChangeKind::Added),
                    lost(),
                    change(&a, DirChangeKind::Added),
                ],
            ],
        );
        assert_eq!(watch.next().await, Some(vec![lost()]));
        assert_eq!(
            watch.next().await,
            Some(vec![lost(), change("a", DirChangeKind::Added)])
        );
    }

    #[tokio::test]
    async fn a_rename_with_one_side_that_is_no_name_is_an_addition_or_a_removal() {
        let layer = names_over(MemFsBackend::new()).await;
        let [a, b] = ["a", "b"].map(stored_name);
        let mut watch = watch_over(
            &layer,
            true,
            vec![vec![
                renamed(&a, &b),
                renamed("junk", &a),
                DirChange::new(
                    &a,
                    DirChangeKind::Renamed {
                        from: "junk".into(),
                    },
                    true,
                ),
                renamed(&a, "junk"),
                DirChange::new("junk", DirChangeKind::Renamed { from: b.clone() }, true),
                renamed("junk", "more-junk"),
                renamed(MARKER_NAME, &b),
                renamed(&a, MARKER_NAME),
                renamed(MARKER_NAME, MARKER_NAME),
            ]],
        );
        assert_eq!(
            watch.next().await,
            Some(vec![
                renamed("a", "b"),
                change("a", DirChangeKind::Added),
                DirChange::new("a", DirChangeKind::Added, true),
                change("a", DirChangeKind::Removed),
                DirChange::new("b", DirChangeKind::Removed, true),
                change("b", DirChangeKind::Added),
                change("a", DirChangeKind::Removed),
            ])
        );
        assert_eq!(watch.next().await, None);
    }

    #[tokio::test]
    async fn a_rename_that_names_an_unknown_long_entry_is_one_lost() {
        let layer = names_over(MemFsBackend::new()).await;
        let long = stored_form(&"x".repeat(150)).entry;
        let a = stored_name("a");
        let mut watch = watch_over(
            &layer,
            false,
            vec![vec![
                renamed(&long, &a),
                renamed(&a, &long),
                renamed("junk", &long),
                renamed(&a, &stored_name("b")),
            ]],
        );
        assert_eq!(
            watch.next().await,
            Some(vec![lost(), renamed("a", "b")]),
            "each rename that names it is lost, once"
        );
    }

    #[tokio::test]
    async fn lost_moved_and_deleted_pass_through_unchanged() {
        let layer = names_over(MemFsBackend::new()).await;
        let batch = vec![
            lost(),
            change("", DirChangeKind::Moved),
            DirChange::new("", DirChangeKind::Moved, true),
            change("", DirChangeKind::Deleted),
            change(MARKER_NAME, DirChangeKind::Deleted),
        ];
        let mut watch = watch_over(&layer, true, vec![batch.clone()]);
        assert_eq!(watch.next().await, Some(batch));
        assert_eq!(watch.next().await, None);
    }

    #[tokio::test]
    async fn the_watch_of_a_handle_wraps_the_inner_watch() {
        let recorder = Recorder::default();
        let layer = EncryptedBackend::new(recorder.clone(), key_schedule(), names_settings());
        for at in ["", "Dir"] {
            let (handle, _) = layer
                .open_handle(&path(at), dir_opts(OpenIntent::Open))
                .await
                .unwrap();
            let mut watch = handle.watch().await.unwrap().expect("a watch");
            // The inner watch reports the name `seen`, which no name of the
            // share encrypts to.
            assert_eq!(watch.next().await, None, "{at:?}");
        }
        let calls = recorder.calls();
        assert_eq!(calls.iter().filter(|call| *call == "watch").count(), 2);
    }

    #[tokio::test]
    async fn a_directory_without_an_inner_watch_has_none() {
        let (files, layer) = layer().await;
        seed_dir(&files, "Docs");
        for at in ["", "Docs"] {
            assert!(open_dir(&layer, at).await.watch().await.unwrap().is_none());
        }
    }
}
