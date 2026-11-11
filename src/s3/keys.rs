//! Object keys, and the directory listings built from the keys of a store.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::time::SystemTime;

use crate::error::{SmbError, SmbResult};
use crate::path::is_valid_component;

use super::xml::Listing;

/// Longest object key, in bytes.
pub(super) const MAX_KEY_LEN: usize = 1024;

/// The key of the entry `name` in the directory with key `dir`. The root of a
/// share without a prefix has the key `""`.
pub(super) fn join_key(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// [`join_key`], failing for a key longer than the store takes.
pub(super) fn child_key(dir: &str, name: &str) -> SmbResult<String> {
    let key = join_key(dir, name);
    if key.len() > MAX_KEY_LEN {
        return Err(SmbError::NameInvalid);
    }
    Ok(key)
}

/// The last name of `key`.
pub(super) fn last_name(key: &str) -> &str {
    key.rsplit_once('/').map_or(key, |(_, name)| name)
}

/// The prefix of the keys below the directory with key `dir`, which is also
/// the key of its marker object. Empty for the root of a share without a
/// prefix, which has no marker.
pub(super) fn dir_prefix(dir: &str) -> String {
    if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    }
}

/// `text`, a key or a name, as names are compared: lowercased when `fold` is
/// set, which is when names match without regard to case.
pub(super) fn slot(text: &str, fold: bool) -> String {
    if fold {
        text.to_lowercase()
    } else {
        text.to_owned()
    }
}

/// The key of the entry at `components` below the share root `root`.
pub(super) fn path_key(root: &str, components: &[String]) -> SmbResult<String> {
    components
        .iter()
        .try_fold(root.to_owned(), |dir, name| child_key(&dir, name))
}

/// What a listing says about an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileStamp {
    pub(super) size: u64,
    pub(super) etag: String,
    pub(super) last_modified: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RowKind {
    File(FileStamp),
    Dir,
}

/// An entry of a directory: a name in its stored spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Row {
    pub(super) name: String,
    pub(super) kind: RowKind,
}

impl Row {
    fn is_dir(&self) -> bool {
        matches!(self.kind, RowKind::Dir)
    }

    /// The bytes of the key the row stands for, relative to its directory.
    fn key_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.name.bytes().chain(self.is_dir().then_some(b'/'))
    }
}

/// All the entries of one directory.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DirListing {
    /// In the order of the keys they stand for.
    pub(super) rows: Vec<Row>,
}

impl DirListing {
    /// The listing with `row` added, in place of a row of the same name.
    pub(super) fn with_row(&self, row: Row) -> DirListing {
        let mut rows: Vec<Row> = self
            .rows
            .iter()
            .filter(|held| held.name != row.name)
            .cloned()
            .collect();
        rows.push(row);
        rows.sort_by(by_key);
        DirListing { rows }
    }

    /// The row named exactly `name`.
    pub(super) fn find_exact(&self, name: &str) -> Option<&Row> {
        self.rows.iter().find(|row| row.name == name)
    }

    /// The row named `name`, or else the first row in key order whose name
    /// folds to the same lowercase text. With `dirs_only`, only directories
    /// count.
    pub(super) fn find_folded(&self, name: &str, dirs_only: bool) -> Option<&Row> {
        let wanted = |row: &&Row| !dirs_only || row.is_dir();
        if let Some(row) = self.find_exact(name).filter(wanted) {
            return Some(row);
        }
        let folded = name.to_lowercase();
        self.rows
            .iter()
            .filter(wanted)
            .find(|row| folds_to(&row.name, &folded))
    }
}

/// Whether `name` is `folded` once lowercased. `folded` is already lowercase.
fn folds_to(name: &str, folded: &str) -> bool {
    if name.is_ascii() {
        name.len() == folded.len()
            && name
                .bytes()
                .zip(folded.bytes())
                .all(|(a, b)| a.to_ascii_lowercase() == b)
    } else {
        name.to_lowercase() == folded
    }
}

/// Builds a [`DirListing`] from the pages of a delimited listing of one
/// directory.
pub(super) struct ListingBuilder {
    prefix: String,
    /// Whether any key below the directory was seen.
    any: bool,
    files: Vec<Row>,
    dirs: Vec<Row>,
}

impl ListingBuilder {
    /// A builder for the directory whose keys start with `prefix`.
    pub(super) fn new(prefix: String) -> Self {
        ListingBuilder {
            prefix,
            any: false,
            files: Vec::new(),
            dirs: Vec::new(),
        }
    }

    /// Takes in one page. Keys outside the directory, with an empty path
    /// component, or that no client could open are left out of the rows, but
    /// the directory exists for them.
    pub(super) fn add(&mut self, page: &Listing) {
        for object in &page.objects {
            let Some(rest) = object.key.strip_prefix(&self.prefix) else {
                continue;
            };
            self.any = true;
            if is_valid_component(rest) {
                self.files.push(Row {
                    name: rest.to_owned(),
                    kind: RowKind::File(FileStamp {
                        size: object.size,
                        etag: object.etag.clone(),
                        last_modified: object.last_modified,
                    }),
                });
            }
        }
        for common in &page.prefixes {
            let Some(rest) = common
                .strip_prefix(&self.prefix)
                .and_then(|rest| rest.strip_suffix('/'))
            else {
                continue;
            };
            self.any = true;
            if is_valid_component(rest) {
                self.dirs.push(Row {
                    name: rest.to_owned(),
                    kind: RowKind::Dir,
                });
            }
        }
    }

    /// The listing, or `None` when the store has no key below the directory.
    /// A name that is both a directory and an object is the directory.
    pub(super) fn finish(self) -> Option<DirListing> {
        let ListingBuilder {
            any, files, dirs, ..
        } = self;
        if !any {
            return None;
        }
        let dir_names: HashSet<&str> = dirs.iter().map(|row| row.name.as_str()).collect();
        let mut rows: Vec<Row> = files
            .into_iter()
            .filter(|row| !dir_names.contains(row.name.as_str()))
            .collect();
        rows.extend(dirs);
        rows.sort_by(by_key);
        rows.dedup_by(|a, b| a.name == b.name && a.is_dir() == b.is_dir());
        Some(DirListing { rows })
    }
}

fn by_key(a: &Row, b: &Row) -> Ordering {
    a.key_bytes().cmp(b.key_bytes())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::s3::xml::ListedObject;

    fn object(key: &str) -> ListedObject {
        ListedObject {
            key: key.to_owned(),
            size: key.len() as u64,
            etag: "\"e\"".to_owned(),
            last_modified: UNIX_EPOCH + Duration::from_secs(1_000),
        }
    }

    fn page(objects: &[&str], prefixes: &[&str]) -> Listing {
        Listing {
            objects: objects.iter().map(|key| object(key)).collect(),
            prefixes: prefixes.iter().map(|p| (*p).to_owned()).collect(),
            next_token: None,
        }
    }

    fn listing(prefix: &str, pages: &[Listing]) -> DirListing {
        built(prefix, pages).unwrap_or_default()
    }

    fn built(prefix: &str, pages: &[Listing]) -> Option<DirListing> {
        let mut builder = ListingBuilder::new(prefix.to_owned());
        for page in pages {
            builder.add(page);
        }
        builder.finish()
    }

    fn names(listing: &DirListing) -> Vec<(&str, bool)> {
        listing
            .rows
            .iter()
            .map(|row| (row.name.as_str(), row.is_dir()))
            .collect()
    }

    #[test]
    fn keys_join_the_prefix_and_the_components() {
        let components = ["a".to_owned(), "b c".to_owned()];
        assert_eq!(path_key("", &components).unwrap(), "a/b c");
        assert_eq!(path_key("p/q", &components).unwrap(), "p/q/a/b c");
        assert_eq!(path_key("p", &[]).unwrap(), "p");
        assert_eq!(path_key("", &[]).unwrap(), "");
        assert_eq!(join_key("", "x"), "x");
        assert_eq!(join_key("p/q", "x"), "p/q/x");
        assert_eq!(child_key("p/q", "x").unwrap(), "p/q/x");
        assert_eq!(dir_prefix(""), "");
        assert_eq!(dir_prefix("p"), "p/");
    }

    #[test]
    fn the_name_of_a_key_is_its_last_component() {
        assert_eq!(last_name("a/b/c.txt"), "c.txt");
        assert_eq!(last_name("c.txt"), "c.txt");
        assert_eq!(last_name(""), "");
    }

    #[test]
    fn names_are_compared_as_lowercase_only_when_case_is_ignored() {
        assert_eq!(slot("Dir/\u{c9}COLE.TXT", true), "dir/\u{e9}cole.txt");
        assert_eq!(slot("Dir/\u{c9}COLE.TXT", false), "Dir/\u{c9}COLE.TXT");
        assert_eq!(slot("A\u{3a3}/B", true), slot("a\u{3c2}/b", true));
    }

    #[test]
    fn a_key_over_the_limit_is_an_invalid_name() {
        // Four names and three separators take 803 bytes.
        let mut components = vec!["x".repeat(200); 4];
        components.push("y".repeat(220));
        assert_eq!(path_key("", &components).unwrap().len(), MAX_KEY_LEN);
        components[4].push('y');
        assert!(matches!(
            path_key("", &components),
            Err(SmbError::NameInvalid)
        ));
        components[4].pop();
        components[4].pop();
        assert_eq!(path_key("", &components).unwrap().len(), MAX_KEY_LEN - 1);
        // The prefix and its separator count.
        assert!(matches!(
            path_key("p", &components),
            Err(SmbError::NameInvalid)
        ));
        components[4].pop();
        components[4].pop();
        assert_eq!(path_key("p", &components).unwrap().len(), MAX_KEY_LEN - 1);
    }

    #[test]
    fn multibyte_names_count_bytes_in_the_key() {
        // 255 UTF-16 units of 3 bytes each.
        let name = "\u{20ac}".repeat(255);
        let components = vec![name; 2];
        assert!(matches!(
            path_key("", &components),
            Err(SmbError::NameInvalid)
        ));
        assert!(path_key("", &components[..1]).is_ok());
    }

    #[test]
    fn rows_come_from_objects_and_common_prefixes() {
        let listing = listing("d/", &[page(&["d/a.txt", "d/b"], &["d/sub/", "d/other/"])]);
        assert_eq!(
            names(&listing),
            [
                ("a.txt", false),
                ("b", false),
                ("other", true),
                ("sub", true)
            ]
        );
        let RowKind::File(stamp) = &listing.find_exact("a.txt").unwrap().kind else {
            panic!("not a file");
        };
        assert_eq!(stamp.size, 7);
        assert_eq!(stamp.etag, "\"e\"");
        assert_eq!(stamp.last_modified, UNIX_EPOCH + Duration::from_secs(1_000));
    }

    #[test]
    fn a_row_added_takes_its_place_in_key_order_and_replaces_one_of_its_name() {
        let base = listing("", &[page(&["a0", "a.txt"], &["b/"])]);
        let row = |name: &str, is_dir: bool| Row {
            name: name.to_owned(),
            kind: if is_dir {
                RowKind::Dir
            } else {
                RowKind::File(FileStamp {
                    size: 1,
                    etag: String::new(),
                    last_modified: UNIX_EPOCH,
                })
            },
        };
        let added = base.with_row(row("a", true));
        assert_eq!(
            names(&added),
            [("a.txt", false), ("a", true), ("a0", false), ("b", true)]
        );
        let replaced = added.with_row(row("b", false));
        assert_eq!(
            names(&replaced),
            [("a.txt", false), ("a", true), ("a0", false), ("b", false)]
        );
        assert_eq!(names(&base).len(), 3, "the original is not changed");
    }

    #[test]
    fn rows_follow_the_order_of_the_keys() {
        // "a.txt" sorts before "a/", and "a/" before "a0".
        let listing = listing("", &[page(&["a0", "a.txt", "a-b"], &["a/"])]);
        assert_eq!(
            names(&listing),
            [("a-b", false), ("a.txt", false), ("a", true), ("a0", false)]
        );
    }

    #[test]
    fn pages_are_merged() {
        let listing = listing(
            "",
            &[
                page(&["b", "c"], &["a/"]),
                page(&["d"], &["e/"]),
                page(&[], &[]),
            ],
        );
        assert_eq!(
            names(&listing),
            [
                ("a", true),
                ("b", false),
                ("c", false),
                ("d", false),
                ("e", true)
            ]
        );
    }

    #[test]
    fn the_marker_is_not_a_row_and_shows_that_the_directory_exists() {
        let marker = built("d/", &[page(&["d/"], &[])]).unwrap();
        assert!(marker.rows.is_empty());
        assert!(built("d/", &[page(&[], &[])]).is_none());
        assert!(built("d/", &[]).is_none());
    }

    #[test]
    fn names_no_client_can_open_are_left_out() {
        let long = "x".repeat(256);
        let listing = listing(
            "",
            &[page(
                &[
                    "ok",
                    "bad:name",
                    "bad*name",
                    "tab\tname",
                    "back\\slash",
                    ".",
                    "..",
                    &long,
                ],
                &["fine/", "wild?/", "a:b/"],
            )],
        );
        assert_eq!(names(&listing), [("fine", true), ("ok", false)]);
    }

    #[test]
    fn keys_with_an_empty_component_are_left_out() {
        let listing = listing("d/", &[page(&["d//x", "d/ok"], &["d//", "d/a//", "d/b/"])]);
        assert_eq!(names(&listing), [("b", true), ("ok", false)]);
    }

    #[test]
    fn a_directory_of_unlistable_keys_exists_with_no_rows() {
        let junk = built("d/", &[page(&["d//x", "d/bad:name"], &["d/a//"])]).unwrap();
        assert!(junk.rows.is_empty());
    }

    #[test]
    fn keys_outside_the_directory_are_left_out() {
        let listing = listing(
            "d/",
            &[page(
                &["other/x", "dd/x", "d/in"],
                &["other/", "dd/", "d/sub/"],
            )],
        );
        assert_eq!(names(&listing), [("in", false), ("sub", true)]);
        assert!(built("d/", &[page(&["other/x", "dd/x"], &["other/"])]).is_none());
    }

    #[test]
    fn keys_below_a_subdirectory_are_not_rows_of_the_directory() {
        let listing = listing("d/", &[page(&["d/sub/deep", "d/file"], &[])]);
        assert_eq!(names(&listing), [("file", false)]);
    }

    #[test]
    fn a_directory_wins_over_an_object_of_the_same_name() {
        let listing = listing(
            "",
            &[page(&["a", "b"], &["a/"]), page(&["A"], &["c/", "b/"])],
        );
        assert_eq!(
            names(&listing),
            [("A", false), ("a", true), ("b", true), ("c", true)]
        );
        assert!(matches!(
            listing.find_exact("a").unwrap().kind,
            RowKind::Dir
        ));
        assert!(matches!(
            listing.find_exact("b").unwrap().kind,
            RowKind::Dir
        ));
    }

    #[test]
    fn a_repeated_row_is_kept_once() {
        let listing = listing("", &[page(&["a"], &["d/"]), page(&["a"], &["d/"])]);
        assert_eq!(names(&listing), [("a", false), ("d", true)]);
    }

    #[test]
    fn an_exact_name_is_found_exactly() {
        let listing = listing("", &[page(&["File", "file", "FILE"], &[])]);
        assert_eq!(listing.find_exact("file").unwrap().name, "file");
        assert!(listing.find_exact("fIle").is_none());
        assert_eq!(listing.find_folded("file", false).unwrap().name, "file");
        assert_eq!(listing.find_folded("FILE", false).unwrap().name, "FILE");
    }

    #[test]
    fn a_folded_name_takes_the_first_match_in_key_order() {
        // Uppercase letters sort before lowercase ones.
        let listing = listing("", &[page(&["readme", "README", "Readme"], &[])]);
        assert_eq!(listing.find_folded("rEaDmE", false).unwrap().name, "README");
        assert!(listing.find_folded("readm", false).is_none());
        assert!(listing.find_folded("readmee", false).is_none());
    }

    #[test]
    fn a_folded_name_can_be_limited_to_directories() {
        let listing = listing("", &[page(&["Data", "DATA"], &["data/", "dAtA/"])]);
        assert_eq!(listing.find_folded("DaTa", true).unwrap().name, "dAtA");
        assert_eq!(listing.find_folded("DaTa", false).unwrap().name, "DATA");
        assert_eq!(listing.find_folded("Data", true).unwrap().name, "dAtA");
        assert_eq!(listing.find_folded("data", true).unwrap().name, "data");
        let files_first = self::listing("", &[page(&["Cfg"], &["cfg/"])]);
        assert_eq!(files_first.find_folded("CFG", true).unwrap().name, "cfg");
        assert!(
            self::listing("", &[page(&["Cfg"], &[])])
                .find_folded("cfg", true)
                .is_none()
        );
    }

    #[test]
    fn folding_uses_unicode_lowercase() {
        let listing = listing(
            "",
            &[page(&["\u{c9}t\u{e9}", "stra\u{df}e", "\u{3a3}"], &[])],
        );
        let found = |name| {
            listing
                .find_folded(name, false)
                .map(|row| row.name.as_str())
        };
        assert_eq!(found("\u{e9}T\u{c9}"), Some("\u{c9}t\u{e9}"));
        assert_eq!(found("STRA\u{df}E"), Some("stra\u{df}e"));
        assert_eq!(found("\u{3c3}"), Some("\u{3a3}"));
        assert!(folds_to("ABC", "abc"));
        assert!(!folds_to("ABC", "abd"));
        assert!(!folds_to("AB", "abc"));
        assert!(!folds_to("ab", "\u{e0}b"));
        assert!(folds_to("\u{39f}\u{3a3}", "\u{3bf}\u{3c2}"));
    }
}
