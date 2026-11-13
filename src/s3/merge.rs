//! The entries of a directory: the rows of its listing in the bucket, and
//! what the overlay adds to them or takes from them.

use std::cmp::Ordering;
use std::collections::HashMap;

use super::keys::{Row, RowKind, Slot, slot};

/// An entry of the overlay directly in the directory.
pub(super) struct Direct {
    pub(super) name: String,
    pub(super) is_dir: bool,
}

/// Where an entry of the merged listing comes from, by position in the
/// slice it was given in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
    Row(usize),
    Entry(usize),
    /// A directory that only entries below it imply.
    Implied(usize),
}

/// One entry of the merged listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Picked {
    pub(super) name: String,
    pub(super) is_dir: bool,
    pub(super) source: Source,
}

/// What the overlay has for one name.
#[derive(Default)]
struct Touch {
    row: Option<usize>,
    entry: Option<usize>,
    implied: Option<usize>,
}

fn is_dir(row: &Row) -> bool {
    matches!(row.kind, RowKind::Dir)
}

/// The entries of a directory in the order of their keys: the `rows` of its
/// listing, with the `direct` entries of the overlay in place of the rows of
/// their names, and a directory for each of the `implied` names that has no
/// row. A name that is both a file and a directory is the directory. Names
/// that differ only in case are one name when `fold` is set; the overlay's
/// names are, for the rows they replace.
pub(super) fn merge(
    rows: &[&Row],
    direct: &[Direct],
    implied: &[String],
    fold: bool,
) -> Vec<Picked> {
    let key = |name: &str| slot(name, fold);
    let mut touched: HashMap<Slot, Touch> = HashMap::new();
    for (at, entry) in direct.iter().enumerate() {
        touched.entry(key(&entry.name)).or_default().entry = Some(at);
    }
    for (at, name) in implied.iter().enumerate() {
        touched.entry(key(name)).or_default().implied = Some(at);
    }

    let mut picked = Vec::with_capacity(rows.len() + direct.len());
    for (at, row) in rows.iter().enumerate() {
        match touched.get_mut(&key(&row.name)) {
            Some(touch) => {
                touch.row.get_or_insert(at);
            }
            None => picked.push(Picked {
                name: row.name.clone(),
                is_dir: is_dir(row),
                source: Source::Row(at),
            }),
        }
    }
    for touch in touched.into_values() {
        let row = touch.row.map(|at| (at, rows[at]));
        let entry = touch.entry.map(|at| (at, &direct[at]));
        // A directory wins over a file of the same name.
        let pick = if let Some((at, entry)) = entry.filter(|(_, entry)| entry.is_dir) {
            Picked {
                name: entry.name.clone(),
                is_dir: true,
                source: Source::Entry(at),
            }
        } else if let Some((at, row)) = row.filter(|(_, row)| is_dir(row)) {
            Picked {
                name: row.name.clone(),
                is_dir: true,
                source: Source::Row(at),
            }
        } else if let Some(at) = touch.implied {
            Picked {
                name: implied[at].clone(),
                is_dir: true,
                source: Source::Implied(at),
            }
        } else if let Some((at, entry)) = entry {
            Picked {
                name: entry.name.clone(),
                is_dir: false,
                source: Source::Entry(at),
            }
        } else if let Some((at, row)) = row {
            Picked {
                name: row.name.clone(),
                is_dir: false,
                source: Source::Row(at),
            }
        } else {
            continue;
        };
        picked.push(pick);
    }
    picked.sort_by(by_key);
    picked
}

/// The bytes of the key the entry stands for, relative to its directory.
fn key_bytes(picked: &Picked) -> impl Iterator<Item = u8> + '_ {
    picked.name.bytes().chain(picked.is_dir.then_some(b'/'))
}

fn by_key(a: &Picked, b: &Picked) -> Ordering {
    key_bytes(a).cmp(key_bytes(b))
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::s3::keys::FileStamp;

    fn file(name: &str) -> Row {
        Row {
            name: name.to_owned(),
            kind: RowKind::File(FileStamp {
                size: 1,
                etag: String::new(),
                last_modified: UNIX_EPOCH,
            }),
        }
    }

    fn dir(name: &str) -> Row {
        Row {
            name: name.to_owned(),
            kind: RowKind::Dir,
        }
    }

    fn entry(name: &str, is_dir: bool) -> Direct {
        Direct {
            name: name.to_owned(),
            is_dir,
        }
    }

    fn run(rows: &[Row], direct: &[Direct], implied: &[&str], fold: bool) -> Vec<(String, Source)> {
        let rows: Vec<&Row> = rows.iter().collect();
        let implied: Vec<String> = implied.iter().map(|n| (*n).to_owned()).collect();
        merge(&rows, direct, &implied, fold)
            .into_iter()
            .map(|p| (p.name, p.source))
            .collect()
    }

    fn names(picked: &[(String, Source)]) -> Vec<&str> {
        picked.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn rows_alone_come_out_as_they_went_in() {
        let rows = [file("a"), file("b"), dir("c")];
        let picked = run(&rows, &[], &[], false);
        assert_eq!(
            picked,
            [
                ("a".to_owned(), Source::Row(0)),
                ("b".to_owned(), Source::Row(1)),
                ("c".to_owned(), Source::Row(2)),
            ]
        );
    }

    #[test]
    fn new_entries_and_implied_directories_join_the_rows_in_key_order() {
        let rows = [file("b.txt"), dir("m")];
        let direct = [entry("a.txt", false), entry("z", true)];
        let picked = run(&rows, &direct, &["n"], false);
        assert_eq!(names(&picked), ["a.txt", "b.txt", "m", "n", "z"]);
        assert_eq!(picked[0].1, Source::Entry(0));
        assert_eq!(picked[3].1, Source::Implied(0));
        assert_eq!(picked[4].1, Source::Entry(1));
    }

    #[test]
    fn an_entry_replaces_the_row_of_its_name() {
        let rows = [file("a"), file("b")];
        let picked = run(&rows, &[entry("a", false)], &[], false);
        assert_eq!(
            picked,
            [
                ("a".to_owned(), Source::Entry(0)),
                ("b".to_owned(), Source::Row(1)),
            ]
        );
        let rows = [dir("d")];
        let picked = run(&rows, &[entry("d", true)], &[], false);
        assert_eq!(picked, [("d".to_owned(), Source::Entry(0))]);
    }

    #[test]
    fn the_order_is_that_of_keys_where_a_directory_name_ends_in_a_slash() {
        let rows = [file("a0"), file("a-b")];
        let picked = run(
            &rows,
            &[entry("a.txt", false), entry("a", true)],
            &[],
            false,
        );
        assert_eq!(names(&picked), ["a-b", "a.txt", "a", "a0"]);
    }

    #[test]
    fn a_directory_wins_over_a_file_of_the_same_name() {
        // An implied directory over a row that is a file.
        let rows = [file("x")];
        let picked = run(&rows, &[], &["x"], false);
        assert_eq!(picked, [("x".to_owned(), Source::Implied(0))]);
        // A directory row over an entry that is a file.
        let rows = [dir("x")];
        let picked = run(&rows, &[entry("x", false)], &[], false);
        assert_eq!(picked, [("x".to_owned(), Source::Row(0))]);
        // A directory entry over a file row.
        let rows = [file("x")];
        let picked = run(&rows, &[entry("x", true)], &[], false);
        assert_eq!(picked, [("x".to_owned(), Source::Entry(0))]);
        // An implied directory over an entry that is a file.
        let picked = run(&[], &[entry("x", false)], &["x"], false);
        assert_eq!(picked, [("x".to_owned(), Source::Implied(0))]);
    }

    #[test]
    fn a_directory_row_stands_for_an_implied_directory_of_its_name() {
        let rows = [dir("sub")];
        let picked = run(&rows, &[], &["sub"], false);
        assert_eq!(picked, [("sub".to_owned(), Source::Row(0))]);
        let picked = run(&rows, &[entry("sub", true)], &["sub"], false);
        assert_eq!(picked, [("sub".to_owned(), Source::Entry(0))]);
    }

    #[test]
    fn case_decides_what_a_name_is_only_when_it_is_folded() {
        let rows = [file("Readme"), file("readme")];
        let picked = run(&rows, &[], &[], true);
        assert_eq!(names(&picked), ["Readme", "readme"], "rows alone are kept");

        let picked = run(&rows, &[entry("README", false)], &[], true);
        assert_eq!(picked, [("README".to_owned(), Source::Entry(0))]);

        let picked = run(&rows, &[entry("README", false)], &[], false);
        assert_eq!(names(&picked), ["README", "Readme", "readme"]);

        let picked = run(&[], &[], &["Sub", "sub"], true);
        assert_eq!(picked.len(), 1);
    }

    #[test]
    fn non_ascii_names_fold_like_the_server_folds_them() {
        let rows = [file("\u{c9}t\u{e9}")];
        let picked = run(&rows, &[entry("\u{e9}t\u{e9}", false)], &[], true);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].1, Source::Entry(0));
    }
}
