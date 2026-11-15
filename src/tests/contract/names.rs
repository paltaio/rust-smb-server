//! Names of every length and script.

use super::helpers::{Backend, assert_bytes, contents, matching, mkdir, names, put, shown};
use crate::tests::util::path;

/// Name lengths. At the default long-name threshold, 143 is the longest name
/// stored short and 144 the shortest stored long.
const LENGTHS: [usize; 6] = [1, 100, 143, 144, 200, 255];

/// `letter` repeated to each length in `LENGTHS`, plus `extra`, sorted.
fn repeated(letter: &str, extra: &[&str]) -> Vec<String> {
    let mut all: Vec<_> = LENGTHS.iter().map(|&len| letter.repeat(len)).collect();
    all.extend(extra.iter().map(|name| (*name).to_string()));
    all.sort();
    all
}

#[track_caller]
fn assert_names(actual: &[String], expected: &[String], what: &str) {
    let shorten = |names: &[String]| names.iter().map(|name| shown(name)).collect::<Vec<_>>();
    assert!(
        actual == expected,
        "{what}: got {:?}, expected {:?}",
        shorten(actual),
        shorten(expected)
    );
}

pub(super) async fn names_of_every_length_round_trip(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    for len in LENGTHS {
        let name = "a".repeat(len);
        put(backend, &name, name.as_bytes()).await;
        put(backend, &format!("d\\{name}"), b"inner").await;
    }
    assert_names(
        &names(backend, "").await,
        &repeated("a", &["d"]),
        "the root",
    );
    assert_names(&names(backend, "d").await, &repeated("a", &[]), "d");
    for len in LENGTHS {
        let name = "a".repeat(len);
        assert_bytes(&contents(backend, &name).await, name.as_bytes(), &name);
        let inner = format!("d\\{name}");
        assert_bytes(&contents(backend, &inner).await, b"inner", &inner);
    }

    // Each name moves to one of another length, short to long and back.
    for (&from, &to) in LENGTHS.iter().zip(LENGTHS.iter().rev()) {
        backend
            .rename(&path(&"a".repeat(from)), &path(&"b".repeat(to)), false)
            .await
            .unwrap();
    }
    assert_names(
        &names(backend, "").await,
        &repeated("b", &["d"]),
        "the root after the renames",
    );
    for (&from, &to) in LENGTHS.iter().zip(LENGTHS.iter().rev()) {
        assert_bytes(
            &contents(backend, &"b".repeat(to)).await,
            "a".repeat(from).as_bytes(),
            &format!("{from} moved to {to}"),
        );
    }

    for len in LENGTHS {
        backend.unlink(&path(&"b".repeat(len))).await.unwrap();
        let inner = format!("d\\{}", "a".repeat(len));
        backend.unlink(&path(&inner)).await.unwrap();
    }
    assert_eq!(names(backend, "").await, ["d"]);
    assert!(names(backend, "d").await.is_empty());
}

/// Latin with an accent, CJK and Cyrillic.
const SCRIPTS: [&str; 3] = [
    "caf\u{e9}.txt",
    "\u{65e5}\u{672c}\u{8a9e}.txt",
    "\u{441}\u{43c}\u{435}\u{442}\u{430}.txt",
];

pub(super) async fn non_ascii_names_round_trip(backend: Backend<'_>) {
    for name in SCRIPTS {
        put(backend, name, name.as_bytes()).await;
    }
    let mut expected: Vec<_> = SCRIPTS.iter().map(|name| (*name).to_string()).collect();
    expected.sort();
    assert_eq!(names(backend, "").await, expected);
    for name in SCRIPTS {
        assert_bytes(&contents(backend, name).await, name.as_bytes(), name);
    }

    backend
        .rename(&path(SCRIPTS[0]), &path("plain.txt"), false)
        .await
        .unwrap();
    backend.unlink(&path(SCRIPTS[1])).await.unwrap();
    let mut left = vec!["plain.txt".to_string(), SCRIPTS[2].to_string()];
    left.sort();
    assert_eq!(names(backend, "").await, left);
}

pub(super) async fn a_literal_pattern_picks_a_name_of_any_length_or_script(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    let long: Vec<_> = LENGTHS.iter().map(|&len| "a".repeat(len)).collect();
    for name in long.iter().map(String::as_str).chain(SCRIPTS) {
        put(backend, name, b"x").await;
        put(backend, &format!("d\\{name}"), b"x").await;
    }
    for name in long.iter().map(String::as_str).chain(SCRIPTS) {
        let expected = [name.to_string()];
        assert_names(
            &matching(backend, "", Some(name)).await,
            &expected,
            "the root",
        );
        assert_names(&matching(backend, "d", Some(name)).await, &expected, "d");
    }
    let missing = "a".repeat(254);
    assert!(matching(backend, "", Some(&missing)).await.is_empty());
}
