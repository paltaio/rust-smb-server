//! Directory listings, their patterns, and `dir_is_empty`.

use super::helpers::{Backend, listed, matching, mkdir, names, open_dir, put, size};
use crate::tests::data::nonzero_pattern;
use crate::tests::util::path;

pub(super) async fn listings_report_every_entry(backend: Backend<'_>) {
    put(backend, "a.txt", b"abc").await;
    put(backend, "big.bin", &nonzero_pattern(200_000)).await;
    mkdir(backend, "sub").await;
    put(backend, "sub\\inner", b"x").await;

    let root = open_dir(backend, "").await;
    let sized = root.list_dir_sized(None, false).await.unwrap();
    for entries in [root.list_dir(None).await.unwrap(), sized] {
        let mut seen: Vec<_> = entries
            .iter()
            .map(|entry| (entry.info.name.as_str(), entry.info.is_directory))
            .collect();
        seen.sort_unstable();
        assert_eq!(
            seen,
            [("a.txt", false), ("big.bin", false), ("sub", true)],
            "names and kinds"
        );
        assert_eq!(size(&entries, "a.txt"), Some(3));
        assert_eq!(size(&entries, "big.bin"), Some(200_000));
    }
    root.close().await.unwrap();
    assert_eq!(names(backend, "sub").await, ["inner"]);
}

pub(super) async fn listing_an_empty_directory_gives_nothing(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    assert!(names(backend, "d").await.is_empty());
    assert!(matching(backend, "d", Some("*")).await.is_empty());
}

pub(super) async fn a_listing_holds_many_entries(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    let mut expected = Vec::new();
    for n in 0..150_u32 {
        let name = if n.is_multiple_of(5) {
            format!("{}{n:03}", "L".repeat(150))
        } else {
            format!("f{n:03}")
        };
        put(backend, &format!("d\\{name}"), name.as_bytes()).await;
        expected.push(name);
    }
    expected.sort();
    assert_eq!(names(backend, "d").await, expected);
}

pub(super) async fn star_lists_every_entry(backend: Backend<'_>) {
    put(backend, "a.txt", b"").await;
    put(backend, "README", b"").await;
    mkdir(backend, "sub").await;
    assert_eq!(
        matching(backend, "", Some("*")).await,
        ["README", "a.txt", "sub"]
    );
}

pub(super) async fn wildcards_pick_the_names_they_match(backend: Backend<'_>) {
    for name in ["a.txt", "ab.txt", "b.txt", "c.log", "README"] {
        put(backend, name, b"").await;
    }
    mkdir(backend, "sub").await;
    let root = open_dir(backend, "").await;
    let cases: [(&str, &[&str]); 11] = [
        ("*.txt", &["a.txt", "ab.txt", "b.txt"]),
        ("a*", &["a.txt", "ab.txt"]),
        ("?.txt", &["a.txt", "b.txt"]),
        ("??.txt", &["ab.txt"]),
        ("*.log", &["c.log"]),
        ("s?b", &["sub"]),
        ("*b", &["sub"]),
        ("zz*", &[]),
        ("?", &[]),
        ("<.txt", &["a.txt", "ab.txt", "b.txt"]),
        ("a>.txt", &["a.txt", "ab.txt"]),
    ];
    for (pattern, expected) in cases {
        assert_eq!(listed(&*root, Some(pattern)).await, expected, "{pattern}");
    }
    root.close().await.unwrap();
}

pub(super) async fn a_literal_pattern_picks_one_name(backend: Backend<'_>) {
    let odd = [
        "a.txt",
        "ab.txt",
        ".hidden",
        "a.b.c",
        "no_extension",
        "[ab].txt",
        "plus+one.txt",
        "two words.txt",
        "x=1;y,z.txt",
        "(paren)$.txt",
        "tilde~.txt",
    ];
    for name in odd {
        put(backend, name, name.as_bytes()).await;
    }
    mkdir(backend, "sub").await;
    put(backend, "sub\\a.txt", b"inner").await;

    let root = open_dir(backend, "").await;
    for name in odd {
        assert_eq!(listed(&*root, Some(name)).await, [name], "literal {name}");
    }
    assert_eq!(listed(&*root, Some("sub")).await, ["sub"]);
    for name in ["a.tx", "a.txt.", ".txt", "nope.txt", "sub\u{e9}"] {
        assert!(
            listed(&*root, Some(name)).await.is_empty(),
            "literal {name} matches nothing"
        );
    }
    root.close().await.unwrap();

    let entries = {
        let sub = open_dir(backend, "sub").await;
        let entries = sub.list_dir(Some("a.txt")).await.unwrap();
        sub.close().await.unwrap();
        entries
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].info.name, "a.txt");
    assert_eq!(entries[0].info.end_of_file, 5);
}

pub(super) async fn listings_follow_creates_renames_and_unlinks(backend: Backend<'_>) {
    let root = open_dir(backend, "").await;
    assert!(listed(&*root, None).await.is_empty());
    put(backend, "a", b"1").await;
    assert_eq!(listed(&*root, None).await, ["a"]);
    put(backend, "b", b"2").await;
    assert_eq!(listed(&*root, None).await, ["a", "b"]);
    backend.rename(&path("a"), &path("c"), false).await.unwrap();
    assert_eq!(listed(&*root, None).await, ["b", "c"]);
    backend.unlink(&path("b")).await.unwrap();
    assert_eq!(listed(&*root, None).await, ["c"]);
    mkdir(backend, "d").await;
    assert_eq!(listed(&*root, None).await, ["c", "d"]);
    backend
        .rename(&path("c"), &path("d\\c"), false)
        .await
        .unwrap();
    assert_eq!(listed(&*root, None).await, ["d"]);
    assert_eq!(names(backend, "d").await, ["c"]);
    root.close().await.unwrap();
}

pub(super) async fn dir_is_empty_follows_the_entries(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    let dir = open_dir(backend, "d").await;
    assert!(dir.dir_is_empty().await.unwrap());

    put(backend, "d\\f", b"data").await;
    assert!(!dir.dir_is_empty().await.unwrap());
    backend.unlink(&path("d\\f")).await.unwrap();
    assert!(dir.dir_is_empty().await.unwrap());

    mkdir(backend, "d\\sub").await;
    assert!(!dir.dir_is_empty().await.unwrap());
    let sub = open_dir(backend, "d\\sub").await;
    assert!(sub.dir_is_empty().await.unwrap());
    put(backend, "d\\sub\\f", b"data").await;
    assert!(!sub.dir_is_empty().await.unwrap());
    backend.unlink(&path("d\\sub\\f")).await.unwrap();
    backend.unlink(&path("d\\sub")).await.unwrap();
    assert!(dir.dir_is_empty().await.unwrap());
    sub.close().await.unwrap();
    dir.close().await.unwrap();
}
