//! Directory listings, the times they report, and the requests they make.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::fixture::{TestBucket, put};
use super::proxy::Fault;
use super::share::{
    Listed, Rig, Smb, backend, builder, filetime, heads, listing_reply, listings, names,
    open_handle, put_all, put_with, requests,
};
use crate::backend::FILE_ATTRIBUTE_DIRECTORY;
use crate::s3::encode::uri_encode;

fn entry<'a>(listed: &'a [Listed], name: &str) -> &'a Listed {
    listed
        .iter()
        .find(|entry| entry.name == name)
        .unwrap_or_else(|| panic!("{name} is not listed in {:?}", names(listed)))
}

#[tokio::test]
async fn lists_files_and_directories_with_sizes_times_and_attributes() {
    let bucket = TestBucket::new().await;
    put_with(
        &bucket.client,
        "a.txt",
        b"hello",
        &[("mtime", "1700000000"), ("smb-attributes", "22")],
    )
    .await;
    put_with(
        &bucket.client,
        "b.bin",
        &[7; 5000],
        &[("mtime", "1700000100")],
    )
    .await;
    put_with(
        &bucket.client,
        "marked/",
        b"",
        &[("mtime", "1600000000"), ("smb-attributes", "2")],
    )
    .await;
    put(&bucket.client, "implicit/inner.txt", b"x").await;
    let mut smb = Smb::new(backend(&bucket).await).await;
    let root = smb.open_dir("").await.unwrap();
    let listed = smb.list(root.id, "*").await;
    assert_eq!(names(&listed), ["a.txt", "b.bin", "implicit", "marked"]);

    let a = entry(&listed, "a.txt");
    assert_eq!((a.size, a.attributes), (5, 0x22));
    assert_eq!(a.times, [filetime(1_700_000_000, 0); 4]);
    let b = entry(&listed, "b.bin");
    assert_eq!(b.size, 5000);
    assert_eq!(b.times[2], filetime(1_700_000_100, 0));
    let marked = entry(&listed, "marked");
    assert!(marked.is_dir());
    assert_eq!(marked.attributes, FILE_ATTRIBUTE_DIRECTORY | 0x2);
    assert_eq!(marked.times[2], filetime(1_600_000_000, 0));
    let implicit = entry(&listed, "implicit");
    assert_eq!(implicit.attributes, FILE_ATTRIBUTE_DIRECTORY);
    assert_eq!(implicit.size, 0);
    // The listing and an open of the same name agree.
    let opened = smb.open_dir("marked").await.unwrap();
    assert_eq!(opened.times, marked.times);
    let opened = smb.open("a.txt").await.unwrap();
    assert_eq!(opened.times, a.times);
}

#[tokio::test]
async fn a_listing_reads_every_page_of_a_large_directory() {
    let rig = Rig::with(|builder| builder.listing_metadata_max(0)).await;
    let keys: Vec<String> = (0..1150).map(|n| format!("big/file-{n:04}.txt")).collect();
    put_all(rig.store(), keys).await;
    put(rig.store(), "big/sub/inner.txt", b"x").await;
    let mut smb = rig.smb;
    let dir = smb.open_dir("big").await.unwrap();
    let listed = smb.list(dir.id, "*").await;
    assert_eq!(listed.len(), 1151);
    assert!(entry(&listed, "file-1149.txt").size > 0);
    assert!(entry(&listed, "sub").is_dir());
    assert_eq!(
        listings(&rig.proxy),
        2,
        "a page holds at most a thousand keys"
    );
}

#[tokio::test]
async fn a_directory_that_holds_only_its_marker_lists_nothing() {
    let bucket = TestBucket::new().await;
    put_with(&bucket.client, "empty/", b"", &[]).await;
    put_with(&bucket.client, "full/", b"", &[]).await;
    put(&bucket.client, "full/x", b"x").await;
    let mut smb = Smb::new(backend(&bucket).await).await;
    let empty = smb.open_dir("empty").await.unwrap();
    assert!(smb.list(empty.id, "*").await.is_empty());
    let full = smb.open_dir("full").await.unwrap();
    assert_eq!(names(&smb.list(full.id, "*").await), ["x"]);
    let root = smb.open_dir("").await.unwrap();
    assert_eq!(names(&smb.list(root.id, "*").await), ["empty", "full"]);
}

#[tokio::test]
async fn patterns_filter_a_listing_with_the_wildcards_of_the_protocol() {
    let bucket = TestBucket::new().await;
    for name in [
        "a.txt",
        "b.TXT",
        "c.bin",
        "notes",
        "report 1.txt",
        "report 2.doc",
        "x.tar.gz",
    ] {
        put(&bucket.client, name, name).await;
    }
    put(&bucket.client, "dir/inner.txt", b"x").await;
    let mut smb = Smb::new(backend(&bucket).await).await;
    let root = smb.open_dir("").await.unwrap();
    for (pattern, expected) in [
        (
            "*",
            vec![
                "a.txt",
                "b.TXT",
                "c.bin",
                "dir",
                "notes",
                "report 1.txt",
                "report 2.doc",
                "x.tar.gz",
            ],
        ),
        (
            "*.*",
            vec![
                "a.txt",
                "b.TXT",
                "c.bin",
                "dir",
                "notes",
                "report 1.txt",
                "report 2.doc",
                "x.tar.gz",
            ],
        ),
        ("*.txt", vec!["a.txt", "b.TXT", "report 1.txt"]),
        ("report ?.*", vec!["report 1.txt", "report 2.doc"]),
        ("?.txt", vec!["a.txt", "b.TXT"]),
        ("*.gz", vec!["x.tar.gz"]),
        ("d*", vec!["dir"]),
        ("<.txt", vec!["a.txt", "b.TXT", "report 1.txt"]),
        ("nomatch*", vec![]),
    ] {
        assert_eq!(
            names(&smb.list(root.id, pattern).await),
            expected,
            "{pattern}"
        );
    }
}

#[tokio::test]
async fn a_pattern_follows_the_case_rule_of_the_backend() {
    let rig = Rig::with(|builder| builder.case_insensitive(false)).await;
    put(rig.store(), "beta.txt", "b").await;
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    assert_eq!(names(&smb.list(root.id, "beta.*").await), ["beta.txt"]);
    assert!(smb.list(root.id, "BETA.*").await.is_empty());

    let rig = Rig::new().await;
    put(rig.store(), "beta.txt", "b").await;
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    assert_eq!(names(&smb.list(root.id, "BETA.*").await), ["beta.txt"]);
}

#[tokio::test]
async fn a_pattern_without_wildcards_is_resolved_without_listing_the_directory() {
    let mut rig = Rig::with(|builder| builder.case_insensitive(false)).await;
    for name in ["d/a.txt", "d/b.txt", "d/c.txt"] {
        put_with(
            rig.store(),
            name,
            name.as_bytes(),
            &[("mtime", "1700000000")],
        )
        .await;
    }
    let dir = rig.smb.open_dir("d").await.unwrap();
    let (listed_before, heads_before) = (listings(&rig.proxy), heads(&rig.proxy));

    let found = rig.smb.list(dir.id, "b.txt").await;
    assert_eq!(names(&found), ["b.txt"]);
    assert_eq!(found[0].size, 7);
    assert_eq!(found[0].times, [filetime(1_700_000_000, 0); 4]);
    assert!(rig.smb.list(dir.id, "nothing.txt").await.is_empty());
    assert!(rig.smb.list(dir.id, "b.txt ").await.is_empty());
    assert_eq!(
        listings(&rig.proxy),
        listed_before,
        "no directory was listed"
    );
    // The HEADs are those of b.txt, nothing.txt and "b.txt ".
    assert_eq!(heads(&rig.proxy) - heads_before, 3);

    // The same names through a pattern that has a wildcard list the directory.
    assert_eq!(names(&rig.smb.list(dir.id, "b.tx?").await), ["b.txt"]);
    assert_eq!(listings(&rig.proxy), listed_before + 1);
}

#[tokio::test]
async fn a_name_with_the_wrong_case_is_found_through_the_listing_and_reported_as_stored() {
    let rig = Rig::new().await;
    put(rig.store(), "d/Report.TXT", "x").await;
    rig.hide("d/report.txt");
    let mut smb = rig.smb;
    let dir = smb.open_dir("d").await.unwrap();
    let found = smb.list(dir.id, "report.txt").await;
    assert_eq!(names(&found), ["Report.TXT"]);
    assert_eq!(found[0].size, 1);
}

#[tokio::test]
async fn a_name_that_is_not_a_valid_file_name_matches_nothing() {
    let rig = Rig::new().await;
    put(rig.store(), "d/a.txt", "x").await;
    let mut smb = rig.smb;
    let dir = smb.open_dir("d").await.unwrap();
    let before = requests(&rig.proxy);
    for pattern in [".", ".."] {
        assert!(smb.list(dir.id, pattern).await.is_empty(), "{pattern}");
    }
    assert_eq!(requests(&rig.proxy), before);
}

#[tokio::test]
async fn listing_times_come_from_metadata_up_to_the_configured_number_of_entries() {
    let bucket = TestBucket::new().await;
    for (name, secs) in [
        ("a", "1700000001"),
        ("b", "1700000002"),
        ("c", "1700000003"),
    ] {
        put_with(&bucket.client, name, b"x", &[("mtime", secs)]).await;
    }
    for (max, from_metadata) in [(1000, 3), (3, 3), (2, 2), (1, 1), (0, 0)] {
        let rig_backend = builder(&bucket, bucket.gateway.addr)
            .listing_metadata_max(max)
            .build()
            .await
            .unwrap();
        let mut smb = Smb::new(rig_backend).await;
        let root = smb.open_dir("").await.unwrap();
        let listed = smb.list(root.id, "*").await;
        let stored = |name: &str, secs: u64| entry(&listed, name).times[2] == filetime(secs, 0);
        let by_metadata = [
            stored("a", 1_700_000_001),
            stored("b", 1_700_000_002),
            stored("c", 1_700_000_003),
        ];
        // The entries that come first are the ones read.
        for (n, stored) in by_metadata.iter().enumerate() {
            assert_eq!(*stored, n < from_metadata, "max {max}, entry {n}");
        }
        // The others have the time the store modified them, which is no
        // older than the write.
        for (n, name) in ["a", "b", "c"].into_iter().enumerate() {
            if n >= from_metadata {
                assert!(
                    entry(&listed, name).times[2] > filetime(1_700_001_000, 0),
                    "max {max} {name}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_listing_makes_one_request_per_entry_it_reads_and_none_when_told_to_read_none() {
    for (max, expected) in [(0, 0), (2, 2), (1000, 5)] {
        let rig = Rig::with(|builder| builder.listing_metadata_max(max)).await;
        for n in 0..5 {
            put_with(
                rig.store(),
                &format!("f{n}"),
                b"x",
                &[("mtime", "1700000000")],
            )
            .await;
        }
        let mut smb = rig.smb;
        let root = smb.open_dir("").await.unwrap();
        let before = heads(&rig.proxy);
        assert_eq!(smb.list(root.id, "*").await.len(), 5);
        assert_eq!(heads(&rig.proxy) - before, expected, "max {max}");
    }
}

#[tokio::test]
async fn a_listing_reads_the_marker_of_each_subdirectory() {
    let rig = Rig::new().await;
    put_with(rig.store(), "marked/", b"", &[("mtime", "1600000000")]).await;
    put(rig.store(), "implicit/x", b"x").await;
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    let before = heads(&rig.proxy);
    let listed = smb.list(root.id, "*").await;
    assert_eq!(
        entry(&listed, "marked").times[2],
        filetime(1_600_000_000, 0)
    );
    let implicit = entry(&listed, "implicit");
    assert_eq!(implicit.times[2], implicit.times[0]);
    assert_ne!(implicit.times[2], filetime(1_600_000_000, 0));
    assert_eq!(heads(&rig.proxy) - before, 2);

    // What the listing read is known to a second one and to opens.
    let before = requests(&rig.proxy);
    assert_eq!(smb.list(root.id, "*").await.len(), 2);
    assert!(smb.open_dir("marked").await.is_ok());
    assert!(smb.open_dir("implicit").await.is_ok());
    assert_eq!(requests(&rig.proxy), before);
}

#[tokio::test]
async fn a_listing_keeps_at_most_four_times_the_upload_concurrency_requests_in_flight() {
    const FILES: usize = 30;
    let rig = Rig::with(|builder| builder.upload_concurrency(1)).await;
    put_all(
        rig.store(),
        (0..FILES).map(|n| format!("f{n:02}")).collect(),
    )
    .await;
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        |seen| seen.method == "HEAD",
        Fault::Hold(Arc::clone(&gate)),
        usize::MAX,
    );
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    let list = tokio::spawn(async move { smb.list(root.id, "*").await });

    let started = Instant::now();
    let wait_for = |count: usize| {
        let proxy = &rig.proxy;
        async move {
            while heads(proxy) < count {
                assert!(
                    started.elapsed() < Duration::from_secs(30),
                    "stuck at {}",
                    heads(proxy)
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Nothing more starts while the requests wait.
            tokio::time::sleep(Duration::from_millis(50)).await;
            heads(proxy)
        }
    };
    assert_eq!(wait_for(4).await, 4);
    for released in 1..=FILES {
        gate.notify_one();
        let expected = (released + 4).min(FILES);
        assert_eq!(
            wait_for(expected).await,
            expected,
            "after {released} answers"
        );
    }
    assert_eq!(list.await.unwrap().len(), FILES);
}

#[tokio::test]
async fn rows_whose_request_does_not_arrive_in_time_report_the_time_the_store_modified_them() {
    let rig = Rig::with(|builder| builder.request_timeout(Duration::from_secs(2))).await;
    for name in ["fast", "slow"] {
        put_with(rig.store(), name, b"x", &[("mtime", "1700000000")]).await;
    }
    let slow = format!("/{}/slow", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "HEAD" && seen.target == slow,
        Fault::Stall,
        usize::MAX,
    );
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    let started = Instant::now();
    let listed = smb.list(root.id, "*").await;
    let elapsed = started.elapsed();
    assert_eq!(names(&listed), ["fast", "slow"]);
    assert_eq!(entry(&listed, "fast").times[2], filetime(1_700_000_000, 0));
    let slow = entry(&listed, "slow");
    assert!(
        slow.times[2] > filetime(1_700_001_000, 0),
        "{}",
        slow.times[2]
    );
    assert_eq!(slow.times[0], slow.times[2]);
    assert!(elapsed >= Duration::from_millis(1800), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[tokio::test]
async fn a_row_whose_request_fails_reports_the_time_the_store_modified_it() {
    let rig = Rig::new().await;
    put_with(rig.store(), "ok", b"x", &[("mtime", "1700000000")]).await;
    put_with(rig.store(), "denied", b"x", &[("mtime", "1700000000")]).await;
    let target = format!("/{}/denied", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "HEAD" && seen.target == target,
        Fault::Reply(super::proxy::Reply::new(403, "")),
        usize::MAX,
    );
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    let listed = smb.list(root.id, "*").await;
    assert_eq!(entry(&listed, "ok").times[2], filetime(1_700_000_000, 0));
    assert!(entry(&listed, "denied").times[2] > filetime(1_700_001_000, 0));
}

#[tokio::test]
async fn a_cached_description_serves_a_row_with_the_same_etag_at_any_age() {
    let rig = Rig::with(|builder| builder.metadata_ttl(Duration::from_millis(150))).await;
    let store = rig.store().clone();
    put_with(&store, "f.txt", b"one", &[("mtime", "1700000000")]).await;
    let mut smb = rig.smb;
    // An open reads the object's metadata.
    let opened = smb.open("f.txt").await.unwrap();
    assert_eq!(opened.times[2], filetime(1_700_000_000, 0));
    tokio::time::sleep(Duration::from_millis(300)).await;

    let root = smb.open_dir("").await.unwrap();
    let before = heads(&rig.proxy);
    let listed = smb.list(root.id, "*").await;
    assert_eq!(entry(&listed, "f.txt").times[2], filetime(1_700_000_000, 0));
    assert_eq!(
        heads(&rig.proxy),
        before,
        "the description of an object the listing says has not changed is still good"
    );

    // An object with another ETag is read again.
    put_with(&store, "f.txt", b"two!", &[("mtime", "1700000500")]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let listed = smb.list(root.id, "*").await;
    assert_eq!(entry(&listed, "f.txt").times[2], filetime(1_700_000_500, 0));
    assert_eq!(entry(&listed, "f.txt").size, 4);
    assert_eq!(heads(&rig.proxy), before + 1);
}

#[tokio::test]
async fn a_second_listing_within_the_ttl_makes_no_request() {
    let rig = Rig::new().await;
    for name in ["a", "b", "d/c"] {
        put(rig.store(), name, name).await;
    }
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    let first = smb.list(root.id, "*").await;
    let before = requests(&rig.proxy);
    let second = smb.list(root.id, "*").await;
    assert_eq!(names(&first), names(&second));
    assert_eq!(requests(&rig.proxy), before);
    // A different pattern is answered from the same listing.
    assert_eq!(names(&smb.list(root.id, "?").await), ["a", "b", "d"]);
    assert_eq!(requests(&rig.proxy), before);
}

#[tokio::test]
async fn a_listing_after_the_ttl_reads_the_directory_again() {
    let rig = Rig::with(|builder| builder.metadata_ttl(Duration::from_millis(200))).await;
    let store = rig.store().clone();
    put(&store, "a", "a").await;
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    assert_eq!(names(&smb.list(root.id, "*").await), ["a"]);
    put(&store, "b", "b").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(names(&smb.list(root.id, "*").await), ["a", "b"]);
}

#[tokio::test]
async fn a_listing_goes_out_under_one_delimiter_and_prefix() {
    let rig = Rig::with(|builder| builder.prefix("p/q")).await;
    put(rig.store(), "p/q/a", "a").await;
    put(rig.store(), "p/q/s/b", "b").await;
    let mut smb = rig.smb;
    let dir = smb.open_dir("s").await.unwrap();
    smb.list(dir.id, "*").await;
    let seen = rig.proxy.seen();
    let listing = seen
        .iter()
        .rev()
        .find(|seen| seen.has_param("delimiter"))
        .expect("a listing");
    assert!(
        listing.query().contains("delimiter=%2F"),
        "{}",
        listing.query()
    );
    assert!(
        listing
            .query()
            .contains(&format!("prefix={}", uri_encode("p/q/s/", false))),
        "{}",
        listing.query()
    );
    assert!(listing.query().contains("encoding-type=url"));
    assert!(!listing.has_param("max-keys"));
}

#[tokio::test]
async fn is_the_directory_empty_asks_for_two_keys_below_it() {
    let rig = Rig::new().await;
    put_with(rig.store(), "marker-only/", b"", &[]).await;
    put_with(rig.store(), "with-child/", b"", &[]).await;
    put(rig.store(), "with-child/x", b"x").await;
    put(rig.store(), "implicit/y", b"y").await;
    put(rig.store(), "unlistable/z", b"z").await;
    // Whatever is below the directory, a name no client could open included,
    // keeps it from being empty.
    rig.proxy.inject(
        |seen| {
            seen.method == "GET"
                && seen.has_param("max-keys")
                && seen.query().contains("prefix=unlistable%2F")
        },
        Fault::Reply(listing_reply(
            &[("unlistable/", 0), ("unlistable/bad:name", 1)],
            &[],
        )),
        usize::MAX,
    );
    for (path, empty) in [
        ("marker-only", true),
        ("with-child", false),
        ("implicit", false),
        ("unlistable", false),
    ] {
        let handle = open_handle(&rig.backend, path).await;
        let sent = requests(&rig.proxy);
        assert_eq!(handle.dir_is_empty().await.unwrap(), empty, "{path}");
        assert_eq!(requests(&rig.proxy), sent + 1, "{path}");
        let last = rig.proxy.seen().pop().unwrap();
        assert!(last.query().contains("max-keys=2"), "{}", last.query());
        assert!(
            last.query().contains(&format!("prefix={path}%2F")),
            "{}",
            last.query()
        );
        assert!(!last.has_param("delimiter"));
        handle.close().await.unwrap();
    }
}

#[tokio::test]
async fn the_root_is_empty_when_nothing_but_its_marker_is_below_it() {
    let rig = Rig::with(|builder| builder.prefix("p")).await;
    let root = || open_handle(&rig.backend, "");
    assert!(root().await.dir_is_empty().await.unwrap());
    put_with(rig.store(), "p/", b"", &[]).await;
    assert!(root().await.dir_is_empty().await.unwrap());
    put(rig.store(), "p/x", b"x").await;
    assert!(!root().await.dir_is_empty().await.unwrap());
}

#[tokio::test]
async fn a_file_is_not_a_directory_to_ask_about() {
    let rig = Rig::new().await;
    put(rig.store(), "f", b"x").await;
    let file = open_handle(&rig.backend, "f").await;
    assert!(matches!(
        file.dir_is_empty().await,
        Err(crate::SmbError::NotADirectory)
    ));
    assert!(matches!(
        file.list_dir(None).await,
        Err(crate::SmbError::NotADirectory)
    ));
}

#[tokio::test]
async fn a_listing_names_each_entry_once_in_key_order() {
    let rig = Rig::new().await;
    for key in ["z", "a", "m/x", "m/y", "B", "a b", "a-b"] {
        put(rig.store(), key, key).await;
    }
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    let listed = smb.list(root.id, "*").await;
    let in_order: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(in_order, ["B", "a", "a b", "a-b", "m", "z"]);
}

#[tokio::test]
async fn a_listing_that_the_store_refuses_fails_the_query() {
    let rig = Rig::new().await;
    put(rig.store(), "a", "a").await;
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    rig.proxy.inject(
        |seen| seen.method == "GET" && seen.has_param("delimiter"),
        Fault::Reply(super::proxy::Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    assert_eq!(
        smb.try_list(root.id, "*").await.unwrap_err(),
        crate::ntstatus::STATUS_ACCESS_DENIED
    );
}
