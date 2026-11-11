//! Opening and reading files and directories of a bucket through the
//! dispatcher.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ShareBackend as _;

use super::fixture::{MIB, TestBucket, pattern, put};
use super::share::{
    Rig, Smb, Spec, answer_listing, backend, builder, filetime, heads, listing_reply, listings,
    names, put_all, put_with, requests,
};
use crate::backend::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};
use crate::ntstatus::{
    STATUS_END_OF_FILE, STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};
use crate::s3::encode::uri_encode;
use crate::utils::system_time_to_filetime;

fn now() -> u64 {
    system_time_to_filetime(SystemTime::now())
}

async fn serve(bucket: &TestBucket) -> Smb {
    Smb::new(backend(bucket).await).await
}

#[tokio::test]
async fn opens_a_file_with_the_size_times_and_attributes_stored_with_it() {
    let bucket = TestBucket::new().await;
    put_with(
        &bucket.client,
        "docs/readme.txt",
        b"hello world",
        &[
            ("mtime", "1700000000.123456789"),
            ("btime", "1600000000.5"),
            ("atime", "1800000000"),
            ("ctime", "1650000000.000000100"),
            ("smb-attributes", "21"),
        ],
    )
    .await;
    let mut smb = serve(&bucket).await;
    let file = smb.open("docs\\readme.txt").await.unwrap();
    assert_eq!(file.action, 1, "FILE_OPENED");
    assert_eq!(file.size, 11);
    assert_eq!(file.allocation, 4096);
    assert_eq!(file.attributes, 0x21);
    assert_eq!(
        file.times,
        [
            filetime(1_600_000_000, 500_000_000),
            filetime(1_800_000_000, 0),
            filetime(1_700_000_000, 123_456_789),
            filetime(1_650_000_000, 100),
        ]
    );
}

#[tokio::test]
async fn a_file_without_stored_times_has_the_time_the_store_modified_it() {
    let bucket = TestBucket::new().await;
    let before = now();
    put(&bucket.client, "plain.bin", b"abc").await;
    let mut smb = serve(&bucket).await;
    let file = smb.open("plain.bin").await.unwrap();
    let after = now() + 2 * 10_000_000;
    assert_eq!(file.attributes, FILE_ATTRIBUTE_NORMAL);
    assert_eq!(file.times[0], file.times[2]);
    assert_eq!(file.times[1], file.times[2]);
    assert_eq!(file.times[3], file.times[2]);
    // The header has whole seconds.
    let floor = before / 10_000_000 * 10_000_000;
    assert!(
        (floor..=after).contains(&file.times[2]),
        "{} not in {floor}..={after}",
        file.times[2]
    );
}

#[tokio::test]
async fn the_write_time_falls_back_to_the_time_the_source_system_gave() {
    let bucket = TestBucket::new().await;
    put_with(
        &bucket.client,
        "imported.bin",
        b"x",
        &[("src_last_modified_millis", "1500000000250")],
    )
    .await;
    let mut smb = serve(&bucket).await;
    let file = smb.open("imported.bin").await.unwrap();
    assert_eq!(file.times, [filetime(1_500_000_000, 250_000_000); 4]);
}

#[tokio::test]
async fn reads_the_data_of_a_file_in_ranges() {
    let bucket = TestBucket::new().await;
    let data = pattern(3, 5 * MIB / 2 + 17);
    put(&bucket.client, "big/data.bin", &data).await;
    let mut smb = serve(&bucket).await;
    assert_eq!(smb.contents("big\\data.bin", 65_536).await, data.to_vec());

    let file = smb.open("big\\data.bin").await.unwrap();
    assert_eq!(file.size, data.len() as u64);
    let middle = smb.read(file.id, 1000, 5000).await.unwrap();
    assert_eq!(middle, &data[1000..6000]);
    let end = smb
        .read(file.id, data.len() as u64 - 10, 100)
        .await
        .unwrap();
    assert_eq!(end, &data[data.len() - 10..]);
    for offset in [data.len() as u64, data.len() as u64 + 5000] {
        assert_eq!(
            smb.read(file.id, offset, 100).await,
            Err(STATUS_END_OF_FILE),
            "{offset}"
        );
    }
    smb.close(file.id).await;
}

#[tokio::test]
async fn an_empty_file_opens_and_reads_nothing() {
    let bucket = TestBucket::new().await;
    put(&bucket.client, "empty", b"").await;
    let mut smb = serve(&bucket).await;
    let file = smb.open("empty").await.unwrap();
    assert_eq!((file.size, file.allocation), (0, 0));
    assert_eq!(smb.read(file.id, 0, 10).await, Err(STATUS_END_OF_FILE));
    smb.close(file.id).await;
}

#[tokio::test]
async fn opens_a_directory_with_a_marker_object_and_reads_its_stored_times() {
    let bucket = TestBucket::new().await;
    put_with(
        &bucket.client,
        "marked/",
        b"",
        &[
            ("mtime", "1700000000.5"),
            ("btime", "1600000000"),
            ("smb-attributes", "2"),
        ],
    )
    .await;
    let mut smb = serve(&bucket).await;
    let dir = smb.open_dir("marked").await.unwrap();
    assert_eq!(dir.attributes, FILE_ATTRIBUTE_DIRECTORY | 0x2);
    assert_eq!(dir.times[0], filetime(1_600_000_000, 0));
    assert_eq!(dir.times[2], filetime(1_700_000_000, 500_000_000));
    assert_eq!(dir.size, 0);
    // The same name opens with no flag at all.
    let any = smb.create("marked", Spec::ANY).await.unwrap();
    assert_eq!(any.attributes, dir.attributes);
}

#[tokio::test]
async fn implicit_directories_and_the_root_have_the_time_the_backend_was_built() {
    let bucket = TestBucket::new().await;
    put(&bucket.client, "implicit/deep/inner.txt", b"x").await;
    let before = now();
    let mut smb = serve(&bucket).await;
    let after = now();

    for name in ["implicit", "implicit\\deep"] {
        let dir = smb.open_dir(name).await.unwrap();
        assert_eq!(dir.attributes, FILE_ATTRIBUTE_DIRECTORY, "{name}");
        assert_eq!(dir.times[0], dir.times[2], "{name}");
        assert_eq!(dir.times[1], dir.times[2], "{name}");
        assert_eq!(dir.times[3], dir.times[2], "{name}");
        assert!((before..=after).contains(&dir.times[2]), "{name}");
        smb.close(dir.id).await;
    }
    let root = smb.open_dir("").await.unwrap();
    assert_eq!(root.attributes, FILE_ATTRIBUTE_DIRECTORY);
    assert!((before..=after).contains(&root.times[2]));
}

#[tokio::test]
async fn directories_that_only_their_keys_imply_nest() {
    let bucket = TestBucket::new().await;
    put_all(
        &bucket.client,
        ["a/b/c.txt", "a/b/d.txt", "a/e.txt", "f.txt"]
            .map(str::to_owned)
            .to_vec(),
    )
    .await;
    let mut smb = serve(&bucket).await;
    let root = smb.open_dir("").await.unwrap();
    let top = smb.list(root.id, "*").await;
    assert_eq!(names(&top), ["a", "f.txt"]);
    assert!(
        top.iter()
            .any(|e| e.name == "a" && e.attributes == FILE_ATTRIBUTE_DIRECTORY)
    );
    let a = smb.open_dir("a").await.unwrap();
    assert_eq!(names(&smb.list(a.id, "*").await), ["b", "e.txt"]);
    let b = smb.open_dir("a\\b").await.unwrap();
    let inner = smb.list(b.id, "*").await;
    assert_eq!(names(&inner), ["c.txt", "d.txt"]);
    assert_eq!(inner[0].size, "a/b/c.txt".len() as u64);
    assert_eq!(smb.contents("a\\b\\d.txt", 100).await, b"a/b/d.txt");
}

#[tokio::test]
async fn a_name_that_is_missing_is_not_found_and_one_below_a_missing_directory_is_a_missing_path() {
    let bucket = TestBucket::new().await;
    put(&bucket.client, "file.txt", b"x").await;
    put(&bucket.client, "dir/inner.txt", b"x").await;
    put(&bucket.client, "marked/", b"").await;
    let mut smb = serve(&bucket).await;
    for (name, status) in [
        ("nope.txt", STATUS_OBJECT_NAME_NOT_FOUND),
        ("dir\\nope.txt", STATUS_OBJECT_NAME_NOT_FOUND),
        ("marked\\nope.txt", STATUS_OBJECT_NAME_NOT_FOUND),
        ("nodir\\x.txt", STATUS_OBJECT_PATH_NOT_FOUND),
        ("nodir\\deeper\\x.txt", STATUS_OBJECT_PATH_NOT_FOUND),
        ("dir\\nodir\\x.txt", STATUS_OBJECT_PATH_NOT_FOUND),
        ("file.txt\\x", STATUS_OBJECT_PATH_NOT_FOUND),
        ("file.txt\\x\\y", STATUS_OBJECT_PATH_NOT_FOUND),
        ("dir\\inner.txt\\x", STATUS_OBJECT_PATH_NOT_FOUND),
    ] {
        assert_eq!(
            smb.create(name, Spec::ANY).await.unwrap_err(),
            status,
            "{name}"
        );
    }
}

#[tokio::test]
async fn the_flags_of_an_open_tell_files_and_directories_apart() {
    let bucket = TestBucket::new().await;
    put(&bucket.client, "file.txt", b"x").await;
    put(&bucket.client, "implicit/inner.txt", b"x").await;
    put(&bucket.client, "marked/", b"").await;
    let mut smb = serve(&bucket).await;
    assert_eq!(
        smb.create("file.txt", Spec::DIR).await.unwrap_err(),
        STATUS_NOT_A_DIRECTORY
    );
    for dir in ["implicit", "marked", ""] {
        assert_eq!(
            smb.create(dir, Spec::FILE).await.unwrap_err(),
            STATUS_FILE_IS_A_DIRECTORY,
            "{dir:?}"
        );
    }
    assert!(smb.create("file.txt", Spec::ANY).await.is_ok());
}

#[tokio::test]
async fn a_key_over_the_limit_is_an_invalid_name_and_costs_no_request() {
    let mut rig = Rig::new().await;
    let sent = requests(&rig.proxy);
    let path = |names: usize, last: usize| {
        let mut parts = vec!["x".repeat(255); names];
        parts.push("y".repeat(last));
        parts.join("\\")
    };
    // Four names and the separators after them take 1024 bytes.
    assert_eq!(
        rig.smb.create(&path(4, 1), Spec::ANY).await.unwrap_err(),
        STATUS_OBJECT_NAME_INVALID
    );
    assert_eq!(requests(&rig.proxy), sent);

    // A key of exactly 1024 bytes is looked up, but no key below it can exist,
    // so only the key itself is asked for.
    let parts = vec!["z".repeat(204); 5];
    // Paths this long are past what the file system under some gateways takes,
    // so the proxy says there are no such keys.
    for depth in 1..=5 {
        rig.hide(&parts[..depth].join("/"));
    }
    assert_eq!(
        rig.smb
            .create(&parts.join("\\"), Spec::ANY)
            .await
            .unwrap_err(),
        STATUS_OBJECT_PATH_NOT_FOUND
    );
    let key = parts.join("/");
    assert_eq!(key.len(), 1024);
    let seen = rig.proxy.seen();
    assert!(
        seen.iter()
            .any(|s| s.method == "HEAD" && s.target.ends_with(&key)),
        "the key is asked for"
    );
    let below = format!("prefix={}%2F", uri_encode(&key, false));
    assert!(
        !seen.iter().any(|s| s.query().contains(&below)),
        "no listing of the keys below it"
    );

    // One byte less leaves room for the marker `key/`, so the keys below the
    // key are asked for.
    let mut parts = parts;
    parts[4].pop();
    let key = parts.join("/");
    assert_eq!(key.len(), 1023);
    rig.hide(&key);
    assert_eq!(
        rig.smb
            .create(&parts.join("\\"), Spec::ANY)
            .await
            .unwrap_err(),
        STATUS_OBJECT_PATH_NOT_FOUND
    );
    let below = format!("prefix={}%2F", uri_encode(&key, false));
    assert!(
        rig.proxy.seen().iter().any(|s| s.query().contains(&below)),
        "the keys below it are asked for"
    );
}

#[tokio::test]
async fn names_that_need_encoding_list_and_open() {
    let bucket = TestBucket::new().await;
    let files = [
        "a b.txt",
        "plus+sign.txt",
        "percent%20.txt",
        "percent%.txt",
        "tilde~.txt",
        "caf\u{e9}.txt",
        "\u{65e5}\u{672c}\u{8a9e}.txt",
        "hash#.txt",
        "amp&.txt",
        "equals=.txt",
        "semi;.txt",
        "comma,.txt",
        "dollar$.txt",
        "at@.txt",
        "paren(1).txt",
        "quote'.txt",
        "bracket[1].txt",
        "dir with space/inner file.txt",
        "dir+plus/in%ner.txt",
        "d\u{e9}j\u{e0}/vu.txt",
    ];
    put_all(
        &bucket.client,
        files.iter().map(|name| (*name).to_owned()).collect(),
    )
    .await;
    let mut smb = serve(&bucket).await;
    let root = smb.open_dir("").await.unwrap();
    let listed = smb.list(root.id, "*").await;
    assert_eq!(
        names(&listed),
        [
            "a b.txt",
            "amp&.txt",
            "at@.txt",
            "bracket[1].txt",
            "caf\u{e9}.txt",
            "comma,.txt",
            "dir with space",
            "dir+plus",
            "dollar$.txt",
            "d\u{e9}j\u{e0}",
            "equals=.txt",
            "hash#.txt",
            "paren(1).txt",
            "percent%.txt",
            "percent%20.txt",
            "plus+sign.txt",
            "quote'.txt",
            "semi;.txt",
            "tilde~.txt",
            "\u{65e5}\u{672c}\u{8a9e}.txt",
        ]
    );
    for file in files {
        let path = file.replace('/', "\\");
        let data = smb.contents(&path, 64).await;
        assert_eq!(data, file.as_bytes(), "{file}");
    }
}

#[tokio::test]
async fn a_prefix_makes_its_keys_the_share() {
    let bucket = TestBucket::new().await;
    for key in [
        "photos/2024/a.jpg",
        "photos/b.jpg",
        "other/c.jpg",
        "photosextra/d.jpg",
        "x.txt",
    ] {
        put(&bucket.client, key, key).await;
    }
    put_with(&bucket.client, "photos/marked/", b"", &[]).await;
    for prefix in ["photos", "/photos/", "photos//"] {
        let backend = builder(&bucket, bucket.gateway.addr)
            .prefix(prefix)
            .build()
            .await
            .unwrap();
        let mut smb = Smb::new(backend).await;
        let root = smb.open_dir("").await.unwrap();
        assert_eq!(
            names(&smb.list(root.id, "*").await),
            ["2024", "b.jpg", "marked"],
            "{prefix}"
        );
        assert_eq!(smb.contents("2024\\a.jpg", 100).await, b"photos/2024/a.jpg");
        assert_eq!(smb.contents("b.jpg", 100).await, b"photos/b.jpg");
        for (name, status) in [
            ("x.txt", STATUS_OBJECT_NAME_NOT_FOUND),
            ("other", STATUS_OBJECT_NAME_NOT_FOUND),
            ("other\\c.jpg", STATUS_OBJECT_PATH_NOT_FOUND),
            ("photos", STATUS_OBJECT_NAME_NOT_FOUND),
            ("photosextra", STATUS_OBJECT_NAME_NOT_FOUND),
        ] {
            assert_eq!(
                smb.create(name, Spec::ANY).await.unwrap_err(),
                status,
                "{prefix} {name}"
            );
        }
    }
}

#[tokio::test]
async fn a_prefix_can_name_a_nested_directory_and_need_not_exist() {
    let bucket = TestBucket::new().await;
    put(&bucket.client, "a/b/c.txt", b"deep").await;
    let nested = builder(&bucket, bucket.gateway.addr)
        .prefix("a/b")
        .build()
        .await
        .unwrap();
    let mut smb = Smb::new(nested).await;
    assert_eq!(smb.contents("c.txt", 10).await, b"deep");

    let empty = builder(&bucket, bucket.gateway.addr)
        .prefix("nothing/here")
        .build()
        .await
        .unwrap();
    let mut smb = Smb::new(empty).await;
    let root = smb.open_dir("").await.unwrap();
    assert!(smb.list(root.id, "*").await.is_empty());
    assert_eq!(
        smb.open("c.txt").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn keys_no_client_could_open_are_left_out_of_listings() {
    let rig = Rig::new().await;
    for key in ["ok.txt", "dir/ok.txt", "only-bad/placeholder"] {
        put(rig.store(), key, key).await;
    }
    let long = "x".repeat(256);
    answer_listing(
        &rig.proxy,
        "",
        listing_reply(
            &[
                ("ok.txt", 6),
                ("bad:name.txt", 1),
                ("star*.txt", 1),
                ("tab\tname", 1),
                ("back\\slash", 1),
                (".", 1),
                ("..", 1),
                (&long, 1),
            ],
            &["dir/", "only-bad/", "/", "a:b/", "wild?/", "pipe|/"],
        ),
    );
    answer_listing(
        &rig.proxy,
        "dir/",
        listing_reply(
            &[
                ("dir/ok.txt", 6),
                ("dir/bad:name.txt", 1),
                ("dir/pipe|.txt", 1),
                ("dir//x", 1),
                ("dir/", 0),
            ],
            &["dir//", "dir/a:b/"],
        ),
    );
    answer_listing(
        &rig.proxy,
        "only-bad/",
        listing_reply(
            &[("only-bad/bad:name", 1), ("only-bad//x", 1)],
            &["only-bad/a//"],
        ),
    );
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    assert_eq!(
        names(&smb.list(root.id, "*").await),
        ["dir", "ok.txt", "only-bad"]
    );
    let dir = smb.open_dir("dir").await.unwrap();
    assert_eq!(names(&smb.list(dir.id, "*").await), ["ok.txt"]);
    let only_bad = smb.open_dir("only-bad").await.unwrap();
    assert!(smb.list(only_bad.id, "*").await.is_empty());
    // The server refuses these names before the backend sees them, and a
    // path with an empty component never becomes one.
    for name in [
        "bad:name.txt",
        "star*.txt",
        "dir\\bad:name.txt",
        "dir\\pipe|.txt",
        "dir\\\\x",
    ] {
        assert!(smb.create(name, Spec::ANY).await.is_err(), "{name}");
    }
}

#[tokio::test]
async fn keys_outside_the_prefix_are_left_out_of_listings() {
    let rig = Rig::with(|builder| builder.prefix("data")).await;
    put(rig.store(), "data/ok.txt", "ok").await;
    put(rig.store(), "data/dir/inner.txt", "inner").await;
    put(rig.store(), "other/x", "x").await;
    answer_listing(
        &rig.proxy,
        "data/",
        listing_reply(
            &[
                ("data/ok.txt", 2),
                ("other/x", 1),
                ("datax/y", 1),
                ("data", 1),
                ("data/", 0),
                ("data//z", 1),
            ],
            &["data/dir/", "elsewhere/", "datax/", "data//"],
        ),
    );
    let mut smb = rig.smb;
    let root = smb.open_dir("").await.unwrap();
    assert_eq!(names(&smb.list(root.id, "*").await), ["dir", "ok.txt"]);
    for name in ["other", "other\\x", "datax", "data", "elsewhere"] {
        assert!(smb.create(name, Spec::ANY).await.is_err(), "{name}");
    }
}

#[tokio::test]
async fn names_open_with_any_case_and_list_as_stored() {
    let rig = Rig::new().await;
    for key in ["Docs/Sub Dir/Report.TXT", "Docs/readme.md", "Top.bin"] {
        put(rig.store(), key, key).await;
    }
    // A store that tells names apart by case has no key with these
    // spellings.
    for key in [
        "docs/sub dir/report.txt",
        "docs/sub dir",
        "DOCS/SUB DIR/REPORT.TXT",
        "DOCS/SUB DIR",
        "DOCS/sub dir",
        "docs/sub dir/other.txt",
        "docs/nope/report.txt",
        "docs",
        "DOCS",
        "docs/README.md",
        "top.BIN",
    ] {
        rig.hide(key);
    }
    let mut smb = rig.smb;
    for (given, stored) in [
        ("docs\\sub dir\\report.txt", "Docs/Sub Dir/Report.TXT"),
        ("DOCS\\SUB DIR\\REPORT.TXT", "Docs/Sub Dir/Report.TXT"),
        ("Docs\\Sub Dir\\Report.TXT", "Docs/Sub Dir/Report.TXT"),
        ("docs\\README.md", "Docs/readme.md"),
        ("top.BIN", "Top.bin"),
    ] {
        assert_eq!(smb.contents(given, 100).await, stored.as_bytes(), "{given}");
    }
    let dir = smb.open_dir("DOCS\\sub dir").await.unwrap();
    assert_eq!(names(&smb.list(dir.id, "*").await), ["Report.TXT"]);
    let docs = smb.open_dir("docs").await.unwrap();
    assert_eq!(
        names(&smb.list(docs.id, "*").await),
        ["Sub Dir", "readme.md"]
    );
    // A name with no spelling at all is still missing.
    assert_eq!(
        smb.open("docs\\sub dir\\other.txt").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        smb.open("docs\\nope\\report.txt").await.unwrap_err(),
        STATUS_OBJECT_PATH_NOT_FOUND
    );
}

#[tokio::test]
async fn a_directory_over_the_row_limit_is_listed_once_for_all_its_lookups() {
    let mut rig = Rig::new().await;
    rig.backend.limit_listing_rows(3);
    let keys: Vec<String> = (1..=5).map(|n| format!("big/file{n}.txt")).collect();
    put_all(rig.store(), keys).await;
    let all = [
        "file1.txt",
        "file2.txt",
        "file3.txt",
        "file4.txt",
        "file5.txt",
    ];
    let dir = rig.smb.open_dir("big").await.unwrap();
    assert_eq!(names(&rig.smb.list(dir.id, "*").await), all);
    assert_eq!(listings(&rig.proxy), 1);

    assert_eq!(
        rig.smb.open("big\\NOPE.TXT").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    let file = rig.smb.open("big\\FILE3.TXT").await.unwrap();
    assert_eq!(file.size, "big/file3.txt".len() as u64);
    assert_eq!(names(&rig.smb.list(dir.id, "*").await), all);
    assert_eq!(listings(&rig.proxy), 1, "the listing was kept whole");
}

#[tokio::test]
async fn a_directory_read_from_a_listing_is_not_looked_up_again_while_it_is_fresh() {
    let mut rig = Rig::new().await;
    put(rig.store(), "Docs/x.txt", "x").await;
    rig.hide("docs");
    rig.smb.open_dir("docs").await.unwrap();
    let sent = heads(&rig.proxy);
    rig.smb.open_dir("docs").await.unwrap();
    assert_eq!(heads(&rig.proxy), sent);
}

#[tokio::test]
async fn names_are_exact_keys_when_the_backend_is_case_sensitive() {
    let rig = Rig::with(|builder| builder.case_insensitive(false)).await;
    for key in ["Docs/Report.TXT", "Top.bin"] {
        put(rig.store(), key, key).await;
    }
    for key in ["docs/Report.TXT", "Docs/report.txt", "docs", "top.bin"] {
        rig.hide(key);
    }
    let mut smb = rig.smb;
    assert_eq!(
        smb.contents("Docs\\Report.TXT", 100).await,
        b"Docs/Report.TXT"
    );
    assert_eq!(smb.contents("Top.bin", 100).await, b"Top.bin");
    for (name, status) in [
        ("docs\\Report.TXT", STATUS_OBJECT_PATH_NOT_FOUND),
        ("Docs\\report.txt", STATUS_OBJECT_NAME_NOT_FOUND),
        ("top.bin", STATUS_OBJECT_NAME_NOT_FOUND),
    ] {
        assert_eq!(
            smb.create(name, Spec::ANY).await.unwrap_err(),
            status,
            "{name}"
        );
    }
    assert!(rig.backend.capabilities().case_sensitive);
    assert_eq!(listings(&rig.proxy), 0, "every name is a key");
}

#[tokio::test]
async fn times_before_1970_and_after_2106_convert() {
    let bucket = TestBucket::new().await;
    put_with(&bucket.client, "old", b"", &[("mtime", "-86400.5")]).await;
    put_with(&bucket.client, "far", b"", &[("mtime", "5000000000")]).await;
    let mut smb = serve(&bucket).await;
    let old = smb.open("old").await.unwrap();
    assert_eq!(
        old.times[2],
        system_time_to_filetime(UNIX_EPOCH - Duration::new(86_400, 500_000_000))
    );
    let far = smb.open("far").await.unwrap();
    assert_eq!(far.times[2], filetime(5_000_000_000, 0));
}
