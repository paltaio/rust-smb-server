//! What a read-only backend refuses, what a read asks the store for, and how
//! the backend is built.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Notify;

use super::fixture::{MIB, OLD, TestBucket, foreground, pattern, put};
use super::gateway::REGION;
use super::proxy::{Fault, Proxy, Reply};
use super::share::{
    DELETE, FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF,
    READ, Rig, Spec, WRITE, WRITE_ATTRIBUTES, builder, filetime, heads, listings, names,
    open_handle, put_with, reads, requests,
};
use crate::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_FILE_IS_A_DIRECTORY, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_UNEXPECTED_IO_ERROR,
};
use crate::s3::error::S3Error;
use crate::{
    FileTimes, OpenIntent, OpenOptions, S3Backend, ShareBackend, SmbError, SmbPath, VolumeInfo,
};

fn path(text: &str) -> SmbPath {
    text.parse().unwrap()
}

/// Requests that could change the bucket.
fn changes(rig: &Rig) -> usize {
    rig.proxy
        .count(|seen| !matches!(seen.method.as_str(), "GET" | "HEAD"))
}

#[tokio::test]
async fn every_open_that_would_change_something_is_refused() {
    let mut rig = Rig::new().await;
    put(rig.store(), "file.txt", b"data").await;
    put_with(rig.store(), "dir/", b"", &[]).await;
    put(rig.store(), "dir/inner", b"x").await;
    let write_flags = [WRITE, WRITE_ATTRIBUTES, WRITE | WRITE_ATTRIBUTES];
    for name in [
        "file.txt",
        "dir",
        "missing.txt",
        "nodir\\missing.txt",
        "dir\\new.txt",
    ] {
        for disposition in [FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF] {
            let spec = Spec::ANY.disposition(disposition);
            let status = rig.smb.create(name, spec).await.unwrap_err();
            // The server asks whether a file exists before it truncates it,
            // and a name that is missing is not found.
            let expected = match (disposition, name) {
                (FILE_OVERWRITE, "missing.txt" | "dir\\new.txt") => STATUS_OBJECT_NAME_NOT_FOUND,
                (FILE_OVERWRITE, "nodir\\missing.txt") => STATUS_OBJECT_PATH_NOT_FOUND,
                _ => STATUS_ACCESS_DENIED,
            };
            assert_eq!(status, expected, "{name} disposition {disposition}");
        }
        for access in write_flags {
            let spec = Spec::ANY.access(READ | access);
            let status = rig.smb.create(name, spec).await.unwrap_err();
            assert_eq!(status, STATUS_ACCESS_DENIED, "{name} access {access:#x}");
        }
        let delete = Spec::ANY
            .access(READ | DELETE)
            .options(FILE_DELETE_ON_CLOSE);
        assert_eq!(
            rig.smb.create(name, delete).await.unwrap_err(),
            STATUS_ACCESS_DENIED,
            "{name} delete on close"
        );
    }
    for name in ["newdir", "dir\\newdir", "file.txt", "dir"] {
        let make = Spec::DIR.disposition(FILE_CREATE);
        assert_eq!(
            rig.smb.create(name, make).await.unwrap_err(),
            STATUS_ACCESS_DENIED,
            "{name}"
        );
        let open_or_make = Spec::DIR.disposition(FILE_OPEN_IF);
        assert_eq!(
            rig.smb.create(name, open_or_make).await.unwrap_err(),
            STATUS_ACCESS_DENIED,
            "{name}"
        );
    }
    assert_eq!(changes(&rig), 0);
}

#[tokio::test]
async fn the_backend_refuses_each_kind_of_change_directly() {
    let rig = Rig::new().await;
    put(rig.store(), "file.txt", b"data").await;
    put(rig.store(), "dir/inner", b"x").await;
    let backend = &rig.backend;
    let sent = requests(&rig.proxy);
    let intents = [
        OpenIntent::Create,
        OpenIntent::OpenOrCreate,
        OpenIntent::OverwriteOrCreate,
        OpenIntent::Truncate,
    ];
    for intent in intents {
        for name in ["file.txt", "dir", "none"] {
            let opts = OpenOptions {
                intent,
                ..OpenOptions::default()
            };
            assert!(
                matches!(
                    backend.open(&path(name), opts).await,
                    Err(SmbError::AccessDenied)
                ),
                "{name} {intent:?}"
            );
        }
    }
    for opts in [
        OpenOptions {
            write: true,
            ..OpenOptions::default()
        },
        OpenOptions {
            write_attributes: true,
            ..OpenOptions::default()
        },
        OpenOptions {
            delete_on_close: true,
            ..OpenOptions::default()
        },
    ] {
        assert!(matches!(
            backend.open(&path("file.txt"), opts).await,
            Err(SmbError::AccessDenied)
        ));
    }
    assert!(matches!(
        backend.unlink(&path("file.txt")).await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        backend.unlink(&path("dir")).await,
        Err(SmbError::AccessDenied)
    ));
    assert!(matches!(
        backend.unlink(&SmbPath::root()).await,
        Err(SmbError::AccessDenied)
    ));
    for replace in [false, true] {
        assert!(matches!(
            backend
                .rename(&path("file.txt"), &path("other.txt"), replace)
                .await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            backend
                .rename(&path("dir"), &path("elsewhere"), replace)
                .await,
            Err(SmbError::AccessDenied)
        ));
    }

    assert_eq!(
        requests(&rig.proxy),
        sent,
        "a refused call asks the store nothing"
    );

    let file = open_handle(backend, "file.txt").await;
    let dir = open_handle(backend, "dir").await;
    let sent = requests(&rig.proxy);
    for handle in [&file, &dir] {
        assert!(matches!(
            handle.write(0, b"x").await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            handle.write_owned(0, vec![1, 2, 3]).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            handle.truncate(0).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            handle.truncate(100).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            handle.set_times(FileTimes::all(SystemTime::now())).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            handle.set_attributes(0x1).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            handle.set_attributes(0).await,
            Err(SmbError::AccessDenied)
        ));
    }
    assert_eq!(requests(&rig.proxy), sent);
    assert_eq!(changes(&rig), 0);
}

#[tokio::test]
async fn a_rename_or_a_delete_through_the_server_changes_nothing() {
    let mut rig = Rig::new().await;
    put(rig.store(), "file.txt", b"data").await;
    put(rig.store(), "dir/inner", b"x").await;
    for name in ["file.txt", "dir"] {
        let open = Spec::ANY.access(READ | DELETE);
        let target = rig.smb.create(name, open).await.unwrap();
        assert_eq!(
            rig.smb.rename(target.id, "renamed").await,
            STATUS_ACCESS_DENIED,
            "{name}"
        );
        rig.smb.close(target.id).await;
    }
    // Marking an open for deletion makes the server delete at the last close,
    // which the backend refuses.
    let target = rig
        .smb
        .create("file.txt", Spec::FILE.access(READ | DELETE))
        .await
        .unwrap();
    let _ = rig.smb.set_delete(target.id).await;
    rig.smb.close(target.id).await;
    let other = rig
        .smb
        .create("dir", Spec::DIR.access(READ | DELETE))
        .await
        .unwrap();
    let _ = rig.smb.set_delete(other.id).await;
    rig.smb.close(other.id).await;

    assert_eq!(rig.smb.contents("file.txt", 100).await, b"data");
    assert_eq!(rig.smb.contents("dir\\inner", 100).await, b"x");
    assert_eq!(
        rig.smb.open("renamed").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(changes(&rig), 0);
}

#[tokio::test]
async fn the_handle_of_a_file_and_of_a_directory_answer_what_they_are() {
    let rig = Rig::new().await;
    put(rig.store(), "file.txt", b"data").await;
    put(rig.store(), "dir/inner", b"x").await;
    let file = open_handle(&rig.backend, "file.txt").await;
    let dir = open_handle(&rig.backend, "dir").await;
    assert!(file.as_any().is_some());
    assert!(dir.as_any().is_some());
    file.flush().await.unwrap();
    dir.flush().await.unwrap();
    assert!(matches!(dir.read(0, 10).await, Err(SmbError::IsDirectory)));

    let info = file.stat().await.unwrap();
    assert_eq!(info.name, "file.txt");
    assert_eq!((info.end_of_file, info.allocation_size), (4, 4096));
    assert!(!info.is_directory && !info.read_only);
    let info = dir.stat().await.unwrap();
    assert_eq!(info.name, "dir");
    assert!(info.is_directory);
    assert_eq!((info.end_of_file, info.allocation_size), (0, 0));
    file.close().await.unwrap();
    dir.close().await.unwrap();
}

#[tokio::test]
async fn stat_makes_no_request_and_a_close_makes_none_either() {
    let rig = Rig::new().await;
    put(rig.store(), "file.txt", b"data").await;
    let file = open_handle(&rig.backend, "file.txt").await;
    let sent = requests(&rig.proxy);
    for _ in 0..3 {
        file.stat().await.unwrap();
    }
    file.close().await.unwrap();
    assert_eq!(requests(&rig.proxy), sent);
}

#[tokio::test]
async fn capabilities_and_the_volume_describe_a_read_only_share() {
    let rig = Rig::new().await;
    let caps = rig.backend.capabilities();
    assert!(caps.is_read_only);
    assert!(!caps.case_sensitive);
    assert!(!caps.named_streams && !caps.extended_attributes && !caps.block_cloning);
    assert_eq!(
        rig.backend.volume_info().await.unwrap(),
        VolumeInfo::default()
    );

    let sensitive = Rig::with(|builder| builder.case_insensitive(false)).await;
    let caps = sensitive.backend.capabilities();
    assert!(caps.is_read_only && caps.case_sensitive);
}

#[tokio::test]
async fn a_read_asks_for_exactly_the_range_with_the_etag_of_the_open() {
    let mut rig = Rig::new().await;
    let data = pattern(0, 3 * MIB + 5);
    let etag = put(rig.store(), "data.bin", &data).await;
    let file = rig.smb.open("data.bin").await.unwrap();
    let size = data.len() as u64;
    let cases = [
        (0, 10, (0, 9)),
        (100, 65_536, (100, 65_635)),
        (1 << 20, 65_536, (1 << 20, (1 << 20) + 65_535)),
        (size - 5, 1000, (size - 5, size - 1)),
        (size - 1, 1, (size - 1, size - 1)),
    ];
    for (n, &(offset, len, wanted)) in cases.iter().enumerate() {
        let got = rig.smb.read(file.id, offset, len).await.unwrap();
        assert_eq!(got, &data[wanted.0 as usize..=wanted.1 as usize]);
        let last = rig.proxy.seen().pop().unwrap();
        assert_eq!(
            last.header("range"),
            Some(format!("bytes={}-{}", wanted.0, wanted.1).as_str())
        );
        assert_eq!(last.header("if-match"), Some(etag.as_str()));
        assert_eq!(reads(&rig.proxy), n + 1, "one request per read");
    }
    // Past the end nothing is asked for.
    assert!(rig.smb.read(file.id, size, 10).await.is_err());
    assert!(rig.smb.read(file.id, size + 1, 10).await.is_err());
    assert_eq!(reads(&rig.proxy), cases.len());
}

#[tokio::test]
async fn a_read_of_an_object_that_changed_fails_and_the_next_open_sees_the_new_one() {
    let mut rig = Rig::new().await;
    put(rig.store(), "f.txt", b"first version").await;
    let file = rig.smb.open("f.txt").await.unwrap();
    assert_eq!(
        rig.smb.read(file.id, 0, 100).await.unwrap(),
        b"first version"
    );
    put(rig.store(), "f.txt", b"second, longer version").await;
    assert_eq!(
        rig.smb.read(file.id, 0, 100).await.unwrap_err(),
        STATUS_UNEXPECTED_IO_ERROR
    );
    // Within the ttl, but what the failure showed is not trusted any more.
    let again = rig.smb.open("f.txt").await.unwrap();
    assert_eq!(again.size, 22);
    assert_eq!(
        rig.smb.read(again.id, 0, 100).await.unwrap(),
        b"second, longer version"
    );
}

#[tokio::test]
async fn a_read_of_an_object_that_is_gone_fails() {
    let mut rig = Rig::new().await;
    put(rig.store(), "f.txt", b"data").await;
    let file = rig.smb.open("f.txt").await.unwrap();
    rig.store()
        .delete_object("f.txt", foreground())
        .await
        .unwrap();
    assert_eq!(
        rig.smb.read(file.id, 0, 100).await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        rig.smb.open("f.txt").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

/// Makes the proxy answer for the object `key`, `abc`, as a store that sends
/// no ETag does. `modified` and `total` are the `Last-Modified` and the
/// `Content-Range` length of ranged reads, and `etag` the `ETag` they carry, if
/// any.
fn bare_object(rig: &Rig, key: &str, modified: &str, total: u64, etag: Option<&str>) {
    let target = format!("/{}/{key}", rig.bucket.name);
    let head = target.clone();
    rig.proxy.inject(
        move |seen| seen.method == "HEAD" && seen.target == head,
        Fault::Reply(
            Reply::new(200, "")
                .declaring(3)
                .header("Last-Modified", OLD)
                .header("X-Amz-Meta-Mtime", "1700000000"),
        ),
        usize::MAX,
    );
    let mut read = Reply::new(206, "abc")
        .header("Last-Modified", modified)
        .header("Content-Range", &format!("bytes 0-2/{total}"));
    if let Some(etag) = etag {
        read = read.header("ETag", etag);
    }
    rig.proxy.inject(
        move |seen| seen.method == "GET" && seen.target == target && seen.header("range").is_some(),
        Fault::Reply(read),
        usize::MAX,
    );
}

#[tokio::test]
async fn an_object_without_an_etag_is_read_without_if_match() {
    let mut rig = Rig::new().await;
    bare_object(&rig, "bare", OLD, 3, None);
    let file = rig.smb.open("bare").await.unwrap();
    assert_eq!(file.size, 3);
    assert_eq!(file.times[2], filetime(1_700_000_000, 0));
    assert_eq!(rig.smb.read(file.id, 0, 10).await.unwrap(), b"abc");
    let read = rig.proxy.seen().pop().unwrap();
    assert_eq!(read.header("range"), Some("bytes=0-2"));
    assert_eq!(read.header("if-match"), None, "there is no ETag to match");
}

#[tokio::test]
async fn an_object_without_an_etag_that_changes_size_or_time_or_gets_one_is_not_read() {
    for (modified, total, etag) in [
        ("Fri, 25 May 2013 00:00:00 GMT", 3, None),
        (OLD, 4, None),
        (OLD, 3, Some("\"abc\"")),
    ] {
        let mut rig = Rig::new().await;
        // The open sees one object and the read another.
        bare_object(&rig, "bare", OLD, 3, None);
        let file = rig.smb.open("bare").await.unwrap();
        rig.proxy.clear_rules();
        bare_object(&rig, "bare", modified, total, etag);
        assert_eq!(
            rig.smb.read(file.id, 0, 10).await.unwrap_err(),
            STATUS_UNEXPECTED_IO_ERROR,
            "{modified} {total} {etag:?}"
        );
    }
}

#[tokio::test]
async fn the_bucket_check_is_one_listing_of_the_prefix_for_one_key() {
    let bucket = TestBucket::new().await;
    let proxy = Proxy::start(bucket.gateway.addr).await;
    for (prefix, wanted) in [("", None), ("a/b", Some("a%2Fb%2F")), ("/x/", Some("x%2F"))] {
        let before = proxy.seen().len();
        builder(&bucket, proxy.addr)
            .prefix(prefix)
            .build()
            .await
            .unwrap();
        let seen = proxy.seen();
        assert_eq!(seen.len(), before + 1, "{prefix:?}");
        let check = &seen[before];
        assert_eq!(check.method, "GET");
        assert!(check.has_param("list-type") && check.has_param("max-keys"));
        assert!(check.query().contains("max-keys=1"), "{}", check.query());
        assert!(!check.has_param("delimiter"));
        match wanted {
            Some(wanted) => assert!(
                check.query().contains(&format!("prefix={wanted}")),
                "{}",
                check.query()
            ),
            None => assert!(!check.has_param("prefix")),
        }
    }
}

#[tokio::test]
async fn a_missing_bucket_fails_the_build_with_the_store_answer() {
    let bucket = TestBucket::new().await;
    let error = S3Backend::builder(
        format!("http://{}", bucket.gateway.addr),
        REGION,
        "no-such-bucket-here",
    )
    .credentials(&bucket.gateway.access_key, &bucket.gateway.secret_key)
    .read_only()
    .build()
    .await
    .unwrap_err();
    assert_eq!(error.http_status(), Some(404), "{error:?}");
    assert_eq!(error.code(), Some("NoSuchBucket"));
}

#[tokio::test]
async fn credentials_the_store_refuses_fail_the_build_and_leak_nothing() {
    let bucket = TestBucket::new().await;
    let secret = "not-the-secret-0123456789";
    for (access, secret_key) in [
        (bucket.gateway.access_key.as_str(), secret),
        ("nobody", bucket.gateway.secret_key.as_str()),
    ] {
        let error = builder(&bucket, bucket.gateway.addr)
            .credentials(access, secret_key)
            .build()
            .await
            .unwrap_err();
        assert_eq!(error.http_status(), Some(403), "{error:?}");
        for shown in [error.to_string(), format!("{error:?}")] {
            for private in [secret, access, secret_key, "Authorization", "Signature="] {
                assert!(!shown.contains(private), "{private} in {shown}");
            }
        }
    }
    let proxy = Proxy::start(bucket.gateway.addr).await;
    proxy.inject(
        |_| true,
        Fault::Reply(Reply::error(403, "AccessDenied")),
        usize::MAX,
    );
    let error = builder(&bucket, proxy.addr)
        .session_token("a-session-token-value")
        .build()
        .await
        .unwrap_err();
    assert_eq!(error.http_status(), Some(403), "{error:?}");
    let sent = proxy.seen().pop().unwrap();
    assert_eq!(
        sent.header("x-amz-security-token"),
        Some("a-session-token-value")
    );
    assert!(!format!("{error:?} {error}").contains("a-session-token-value"));
}

#[tokio::test]
async fn a_backend_that_is_not_read_only_is_refused_before_any_request() {
    let bucket = TestBucket::new().await;
    let proxy = Proxy::start(bucket.gateway.addr).await;
    let error = S3Backend::builder(format!("http://{}", proxy.addr), REGION, &bucket.name)
        .credentials(&bucket.gateway.access_key, &bucket.gateway.secret_key)
        .build()
        .await
        .unwrap_err();
    let S3Error::InvalidArgument(why) = error else {
        panic!("{error:?}");
    };
    assert!(why.contains("read_only()"), "{why}");
    assert!(proxy.seen().is_empty());
}

#[tokio::test]
async fn settings_that_cannot_be_used_are_refused_before_any_request() {
    let bucket = TestBucket::new().await;
    let proxy = Proxy::start(bucket.gateway.addr).await;
    let base = || builder(&bucket, proxy.addr);
    for (what, built) in [
        (
            "zero timeout",
            base().request_timeout(Duration::ZERO).build().await,
        ),
        (
            "zero concurrency",
            base().upload_concurrency(0).build().await,
        ),
        ("bad prefix", base().prefix("a//b").build().await),
        (
            "no credentials",
            S3Backend::builder(format!("http://{}", proxy.addr), REGION, &bucket.name)
                .read_only()
                .build()
                .await,
        ),
        (
            "userinfo",
            S3Backend::builder(
                format!("http://user:hunter2-secret@{}", proxy.addr),
                REGION,
                &bucket.name,
            )
            .credentials("a", "s")
            .read_only()
            .build()
            .await,
        ),
        (
            "scheme",
            S3Backend::builder(format!("ftp://{}", proxy.addr), REGION, &bucket.name)
                .credentials("a", "s")
                .read_only()
                .build()
                .await,
        ),
        (
            "empty region",
            S3Backend::builder(format!("http://{}", proxy.addr), "", &bucket.name)
                .credentials("a", "s")
                .read_only()
                .build()
                .await,
        ),
        (
            "empty bucket",
            S3Backend::builder(format!("http://{}", proxy.addr), REGION, "")
                .credentials("a", "s")
                .read_only()
                .build()
                .await,
        ),
    ] {
        let error = built.map(|_| ()).unwrap_err();
        assert!(
            matches!(error, S3Error::InvalidArgument(_)),
            "{what}: {error:?}"
        );
        let shown = error.to_string();
        assert!(!shown.contains("hunter2-secret"), "{what}: {shown}");
    }
    assert!(proxy.seen().is_empty());
}

#[tokio::test]
async fn the_debug_output_of_a_backend_hides_its_credentials() {
    let rig = Rig::new().await;
    let shown = format!("{:?}", rig.backend);
    assert!(!shown.contains(&rig.bucket.gateway.secret_key), "{shown}");
    assert!(!shown.contains(&rig.bucket.gateway.access_key), "{shown}");
}

#[tokio::test]
async fn clones_share_what_one_of_them_learned() {
    let rig = Rig::new().await;
    put(rig.store(), "f.txt", b"data").await;
    let other = rig.backend.clone();
    open_handle(&rig.backend, "f.txt").await;
    let sent = requests(&rig.proxy);
    let file = open_handle(&other, "f.txt").await;
    assert_eq!(file.stat().await.unwrap().end_of_file, 4);
    assert_eq!(requests(&rig.proxy), sent);
}

#[tokio::test]
async fn a_second_open_within_the_ttl_makes_no_request() {
    let mut rig = Rig::new().await;
    put(rig.store(), "d/f.txt", b"data").await;
    let first = rig.smb.open("d\\f.txt").await.unwrap();
    rig.smb.close(first.id).await;
    let sent = requests(&rig.proxy);
    assert_eq!(heads(&rig.proxy), 1);
    for _ in 0..3 {
        let again = rig.smb.open("d\\f.txt").await.unwrap();
        assert_eq!(again.size, 4);
        rig.smb.close(again.id).await;
    }
    let dir = rig.smb.open_dir("d").await.unwrap();
    rig.smb.close(dir.id).await;
    let dir = rig.smb.open_dir("d").await.unwrap();
    rig.smb.close(dir.id).await;
    // The directory was a new name, so it cost its requests once.
    assert_eq!(requests(&rig.proxy), sent + 2);
}

#[tokio::test]
async fn a_name_that_was_missing_is_remembered_as_missing() {
    let mut rig = Rig::with(|builder| builder.case_insensitive(false)).await;
    put(rig.store(), "d/x", b"x").await;
    for _ in 0..3 {
        assert_eq!(
            rig.smb.open("d\\nope").await.unwrap_err(),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
    }
    // The first call asked for the name and for the directory, the others for nothing.
    assert_eq!(heads(&rig.proxy), 2);
}

#[tokio::test]
async fn a_name_missing_from_a_fresh_listing_costs_no_request() {
    let mut rig = Rig::new().await;
    for key in ["d/a.txt", "d/b.txt"] {
        put(rig.store(), key, b"x").await;
    }
    let dir = rig.smb.open_dir("d").await.unwrap();
    assert_eq!(rig.smb.list(dir.id, "*").await.len(), 2);
    let sent = requests(&rig.proxy);
    for name in ["d\\desktop.ini", "d\\Thumbs.db", "d\\desktop.ini"] {
        assert_eq!(
            rig.smb.open(name).await.unwrap_err(),
            STATUS_OBJECT_NAME_NOT_FOUND,
            "{name}"
        );
    }
    assert_eq!(requests(&rig.proxy), sent);
    // A name the listing has needs no HEAD either, as the listing read it.
    let a = rig.smb.open("d\\a.txt").await.unwrap();
    assert_eq!(a.size, 1);
    assert_eq!(requests(&rig.proxy), sent);
}

#[tokio::test]
async fn an_open_of_a_listed_file_reads_its_metadata_once_when_listings_read_none() {
    let mut rig = Rig::with(|builder| builder.listing_metadata_max(0)).await;
    put_with(rig.store(), "d/a.txt", b"x", &[("mtime", "1700000000")]).await;
    let dir = rig.smb.open_dir("d").await.unwrap();
    let listed = rig.smb.list(dir.id, "*").await;
    assert_eq!(names(&listed), ["a.txt"]);
    assert!(
        listed[0].times[2] > filetime(1_700_001_000, 0),
        "the time the store modified it"
    );
    let (head_count, list_count) = (heads(&rig.proxy), listings(&rig.proxy));
    let opened = rig.smb.open("d\\a.txt").await.unwrap();
    assert_eq!(heads(&rig.proxy), head_count + 1);
    assert_eq!(listings(&rig.proxy), list_count);
    // The open knows the stored time the listing did not.
    assert_eq!(opened.times[2], filetime(1_700_000_000, 0));
    let again = rig.smb.open("d\\a.txt").await.unwrap();
    assert_eq!(heads(&rig.proxy), head_count + 1);
    assert_eq!(again.times, opened.times);
}

#[tokio::test]
async fn an_object_changed_in_the_store_shows_after_the_ttl() {
    let rig = Rig::with(|builder| builder.metadata_ttl(Duration::from_millis(250))).await;
    let store = rig.store().clone();
    put_with(&store, "f.txt", b"one", &[("mtime", "1700000000")]).await;
    let mut smb = rig.smb;
    let first = smb.open("f.txt").await.unwrap();
    assert_eq!(first.size, 3);
    put_with(&store, "f.txt", b"three", &[("mtime", "1700000600")]).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let before = heads(&rig.proxy);
    let second = smb.open("f.txt").await.unwrap();
    assert_eq!(second.size, 5);
    assert_eq!(second.times[2], filetime(1_700_000_600, 0));
    assert_eq!(heads(&rig.proxy), before + 1);
}

#[tokio::test]
async fn a_zero_ttl_asks_the_store_every_time() {
    let mut rig = Rig::with(|builder| builder.metadata_ttl(Duration::ZERO)).await;
    put(rig.store(), "f.txt", b"data").await;
    for n in 1..=3 {
        rig.smb.open("f.txt").await.unwrap();
        assert_eq!(heads(&rig.proxy), n);
    }
}

#[tokio::test]
async fn a_directory_wins_over_an_object_of_the_same_name() {
    let mut rig = Rig::new().await;
    put(rig.store(), "both/inner.txt", b"x").await;
    // The gateway cannot hold an object and a directory under one name, so the
    // proxy answers for the object.
    rig.proxy.inject(
        |seen| seen.method == "HEAD" && seen.target.ends_with("/both"),
        Fault::Reply(
            Reply::new(200, "")
                .header("Last-Modified", OLD)
                .header("ETag", "\"abc\""),
        ),
        usize::MAX,
    );
    let opened = rig.smb.create("both", Spec::ANY).await.unwrap();
    assert_eq!(opened.attributes & 0x10, 0x10);
    assert_eq!(
        rig.smb.create("both", Spec::FILE).await.unwrap_err(),
        STATUS_FILE_IS_A_DIRECTORY
    );
    let dir = rig.smb.open_dir("both").await.unwrap();
    assert_eq!(names(&rig.smb.list(dir.id, "*").await), ["inner.txt"]);
}

#[tokio::test]
async fn a_store_that_refuses_access_fails_the_open_as_denied() {
    let mut rig = Rig::new().await;
    put(rig.store(), "f.txt", b"x").await;
    rig.proxy.inject(
        |seen| seen.method == "HEAD",
        Fault::Reply(Reply::new(403, "")),
        usize::MAX,
    );
    assert_eq!(
        rig.smb.open("f.txt").await.unwrap_err(),
        STATUS_ACCESS_DENIED
    );
}

#[tokio::test]
async fn a_store_that_keeps_failing_fails_the_open_after_five_tries() {
    let mut rig = Rig::new().await;
    put(rig.store(), "f.txt", b"x").await;
    rig.proxy.inject(
        |seen| seen.method == "HEAD",
        Fault::Reply(Reply::error(503, "SlowDown")),
        usize::MAX,
    );
    assert_eq!(
        rig.smb.open("f.txt").await.unwrap_err(),
        STATUS_UNEXPECTED_IO_ERROR
    );
    assert_eq!(heads(&rig.proxy), 5);
}

#[tokio::test]
async fn the_requests_of_one_call_share_one_deadline() {
    let mut rig = Rig::with(|builder| builder.request_timeout(Duration::from_secs(2))).await;
    put_with(rig.store(), "d/", b"", &[]).await;
    put(rig.store(), "d/x", b"x").await;
    // The listing of the keys below the directory answers after 1.5 s, and
    // the HEAD of its marker never answers. The marker is asked for with the
    // time that is left of the two seconds, not with two seconds of its own,
    // which would end the call after 3.5 s.
    let gate = Arc::new(Notify::new());
    rig.proxy.inject(
        |seen| {
            seen.method == "GET"
                && seen.has_param("max-keys")
                && seen.query().contains("prefix=d%2F")
        },
        Fault::Hold(Arc::clone(&gate)),
        1,
    );
    rig.proxy.inject(
        |seen| seen.method == "HEAD" && seen.target.ends_with("/d/"),
        Fault::Stall,
        usize::MAX,
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        gate.notify_one();
    });
    let started = Instant::now();
    assert_eq!(
        rig.smb.open_dir("d").await.unwrap_err(),
        STATUS_UNEXPECTED_IO_ERROR
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(1800), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(3200), "{elapsed:?}");
}

#[tokio::test]
async fn requests_that_go_out_together_stop_together() {
    let mut rig = Rig::with(|builder| builder.request_timeout(Duration::from_secs(2))).await;
    put(rig.store(), "f.txt", b"x").await;
    rig.proxy.inject(|_| true, Fault::Stall, usize::MAX);
    let started = Instant::now();
    assert_eq!(
        rig.smb.open("f.txt").await.unwrap_err(),
        STATUS_UNEXPECTED_IO_ERROR
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(1800), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(3500), "{elapsed:?}");
}

#[tokio::test]
async fn a_stall_in_a_read_ends_at_the_deadline() {
    let mut rig = Rig::with(|builder| builder.request_timeout(Duration::from_secs(1))).await;
    put(rig.store(), "f.txt", pattern(0, 100)).await;
    let file = rig.smb.open("f.txt").await.unwrap();
    rig.proxy
        .inject(|seen| seen.method == "GET", Fault::Stall, usize::MAX);
    let started = Instant::now();
    assert_eq!(
        rig.smb.read(file.id, 0, 10).await.unwrap_err(),
        STATUS_UNEXPECTED_IO_ERROR
    );
    // A call that waited for the idle limit of a minute would take longer.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn data_is_read_from_the_store_every_time() {
    let mut rig = Rig::new().await;
    put(rig.store(), "f.bin", pattern(0, 1000)).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    for _ in 0..3 {
        assert_eq!(
            rig.smb.read(file.id, 0, 100).await.unwrap(),
            pattern(0, 100)
        );
    }
    assert_eq!(reads(&rig.proxy), 3);
}
