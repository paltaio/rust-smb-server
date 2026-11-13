//! Every call of the S3 client against the gateway.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use md5::{Digest as _, Md5};

use super::fixture::{
    MIB, TestBucket, file_payload, file_with, foreground, is_missing, overwrite, pattern, put,
    range, user_metadata,
};
use crate::s3::client::{CopyMetadata, ListRequest, MAX_DELETE_KEYS, S3Client};
use crate::s3::encode::hex;
use crate::s3::error::S3Error;
use crate::s3::object::Metadata;
use crate::s3::payload::BODY_CHUNK;
use crate::s3::xml::{CompletedPart, Listing};

async fn read(client: &S3Client, key: &str, start: u64, len: u64) -> Bytes {
    client
        .get_object(key, range(start, len), None, foreground())
        .await
        .unwrap()
        .data
}

/// One page of a listing.
async fn page(
    client: &S3Client,
    prefix: &str,
    token: Option<&str>,
    max_keys: Option<u32>,
) -> Listing {
    let request = ListRequest {
        prefix,
        delimited: false,
        continuation_token: token,
        max_keys,
    };
    client.list_objects(&request, foreground()).await.unwrap()
}

/// The keys and common prefixes of every page of a listing, and the number of
/// pages.
async fn list_all(
    client: &S3Client,
    prefix: &str,
    delimited: bool,
    max_keys: Option<u32>,
) -> (Vec<String>, Vec<String>, usize) {
    let (mut keys, mut prefixes) = (Vec::new(), Vec::new());
    let mut token: Option<String> = None;
    let mut pages = 0;
    loop {
        let request = ListRequest {
            prefix,
            delimited,
            continuation_token: token.as_deref(),
            max_keys,
        };
        let listing = client.list_objects(&request, foreground()).await.unwrap();
        pages += 1;
        keys.extend(listing.objects.into_iter().map(|o| o.key));
        prefixes.extend(listing.prefixes);
        match listing.next_token {
            Some(next) => token = Some(next),
            None => return (keys, prefixes, pages),
        }
    }
}

fn keys_of(listing: &Listing) -> Vec<&str> {
    listing.objects.iter().map(|o| o.key.as_str()).collect()
}

#[tokio::test]
async fn puts_heads_and_reads_an_object() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let metadata = Metadata {
        content_type: Some("text/plain".into()),
        cache_control: Some("max-age=60".into()),
        content_disposition: Some("attachment; filename=\"a.txt\"".into()),
        content_language: Some("en".into()),
        content_encoding: Some("identity".into()),
        expires: Some("Fri, 24 May 2030 00:00:00 GMT".into()),
        ..user_metadata(&[("mtime", "1700000000.123456789"), ("smb-attributes", "20")])
    };
    let etag = client
        .put_object(
            "hello.txt",
            Bytes::from_static(b"hello world"),
            &metadata,
            foreground(),
        )
        .await
        .unwrap();

    let head = client.head_object("hello.txt", foreground()).await.unwrap();
    assert_eq!(head.size, 11);
    assert_eq!(head.etag, etag);
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
    assert_eq!(head.metadata, metadata);
    let skew = SystemTime::now()
        .duration_since(head.last_modified)
        .unwrap_or_else(|e| e.duration());
    assert!(skew < Duration::from_secs(120), "{skew:?}");

    let object = client
        .get_object("hello.txt", range(6, 5), None, foreground())
        .await
        .unwrap();
    assert_eq!(object.data, "world");
    assert_eq!(object.head, head);
}

#[tokio::test]
async fn a_range_past_the_end_of_an_object_is_clipped() {
    let bucket = TestBucket::new().await;
    put(&bucket.client, "short", b"0123456789").await;
    let object = bucket
        .client
        .get_object("short", range(4, 100), None, foreground())
        .await
        .unwrap();
    assert_eq!(object.data, "456789");
    assert_eq!(object.head.size, 10);
    let whole = bucket
        .client
        .get_object("short", range(0, 100), None, foreground())
        .await
        .unwrap();
    assert_eq!(whole.data, "0123456789");
}

#[tokio::test]
async fn a_missing_key_is_reported_as_missing() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let head = client
        .head_object("nothing", foreground())
        .await
        .unwrap_err();
    assert!(head.is_no_such_key(), "{head:?}");
    let get = client
        .get_object("nothing", range(0, 1), None, foreground())
        .await
        .unwrap_err();
    assert!(get.is_no_such_key(), "{get:?}");
    assert_eq!(get.code(), Some("NoSuchKey"));
}

#[tokio::test]
async fn a_get_with_a_stale_etag_is_a_failed_precondition() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let first = put(client, "doc", b"first version").await;
    let object = client
        .get_object("doc", range(0, 5), Some(&first), foreground())
        .await
        .unwrap();
    assert_eq!(object.data, "first");
    let unquoted = first.trim_matches('"');
    client
        .get_object("doc", range(0, 5), Some(unquoted), foreground())
        .await
        .unwrap();

    let second = put(client, "doc", b"second version").await;
    assert_ne!(first, second);
    let error = client
        .get_object("doc", range(0, 5), Some(&first), foreground())
        .await
        .unwrap_err();
    assert!(error.is_precondition_failed(), "{error:?}");
    let current = client
        .get_object("doc", range(0, 6), Some(&second), foreground())
        .await
        .unwrap();
    assert_eq!(current.data, "second");
}

#[tokio::test]
async fn keys_that_need_encoding_round_trip() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let keys = [
        "a b",
        "a+b",
        "100%",
        "~tilde~",
        "50%25 off",
        "a%2Fb",
        "semi;colon&amp=eq",
        "dollar$sign@at!bang",
        "hash#tag",
        "(paren)'quote'[bracket],comma",
        "dir/sub dir/caf\u{e9}.txt",
        "\u{65e5}\u{672c}/\u{8a9e}.txt",
        "\u{1f600}",
        "plus+dir/a+b",
    ];
    for key in keys {
        let body = format!("body of {key}");
        put(client, key, body.as_bytes()).await;
    }
    for key in keys {
        let body = format!("body of {key}");
        let head = client.head_object(key, foreground()).await.unwrap();
        assert_eq!(head.size, body.len() as u64, "{key}");
        assert_eq!(read(client, key, 0, 1000).await, body.as_bytes(), "{key}");
    }
    let (listed, prefixes, _) = list_all(client, "", false, None).await;
    assert!(prefixes.is_empty());
    assert_eq!(
        listed.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        keys.into_iter().collect::<BTreeSet<_>>()
    );
}

#[tokio::test]
async fn lists_pages_with_continuation_tokens() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    for n in 0..5 {
        put(client, &format!("page/{n}"), b"x").await;
    }
    let first = page(client, "page/", None, Some(2)).await;
    assert_eq!(keys_of(&first), ["page/0", "page/1"]);
    let token = first
        .next_token
        .as_deref()
        .expect("a token after a full page");
    let second = page(client, "page/", Some(token), Some(2)).await;
    assert_eq!(keys_of(&second), ["page/2", "page/3"]);
    let token = second
        .next_token
        .as_deref()
        .expect("a token after a full page");
    let third = page(client, "page/", Some(token), Some(2)).await;
    assert_eq!(keys_of(&third), ["page/4"]);
    assert_eq!(third.next_token, None);
    assert_eq!(first.objects[0].size, 1);

    let one = page(client, "page/", None, Some(1)).await;
    assert_eq!(keys_of(&one), ["page/0"]);
    assert!(one.next_token.is_some());
    let all = page(client, "page/", None, None).await;
    assert_eq!(all.objects.len(), 5);
    assert_eq!(all.next_token, None);
}

#[tokio::test]
async fn lists_common_prefixes_with_a_delimiter() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    for key in [
        "top.txt",
        "a/one",
        "a/two",
        "b/sub/deep",
        "x y/caf\u{e9}",
        "p+q/r",
    ] {
        put(client, key, b"x").await;
    }
    let list = |prefix, delimited| async move {
        let (keys, prefixes, _) = list_all(client, prefix, delimited, None).await;
        (
            keys.into_iter().collect::<BTreeSet<_>>(),
            prefixes.into_iter().collect::<BTreeSet<_>>(),
        )
    };
    let set = |items: &[&str]| {
        items
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>()
    };

    assert_eq!(
        list("", true).await,
        (set(&["top.txt"]), set(&["a/", "b/", "x y/", "p+q/"]))
    );
    assert_eq!(list("a/", true).await, (set(&["a/one", "a/two"]), set(&[])));
    assert_eq!(list("b/", true).await, (set(&[]), set(&["b/sub/"])));
    assert_eq!(list("b/", false).await, (set(&["b/sub/deep"]), set(&[])));
    assert_eq!(
        list("x y/", true).await,
        (set(&["x y/caf\u{e9}"]), set(&[]))
    );
    assert_eq!(list("p+q/", true).await, (set(&["p+q/r"]), set(&[])));
    assert_eq!(list("nothing/", true).await, (set(&[]), set(&[])));
}

#[tokio::test]
async fn a_directory_marker_is_an_object_with_a_trailing_slash() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    put(client, "marker/", b"").await;
    let head = client.head_object("marker/", foreground()).await.unwrap();
    assert_eq!(head.size, 0);
    let (keys, prefixes, _) = list_all(client, "marker/", false, None).await;
    assert_eq!((keys, prefixes), (vec!["marker/".to_owned()], vec![]));
    let (keys, prefixes, _) = list_all(client, "", true, None).await;
    assert_eq!((keys, prefixes), (vec![], vec!["marker/".to_owned()]));
}

#[tokio::test]
async fn uploads_an_object_in_two_5_mib_parts() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let metadata = Metadata {
        content_type: Some("application/x-test".into()),
        ..user_metadata(&[("mtime", "1700000000.5")])
    };
    let id = client
        .create_multipart_upload("big", &metadata, foreground())
        .await
        .unwrap();
    assert!(!id.is_empty());
    let first = client
        .upload_part("big", &id, 1, pattern(0, 5 * MIB), foreground())
        .await
        .unwrap();
    let second = client
        .upload_part("big", &id, 2, pattern(5 * MIB, 5 * MIB), foreground())
        .await
        .unwrap();
    assert_ne!(first, second);
    let parts = [
        CompletedPart {
            number: 1,
            etag: first,
        },
        CompletedPart {
            number: 2,
            etag: second,
        },
    ];
    let etag = client
        .complete_multipart_upload("big", &id, &parts, (10 * MIB) as u64, None, foreground())
        .await
        .unwrap();
    assert!(etag.ends_with("-2\""), "{etag}");

    let head = client.head_object("big", foreground()).await.unwrap();
    assert_eq!(head.size, (10 * MIB) as u64);
    assert_eq!(head.etag, etag);
    assert_eq!(head.metadata, metadata);
    let across = read(client, "big", (5 * MIB - 8) as u64, 16).await;
    assert_eq!(across, pattern(5 * MIB - 8, 16));
    let tail = read(client, "big", (10 * MIB - 4) as u64, 100).await;
    assert_eq!(tail, pattern(10 * MIB - 4, 4));
}

#[tokio::test]
async fn an_aborted_upload_cannot_be_completed() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let id = client
        .create_multipart_upload("gone", &Metadata::default(), foreground())
        .await
        .unwrap();
    let etag = client
        .upload_part("gone", &id, 1, Bytes::from_static(b"part"), foreground())
        .await
        .unwrap();
    client
        .abort_multipart_upload("gone", &id, foreground())
        .await
        .unwrap();
    client
        .abort_multipart_upload("gone", &id, foreground())
        .await
        .unwrap();

    let parts = [CompletedPart { number: 1, etag }];
    let error = client
        .complete_multipart_upload("gone", &id, &parts, 4, None, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("NoSuchUpload"), "{error:?}");
    assert!(is_missing(client, "gone").await);
}

#[tokio::test]
async fn builds_parts_from_ranges_of_another_object() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let source = pattern(0, 6 * MIB);
    client
        .put_object("source", source.clone(), &Metadata::default(), foreground())
        .await
        .unwrap();
    let id = client
        .create_multipart_upload("copy", &Metadata::default(), foreground())
        .await
        .unwrap();
    let first = client
        .upload_part_copy(
            "copy",
            &id,
            1,
            "source",
            range(0, (5 * MIB) as u64),
            foreground(),
        )
        .await
        .unwrap();
    let second = client
        .upload_part_copy(
            "copy",
            &id,
            2,
            "source",
            range((5 * MIB) as u64, 100),
            foreground(),
        )
        .await
        .unwrap();
    assert!(!first.etag.is_empty() && first.etag != second.etag);
    let parts = [
        CompletedPart {
            number: 1,
            etag: first.etag,
        },
        CompletedPart {
            number: 2,
            etag: second.etag,
        },
    ];
    let size = (5 * MIB + 100) as u64;
    client
        .complete_multipart_upload("copy", &id, &parts, size, None, foreground())
        .await
        .unwrap();

    let head = client.head_object("copy", foreground()).await.unwrap();
    assert_eq!(head.size, size);
    assert_eq!(read(client, "copy", 0, 64).await, source.slice(0..64));
    let boundary = (5 * MIB - 32) as u64;
    assert_eq!(
        read(client, "copy", boundary, 64).await,
        source.slice(5 * MIB - 32..5 * MIB + 32)
    );
    assert_eq!(
        read(client, "copy", size - 10, 10).await,
        source.slice(5 * MIB + 90..5 * MIB + 100)
    );
}

#[tokio::test]
async fn copies_an_object_with_its_metadata_or_with_new_metadata() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let original = Metadata {
        content_type: Some("text/plain".into()),
        ..user_metadata(&[("mtime", "1"), ("tag", "a")])
    };
    client
        .put_object(
            "src key+1",
            Bytes::from_static(b"payload"),
            &original,
            foreground(),
        )
        .await
        .unwrap();

    let copied = client
        .copy_object(
            "src key+1",
            "copies/a b/\u{e9}",
            CopyMetadata::Copy {
                storage_class: None,
            },
            foreground(),
        )
        .await
        .unwrap();
    let head = client
        .head_object("copies/a b/\u{e9}", foreground())
        .await
        .unwrap();
    assert_eq!(head.metadata, original);
    assert_eq!(head.etag, copied.etag);
    assert_eq!(read(client, "copies/a b/\u{e9}", 0, 100).await, "payload");

    let replacement = Metadata {
        content_type: Some("application/x-test".into()),
        cache_control: Some("no-cache".into()),
        ..user_metadata(&[("mtime", "2")])
    };
    client
        .copy_object(
            "src key+1",
            "replaced",
            CopyMetadata::Replace(&replacement),
            foreground(),
        )
        .await
        .unwrap();
    let head = client.head_object("replaced", foreground()).await.unwrap();
    assert_eq!(head.metadata, replacement);
    assert_eq!(read(client, "replaced", 0, 100).await, "payload");
    let untouched = client.head_object("src key+1", foreground()).await.unwrap();
    assert_eq!(untouched.metadata, original);
}

#[tokio::test]
async fn replaces_the_metadata_of_an_object_by_copying_it_onto_itself() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let before = user_metadata(&[("mtime", "1"), ("smb-attributes", "20")]);
    client
        .put_object(
            "self",
            Bytes::from_static(b"unchanged"),
            &before,
            foreground(),
        )
        .await
        .unwrap();
    let after = Metadata {
        content_type: Some("text/plain".into()),
        ..user_metadata(&[("mtime", "3"), ("smb-attributes", "21")])
    };
    client
        .copy_object("self", "self", CopyMetadata::Replace(&after), foreground())
        .await
        .unwrap();
    let head = client.head_object("self", foreground()).await.unwrap();
    assert_eq!(head.metadata, after);
    assert_eq!(head.size, 9);
    assert_eq!(read(client, "self", 0, 100).await, "unchanged");
}

#[tokio::test]
async fn copying_a_missing_object_fails_as_missing() {
    let bucket = TestBucket::new().await;
    let error = bucket
        .client
        .copy_object(
            "absent",
            "target",
            CopyMetadata::Copy {
                storage_class: None,
            },
            foreground(),
        )
        .await
        .unwrap_err();
    assert!(error.is_no_such_key(), "{error:?}");
}

#[tokio::test]
async fn deletes_an_object_and_a_missing_one() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    put(client, "doomed", b"x").await;
    client.delete_object("doomed", foreground()).await.unwrap();
    assert!(is_missing(client, "doomed").await);
    client.delete_object("doomed", foreground()).await.unwrap();
    client
        .delete_object("never existed", foreground())
        .await
        .unwrap();
}

#[tokio::test]
async fn deletes_several_objects_at_once() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let keep = ["keep one", "dir/keep two"];
    let remove = ["rm/a", "rm/b c", "rm/caf\u{e9}", "rm/x&y;z"];
    for key in keep.iter().chain(&remove) {
        put(client, key, b"x").await;
    }
    let mut targets: Vec<&str> = remove.to_vec();
    targets.push("never existed");
    let failed = client.delete_objects(&targets, foreground()).await.unwrap();
    assert!(failed.is_empty(), "{failed:?}");
    for key in remove {
        assert!(is_missing(client, key).await, "{key}");
    }
    for key in keep {
        client.head_object(key, foreground()).await.unwrap();
    }
}

#[tokio::test]
async fn deletes_the_most_keys_one_call_takes() {
    let bucket = TestBucket::new().await;
    let keys: Vec<String> = (0..MAX_DELETE_KEYS)
        .map(|n| format!("absent/{n:04}"))
        .collect();
    let failed = bucket
        .client
        .delete_objects(&keys, foreground())
        .await
        .unwrap();
    assert!(failed.is_empty(), "{failed:?}");
}

#[tokio::test]
async fn a_wrong_secret_is_refused_and_never_shown() {
    let bucket = TestBucket::new().await;
    let secret = "wrong-secret-value-1234";
    let client = bucket.client_at(bucket.gateway.addr, |settings| {
        settings.credentials.secret_key = secret.into();
    });
    let error = client
        .head_object("anything", foreground())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, S3Error::Status { status: 403, .. }),
        "{error:?}"
    );
    for shown in [error.to_string(), format!("{error:?}")] {
        for forbidden in [secret, "AWS4-HMAC-SHA256", &bucket.gateway.secret_key] {
            assert!(!shown.contains(forbidden), "{shown}");
        }
    }
    assert!(matches!(
        error.into_smb_error(),
        crate::SmbError::AccessDenied
    ));
}

#[tokio::test]
async fn a_missing_bucket_is_not_a_missing_key() {
    let bucket = TestBucket::new().await;
    let client = bucket.client_at(bucket.gateway.addr, |settings| {
        settings.location.bucket = "smb-test-no-such-bucket".into();
    });
    let error = client
        .list_objects(&ListRequest::default(), foreground())
        .await
        .unwrap_err();
    assert_eq!(error.http_status(), Some(404), "{error:?}");
    assert_eq!(error.code(), Some("NoSuchBucket"));
    assert!(!error.is_no_such_key());
}

/// Contents with piece boundaries inside, at a size no piece divides.
fn file_contents() -> Vec<u8> {
    pattern(0, 3 * BODY_CHUNK + 4_321).to_vec()
}

#[tokio::test]
async fn puts_a_range_of_a_file() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let contents = file_contents();
    let file = file_with(&contents);
    for (key, offset, len) in [
        ("whole", 0, contents.len()),
        ("inner", 12_345, 150_000),
        ("one piece", 100, 1000),
        ("one byte", 7, 1),
        ("exactly one piece", 5, BODY_CHUNK),
    ] {
        let wanted = &contents[offset..offset + len];
        let payload = file_payload(&file, offset as u64, wanted);
        let etag = client
            .put_object(key, payload, &Metadata::default(), foreground())
            .await
            .unwrap();
        let head = client.head_object(key, foreground()).await.unwrap();
        assert_eq!(
            (head.size, head.etag.as_str()),
            (len as u64, etag.as_str()),
            "{key}"
        );
        assert_eq!(read(client, key, 0, len as u64 + 10).await, wanted, "{key}");
    }
}

#[tokio::test]
async fn puts_an_empty_range_of_a_file() {
    let bucket = TestBucket::new().await;
    let file = file_with(b"unused");
    let payload = file_payload(&file, 3, b"");
    bucket
        .client
        .put_object("empty", payload, &Metadata::default(), foreground())
        .await
        .unwrap();
    let head = bucket
        .client
        .head_object("empty", foreground())
        .await
        .unwrap();
    assert_eq!(head.size, 0);
}

#[tokio::test]
async fn uploads_parts_from_ranges_of_a_file() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let contents = pattern(0, 10 * MIB + 3_000).to_vec();
    let file = file_with(&contents);
    let id = client
        .create_multipart_upload("from file", &Metadata::default(), foreground())
        .await
        .unwrap();
    let mut parts = Vec::new();
    for (number, offset, len) in [(1, 0, 5 * MIB), (2, 5 * MIB, 5 * MIB + 3_000)] {
        let payload = file_payload(&file, offset as u64, &contents[offset..offset + len]);
        let etag = client
            .upload_part("from file", &id, number, payload, foreground())
            .await
            .unwrap();
        parts.push(CompletedPart { number, etag });
    }
    let size = contents.len() as u64;
    client
        .complete_multipart_upload("from file", &id, &parts, size, None, foreground())
        .await
        .unwrap();
    let head = client.head_object("from file", foreground()).await.unwrap();
    assert_eq!(head.size, size);
    for at in [0, 5 * MIB - 100, 10 * MIB - 50] {
        assert_eq!(
            read(client, "from file", at as u64, 200).await,
            contents[at..at + 200]
        );
    }
}

#[tokio::test]
async fn a_file_that_changed_since_it_was_hashed_leaves_the_object_that_was_there() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let contents = file_contents();
    let file = file_with(&contents);
    let payload = file_payload(&file, 0, &contents);
    // A change near the end, in the last piece, so the pieces before it look right.
    overwrite(&file, contents.len() as u64 - 10, b"overwritten");
    let old = pattern(9, 500);
    let old_etag = client
        .put_object("old", old.clone(), &Metadata::default(), foreground())
        .await
        .unwrap();
    let error = client
        .put_object("old", payload, &Metadata::default(), foreground())
        .await
        .unwrap_err();
    assert!(matches!(error, S3Error::SourceChanged), "{error:?}");
    let head = client.head_object("old", foreground()).await.unwrap();
    assert_eq!((head.size, head.etag), (500, old_etag));
    assert_eq!(read(client, "old", 0, 500).await, old);
}

#[tokio::test]
async fn a_file_that_became_shorter_is_not_stored() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let contents = file_contents();
    let file = file_with(&contents);
    let payload = file_payload(&file, 0, &contents);
    file.set_len(70_000).unwrap();
    let error = client
        .put_object("short", payload, &Metadata::default(), foreground())
        .await
        .unwrap_err();
    assert!(error.is_source_changed(), "{error:?}");
    assert!(is_missing(client, "short").await);
}

#[tokio::test]
async fn a_part_whose_file_changed_is_not_uploaded() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let first = pattern(0, 5 * MIB);
    let second = pattern(7, 150_000);
    let file = file_with(&second);
    let payload = file_payload(&file, 0, &second);
    overwrite(&file, 1_000, b"changed");
    let id = client
        .create_multipart_upload("parts", &Metadata::default(), foreground())
        .await
        .unwrap();
    let etag = client
        .upload_part("parts", &id, 1, first.clone(), foreground())
        .await
        .unwrap();
    let error = client
        .upload_part("parts", &id, 2, payload, foreground())
        .await
        .unwrap_err();
    assert!(error.is_source_changed(), "{error:?}");

    // Part 2 is never sent again. Had the changed bytes landed as that part,
    // the store would complete the upload with the ETag they hash to.
    let mut changed = second.to_vec();
    changed[1_000..1_007].copy_from_slice(b"changed");
    let part_1 = CompletedPart { number: 1, etag };
    let part_2 = CompletedPart {
        number: 2,
        etag: format!("\"{}\"", hex(&Md5::digest(&changed))),
    };
    let size = (first.len() + second.len()) as u64;
    let error = client
        .complete_multipart_upload(
            "parts",
            &id,
            &[part_1.clone(), part_2],
            size,
            None,
            foreground(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("InvalidPart"), "{error:?}");

    // The upload is still open for the parts that did land.
    client
        .complete_multipart_upload(
            "parts",
            &id,
            &[part_1],
            first.len() as u64,
            None,
            foreground(),
        )
        .await
        .unwrap();
    let head = client.head_object("parts", foreground()).await.unwrap();
    assert_eq!(head.size, first.len() as u64);
    assert_eq!(
        read(client, "parts", 0, 2 * MIB as u64).await,
        first[..2 * MIB]
    );
}

#[tokio::test]
async fn lists_pages_of_keys_that_need_encoding() {
    let bucket = TestBucket::new().await;
    let client = &bucket.client;
    let keys = [
        "enc/a b",
        "enc/c+d",
        "enc/caf\u{e9}",
        "enc/100%",
        "enc/\u{65e5}\u{672c}\u{8a9e}",
        "enc/sub dir/x+y z",
        "enc/~tilde",
        "enc/semi;&=colon",
        "enc/\u{1f600}",
    ];
    for key in keys {
        put(client, key, b"x").await;
    }
    let (seen, _, pages) = list_all(client, "enc/", false, Some(2)).await;
    assert_eq!(pages, keys.len().div_ceil(2));
    assert_eq!(seen.len(), keys.len(), "{seen:?}");
    assert_eq!(
        seen.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        keys.into_iter().collect::<BTreeSet<_>>()
    );
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(seen, sorted, "pages come in key order");
}
