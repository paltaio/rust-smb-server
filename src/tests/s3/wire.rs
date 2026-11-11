//! The requests the client writes, read at a proxy that answers them itself.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest, Sha256};

use super::fixture::{
    OLD, credentials, file_payload, file_with, foreground, location, pattern, range, user_metadata,
};
use super::proxy::{Fault, Proxy, Reply, Seen};
use crate::s3::client::{CopyMetadata, ListRequest, S3Client, Settings};
use crate::s3::encode::hex;
use crate::s3::object::Metadata;
use crate::s3::payload::BODY_CHUNK;
use crate::s3::xml::CompletedPart;

const REGION: &str = "eu-west-1";
const BUCKET: &str = "wire-bucket";
const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET_KEY: &str = "SECRETEXAMPLE";
const TOKEN: &str = "TOKENEXAMPLE";
const KEY: &str = "dir/a b+c\u{e9}";
const ENCODED_KEY: &str = "dir/a%20b%2Bc%C3%A9";
const UPLOAD_ID: &str = "a/b+c=";
const ENCODED_UPLOAD_ID: &str = "a%2Fb%2Bc%3D";

const COPY_RESULT: &str = "<CopyObjectResult><LastModified>2009-10-12T17:50:30.000Z</LastModified>\
                           <ETag>&quot;copy&quot;</ETag></CopyObjectResult>";
const PART_COPY_RESULT: &str = "<CopyPartResult><ETag>&quot;partcopy&quot;</ETag></CopyPartResult>";
const INITIATE_RESULT: &str =
    "<InitiateMultipartUploadResult><UploadId>a/b+c=</UploadId></InitiateMultipartUploadResult>";
const COMPLETE_RESULT: &str =
    "<CompleteMultipartUploadResult><ETag>\"done-2\"</ETag></CompleteMultipartUploadResult>";
const LISTING: &str = "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";

/// A client whose requests a proxy answers. Every request gets a canned answer;
/// none reaches the upstream.
async fn wire() -> (Proxy, S3Client) {
    let proxy = Proxy::start("127.0.0.1:9".parse::<SocketAddr>().unwrap()).await;
    let ok = |body: &str| Reply::new(200, body);
    let canned = |matches: fn(&Seen) -> bool, reply: Reply| {
        proxy.inject(matches, Fault::Reply(reply), usize::MAX);
    };
    canned(
        |s| s.header("x-amz-copy-source").is_some() && s.has_param("partNumber"),
        ok(PART_COPY_RESULT),
    );
    canned(|s| s.header("x-amz-copy-source").is_some(), ok(COPY_RESULT));
    canned(
        |s| s.method == "PUT" && s.has_param("partNumber"),
        ok("").header("ETag", "\"part\""),
    );
    canned(|s| s.method == "PUT", ok("").header("ETag", "\"put\""));
    canned(
        |s| s.method == "POST" && s.has_param("uploads"),
        ok(INITIATE_RESULT),
    );
    canned(
        |s| s.method == "POST" && s.has_param("uploadId"),
        ok(COMPLETE_RESULT),
    );
    canned(
        |s| s.method == "POST" && s.has_param("delete"),
        ok("<DeleteResult/>"),
    );
    canned(|s| s.method == "DELETE", Reply::new(204, ""));
    canned(
        |s| s.method == "HEAD",
        ok("")
            .header("ETag", "\"head\"")
            .header("Last-Modified", OLD),
    );
    canned(
        |s| s.method == "GET" && s.header("range").is_some(),
        Reply::new(206, pattern(5, 10).to_vec())
            .header("ETag", "\"abc\"")
            .header("Last-Modified", OLD)
            .header("Content-Range", "bytes 5-14/100"),
    );
    canned(|s| s.method == "GET", ok(LISTING));
    let mut settings = Settings::new(
        location(proxy.addr, REGION, BUCKET),
        credentials(ACCESS_KEY, SECRET_KEY),
    );
    settings.credentials.session_token = Some(TOKEN.into());
    settings.backoff_base = Duration::from_millis(1);
    (proxy, S3Client::new(settings).unwrap())
}

/// The request the proxy saw last.
fn last(proxy: &Proxy) -> Seen {
    proxy.seen().pop().expect("no request arrived")
}

fn metadata() -> Metadata {
    Metadata {
        content_type: Some("text/plain".into()),
        cache_control: Some("max-age=60".into()),
        content_disposition: Some("attachment".into()),
        content_encoding: Some("gzip".into()),
        content_language: Some("en".into()),
        expires: Some(OLD.into()),
        storage_class: Some("STANDARD_IA".into()),
        ..user_metadata(&[("mtime", "1.5"), ("smb-attributes", "20")])
    }
}

/// The headers [`metadata`] is sent as.
const METADATA_HEADERS: [(&str, &str); 9] = [
    ("content-type", "text/plain"),
    ("cache-control", "max-age=60"),
    ("content-disposition", "attachment"),
    ("content-encoding", "gzip"),
    ("content-language", "en"),
    ("expires", OLD),
    ("x-amz-storage-class", "STANDARD_IA"),
    ("x-amz-meta-mtime", "1.5"),
    ("x-amz-meta-smb-attributes", "20"),
];

/// Checks that `seen` carries every header of [`METADATA_HEADERS`], signed.
fn assert_metadata_sent(seen: &Seen) {
    let signed = signed_headers(seen);
    for (name, value) in METADATA_HEADERS {
        assert_eq!(seen.header(name), Some(value), "{name}");
        assert!(signed.iter().any(|n| n == name), "{name} is signed");
    }
}

/// The names in the `SignedHeaders` field of the `Authorization` header.
fn signed_headers(seen: &Seen) -> Vec<String> {
    let authorization = seen
        .header("authorization")
        .expect("no Authorization header");
    let (_, rest) = authorization.split_once("SignedHeaders=").unwrap();
    let (names, _) = rest.split_once(',').unwrap();
    names.split(';').map(str::to_owned).collect()
}

#[tokio::test]
async fn signs_every_request_with_the_hash_of_its_body() {
    let (proxy, client) = wire().await;
    let copy = CopyMetadata::Copy {
        storage_class: None,
    };
    client.head_object(KEY, foreground()).await.unwrap();
    client
        .put_object(
            KEY,
            Bytes::from_static(b"body"),
            &Metadata::default(),
            foreground(),
        )
        .await
        .unwrap();
    client
        .get_object(KEY, range(5, 10), None, foreground())
        .await
        .unwrap();
    client
        .copy_object("from", KEY, copy, foreground())
        .await
        .unwrap();
    let id = client
        .create_multipart_upload(KEY, &Metadata::default(), foreground())
        .await
        .unwrap();
    client
        .upload_part(KEY, &id, 1, Bytes::from_static(b"part"), foreground())
        .await
        .unwrap();
    client
        .upload_part_copy(KEY, &id, 2, "from", range(0, 10), foreground())
        .await
        .unwrap();
    let parts = [CompletedPart {
        number: 1,
        etag: "\"p\"".into(),
    }];
    client
        .complete_multipart_upload(KEY, &id, &parts, 4, None, foreground())
        .await
        .unwrap();
    client
        .abort_multipart_upload(KEY, &id, foreground())
        .await
        .unwrap();
    client.delete_object(KEY, foreground()).await.unwrap();
    client
        .delete_objects(&[KEY, "other"], foreground())
        .await
        .unwrap();
    client
        .list_objects(&ListRequest::default(), foreground())
        .await
        .unwrap();

    let seen = proxy.seen();
    assert_eq!(seen.len(), 12);
    for request in &seen {
        let what = format!("{} {}", request.method, request.target);
        let authorization = request.header("authorization").unwrap();
        let date = request.header("x-amz-date").unwrap();
        assert_eq!(date.len(), 16, "{what}");
        assert!(date.ends_with('Z') && date.as_bytes()[8] == b'T', "{what}");
        assert!(
            authorization.starts_with(&format!(
                "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{}/{REGION}/s3/aws4_request,SignedHeaders=",
                &date[..8]
            )),
            "{what}: {authorization}"
        );
        let signature = authorization.rsplit_once("Signature=").unwrap().1;
        assert!(
            signature.len() == 64
                && signature
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{what}: {signature}"
        );
        let mut names = signed_headers(request);
        for required in [
            "host",
            "x-amz-content-sha256",
            "x-amz-date",
            "x-amz-security-token",
        ] {
            assert!(names.iter().any(|n| n == required), "{what}: {required}");
        }
        assert!(names.is_sorted(), "{what}: {names:?}");
        names.dedup();
        assert_eq!(names.len(), signed_headers(request).len());

        assert_eq!(
            request.header("x-amz-content-sha256"),
            Some(hex(&Sha256::digest(&request.body)).as_str()),
            "{what}"
        );
        assert_eq!(
            request.header("host"),
            Some(proxy.addr.to_string().as_str()),
            "{what}"
        );
        assert_eq!(
            request.header("x-amz-security-token"),
            Some(TOKEN),
            "{what}"
        );
        assert!(request.header("x-amz-trailer").is_none(), "{what}");
        assert!(request.header("content-encoding").is_none(), "{what}");
        assert!(
            !request
                .headers()
                .any(|(name, _)| name.starts_with("x-amz-checksum-")),
            "{what}"
        );
        assert!(!authorization.contains(TOKEN) && !authorization.contains(SECRET_KEY));
    }
}

#[tokio::test]
async fn writes_an_object_with_its_metadata_and_the_hash_of_its_body() {
    let (proxy, client) = wire().await;
    let etag = client
        .put_object(
            KEY,
            Bytes::from_static(b"Welcome to Amazon S3."),
            &metadata(),
            foreground(),
        )
        .await
        .unwrap();
    assert_eq!(etag, "\"put\"");
    let seen = last(&proxy);
    assert_eq!(seen.method, "PUT");
    assert_eq!(seen.target, format!("/{BUCKET}/{ENCODED_KEY}"));
    assert_eq!(seen.body, b"Welcome to Amazon S3.");
    assert_eq!(seen.header("content-length"), Some("21"));
    assert_eq!(
        seen.header("x-amz-content-sha256"),
        Some("44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")
    );
    assert_metadata_sent(&seen);
}

#[tokio::test]
async fn sends_a_range_of_a_file_under_the_hash_it_was_given() {
    let (proxy, client) = wire().await;
    let contents = pattern(0, 200_000);
    let file = file_with(&contents);
    let wanted = contents.slice(1_000..150_000);
    let payload = file_payload(&file, 1_000, &wanted);
    let hash = payload.sha256().to_owned();
    client
        .put_object(KEY, payload, &metadata(), foreground())
        .await
        .unwrap();
    let seen = last(&proxy);
    assert_eq!(seen.body, wanted);
    assert_eq!(seen.header("content-length"), Some("149000"));
    assert_eq!(seen.header("x-amz-content-sha256"), Some(hash.as_str()));
    assert_eq!(hash, hex(&Sha256::digest(&wanted)));
    assert_metadata_sent(&seen);

    let id = client
        .create_multipart_upload(KEY, &Metadata::default(), foreground())
        .await
        .unwrap();
    let part = contents.slice(..BODY_CHUNK);
    client
        .upload_part(KEY, &id, 1, file_payload(&file, 0, &part), foreground())
        .await
        .unwrap();
    let seen = last(&proxy);
    assert_eq!(seen.body, part);
    assert_eq!(
        seen.header("content-length"),
        Some(BODY_CHUNK.to_string().as_str())
    );
}

#[tokio::test]
async fn reads_a_range_that_must_match_an_etag() {
    let (proxy, client) = wire().await;
    client
        .get_object(KEY, range(5, 10), Some("abc"), foreground())
        .await
        .unwrap();
    let seen = last(&proxy);
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.target, format!("/{BUCKET}/{ENCODED_KEY}"));
    assert_eq!(seen.header("range"), Some("bytes=5-14"));
    assert_eq!(seen.header("if-match"), Some("\"abc\""));

    // The canned answer is for another range, so the call fails.
    client
        .get_object(KEY, range(0, 1), None, foreground())
        .await
        .unwrap_err();
    let seen = last(&proxy);
    assert_eq!(seen.header("range"), Some("bytes=0-0"));
    assert_eq!(seen.header("if-match"), None);
}

#[tokio::test]
async fn copies_name_their_source_and_say_what_happens_to_the_metadata() {
    let (proxy, client) = wire().await;
    let copied = client
        .copy_object(
            KEY,
            "to/target key",
            CopyMetadata::Copy {
                storage_class: Some("STANDARD_IA"),
            },
            foreground(),
        )
        .await
        .unwrap();
    assert_eq!(copied.etag, "\"copy\"");
    let seen = last(&proxy);
    assert_eq!(seen.method, "PUT");
    assert_eq!(seen.target, format!("/{BUCKET}/to/target%20key"));
    assert_eq!(
        seen.header("x-amz-copy-source"),
        Some(format!("{BUCKET}/{ENCODED_KEY}").as_str())
    );
    assert_eq!(seen.header("x-amz-metadata-directive"), Some("COPY"));
    assert_eq!(seen.header("x-amz-storage-class"), Some("STANDARD_IA"));
    assert_eq!(seen.header("content-type"), None);
    assert_eq!(seen.header("x-amz-meta-mtime"), None);

    client
        .copy_object(
            KEY,
            KEY,
            CopyMetadata::Copy {
                storage_class: None,
            },
            foreground(),
        )
        .await
        .unwrap();
    assert_eq!(last(&proxy).header("x-amz-storage-class"), None);

    client
        .copy_object(KEY, KEY, CopyMetadata::Replace(&metadata()), foreground())
        .await
        .unwrap();
    let seen = last(&proxy);
    assert_eq!(seen.header("x-amz-metadata-directive"), Some("REPLACE"));
    assert_eq!(
        seen.header("x-amz-copy-source"),
        Some(format!("{BUCKET}/{ENCODED_KEY}").as_str())
    );
    assert_metadata_sent(&seen);
}

#[tokio::test]
async fn writes_the_requests_of_a_multipart_upload() {
    let (proxy, client) = wire().await;

    let id = client
        .create_multipart_upload(KEY, &metadata(), foreground())
        .await
        .unwrap();
    assert_eq!(id, UPLOAD_ID);
    let seen = last(&proxy);
    assert_eq!(
        (seen.method.as_str(), seen.target.as_str()),
        ("POST", format!("/{BUCKET}/{ENCODED_KEY}?uploads").as_str())
    );
    assert_eq!(seen.header("content-type"), Some("text/plain"));
    assert_eq!(seen.header("x-amz-meta-mtime"), Some("1.5"));
    assert_eq!(seen.header("x-amz-storage-class"), Some("STANDARD_IA"));
    assert_eq!(seen.header("content-length"), Some("0"));

    let etag = client
        .upload_part(KEY, &id, 3, Bytes::from_static(b"part body"), foreground())
        .await
        .unwrap();
    assert_eq!(etag, "\"part\"");
    let seen = last(&proxy);
    assert_eq!(seen.method, "PUT");
    assert_eq!(
        seen.target,
        format!("/{BUCKET}/{ENCODED_KEY}?partNumber=3&uploadId={ENCODED_UPLOAD_ID}")
    );
    assert_eq!(seen.body, b"part body");

    let copied = client
        .upload_part_copy(KEY, &id, 4, "src/obj \u{e9}", range(10, 10), foreground())
        .await
        .unwrap();
    assert_eq!(copied.etag, "\"partcopy\"");
    let seen = last(&proxy);
    assert_eq!(
        seen.target,
        format!("/{BUCKET}/{ENCODED_KEY}?partNumber=4&uploadId={ENCODED_UPLOAD_ID}")
    );
    assert_eq!(
        seen.header("x-amz-copy-source"),
        Some(format!("{BUCKET}/src/obj%20%C3%A9").as_str())
    );
    assert_eq!(seen.header("x-amz-copy-source-range"), Some("bytes=10-19"));

    let parts = [
        CompletedPart {
            number: 3,
            etag: "\"a54357aff0632cce46d942af68356b38\"".into(),
        },
        CompletedPart {
            number: 4,
            etag: "\"0c78aef83f66abc1fa1e8477f296d394\"".into(),
        },
    ];
    let etag = client
        .complete_multipart_upload(KEY, &id, &parts, 20, None, foreground())
        .await
        .unwrap();
    assert_eq!(etag, "\"done-2\"");
    let seen = last(&proxy);
    assert_eq!(seen.method, "POST");
    assert_eq!(
        seen.target,
        format!("/{BUCKET}/{ENCODED_KEY}?uploadId={ENCODED_UPLOAD_ID}")
    );

    client
        .abort_multipart_upload(KEY, &id, foreground())
        .await
        .unwrap();
    let seen = last(&proxy);
    assert_eq!(seen.method, "DELETE");
    assert_eq!(
        seen.target,
        format!("/{BUCKET}/{ENCODED_KEY}?uploadId={ENCODED_UPLOAD_ID}")
    );
}

#[tokio::test]
async fn writes_the_requests_that_delete() {
    let (proxy, client) = wire().await;
    client.delete_object(KEY, foreground()).await.unwrap();
    let seen = last(&proxy);
    assert_eq!(seen.method, "DELETE");
    assert_eq!(seen.target, format!("/{BUCKET}/{ENCODED_KEY}"));

    let failed = client
        .delete_objects(&["a b", "\u{e9}&"], foreground())
        .await
        .unwrap();
    assert!(failed.is_empty());
    let seen = last(&proxy);
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.target, format!("/{BUCKET}?delete"));
    let body = "<Delete><Quiet>true</Quiet><Object><Key>a b</Key></Object>\
                <Object><Key>\u{e9}&amp;</Key></Object></Delete>";
    assert_eq!(seen.body, body.as_bytes());
    assert_eq!(seen.header("content-md5"), Some("1j0f5yRn64P4UmqlcgumsQ=="));
}

#[tokio::test]
async fn writes_a_listing_request() {
    let (proxy, client) = wire().await;
    client
        .list_objects(&ListRequest::default(), foreground())
        .await
        .unwrap();
    let seen = last(&proxy);
    assert_eq!(seen.method, "GET");
    assert_eq!(
        seen.target,
        format!("/{BUCKET}?encoding-type=url&list-type=2")
    );

    client
        .list_objects(
            &ListRequest {
                prefix: "a b/",
                delimited: true,
                continuation_token: Some("t+/="),
                max_keys: Some(5),
            },
            foreground(),
        )
        .await
        .unwrap();
    assert_eq!(
        last(&proxy).target,
        format!(
            "/{BUCKET}?continuation-token=t%2B%2F%3D&delimiter=%2F&encoding-type=url\
             &list-type=2&max-keys=5&prefix=a%20b%2F"
        )
    );
}
