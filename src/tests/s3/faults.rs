//! The client against a proxy that fails chosen requests.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::fixture::{
    MIB, OLD, TestBucket, file_payload, file_with, foreground, is_missing, offline_client,
    overwrite, pattern, put, range,
};
use super::proxy::{Fault, Proxy, Reply, Seen};
use super::share::{wait_for_requests, wait_until};
use crate::s3::client::{CopyMetadata, ListRequest, MAX_BODY, Settings};
use crate::s3::error::S3Error;
use crate::s3::object::Metadata;
use crate::s3::retry::{FOREGROUND_ATTEMPTS, Retry, Stop};
use crate::s3::xml::CompletedPart;

const KEY: &str = "dir/file one.bin";

/// The idle limit of the tests that wait for it against the real gateway. A
/// loaded machine may need most of a second for one request.
const IDLE: Duration = Duration::from_secs(1);

/// Waits of a millisecond between attempts.
fn fast_retries(settings: &mut Settings) {
    settings.backoff_base = Duration::from_millis(1);
}

/// Fast retries, and a request that moves nothing for `idle` fails.
fn idle_after(idle: Duration) -> impl FnOnce(&mut Settings) {
    move |settings| {
        fast_retries(settings);
        settings.idle_timeout = idle;
    }
}

async fn through_a_proxy() -> (TestBucket, Proxy) {
    let bucket = TestBucket::new().await;
    let proxy = Proxy::start(bucket.gateway.addr).await;
    (bucket, proxy)
}

/// A multipart upload with every part uploaded and nothing completed. Returns
/// the upload id, the parts and the size of the object.
async fn pending_upload(bucket: &TestBucket, key: &str) -> (String, Vec<CompletedPart>, u64) {
    let client = &bucket.client;
    let id = client
        .create_multipart_upload(key, &Metadata::default(), foreground())
        .await
        .unwrap();
    let first = client
        .upload_part(key, &id, 1, pattern(0, 5 * MIB), foreground())
        .await
        .unwrap();
    let second = client
        .upload_part(key, &id, 2, pattern(9, 1000), foreground())
        .await
        .unwrap();
    let parts = vec![
        CompletedPart {
            number: 1,
            etag: first,
        },
        CompletedPart {
            number: 2,
            etag: second,
        },
    ];
    (id, parts, (5 * MIB + 1000) as u64)
}

fn completes(seen: &Seen) -> bool {
    seen.method == "POST" && seen.has_param("uploadId")
}

#[tokio::test]
async fn a_stop_ends_the_wait_between_attempts() {
    let (bucket, proxy) = through_a_proxy().await;
    proxy.inject(
        |seen| seen.method == "HEAD",
        Fault::Reply(Reply::error(503, "SlowDown")),
        usize::MAX,
    );
    // The wait after the first failure is a random time up to a minute.
    let client = bucket.client_at(proxy.addr, |settings| {
        settings.backoff_base = Duration::from_secs(3600);
    });
    let stop = Stop::new();
    let call = tokio::spawn({
        let (client, retry) = (client.clone(), Retry::until(&stop));
        async move { client.head_object(KEY, retry).await }
    });
    wait_for_requests(&proxy, 1, |seen| seen.method == "HEAD").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stopped = Instant::now();
    stop.stop();
    let error = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("the call outlived the stop")
        .unwrap()
        .unwrap_err();
    assert!(error.is_stopped(), "{error:?}");
    assert!(!error.is_transient());
    assert!(
        stopped.elapsed() < Duration::from_secs(5),
        "{:?}",
        stopped.elapsed()
    );
}

#[tokio::test]
async fn a_stop_lets_the_request_under_way_finish() {
    let (bucket, proxy) = through_a_proxy().await;
    put(&bucket.client, KEY, pattern(0, 10)).await;
    let gate = Arc::new(Notify::new());
    proxy.inject(|seen| seen.method == "HEAD", Fault::Hold(gate.clone()), 1);
    let client = bucket.client_at(proxy.addr, fast_retries);
    let stop = Stop::new();
    let call = tokio::spawn({
        let (client, retry) = (client.clone(), Retry::until(&stop));
        async move { client.head_object(KEY, retry).await }
    });
    wait_for_requests(&proxy, 1, |seen| seen.method == "HEAD").await;
    stop.stop();
    // A stop that cut the request short would have ended the call by now.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!call.is_finished());
    gate.notify_one();
    let head = call.await.unwrap().unwrap();
    assert_eq!(head.size, 10);
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 1);

    // Once stopped, a call sends nothing.
    let error = client
        .head_object(KEY, Retry::until(&stop))
        .await
        .unwrap_err();
    assert!(error.is_stopped(), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 1);
}

#[tokio::test]
async fn retries_what_trying_again_can_fix_and_nothing_else() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    put(&bucket.client, KEY, pattern(0, 10)).await;
    let read = || client.get_object(KEY, range(0, 10), None, foreground());
    let reads = |proxy: &Proxy| proxy.count(|seen| seen.method == "GET");

    let mut expected = 0;
    for (status, code) in [(503, "SlowDown"), (400, "RequestTimeout")] {
        proxy.inject(
            |seen| seen.method == "GET",
            Fault::Reply(Reply::error(status, code)),
            1,
        );
        read().await.unwrap();
        expected += 2;
        assert_eq!(reads(&proxy), expected, "{status} {code}");
    }

    for (status, code) in [
        (403, "AccessDenied"),
        (404, "NoSuchKey"),
        (403, "RequestTimeTooSkewed"),
    ] {
        proxy.inject(
            |seen| seen.method == "GET",
            Fault::Reply(Reply::error(status, code)),
            1,
        );
        let error = read().await.unwrap_err();
        expected += 1;
        assert_eq!(error.http_status(), Some(status), "{status} {code}");
        assert_eq!(error.code(), Some(code));
        assert_eq!(error.request_id(), Some("PROXYREQ"));
        assert_eq!(reads(&proxy), expected, "{status} {code}");
    }
}

#[tokio::test]
async fn a_foreground_call_stops_at_its_attempt_limit() {
    let (bucket, proxy) = through_a_proxy().await;
    proxy.inject(
        |seen| seen.method == "GET",
        Fault::Reply(Reply::error(503, "SlowDown")),
        usize::MAX,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .get_object(KEY, range(0, 10), None, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.http_status(), Some(503), "{error:?}");
    assert_eq!(error.code(), Some("SlowDown"));
    assert_eq!(
        proxy.count(|seen| seen.method == "GET"),
        FOREGROUND_ATTEMPTS as usize
    );
}

#[tokio::test]
async fn a_background_call_keeps_trying_past_the_foreground_attempt_limit() {
    let (bucket, proxy) = through_a_proxy().await;
    put(&bucket.client, KEY, pattern(0, 10)).await;
    proxy.inject(
        |seen| seen.method == "HEAD",
        Fault::Reply(Reply::error(503, "SlowDown")),
        8,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let head = client.head_object(KEY, Retry::background()).await.unwrap();
    assert_eq!(head.size, 10);
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 9);
}

#[tokio::test]
async fn the_deadline_ends_retries_before_the_attempts_run_out() {
    let (bucket, proxy) = through_a_proxy().await;
    proxy.inject(
        |seen| seen.method == "GET",
        Fault::Reply(Reply::error(503, "SlowDown")),
        usize::MAX,
    );
    // A wait after the first failure is a random time up to 5 s, almost
    // always far past the deadline, and a call does not sit it out.
    let client = bucket.client_at(proxy.addr, |settings| {
        settings.backoff_base = Duration::from_secs(60);
    });
    for _ in 0..5 {
        let started = Instant::now();
        let error = client
            .get_object(
                KEY,
                range(0, 10),
                None,
                Retry::within(Duration::from_millis(100)),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                S3Error::Status { status: 503, .. } | S3Error::DeadlineExceeded
            ),
            "{error:?}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "{:?}",
            started.elapsed()
        );
    }
    assert!(proxy.count(|seen| seen.method == "GET") < 5 * FOREGROUND_ATTEMPTS as usize);
}

#[tokio::test]
async fn a_stalled_request_ends_at_the_deadline() {
    let (bucket, proxy) = through_a_proxy().await;
    proxy.inject(|seen| seen.method == "GET", Fault::Stall, usize::MAX);
    let client = bucket.client_at(proxy.addr, fast_retries);
    let deadline = Duration::from_millis(1500);
    let started = Instant::now();
    let error = client
        .get_object(KEY, range(0, 10), None, Retry::within(deadline))
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    assert!(matches!(error, S3Error::DeadlineExceeded), "{error:?}");
    assert!(
        elapsed >= deadline - Duration::from_millis(50),
        "{elapsed:?}"
    );
    // The idle limit is a minute, so a call that waited for it would take longer.
    assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
    assert_eq!(proxy.count(|seen| seen.method == "GET"), 1);
}

#[tokio::test]
async fn a_request_that_moves_no_data_fails_and_is_retried() {
    let (bucket, proxy) = through_a_proxy().await;
    put(&bucket.client, KEY, pattern(0, 100)).await;
    proxy.inject(|seen| seen.method == "GET", Fault::Stall, 1);
    let client = bucket.client_at(proxy.addr, idle_after(IDLE));
    let started = Instant::now();
    let object = client
        .get_object(KEY, range(0, 100), None, foreground())
        .await
        .unwrap();
    assert_eq!(object.data, pattern(0, 100));
    assert!(
        started.elapsed() >= IDLE - Duration::from_millis(50),
        "{:?}",
        started.elapsed()
    );
    // A loaded machine may let the second attempt idle out as well.
    assert!(proxy.count(|seen| seen.method == "GET") >= 2);
}

#[tokio::test]
async fn a_response_body_that_stops_arriving_fails_and_is_retried() {
    let (bucket, proxy) = through_a_proxy().await;
    let data = pattern(0, 200_000);
    put(&bucket.client, KEY, data.clone()).await;
    proxy.inject(|seen| seen.method == "GET", Fault::StallBody, 1);
    let client = bucket.client_at(proxy.addr, idle_after(IDLE));
    let object = client
        .get_object(KEY, range(0, 200_000), None, foreground())
        .await
        .unwrap();
    assert_eq!(object.data, data);
    assert!(proxy.count(|seen| seen.method == "GET") >= 2);
}

#[tokio::test]
async fn retries_a_connection_dropped_mid_body() {
    let (bucket, proxy) = through_a_proxy().await;
    let data = pattern(0, 300_000);
    put(&bucket.client, KEY, data.clone()).await;
    proxy.inject(|seen| seen.method == "GET", Fault::CutBody, 2);
    let client = bucket.client_at(proxy.addr, fast_retries);
    let object = client
        .get_object(KEY, range(0, 300_000), None, foreground())
        .await
        .unwrap();
    assert_eq!(object.data, data);
    assert_eq!(proxy.count(|seen| seen.method == "GET"), 3);
}

#[tokio::test]
async fn retries_a_request_whose_connection_is_dropped_after_it_was_served() {
    let (bucket, proxy) = through_a_proxy().await;
    proxy.inject(|seen| seen.method == "PUT", Fault::DropAnswer, 1);
    let client = bucket.client_at(proxy.addr, fast_retries);
    client
        .put_object(KEY, pattern(0, 50), &Metadata::default(), foreground())
        .await
        .unwrap();
    assert_eq!(proxy.count(|seen| seen.method == "PUT"), 2);
    assert_eq!(
        bucket
            .client
            .head_object(KEY, foreground())
            .await
            .unwrap()
            .size,
        50
    );
}

#[tokio::test]
async fn retries_the_data_of_a_part_that_failed_to_send() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    let id = client
        .create_multipart_upload(KEY, &Metadata::default(), foreground())
        .await
        .unwrap();
    proxy.inject(
        |seen| seen.method == "PUT" && seen.has_param("partNumber"),
        Fault::Reply(Reply::error(500, "InternalError")),
        1,
    );
    let part = pattern(3, 6 * MIB);
    client
        .upload_part(KEY, &id, 1, part.clone(), foreground())
        .await
        .unwrap();
    let sent: Vec<_> = proxy
        .seen()
        .into_iter()
        .filter(|seen| seen.method == "PUT" && seen.has_param("partNumber"))
        .collect();
    assert_eq!(sent.len(), 2);
    for seen in sent {
        assert_eq!(seen.body, part, "the whole part is sent again");
    }
}

#[tokio::test]
async fn a_retried_put_reads_the_file_again_from_its_offset() {
    let (bucket, proxy) = through_a_proxy().await;
    let contents = pattern(0, 300_000);
    let file = file_with(&contents);
    let wanted = contents.slice(1_234..221_234);
    let payload = file_payload(&file, 1_234, &wanted);
    proxy.inject(
        |seen| seen.method == "PUT",
        Fault::Reply(Reply::error(503, "SlowDown")),
        1,
    );
    proxy.inject(|seen| seen.method == "PUT", Fault::DropAnswer, 1);
    let client = bucket.client_at(proxy.addr, fast_retries);
    client
        .put_object(KEY, payload, &Metadata::default(), foreground())
        .await
        .unwrap();
    let sent: Vec<_> = proxy
        .seen()
        .into_iter()
        .filter(|seen| seen.method == "PUT")
        .collect();
    assert_eq!(sent.len(), 3);
    for seen in &sent {
        assert_eq!(seen.body, wanted, "every attempt sends the whole range");
    }
    let stored = bucket
        .client
        .get_object(KEY, range(0, 300_000), None, foreground())
        .await
        .unwrap();
    assert_eq!(stored.data, wanted);
}

#[tokio::test]
async fn a_file_that_changed_aborts_the_request_and_is_not_retried() {
    let (bucket, proxy) = through_a_proxy().await;
    let contents = pattern(0, 400_000);
    let file = file_with(&contents);
    let payload = file_payload(&file, 0, &contents);
    overwrite(&file, 399_990, b"overwritten");
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .put_object(KEY, payload, &Metadata::default(), foreground())
        .await
        .unwrap_err();
    assert!(matches!(error, S3Error::SourceChanged), "{error:?}");
    wait_until("the client did not break off the request", || {
        proxy.aborted() > 0
    })
    .await;
    assert_eq!(proxy.aborted(), 1, "the client broke off the request");
    assert_eq!(proxy.count(|seen| seen.method == "PUT"), 0);
    assert!(is_missing(&bucket.client, KEY).await);
}

#[tokio::test]
async fn a_store_that_answers_before_the_body_is_in_gets_no_more_of_it() {
    let (bucket, proxy) = through_a_proxy().await;
    proxy.inject(
        |seen| seen.method == "PUT",
        Fault::AnswerEarly(Reply::error(403, "AccessDenied")),
        1,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let contents = pattern(0, 24 * MIB);
    let file = file_with(&contents);
    let payload = file_payload(&file, 0, &contents);
    let error = client
        .put_object(KEY, payload, &Metadata::default(), foreground())
        .await
        .unwrap_err();
    assert_eq!(error.http_status(), Some(403), "{error:?}");
    assert_eq!(error.code(), Some("AccessDenied"));
    assert_eq!(proxy.count(|seen| seen.method == "PUT"), 1);
    // The proxy takes about a megabyte a second, so a connection that sent the
    // rest of the file would hold it for far longer than this.
    wait_until("the connection still holds the file", || {
        Arc::strong_count(&file) == 1
    })
    .await;
}

#[tokio::test]
async fn a_store_that_finds_the_body_changed_ends_the_call() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    for (round, code) in ["XAmzContentSHA256Mismatch", "BadDigest"]
        .into_iter()
        .enumerate()
    {
        proxy.inject(
            |seen| seen.method == "PUT",
            Fault::Reply(Reply::error(400, code)),
            usize::MAX,
        );
        let error = client
            .put_object(
                KEY,
                pattern(0, 100),
                &Metadata::default(),
                Retry::background(),
            )
            .await
            .unwrap_err();
        assert!(error.is_source_changed(), "{error:?}");
        assert!(!error.is_transient());
        assert_eq!(error.code(), Some(code));
        assert_eq!(proxy.count(|seen| seen.method == "PUT"), round + 1);
        proxy.clear_rules();
    }
}

#[tokio::test]
async fn a_response_body_other_than_object_data_is_capped() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    let document = "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
    let padded = |len: usize| {
        let mut body = document.as_bytes().to_vec();
        body.resize(len, b' ');
        Reply::new(200, body)
    };
    proxy.inject(
        |seen| seen.method == "GET",
        Fault::Reply(padded(MAX_BODY)),
        1,
    );
    let listing = client
        .list_objects(&ListRequest::default(), foreground())
        .await
        .unwrap();
    assert!(listing.objects.is_empty());

    proxy.inject(
        |seen| seen.method == "GET",
        Fault::Reply(padded(MAX_BODY + 1)),
        usize::MAX,
    );
    let error = client
        .list_objects(&ListRequest::default(), foreground())
        .await
        .unwrap_err();
    assert!(matches!(error, S3Error::InvalidResponse(_)), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "GET"), 2);
}

#[tokio::test]
async fn an_error_answer_with_a_body_over_the_cap_is_still_the_stores_status() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    let page = |status| Reply::new(status, vec![b' '; MAX_BODY + 1]);

    proxy.inject(|seen| seen.method == "GET", Fault::Reply(page(403)), 1);
    let error = client
        .get_object(KEY, range(0, 10), None, foreground())
        .await
        .unwrap_err();
    assert_eq!((error.http_status(), error.code()), (Some(403), None));
    assert_eq!(proxy.count(|seen| seen.method == "GET"), 1);

    // A 404 whose body is too long to read is not a deleted key either.
    proxy.inject(|seen| seen.method == "DELETE", Fault::Reply(page(404)), 1);
    let error = client.delete_object(KEY, foreground()).await.unwrap_err();
    assert_eq!(error.http_status(), Some(404), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "DELETE"), 1);
}

#[tokio::test]
async fn a_ranged_get_answered_with_200_is_an_error() {
    let (bucket, proxy) = through_a_proxy().await;
    let data = pattern(0, 100);
    let etag = put(&bucket.client, KEY, data.clone()).await;
    let ignoring_range = Reply::new(200, data.to_vec())
        .header("ETag", &etag)
        .header("Last-Modified", OLD);
    proxy.inject(
        |seen| seen.method == "GET",
        Fault::Reply(ignoring_range),
        usize::MAX,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .get_object(KEY, range(10, 20), None, foreground())
        .await
        .unwrap_err();
    assert!(matches!(error, S3Error::InvalidResponse(_)), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "GET"), 1);
}

#[tokio::test]
async fn a_ranged_get_from_the_start_may_be_answered_with_the_whole_object() {
    let (bucket, proxy) = through_a_proxy().await;
    let data = pattern(0, 100);
    let etag = put(&bucket.client, KEY, data.clone()).await;
    let whole = Reply::new(200, data.to_vec())
        .header("ETag", &etag)
        .header("Last-Modified", OLD);
    proxy.inject(|seen| seen.method == "GET", Fault::Reply(whole), usize::MAX);
    let client = bucket.client_at(proxy.addr, fast_retries);

    let prefix = client
        .get_object(KEY, range(0, 10), Some(&etag), foreground())
        .await
        .unwrap();
    assert_eq!(prefix.data, data.slice(0..10));
    assert_eq!(prefix.head.size, 100);
    let all = client
        .get_object(KEY, range(0, 500), None, foreground())
        .await
        .unwrap();
    assert_eq!(all.data, data);
    assert_eq!(all.head.size, 100);
}

#[tokio::test]
async fn a_206_that_is_not_the_range_asked_for_is_an_error() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    let partial = |range: Option<&str>, body: usize| {
        let reply = Reply::new(206, pattern(5, body).to_vec())
            .header("ETag", "\"e\"")
            .header("Last-Modified", OLD);
        match range {
            Some(range) => reply.header("Content-Range", range),
            None => reply,
        }
    };
    let mut expected_requests = 0;
    for (what, reply) in [
        ("it starts elsewhere", partial(Some("bytes 6-15/100"), 10)),
        ("it has no Content-Range", partial(None, 10)),
        (
            "it ends past the range",
            partial(Some("bytes 5-20/100"), 16),
        ),
        (
            "it stops short of the object",
            partial(Some("bytes 5-9/100"), 5),
        ),
        ("the body is shorter", partial(Some("bytes 5-14/100"), 4)),
        ("the body is longer", partial(Some("bytes 5-14/100"), 12)),
    ] {
        proxy.inject(|seen| seen.method == "GET", Fault::Reply(reply), 1);
        let error = client
            .get_object(KEY, range(5, 10), None, foreground())
            .await
            .unwrap_err();
        expected_requests += 1;
        assert!(
            matches!(error, S3Error::InvalidResponse(_)),
            "{what}: {error:?}"
        );
        assert_eq!(
            proxy.count(|seen| seen.method == "GET"),
            expected_requests,
            "{what}"
        );
    }

    proxy.inject(
        |seen| seen.method == "GET",
        Fault::Reply(partial(Some("bytes 5-14/100"), 10)),
        1,
    );
    let object = client
        .get_object(KEY, range(5, 10), None, foreground())
        .await
        .unwrap();
    assert_eq!((object.head.size, object.data), (100, pattern(5, 10)));
}

#[tokio::test]
async fn a_get_that_returns_another_version_is_a_failed_precondition() {
    let (bucket, proxy) = through_a_proxy().await;
    let data = pattern(0, 100);
    let etag = put(&bucket.client, KEY, data.clone()).await;
    let other_version = Reply::new(206, data.slice(0..10).to_vec())
        .header("ETag", "\"0123456789abcdef0123456789abcdef\"")
        .header("Content-Range", "bytes 0-9/100")
        .header("Last-Modified", OLD);
    proxy.inject(
        |seen| seen.method == "GET",
        Fault::Reply(other_version),
        usize::MAX,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);

    let error = client
        .get_object(KEY, range(0, 10), Some(&etag), foreground())
        .await
        .unwrap_err();
    assert!(error.is_precondition_failed(), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "GET"), 1);

    let unchecked = client
        .get_object(KEY, range(0, 10), None, foreground())
        .await
        .unwrap();
    assert_eq!(unchecked.head.etag, "\"0123456789abcdef0123456789abcdef\"");
}

#[tokio::test]
async fn a_copy_that_answers_200_with_an_error_document_is_an_error() {
    let (bucket, proxy) = through_a_proxy().await;
    put(&bucket.client, "from", pattern(0, 10)).await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    let copy = CopyMetadata::Copy {
        storage_class: None,
    };

    proxy.inject(
        |seen| seen.method == "PUT",
        Fault::Reply(Reply::error(200, "AccessDenied")),
        1,
    );
    let error = client
        .copy_object("from", "to", copy, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.http_status(), Some(200), "{error:?}");
    assert_eq!(error.code(), Some("AccessDenied"));
    assert!(matches!(
        error.into_smb_error(),
        crate::SmbError::AccessDenied
    ));
    assert_eq!(proxy.count(|seen| seen.method == "PUT"), 1);
    assert!(is_missing(&bucket.client, "to").await);

    proxy.inject(
        |seen| seen.method == "PUT",
        Fault::Reply(Reply::error(200, "InternalError")),
        1,
    );
    client
        .copy_object("from", "to", copy, foreground())
        .await
        .unwrap();
    assert_eq!(proxy.count(|seen| seen.method == "PUT"), 3);
    bucket.client.head_object("to", foreground()).await.unwrap();
}

#[tokio::test]
async fn a_part_copy_that_answers_200_with_an_error_document_is_an_error() {
    let (bucket, proxy) = through_a_proxy().await;
    put(&bucket.client, "from", pattern(0, 10)).await;
    let id = bucket
        .client
        .create_multipart_upload("to", &Metadata::default(), foreground())
        .await
        .unwrap();
    proxy.inject(
        |seen| seen.method == "PUT" && seen.has_param("partNumber"),
        Fault::Reply(Reply::error(200, "AccessDenied")),
        usize::MAX,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .upload_part_copy("to", &id, 1, "from", range(0, 10), foreground())
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("AccessDenied"), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "PUT"), 1);
}

#[tokio::test]
async fn a_complete_that_answers_200_with_an_error_document_is_an_error() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    proxy.inject(
        completes,
        Fault::Reply(Reply::error(200, "AccessDenied")),
        usize::MAX,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .complete_multipart_upload(KEY, &id, &parts, size, None, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("AccessDenied"), "{error:?}");
    assert_eq!(proxy.count(completes), 1);
    assert!(is_missing(&bucket.client, KEY).await);
}

/// The faults of a Complete the gateway served and the client never heard of.
/// The first attempt reaches the gateway, which completes the upload, and its
/// answer is dropped. The second gets what a store that forgets finished
/// uploads answers.
fn lost_answer_then_no_such_upload(proxy: &Proxy) {
    proxy.inject(completes, Fault::DropAnswer, 1);
    proxy.inject(
        completes,
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        1,
    );
}

#[tokio::test]
async fn a_retried_complete_succeeds_when_the_object_is_already_there() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    lost_answer_then_no_such_upload(&proxy);
    let client = bucket.client_at(proxy.addr, fast_retries);
    let etag = client
        .complete_multipart_upload(KEY, &id, &parts, size, None, foreground())
        .await
        .unwrap();
    let head = bucket.client.head_object(KEY, foreground()).await.unwrap();
    assert_eq!((head.size, head.etag), (size, etag));
    assert_eq!(proxy.count(completes), 2);
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 1);
}

#[tokio::test]
async fn a_retried_complete_reports_a_failed_look_at_the_object() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    lost_answer_then_no_such_upload(&proxy);
    proxy.inject(
        |seen| seen.method == "HEAD",
        Fault::Reply(Reply::new(403, "")),
        usize::MAX,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .complete_multipart_upload(KEY, &id, &parts, size, None, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.http_status(), Some(403), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 1);
}

#[tokio::test]
async fn a_retried_complete_that_is_stopped_stays_stopped() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    let stop = Stop::new();
    proxy.inject(completes, Fault::DropAnswer, 1);
    // The rule stops the call as the second Complete arrives, so the stop
    // comes while that attempt is under way and before the call looks for the
    // object.
    proxy.inject(
        {
            let stop = stop.clone();
            move |seen| {
                let hit = completes(seen);
                if hit {
                    stop.stop();
                }
                hit
            }
        },
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        1,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .complete_multipart_upload(KEY, &id, &parts, size, None, Retry::until(&stop))
        .await
        .unwrap_err();
    assert!(error.is_stopped(), "{error:?}");
    assert_eq!(proxy.count(completes), 2);
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 0);
}

#[tokio::test]
async fn a_retried_complete_fails_when_the_object_has_another_size() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    lost_answer_then_no_such_upload(&proxy);
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .complete_multipart_upload(KEY, &id, &parts, size + 1, None, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("NoSuchUpload"), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 1);
}

#[tokio::test]
async fn a_retried_complete_fails_when_the_key_still_has_its_old_object() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    // The old object has the size of the new one, so only its ETag differs.
    let old_etag = put(&bucket.client, KEY, pattern(1, size as usize)).await;
    proxy.inject(completes, Fault::Reply(Reply::error(503, "SlowDown")), 1);
    proxy.inject(
        completes,
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        1,
    );
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .complete_multipart_upload(
            KEY,
            &id,
            &parts,
            size,
            Some(old_etag.trim_matches('"')),
            foreground(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("NoSuchUpload"), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 1);
    let head = bucket.client.head_object(KEY, foreground()).await.unwrap();
    assert_eq!(head.etag, old_etag);
}

#[tokio::test]
async fn a_retried_complete_succeeds_when_the_key_has_a_new_object() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    let old_etag = put(&bucket.client, KEY, pattern(1, size as usize)).await;
    lost_answer_then_no_such_upload(&proxy);
    let client = bucket.client_at(proxy.addr, fast_retries);
    let etag = client
        .complete_multipart_upload(KEY, &id, &parts, size, Some(&old_etag), foreground())
        .await
        .unwrap();
    assert_ne!(etag, old_etag);
    let head = bucket.client.head_object(KEY, foreground()).await.unwrap();
    assert_eq!((head.size, head.etag), (size, etag));
}

#[tokio::test]
async fn a_retried_complete_fails_when_there_is_no_object() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    bucket
        .client
        .abort_multipart_upload(KEY, &id, foreground())
        .await
        .unwrap();
    proxy.inject(completes, Fault::Reply(Reply::error(503, "SlowDown")), 1);
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .complete_multipart_upload(KEY, &id, &parts, size, None, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("NoSuchUpload"), "{error:?}");
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 1);
}

#[tokio::test]
async fn a_complete_that_finds_no_upload_at_the_first_attempt_is_an_error() {
    let (bucket, proxy) = through_a_proxy().await;
    let (id, parts, size) = pending_upload(&bucket, KEY).await;
    bucket
        .client
        .complete_multipart_upload(KEY, &id, &parts, size, None, foreground())
        .await
        .unwrap();
    proxy.inject(
        completes,
        Fault::Reply(Reply::error(404, "NoSuchUpload")),
        usize::MAX,
    );
    // The object is there with this size, but no attempt failed before.
    let client = bucket.client_at(proxy.addr, fast_retries);
    let error = client
        .complete_multipart_upload(KEY, &id, &parts, size, None, foreground())
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some("NoSuchUpload"), "{error:?}");
    assert_eq!(proxy.count(completes), 1);
    assert_eq!(proxy.count(|seen| seen.method == "HEAD"), 0);
}

#[tokio::test]
async fn retries_an_abort_and_accepts_an_upload_that_is_gone() {
    let (bucket, proxy) = through_a_proxy().await;
    let id = bucket
        .client
        .create_multipart_upload(KEY, &Metadata::default(), foreground())
        .await
        .unwrap();
    proxy.inject(
        |seen| seen.method == "DELETE",
        Fault::Reply(Reply::error(503, "SlowDown")),
        1,
    );
    proxy.inject(|seen| seen.method == "DELETE", Fault::DropAnswer, 1);
    let client = bucket.client_at(proxy.addr, fast_retries);
    // Attempt 1 gets a 503; attempt 2 aborts the upload and loses the answer;
    // attempt 3 finds the upload gone.
    client
        .abort_multipart_upload(KEY, &id, foreground())
        .await
        .unwrap();
    assert_eq!(proxy.count(|seen| seen.method == "DELETE"), 3);
}

#[tokio::test]
async fn a_delete_that_gets_404_succeeds_only_for_a_missing_key() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    let page = "<html><body><h1>404 Not Found</h1></body></html>";
    for (reply, deleted) in [
        (Reply::new(404, ""), true),
        (Reply::error(404, "NoSuchKey"), true),
        (Reply::error(404, "NoSuchBucket"), false),
        (Reply::new(404, page), false),
        (Reply::new(404, "not found"), false),
    ] {
        proxy.inject(
            |seen| seen.method == "DELETE",
            Fault::Reply(reply.clone()),
            1,
        );
        let result = client.delete_object(KEY, foreground()).await;
        assert_eq!(result.is_ok(), deleted, "{reply:?}: {result:?}");
    }
}

#[tokio::test]
async fn a_404_whose_body_is_cut_is_not_a_deleted_key() {
    let (bucket, proxy) = through_a_proxy().await;
    let client = bucket.client_at(proxy.addr, fast_retries);
    let deletes = |proxy: &Proxy| proxy.count(|seen| seen.method == "DELETE");
    let cut = || Fault::CutReply(Reply::error(404, "NoSuchKey"));
    let is_delete = |seen: &Seen| seen.method == "DELETE";

    // The first answer is lost half way. The second is the store's, and the
    // key goes with it.
    put(&bucket.client, KEY, pattern(0, 10)).await;
    proxy.inject(is_delete, cut(), 1);
    client.delete_object(KEY, foreground()).await.unwrap();
    assert_eq!(deletes(&proxy), 2);
    assert!(is_missing(&bucket.client, KEY).await);

    // No answer is whole, so the key is not known to be gone.
    put(&bucket.client, KEY, pattern(0, 10)).await;
    proxy.inject(is_delete, cut(), usize::MAX);
    let error = client.delete_object(KEY, foreground()).await.unwrap_err();
    assert!(matches!(error, S3Error::Transport(_)), "{error:?}");
    assert_eq!(deletes(&proxy), 2 + FOREGROUND_ATTEMPTS as usize);
    bucket.client.head_object(KEY, foreground()).await.unwrap();
}

/// Accepts connections on loopback and holds them open without reading or
/// writing. Counts the connections.
struct Mute {
    addr: SocketAddr,
    held: Arc<Mutex<Vec<TcpStream>>>,
    accepting: JoinHandle<()>,
}

impl Mute {
    async fn start() -> Mute {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let held = Arc::new(Mutex::new(Vec::new()));
        let keep = held.clone();
        let accepting = tokio::spawn(async move {
            while let Ok((connection, _)) = listener.accept().await {
                keep.lock().unwrap().push(connection);
            }
        });
        Mute {
            addr,
            held,
            accepting,
        }
    }

    fn connections(&self) -> usize {
        self.held.lock().unwrap().len()
    }
}

impl Drop for Mute {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

#[tokio::test]
async fn a_peer_that_stops_reading_fails_the_request_after_the_idle_time() {
    let mute = Mute::start().await;
    let client = offline_client(mute.addr, idle_after(Duration::from_millis(300)));
    let started = Instant::now();
    // More than the sockets of either side buffer.
    let error = client
        .put_object(
            KEY,
            pattern(0, 24 * MIB),
            &Metadata::default(),
            foreground(),
        )
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    assert!(matches!(error, S3Error::TimedOut), "{error:?}");
    wait_until("the listener accepted too few connections", || {
        mute.connections() >= FOREGROUND_ATTEMPTS as usize
    })
    .await;
    assert_eq!(mute.connections(), FOREGROUND_ATTEMPTS as usize);
    assert!(elapsed >= Duration::from_millis(1200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
}

#[tokio::test]
async fn a_closed_port_fails_as_a_transport_error() {
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let client = offline_client(addr, fast_retries);
    let error = client.head_object(KEY, foreground()).await.unwrap_err();
    assert!(matches!(error, S3Error::Transport(_)), "{error:?}");
    assert!(matches!(error.into_smb_error(), crate::SmbError::Io(_)));
}
