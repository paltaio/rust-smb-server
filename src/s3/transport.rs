//! The HTTP client the S3 requests go through.

use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http::Uri;
use hyper::body::{Body, Frame, SizeHint};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};
use tokio::time::Instant;
use tower_service::Service;
use tracing::warn;

use super::error::BoxError;
use super::payload::{BODY_CHUNK, BodyError, Fault, FileBody, Payload, Source};

/// Longest a new connection may take, name lookup and TLS handshake included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most bytes hyper buffers for a connection, for writing and for reading. It
/// polls a request body only while its write buffer is below this, so the data
/// queued behind the last piece the peer took is two pieces at most.
const MAX_BUFFER: usize = BODY_CHUNK;

/// A pooled HTTP/1.1 client for `https://` and `http://` endpoints.
pub(crate) type HttpClient = Client<ConnectTimeout<HttpsConnector<HttpConnector>>, RequestBody>;

/// A client that verifies servers against the platform's root certificates.
/// TLS runs on the ring provider, whatever the process default is. Fails
/// when the platform has no usable root certificate.
pub(crate) fn client() -> io::Result<HttpClient> {
    client_with(CONNECT_TIMEOUT)
}

fn client_with(connect_timeout: Duration) -> io::Result<HttpClient> {
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(platform_roots()?)
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Ok(Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .http1_max_buf_size(MAX_BUFFER)
        .build(ConnectTimeout {
            inner: connector,
            limit: connect_timeout,
        }))
}

/// A connector that fails a connection not finished within `limit`.
#[derive(Clone)]
pub(crate) struct ConnectTimeout<S> {
    inner: S,
    limit: Duration,
}

impl<S> Service<Uri> for ConnectTimeout<S>
where
    S: Service<Uri>,
    S::Response: Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connecting = self.inner.call(uri);
        let limit = self.limit;
        Box::pin(async move {
            match tokio::time::timeout(limit, connecting).await {
                Ok(connected) => connected.map_err(Into::into),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("no connection within {limit:?}"),
                )
                .into()),
            }
        })
    }
}

/// When a request last moved data. The body that sends the request and the
/// code that waits for the answer share one.
#[derive(Clone, Debug)]
pub(crate) struct Activity(Arc<ActivityClock>);

#[derive(Debug)]
struct ActivityClock {
    start: Instant,
    /// Milliseconds after `start` of the last activity.
    last: AtomicU64,
}

impl Activity {
    /// An activity that last moved data just now.
    pub(crate) fn new() -> Self {
        Activity(Arc::new(ActivityClock {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }))
    }

    /// Notes that data moved just now.
    pub(crate) fn touch(&self) {
        let elapsed = self.0.start.elapsed().as_millis();
        self.0.last.store(
            u64::try_from(elapsed).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn last(&self) -> Instant {
        self.0.start + Duration::from_millis(self.0.last.load(Ordering::Relaxed))
    }

    /// Waits for `work`. Gives up with `None` once `idle` has passed since the
    /// last [`touch`](Self::touch) and `work` is still pending.
    pub(crate) async fn watch<F: Future>(&self, idle: Duration, work: F) -> Option<F::Output> {
        let mut work = pin!(work);
        loop {
            tokio::select! {
                biased;
                output = &mut work => return Some(output),
                () = tokio::time::sleep_until(self.last() + idle) => {
                    if self.last() + idle <= Instant::now() {
                        return None;
                    }
                }
            }
        }
    }
}

/// The body of a request. It gives its bytes to the connection in pieces, and
/// the connection asks for the next piece only after it has written the
/// previous ones, so polls stop while the peer takes no data. Each piece marks
/// the [`Activity`] of the request. Once the body is [cut](Self::cut_on_drop),
/// a poll that still has bytes to give fails, which ends the connection.
pub(crate) struct RequestBody {
    kind: Kind,
    activity: Activity,
    fault: Fault,
    cut: Arc<AtomicBool>,
}

enum Kind {
    Memory(Bytes),
    File(FileBody),
}

impl RequestBody {
    /// A body that sends `payload` from its start.
    pub(crate) fn new(payload: &Payload, activity: Activity) -> Self {
        let fault = Fault::default();
        let kind = match &payload.source {
            Source::Memory(data) => Kind::Memory(data.clone()),
            Source::File(range) => Kind::File(FileBody::new(
                range.clone(),
                payload.sha256(),
                fault.clone(),
            )),
        };
        RequestBody {
            kind,
            activity,
            fault,
            cut: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The error that stopped this body, if one did. Where hyper fails a
    /// request for it, this says why.
    pub(crate) fn fault(&self) -> Fault {
        self.fault.clone()
    }

    /// A guard that cuts this body when it is dropped. A store may answer
    /// before it has read the whole body, and the connection goes on sending
    /// the rest, with the file open, after the call that waited for the answer
    /// has returned.
    pub(crate) fn cut_on_drop(&self) -> CutOnDrop {
        CutOnDrop(self.cut.clone())
    }

    /// The bytes not handed out yet.
    fn remaining(&self) -> u64 {
        match &self.kind {
            Kind::Memory(rest) => rest.len() as u64,
            Kind::File(file) => file.remaining(),
        }
    }
}

/// Cuts a [`RequestBody`] when dropped.
pub(crate) struct CutOnDrop(Arc<AtomicBool>);

impl Drop for CutOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.cut.load(Ordering::Acquire) && self.remaining() > 0 {
            return Poll::Ready(Some(Err(BodyError)));
        }
        let this = &mut *self;
        let piece = match &mut this.kind {
            Kind::Memory(rest) => {
                this.activity.touch();
                if rest.is_empty() {
                    return Poll::Ready(None);
                }
                let len = rest.len().min(BODY_CHUNK);
                Some(Ok(rest.split_to(len)))
            }
            Kind::File(file) => {
                // A poll that finds a read still running is not progress.
                if !file.is_reading() {
                    this.activity.touch();
                }
                let piece = ready!(file.poll_piece(cx));
                this.activity.touch();
                piece
            }
        };
        Poll::Ready(piece.map(|piece| piece.map(Frame::data)))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining() == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining())
    }
}

fn platform_roots() -> io::Result<RootCertStore> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
    if ignored > 0 || !loaded.errors.is_empty() {
        warn!(
            added,
            ignored,
            errors = ?loaded.errors,
            "some platform root certificates could not be loaded"
        );
    }
    if added == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no usable root certificates in the platform store",
        ));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::Write as _;
    use std::iter;

    use http::Request;
    use http_body_util::BodyExt as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use sha2::{Digest as _, Sha256};

    use super::super::encode::hex;
    use super::*;

    fn memory(data: Bytes, activity: Activity) -> RequestBody {
        RequestBody::new(&Payload::from(data), activity)
    }

    fn get(url: String) -> Request<RequestBody> {
        let body = memory(Bytes::new(), Activity::new());
        Request::get(url).body(body).unwrap()
    }

    #[tokio::test]
    async fn a_connection_that_never_completes_times_out() {
        // Nothing accepts on the listener, so the handshake gets no reply.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let request = get(format!("https://{}/", listener.local_addr().unwrap()));
        let client = client_with(Duration::from_millis(300)).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), client.request(request))
            .await
            .expect("the request outlived the connect timeout")
            .unwrap_err();
        let timed_out = iter::successors(error.source(), |e| (*e).source()).any(|e| {
            e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut)
        });
        assert!(timed_out, "{error:?}");
    }

    #[tokio::test]
    async fn an_https_request_reaches_the_tls_layer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let request = get(format!("https://{}/", listener.local_addr().unwrap()));
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut hello = [0; 4096];
            let _ = conn.read(&mut hello).await;
            let _ = conn.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            let _ = conn.shutdown().await;
            let _ = conn.read(&mut hello).await;
        });
        let client = client().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), client.request(request))
            .await
            .expect("the request got no answer")
            .unwrap_err();
        assert!(caused_by_rustls(&error), "{error:?}");
    }

    /// Whether `rustls::Error` is in the chain of `error`. `io::Error` hides
    /// the error it wraps from `source`, so that one is read with `get_ref`.
    fn caused_by_rustls(error: &(dyn Error + 'static)) -> bool {
        error.is::<rustls::Error>()
            || error
                .downcast_ref::<io::Error>()
                .and_then(io::Error::get_ref)
                .is_some_and(|inner| caused_by_rustls(inner))
            || error.source().is_some_and(caused_by_rustls)
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_body_hands_out_its_bytes_in_pieces() {
        let data = Bytes::from(
            (0..=255)
                .cycle()
                .take(BODY_CHUNK * 2 + 10)
                .collect::<Vec<u8>>(),
        );
        let mut body = memory(data.clone(), Activity::new());
        assert_eq!(body.size_hint().exact(), Some(data.len() as u64));
        assert!(!body.is_end_stream());
        let mut sizes = Vec::new();
        let mut received = Vec::new();
        while let Some(frame) = body.frame().await {
            let piece = frame.unwrap().into_data().unwrap();
            sizes.push(piece.len());
            received.extend_from_slice(&piece);
            assert_eq!(
                body.size_hint().exact(),
                Some((data.len() - received.len()) as u64)
            );
        }
        assert_eq!(sizes, [BODY_CHUNK, BODY_CHUNK, 10]);
        assert_eq!(received, data);
        assert!(body.is_end_stream());
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_request_body_ends_at_once() {
        let mut body = memory(Bytes::new(), Activity::new());
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.frame().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_cut_body_fails_while_it_has_bytes_left() {
        let mut body = memory(Bytes::from(vec![7; BODY_CHUNK + 1]), Activity::new());
        let cut = body.cut_on_drop();
        body.frame().await.unwrap().unwrap();
        drop(cut);
        assert!(body.frame().await.unwrap().is_err());
        assert!(body.frame().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_cut_file_body_fails_without_a_cause_of_its_own() {
        let contents = vec![9; BODY_CHUNK * 2];
        let mut body = RequestBody::new(&file_payload(&contents), Activity::new());
        let cut = body.cut_on_drop();
        body.frame().await.unwrap().unwrap();
        drop(cut);
        assert!(body.frame().await.unwrap().is_err());
        assert!(body.fault().get().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_cut_body_with_nothing_left_ends_as_usual() {
        let mut body = memory(Bytes::from_static(b"data"), Activity::new());
        let cut = body.cut_on_drop();
        body.frame().await.unwrap().unwrap();
        drop(cut);
        assert!(body.is_end_stream());
        assert!(body.frame().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_is_not_cut_while_its_guard_lives() {
        let mut body = memory(Bytes::from(vec![7; BODY_CHUNK + 1]), Activity::new());
        let _cut = body.cut_on_drop();
        body.frame().await.unwrap().unwrap();
        body.frame().await.unwrap().unwrap();
        assert!(body.frame().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn sending_a_piece_marks_activity() {
        let activity = Activity::new();
        let started = activity.last();
        let mut body = memory(Bytes::from_static(b"data"), activity.clone());
        tokio::time::sleep(Duration::from_secs(7)).await;
        assert_eq!(activity.last(), started);
        body.frame().await.unwrap().unwrap();
        assert_eq!(activity.last(), started + Duration::from_secs(7));
    }

    #[tokio::test(start_paused = true)]
    async fn work_that_moves_no_data_is_given_up_after_the_idle_time() {
        let activity = Activity::new();
        let began = Instant::now();
        let outcome = activity
            .watch(
                Duration::from_secs(5),
                tokio::time::sleep(Duration::from_secs(60)),
            )
            .await;
        assert!(outcome.is_none());
        assert_eq!(began.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn work_that_keeps_moving_data_may_run_past_the_idle_time() {
        let activity = Activity::new();
        let ticker = activity.clone();
        let began = Instant::now();
        let outcome = activity
            .watch(Duration::from_secs(5), async move {
                for _ in 0..4 {
                    tokio::time::sleep(Duration::from_secs(4)).await;
                    ticker.touch();
                }
                "done"
            })
            .await;
        assert_eq!(outcome, Some("done"));
        assert_eq!(began.elapsed(), Duration::from_secs(16));
    }

    #[tokio::test(start_paused = true)]
    async fn work_that_stops_moving_data_is_given_up_after_the_last_activity() {
        let activity = Activity::new();
        let ticker = activity.clone();
        let began = Instant::now();
        let outcome = activity
            .watch(Duration::from_secs(5), async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                ticker.touch();
                tokio::time::sleep(Duration::from_secs(60)).await;
            })
            .await;
        assert!(outcome.is_none());
        assert_eq!(began.elapsed(), Duration::from_secs(8));
    }

    fn file_payload(contents: &[u8]) -> Payload {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(contents).unwrap();
        let hash = hex(&Sha256::digest(contents));
        Payload::file(Arc::new(file), 0, contents.len() as u64, &hash).unwrap()
    }

    #[tokio::test]
    async fn a_file_request_body_hands_out_its_bytes_in_pieces() {
        let contents: Vec<u8> = (0..=250).cycle().take(BODY_CHUNK + 10).collect();
        let mut body = RequestBody::new(&file_payload(&contents), Activity::new());
        assert_eq!(body.size_hint().exact(), Some(contents.len() as u64));
        assert!(!body.is_end_stream());
        let mut received = Vec::new();
        while let Some(frame) = body.frame().await {
            received.extend_from_slice(&frame.unwrap().into_data().unwrap());
        }
        assert_eq!(received, contents);
        assert!(body.is_end_stream());
        assert!(body.fault().get().is_none());
    }

    #[tokio::test]
    async fn reading_a_piece_of_a_file_marks_activity() {
        let activity = Activity::new();
        let mut body = RequestBody::new(&file_payload(b"data"), activity.clone());
        let before = activity.last();
        tokio::time::sleep(Duration::from_millis(30)).await;
        body.frame().await.unwrap().unwrap();
        assert!(activity.last() >= before + Duration::from_millis(30));
    }
}
