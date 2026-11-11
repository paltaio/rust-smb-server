//! The HTTP client the S3 requests go through.

#![cfg_attr(not(test), expect(dead_code, reason = "called by tests only"))]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::Uri;
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};
use tower_service::Service;
use tracing::warn;

/// Longest a new connection may take, name lookup and TLS handshake included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A pooled HTTP/1.1 client for `https://` and `http://` endpoints.
pub(crate) type HttpClient = Client<ConnectTimeout<HttpsConnector<HttpConnector>>, Full<Bytes>>;

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
    use std::iter;

    use http::Request;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn get(url: String) -> Request<Full<Bytes>> {
        Request::get(url).body(Full::new(Bytes::new())).unwrap()
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
}
