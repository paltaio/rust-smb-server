//! The client of an S3 store: the calls the backend makes, signed, sent over
//! the pooled transport, retried and checked.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, ETAG, HOST, IF_MATCH, RANGE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::BodyExt as _;
use hyper::body::{Body as _, Incoming, SizeHint};
use md5::{Digest as _, Md5};

use super::encode::{Query, base64, uri_encode};
use super::error::S3Error;
use super::object::{
    ByteRange, Metadata, ObjectHead, STORAGE_CLASS, header_value, normalize_etag,
    parse_content_range,
};
use super::payload::Payload;
use super::retry::{Attempts, BASE_DELAY, Retry};
use super::sigv4::{Credentials, Signer};
use super::transport::{Activity, HttpClient, RequestBody, client};
use super::xml::{
    self, CompletedPart, CopyResult, DeleteFailure, Listing, error_response, is_error_document,
};

/// How long a request may send or receive nothing before it fails.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest response body other than object data.
pub(crate) const MAX_BODY: usize = 8 << 20;

/// Most keys one DeleteObjects call takes.
pub(crate) const MAX_DELETE_KEYS: usize = 1000;

/// Highest part number of a multipart upload.
const MAX_PART_NUMBER: u32 = 10_000;

const CONTENT_MD5: HeaderName = HeaderName::from_static("content-md5");
const COPY_SOURCE: HeaderName = HeaderName::from_static("x-amz-copy-source");
const COPY_SOURCE_RANGE: HeaderName = HeaderName::from_static("x-amz-copy-source-range");
const METADATA_DIRECTIVE: HeaderName = HeaderName::from_static("x-amz-metadata-directive");
const REQUEST_ID: HeaderName = HeaderName::from_static("x-amz-request-id");

/// Where a bucket is.
#[derive(Clone)]
pub(crate) struct Location {
    /// An `https://` or `http://` URL with a host, an optional port and no
    /// path.
    pub(crate) endpoint: String,
    pub(crate) region: String,
    pub(crate) bucket: String,
}

/// What a client needs to reach a bucket.
#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) location: Location,
    pub(crate) credentials: Credentials,
    /// `true` puts the bucket name in the URL path (path style) and `false`
    /// in the host name (virtual-hosted style). `None` picks virtual-hosted
    /// style for an AWS endpoint and a bucket name that is a DNS label, and
    /// path style otherwise.
    pub(crate) path_style: Option<bool>,
    /// How long a request may send or receive nothing.
    pub(crate) idle_timeout: Duration,
    /// The longest wait after the first failure of a call.
    pub(crate) backoff_base: Duration,
}

impl Settings {
    pub(crate) fn new(location: Location, credentials: Credentials) -> Self {
        Settings {
            location,
            credentials,
            path_style: None,
            idle_timeout: IDLE_TIMEOUT,
            backoff_base: BASE_DELAY,
        }
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("endpoint", &self.location.endpoint)
            .field("region", &self.location.region)
            .field("bucket", &self.location.bucket)
            .finish_non_exhaustive()
    }
}

/// Where the requests for a bucket go and what their paths look like.
#[derive(Debug)]
struct Target {
    https: bool,
    host: String,
    /// The port of the endpoint unless it is the default of the scheme.
    port: Option<u16>,
    bucket: String,
    virtual_hosted: bool,
}

impl Target {
    fn new(endpoint: &str, bucket: &str, path_style: Option<bool>) -> Result<Self, S3Error> {
        let uri: Uri = endpoint
            .parse()
            .map_err(|_| S3Error::InvalidArgument("the endpoint is not a URL"))?;
        let (https, default_port) = match uri.scheme_str() {
            Some("https") => (true, 443),
            Some("http") => (false, 80),
            _ => {
                return Err(S3Error::InvalidArgument(
                    "the endpoint scheme is not http or https",
                ));
            }
        };
        let authority = uri
            .authority()
            .ok_or(S3Error::InvalidArgument("the endpoint has no host"))?;
        if authority.as_str().contains('@') {
            return Err(S3Error::InvalidArgument(
                "the endpoint has a user name or password",
            ));
        }
        if uri.path() != "/" || uri.query().is_some() {
            return Err(S3Error::InvalidArgument(
                "the endpoint has a path or a query",
            ));
        }
        if bucket.is_empty() || bucket.contains('/') {
            return Err(S3Error::InvalidArgument(
                "the bucket name is empty or has a slash",
            ));
        }
        let host = authority.host().to_ascii_lowercase();
        let virtual_hosted = path_style.map_or_else(
            || is_aws_host(&host) && is_dns_label(bucket),
            |path_style| !path_style,
        );
        Ok(Target {
            https,
            host,
            port: authority.port_u16().filter(|port| *port != default_port),
            bucket: bucket.to_owned(),
            virtual_hosted,
        })
    }

    /// The value of the `Host` header.
    fn authority(&self) -> String {
        let mut authority = if self.virtual_hosted {
            format!("{}.{}", self.bucket, self.host)
        } else {
            self.host.clone()
        };
        if let Some(port) = self.port {
            authority.push_str(&format!(":{port}"));
        }
        authority
    }

    /// The encoded path of `key`, or of the bucket itself.
    fn path(&self, key: Option<&str>) -> String {
        let mut path = String::from("/");
        if !self.virtual_hosted {
            path.push_str(&uri_encode(&self.bucket, false));
            if key.is_some() {
                path.push('/');
            }
        }
        if let Some(key) = key {
            path.push_str(&uri_encode(key, true));
        }
        path
    }

    fn url(&self, path: &str, query: &str) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let mut url = format!("{scheme}://{}{path}", self.authority());
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        url
    }

    /// The `x-amz-copy-source` value for `key` in this bucket.
    fn copy_source(&self, key: &str) -> String {
        format!(
            "{}/{}",
            uri_encode(&self.bucket, false),
            uri_encode(key, true)
        )
    }
}

fn is_aws_host(host: &str) -> bool {
    host == "amazonaws.com" || host.ends_with(".amazonaws.com")
}

/// Whether `name` is one DNS label: 1 to 63 lowercase letters, digits and
/// hyphens, starting and ending with a letter or digit.
fn is_dns_label(name: &str) -> bool {
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let bytes = name.as_bytes();
    bytes.len() <= 63
        && edge(bytes.first())
        && edge(bytes.last())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// One request, before it is signed and sent. A retry sends it again.
struct Call {
    method: Method,
    path: String,
    query: Query,
    headers: HeaderMap,
    payload: Payload,
}

impl Call {
    fn header(mut self, name: HeaderName, value: &str) -> Result<Self, S3Error> {
        self.headers.insert(name, header_value(value)?);
        Ok(self)
    }

    fn metadata(mut self, metadata: &Metadata) -> Result<Self, S3Error> {
        metadata.write_headers(&mut self.headers)?;
        Ok(self)
    }

    fn payload(mut self, payload: Payload) -> Self {
        self.payload = payload;
        self
    }
}

/// How much of a response body is read.
#[derive(Debug, Clone, Copy)]
enum BodyLimit {
    /// A body of more bytes is an error.
    Capped(usize),
    /// The first bytes of a body, whatever its length.
    Prefix(usize),
}

/// A response: its status, headers and body.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    /// Whether the body had more bytes than were read: more than a
    /// [`BodyLimit::Prefix`], or more than an error body may have.
    truncated: bool,
}

impl Reply {
    fn header(&self, name: &HeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    fn request_id(&self) -> Option<&str> {
        self.header(&REQUEST_ID)
    }

    fn error(&self) -> S3Error {
        error_response(&self.body, self.status.as_u16(), self.request_id())
    }

    /// Fails with the error of this response unless its status is one of
    /// `statuses`.
    fn expect(&self, statuses: &[u16]) -> Result<(), S3Error> {
        if statuses.contains(&self.status.as_u16()) {
            Ok(())
        } else {
            Err(self.error())
        }
    }

    /// Like [`expect`](Self::expect) for status 200, for the answers that can
    /// be an `Error` document under that status.
    fn expect_document(&self) -> Result<(), S3Error> {
        self.expect(&[200])?;
        if is_error_document(&self.body) {
            return Err(self.error());
        }
        Ok(())
    }

    fn etag(&self) -> Result<String, S3Error> {
        self.header(&ETAG)
            .map(normalize_etag)
            .filter(|etag| !etag.is_empty())
            .ok_or(S3Error::InvalidResponse("the answer has no ETag"))
    }
}

/// An object read: its description and the bytes of the range asked for.
#[derive(Debug)]
pub(crate) struct Object {
    pub(crate) head: ObjectHead,
    pub(crate) data: Bytes,
}

/// What ListObjectsV2 is asked.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ListRequest<'a> {
    pub(crate) prefix: &'a str,
    /// Group the keys below a `/` after the prefix into common prefixes.
    pub(crate) delimited: bool,
    pub(crate) continuation_token: Option<&'a str>,
    pub(crate) max_keys: Option<u32>,
}

/// The metadata a copy gives the new object.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), expect(dead_code, reason = "used by tests only"))]
pub(crate) enum CopyMetadata<'a> {
    /// The metadata of the source, in the storage class given.
    Copy { storage_class: Option<&'a str> },
    /// Exactly this metadata.
    Replace(&'a Metadata),
}

/// A client for one bucket. Clones share the connection pool.
#[derive(Clone)]
pub(crate) struct S3Client {
    inner: Arc<Inner>,
}

struct Inner {
    http: HttpClient,
    signer: Signer,
    target: Target,
    idle_timeout: Duration,
    backoff_base: Duration,
}

impl fmt::Debug for S3Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Client")
            .field("endpoint", &self.inner.target.url("/", ""))
            .field("bucket", &self.inner.target.bucket)
            .finish_non_exhaustive()
    }
}

impl S3Client {
    /// Fails for an endpoint or bucket name that cannot be used and for a
    /// platform without root certificates.
    pub(crate) fn new(settings: Settings) -> Result<Self, S3Error> {
        let Location {
            endpoint,
            region,
            bucket,
        } = settings.location;
        let target = Target::new(&endpoint, &bucket, settings.path_style)?;
        if region.is_empty()
            || !region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(S3Error::InvalidArgument("the region name is not usable"));
        }
        let http = client().map_err(S3Error::transport)?;
        Ok(S3Client {
            inner: Arc::new(Inner {
                http,
                signer: Signer::new(settings.credentials, region),
                target,
                idle_timeout: settings.idle_timeout,
                backoff_base: settings.backoff_base,
            }),
        })
    }

    /// ListObjectsV2, one page. Keys come back URL-decoded.
    pub(crate) async fn list_objects(
        &self,
        request: &ListRequest<'_>,
        retry: Retry,
    ) -> Result<Listing, S3Error> {
        let max_keys = request.max_keys.map(|n| n.to_string());
        let mut params = vec![("list-type", "2"), ("encoding-type", "url")];
        if !request.prefix.is_empty() {
            params.push(("prefix", request.prefix));
        }
        if request.delimited {
            params.push(("delimiter", "/"));
        }
        if let Some(token) = request.continuation_token {
            params.push(("continuation-token", token));
        }
        if let Some(max_keys) = &max_keys {
            params.push(("max-keys", max_keys.as_str()));
        }
        let call = self.call(Method::GET, None, &params);
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect_document()?;
            xml::parse_listing(&reply.body)
        })
        .await
    }

    /// HeadObject.
    pub(crate) async fn head_object(&self, key: &str, retry: Retry) -> Result<ObjectHead, S3Error> {
        let call = self.object_call(Method::HEAD, key, &[])?;
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect(&[200])?;
            let size = reply
                .header(&CONTENT_LENGTH)
                .and_then(|size| size.parse().ok())
                .ok_or(S3Error::InvalidResponse("the answer has no Content-Length"))?;
            ObjectHead::from_headers(&reply.headers, size)
        })
        .await
    }

    /// GetObject for `range`. With `expected_etag`, a version of the object
    /// with another ETag fails the call as a failed precondition, whether the
    /// store checks `If-Match` or not. An empty `expected_etag` is refused.
    ///
    /// The answer must be status 206 with a `Content-Range` that starts where
    /// the range does. A range that starts at 0 may also get status 200, as
    /// from a store that ignores `Range`; the first bytes of its body are
    /// taken then.
    pub(crate) async fn get_object(
        &self,
        key: &str,
        range: ByteRange,
        expected_etag: Option<&str>,
        retry: Retry,
    ) -> Result<Object, S3Error> {
        let max = usize::try_from(range.len())
            .map_err(|_| S3Error::InvalidArgument("the range is too long to read at once"))?;
        let expected = expected_etag.map(normalize_etag);
        if expected.as_deref() == Some("") {
            return Err(S3Error::InvalidArgument("the expected ETag is empty"));
        }
        let mut call = self
            .object_call(Method::GET, key, &[])?
            .header(RANGE, &range.header_value())?;
        if let Some(etag) = &expected {
            call = call.header(IF_MATCH, etag)?;
        }
        self.run(retry, &call, BodyLimit::Prefix(max), |reply| {
            read_object(reply, range, expected.as_deref())
        })
        .await
    }
}

#[cfg_attr(not(test), expect(dead_code, reason = "called by tests only"))]
impl S3Client {
    /// PutObject. Returns the ETag of the new object.
    ///
    /// Every attempt sends `payload` from its start. A file that no longer
    /// hashes to what the payload says fails the call with
    /// [`S3Error::SourceChanged`], and the store keeps nothing of the attempt.
    pub(crate) async fn put_object(
        &self,
        key: &str,
        payload: impl Into<Payload>,
        metadata: &Metadata,
        retry: Retry,
    ) -> Result<String, S3Error> {
        let call = self
            .object_call(Method::PUT, key, &[])?
            .metadata(metadata)?
            .payload(payload.into());
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect(&[200])?;
            reply.etag()
        })
        .await
    }

    /// CopyObject from `source` to `key`, in this bucket.
    pub(crate) async fn copy_object(
        &self,
        source: &str,
        key: &str,
        metadata: CopyMetadata<'_>,
        retry: Retry,
    ) -> Result<CopyResult, S3Error> {
        check_key(source)?;
        let call = self
            .object_call(Method::PUT, key, &[])?
            .header(COPY_SOURCE, &self.inner.target.copy_source(source))?;
        let call = match metadata {
            CopyMetadata::Copy { storage_class } => {
                let call = call.header(METADATA_DIRECTIVE, "COPY")?;
                match storage_class {
                    Some(class) => call.header(STORAGE_CLASS, class)?,
                    None => call,
                }
            }
            CopyMetadata::Replace(metadata) => call
                .header(METADATA_DIRECTIVE, "REPLACE")?
                .metadata(metadata)?,
        };
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect_document()?;
            xml::parse_copy(&reply.body, "CopyObjectResult")
        })
        .await
    }

    /// CreateMultipartUpload. Returns the upload id.
    pub(crate) async fn create_multipart_upload(
        &self,
        key: &str,
        metadata: &Metadata,
        retry: Retry,
    ) -> Result<String, S3Error> {
        let call = self
            .object_call(Method::POST, key, &[("uploads", "")])?
            .metadata(metadata)?;
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect_document()?;
            xml::parse_upload_id(&reply.body)
        })
        .await
    }

    /// UploadPart. Returns the ETag of the part. Sends `payload` as
    /// [`put_object`](Self::put_object) does.
    pub(crate) async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        payload: impl Into<Payload>,
        retry: Retry,
    ) -> Result<String, S3Error> {
        let number = check_part_number(part_number)?;
        let call = self
            .object_call(
                Method::PUT,
                key,
                &[("partNumber", number.as_str()), ("uploadId", upload_id)],
            )?
            .payload(payload.into());
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect(&[200])?;
            reply.etag()
        })
        .await
    }

    /// UploadPartCopy of `range` of `source`.
    pub(crate) async fn upload_part_copy(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        source: &str,
        range: ByteRange,
        retry: Retry,
    ) -> Result<CopyResult, S3Error> {
        check_key(source)?;
        let number = check_part_number(part_number)?;
        let call = self
            .object_call(
                Method::PUT,
                key,
                &[("partNumber", number.as_str()), ("uploadId", upload_id)],
            )?
            .header(COPY_SOURCE, &self.inner.target.copy_source(source))?
            .header(COPY_SOURCE_RANGE, &range.header_value())?;
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect_document()?;
            xml::parse_copy(&reply.body, "CopyPartResult")
        })
        .await
    }

    /// CompleteMultipartUpload of `parts`, which must be in ascending order.
    /// Returns the ETag of the object.
    ///
    /// When an attempt fails and a later one answers `NoSuchUpload`, the
    /// store may have completed the upload before the answer got lost. The
    /// call then succeeds if the object is there with `expected_size` bytes
    /// and an ETag other than `replaced_etag`, the ETag the key had before
    /// the upload (`None` for a key that did not exist). It fails with
    /// `NoSuchUpload` if the object is not there or is not that one, and with
    /// the error of the lookup if that fails for another reason.
    pub(crate) async fn complete_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
        expected_size: u64,
        replaced_etag: Option<&str>,
        retry: Retry,
    ) -> Result<String, S3Error> {
        if parts.is_empty()
            || parts
                .array_windows::<2>()
                .any(|[a, b]| a.number >= b.number)
        {
            return Err(S3Error::InvalidArgument(
                "the parts are empty or not in ascending order",
            ));
        }
        for part in parts {
            check_part_number(part.number)?;
        }
        let call = self
            .object_call(Method::POST, key, &[("uploadId", upload_id)])?
            .payload(Bytes::from(xml::complete_request(parts)).into());
        let replaced = replaced_etag.map(normalize_etag);
        let mut attempts = Attempts::new(retry.clone(), self.inner.backoff_base);
        loop {
            let outcome = attempts
                .attempt(async {
                    let reply = self.send(&call, BodyLimit::Capped(MAX_BODY)).await?;
                    reply.expect_document()?;
                    xml::parse_completed(&reply.body)
                })
                .await;
            match outcome {
                Ok(etag) => return Ok(etag),
                Err(error) if attempts.failures() > 0 && error.code() == Some("NoSuchUpload") => {
                    return match self.head_object(key, retry).await {
                        Ok(head)
                            if head.size == expected_size
                                && replaced.as_deref() != Some(head.etag.as_str()) =>
                        {
                            Ok(head.etag)
                        }
                        Err(head_error) if !head_error.is_no_such_key() => Err(head_error),
                        _ => Err(error),
                    };
                }
                Err(error) => attempts.failed(error).await?,
            }
        }
    }

    /// AbortMultipartUpload. An upload that does not exist is aborted.
    pub(crate) async fn abort_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        retry: Retry,
    ) -> Result<(), S3Error> {
        let call = self.object_call(Method::DELETE, key, &[("uploadId", upload_id)])?;
        self.run(
            retry,
            &call,
            BodyLimit::Capped(MAX_BODY),
            |reply| match reply.expect(&[200, 204]) {
                Err(error) if error.code() == Some("NoSuchUpload") => Ok(()),
                other => other,
            },
        )
        .await
    }

    /// DeleteObject. A key that does not exist is deleted: the store says so
    /// with status 404 and no body, or with the code `NoSuchKey`. Any other 404,
    /// such as a missing bucket or the page of a proxy, is an error.
    pub(crate) async fn delete_object(&self, key: &str, retry: Retry) -> Result<(), S3Error> {
        let call = self.object_call(Method::DELETE, key, &[])?;
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            if reply.status == StatusCode::NOT_FOUND && reply.body.is_empty() && !reply.truncated {
                return Ok(());
            }
            match reply.expect(&[200, 204]) {
                Err(error)
                    if error.http_status() == Some(404) && error.code() == Some("NoSuchKey") =>
                {
                    Ok(())
                }
                other => other,
            }
        })
        .await
    }

    /// DeleteObjects of at most [`MAX_DELETE_KEYS`] keys. Returns the keys
    /// the store did not delete; a key that does not exist is deleted.
    pub(crate) async fn delete_objects<K: AsRef<str>>(
        &self,
        keys: &[K],
        retry: Retry,
    ) -> Result<Vec<DeleteFailure>, S3Error> {
        if keys.len() > MAX_DELETE_KEYS {
            return Err(S3Error::InvalidArgument("too many keys to delete at once"));
        }
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        for key in keys {
            check_key(key.as_ref())?;
        }
        let body = Bytes::from(xml::delete_request(keys)?);
        let digest = base64(&Md5::digest(&body));
        let call = self
            .call(Method::POST, None, &[("delete", "")])
            .header(CONTENT_MD5, &digest)?
            .payload(body.into());
        self.run(retry, &call, BodyLimit::Capped(MAX_BODY), |reply| {
            reply.expect_document()?;
            xml::parse_delete_result(&reply.body)
        })
        .await
    }
}

impl S3Client {
    fn call(&self, method: Method, key: Option<&str>, params: &[(&str, &str)]) -> Call {
        Call {
            method,
            path: self.inner.target.path(key),
            query: Query::new(params),
            headers: HeaderMap::new(),
            payload: Payload::empty(),
        }
    }

    fn object_call(
        &self,
        method: Method,
        key: &str,
        params: &[(&str, &str)],
    ) -> Result<Call, S3Error> {
        check_key(key)?;
        Ok(self.call(method, Some(key), params))
    }

    /// Sends `call` until `decode` accepts the response, or the failure is
    /// final under `retry`.
    async fn run<T>(
        &self,
        retry: Retry,
        call: &Call,
        limit: BodyLimit,
        decode: impl Fn(&Reply) -> Result<T, S3Error>,
    ) -> Result<T, S3Error> {
        let mut attempts = Attempts::new(retry, self.inner.backoff_base);
        loop {
            let outcome = attempts
                .attempt(async { decode(&self.send(call, limit).await?) })
                .await;
            match outcome {
                Ok(value) => return Ok(value),
                Err(error) => attempts.failed(error).await?,
            }
        }
    }

    /// One attempt: signs `call` with the current time, sends it and reads the
    /// response.
    async fn send(&self, call: &Call, limit: BodyLimit) -> Result<Reply, S3Error> {
        let inner = &self.inner;
        let mut headers = call.headers.clone();
        headers.insert(HOST, header_value(&inner.target.authority())?);
        inner.signer.sign(
            &call.method,
            &call.path,
            &call.query.canonical(),
            &mut headers,
            call.payload.sha256(),
            SystemTime::now(),
        )?;
        let activity = Activity::new();
        let body = RequestBody::new(&call.payload, activity.clone());
        let fault = body.fault();
        let _cut = body.cut_on_drop();
        let mut request = Request::builder()
            .method(call.method.clone())
            .uri(inner.target.url(&call.path, &call.query.wire()))
            .body(body)
            .map_err(|_| S3Error::InvalidArgument("the request cannot be built"))?;
        // hyper leaves Content-Length out of a request whose body is empty.
        if call.payload.len() == 0 && matches!(call.method, Method::PUT | Method::POST) {
            headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        *request.headers_mut() = headers;

        let idle = inner.idle_timeout;
        // hyper reports a body that failed as a failed request. The body knows why.
        let response = match activity.watch(idle, inner.http.request(request)).await {
            Some(Ok(response)) => response,
            Some(Err(error)) => {
                return Err(fault
                    .get()
                    .cloned()
                    .unwrap_or_else(|| S3Error::transport(error)));
            }
            None => return Err(fault.get().cloned().unwrap_or(S3Error::TimedOut)),
        };
        activity.touch();
        let (parts, body) = response.into_parts();
        let (body, truncated) = if parts.status.is_success() {
            read_body(body, &activity, idle, limit).await?
        } else {
            match read_body(body, &activity, idle, BodyLimit::Capped(MAX_BODY)).await {
                Ok(read) => read,
                // The status says what went wrong; the body only adds its code.
                Err(S3Error::InvalidResponse(_)) => (Bytes::new(), true),
                Err(error) => return Err(error),
            }
        };
        Ok(Reply {
            status: parts.status,
            headers: parts.headers,
            body,
            truncated,
        })
    }
}

fn check_key(key: &str) -> Result<(), S3Error> {
    if key.is_empty() {
        return Err(S3Error::InvalidArgument("the key is empty"));
    }
    Ok(())
}

fn check_part_number(part_number: u32) -> Result<String, S3Error> {
    if !(1..=MAX_PART_NUMBER).contains(&part_number) {
        return Err(S3Error::InvalidArgument("the part number is out of range"));
    }
    Ok(part_number.to_string())
}

/// The room to reserve for object data of which at most `max` bytes are read:
/// the length the response declares, or `max`. Growing the buffer as data
/// arrives could leave up to twice the bytes allocated.
fn object_capacity(hint: &SizeHint, max: usize) -> usize {
    hint.exact()
        .and_then(|len| usize::try_from(len).ok())
        .map_or(max, |len| len.min(max))
}

/// Reads the body of a response within `limit`. Every chunk counts as
/// activity of the request, and a body that stalls fails the read.
async fn read_body(
    mut body: Incoming,
    activity: &Activity,
    idle: Duration,
    limit: BodyLimit,
) -> Result<(Bytes, bool), S3Error> {
    let (max, truncate) = match limit {
        BodyLimit::Capped(max) => (max, false),
        BodyLimit::Prefix(max) => (max, true),
    };
    let mut data = BytesMut::with_capacity(if truncate {
        object_capacity(&body.size_hint(), max)
    } else {
        0
    });
    while let Some(frame) = activity
        .watch(idle, body.frame())
        .await
        .ok_or(S3Error::TimedOut)?
    {
        activity.touch();
        let Ok(chunk) = frame.map_err(S3Error::transport)?.into_data() else {
            continue;
        };
        let room = max - data.len();
        if chunk.len() <= room {
            data.extend_from_slice(&chunk);
        } else if truncate {
            data.extend_from_slice(&chunk[..room]);
            return Ok((data.freeze(), true));
        } else {
            return Err(S3Error::InvalidResponse("the response body is too large"));
        }
    }
    Ok((data.freeze(), false))
}

/// Checks the answer to a ranged GET and reads the object out of it.
fn read_object(
    reply: &Reply,
    range: ByteRange,
    expected_etag: Option<&str>,
) -> Result<Object, S3Error> {
    reply.expect(&[200, 206])?;
    if let Some(expected) = expected_etag {
        let etag = reply.header(&ETAG).map(normalize_etag).unwrap_or_default();
        if etag != expected {
            return Err(S3Error::status(
                412,
                Some("PreconditionFailed"),
                reply.request_id(),
            ));
        }
    }
    let size = if reply.status.as_u16() == 206 {
        let (first, last, size) = reply
            .header(&CONTENT_RANGE)
            .and_then(parse_content_range)
            .ok_or(S3Error::InvalidResponse(
                "the answer has no usable Content-Range",
            ))?;
        if first != range.start() || last > range.last() {
            return Err(S3Error::InvalidResponse(
                "the Content-Range is not the range asked for",
            ));
        }
        if last < range.last() && last + 1 != size {
            return Err(S3Error::InvalidResponse(
                "the answer ends before the range and the object",
            ));
        }
        if reply.truncated || reply.body.len() as u64 != last - first + 1 {
            return Err(S3Error::InvalidResponse(
                "the body is not the size of its Content-Range",
            ));
        }
        size
    } else if range.start() == 0 {
        let size: u64 = reply
            .header(&CONTENT_LENGTH)
            .and_then(|size| size.parse().ok())
            .ok_or(S3Error::InvalidResponse("the answer has no Content-Length"))?;
        if reply.body.len() as u64 != size.min(range.len()) {
            return Err(S3Error::InvalidResponse(
                "the body is shorter than the object or the range",
            ));
        }
        size
    } else {
        return Err(S3Error::InvalidResponse(
            "the store answered 200 to a range that starts past 0",
        ));
    };
    Ok(Object {
        head: ObjectHead::from_headers(&reply.headers, size)?,
        data: reply.body.clone(),
    })
}

#[cfg(test)]
impl S3Client {
    /// CreateBucket.
    pub(crate) async fn create_bucket(&self) -> Result<(), S3Error> {
        let call = self.call(Method::PUT, None, &[]);
        self.run(
            Retry::within(Duration::from_secs(30)),
            &call,
            BodyLimit::Capped(MAX_BODY),
            |reply| reply.expect(&[200]),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(endpoint: &str) -> Settings {
        Settings::new(
            Location {
                endpoint: endpoint.into(),
                region: "us-east-1".into(),
                bucket: "b".into(),
            },
            Credentials {
                access_key: "a".into(),
                secret_key: "s".into(),
                session_token: None,
            },
        )
    }

    fn secret_settings(endpoint: &str) -> Settings {
        let mut settings = settings(endpoint);
        settings.credentials = Credentials {
            access_key: "access-key-id".into(),
            secret_key: "secret-key-value".into(),
            session_token: Some("token-value".into()),
        };
        settings
    }

    fn target(endpoint: &str, bucket: &str, path_style: Option<bool>) -> Target {
        Target::new(endpoint, bucket, path_style).unwrap()
    }

    #[test]
    fn an_aws_endpoint_gets_virtual_hosted_requests_by_default() {
        let target = target("https://s3.us-east-1.amazonaws.com", "examplebucket", None);
        assert!(target.virtual_hosted);
        assert_eq!(
            target.authority(),
            "examplebucket.s3.us-east-1.amazonaws.com"
        );
        assert_eq!(target.path(Some("photos/a b.jpg")), "/photos/a%20b.jpg");
        assert_eq!(target.path(None), "/");
        assert_eq!(
            target.url("/test%24file.text", "max-keys=2"),
            "https://examplebucket.s3.us-east-1.amazonaws.com/test%24file.text?max-keys=2"
        );
    }

    #[test]
    fn other_endpoints_get_path_style_requests_by_default() {
        for endpoint in [
            "https://s3.store.example",
            "http://127.0.0.1:7070",
            "https://example.com",
            "https://amazonaws.com.example.com",
            "https://notamazonaws.com",
        ] {
            let target = target(endpoint, "examplebucket", None);
            assert!(!target.virtual_hosted, "{endpoint}");
            assert_eq!(target.path(None), "/examplebucket");
            assert_eq!(target.path(Some("a/b")), "/examplebucket/a/b");
        }
    }

    #[test]
    fn a_bucket_that_is_not_a_dns_label_gets_path_style_on_aws() {
        for bucket in [
            "my.bucket",
            "My-Bucket",
            "-bucket",
            "bucket-",
            "bucket_name",
            &"a".repeat(64),
        ] {
            let target = target("https://s3.amazonaws.com", bucket, None);
            assert!(!target.virtual_hosted, "{bucket}");
        }
        assert!(target("https://s3.amazonaws.com", "a", None).virtual_hosted);
        assert!(target("https://s3.amazonaws.com", &"a".repeat(63), None).virtual_hosted);
        assert!(target("https://s3.amazonaws.com", "my-bucket-01", None).virtual_hosted);
    }

    #[test]
    fn the_addressing_style_can_be_set() {
        let aws = target("https://s3.amazonaws.com", "examplebucket", Some(true));
        assert!(!aws.virtual_hosted);
        assert_eq!(aws.authority(), "s3.amazonaws.com");
        let local = target("http://localhost:9000", "examplebucket", Some(false));
        assert!(local.virtual_hosted);
        assert_eq!(local.authority(), "examplebucket.localhost:9000");
    }

    #[test]
    fn the_host_header_keeps_a_port_that_is_not_the_default() {
        assert_eq!(
            target("http://127.0.0.1:8080", "b", None).authority(),
            "127.0.0.1:8080"
        );
        assert_eq!(
            target("http://127.0.0.1:80", "b", None).authority(),
            "127.0.0.1"
        );
        assert_eq!(
            target("https://store.example:443", "b", None).authority(),
            "store.example"
        );
        assert_eq!(
            target("https://store.example:8443/", "b", None).authority(),
            "store.example:8443"
        );
        assert_eq!(
            target("http://[::1]:9000", "b", None).authority(),
            "[::1]:9000"
        );
        assert_eq!(
            target("https://Store.Example", "b", None).authority(),
            "store.example"
        );
    }

    #[test]
    fn paths_encode_every_byte_of_a_key_outside_the_unreserved_set() {
        let target = target("http://127.0.0.1:1", "bucket", None);
        assert_eq!(target.path(Some("a b+c%d~e")), "/bucket/a%20b%2Bc%25d~e");
        assert_eq!(target.path(Some("dir/\u{e9}")), "/bucket/dir/%C3%A9");
        assert_eq!(target.path(Some("a//b/")), "/bucket/a//b/");
        assert_eq!(target.path(Some("/a")), "/bucket//a");
    }

    #[test]
    fn the_copy_source_is_the_encoded_bucket_and_key() {
        let target = target("http://127.0.0.1:1", "bucket", None);
        assert_eq!(target.copy_source("dir/a b+c"), "bucket/dir/a%20b%2Bc");
        let aws = self::target("https://s3.amazonaws.com", "bucket", None);
        assert_eq!(aws.copy_source("x"), "bucket/x");
    }

    #[test]
    fn rejects_endpoints_that_cannot_be_used() {
        for endpoint in [
            "",
            "example.com",
            "ftp://example.com",
            "https://",
            "https://user:pass@example.com",
            "https://example.com/prefix",
            "https://example.com/?x=1",
            "not a url",
        ] {
            assert!(
                matches!(
                    Target::new(endpoint, "bucket", None),
                    Err(S3Error::InvalidArgument(_))
                ),
                "{endpoint:?}"
            );
        }
        assert!(Target::new("https://example.com", "", None).is_err());
        assert!(Target::new("https://example.com", "a/b", None).is_err());
    }

    #[test]
    fn settings_hide_their_secrets_from_debug_output() {
        let shown = format!("{:?}", secret_settings("http://x"));
        for secret in ["access-key-id", "secret-key-value", "token-value"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }

    #[tokio::test]
    async fn a_client_hides_its_secrets_from_debug_output() {
        let client = S3Client::new(secret_settings("http://x")).unwrap();
        let shown = format!("{client:?}");
        for secret in ["access-key-id", "secret-key-value", "token-value"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }

    #[tokio::test]
    async fn rejects_regions_that_cannot_be_scoped() {
        for region in ["", "us east", "us/east", "us-east-1\n"] {
            let mut settings = settings("http://x");
            settings.location.region = region.into();
            assert!(
                matches!(S3Client::new(settings), Err(S3Error::InvalidArgument(_))),
                "{region:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_arguments_before_sending_anything() {
        // Nothing listens here, so a call that got as far as connecting would fail otherwise.
        let client = S3Client::new(settings("http://127.0.0.1:9")).unwrap();
        let retry = || Retry::within(Duration::from_secs(5));
        let invalid = |error: S3Error| matches!(error, S3Error::InvalidArgument(_));
        assert!(invalid(client.head_object("", retry()).await.unwrap_err()));
        assert!(invalid(
            client
                .put_object("", Bytes::new(), &Metadata::default(), retry())
                .await
                .unwrap_err()
        ));
        assert!(invalid(
            client
                .copy_object(
                    "",
                    "k",
                    CopyMetadata::Copy {
                        storage_class: None
                    },
                    retry()
                )
                .await
                .unwrap_err()
        ));
        for number in [0, 10_001] {
            assert!(invalid(
                client
                    .upload_part("k", "id", number, Bytes::new(), retry())
                    .await
                    .unwrap_err()
            ));
        }
        let keys: Vec<String> = (0..=MAX_DELETE_KEYS).map(|n| n.to_string()).collect();
        assert!(invalid(
            client.delete_objects(&keys, retry()).await.unwrap_err()
        ));
        let part = |number| CompletedPart {
            number,
            etag: "\"e\"".into(),
        };
        for parts in [
            vec![],
            vec![part(2), part(1)],
            vec![part(1), part(1)],
            vec![part(0)],
        ] {
            assert!(invalid(
                client
                    .complete_multipart_upload("k", "id", &parts, 1, None, retry())
                    .await
                    .unwrap_err()
            ));
        }
        let metadata = Metadata {
            content_type: Some("a\nb".into()),
            ..Metadata::default()
        };
        assert!(invalid(
            client
                .put_object("k", Bytes::new(), &metadata, retry())
                .await
                .unwrap_err()
        ));
        for etag in ["", " "] {
            assert!(invalid(
                client
                    .get_object("k", ByteRange::new(0, 1).unwrap(), Some(etag), retry())
                    .await
                    .unwrap_err()
            ));
        }
    }

    #[tokio::test]
    async fn deleting_no_keys_sends_nothing() {
        let client = S3Client::new(settings("http://127.0.0.1:9")).unwrap();
        let none: [&str; 0] = [];
        let failed = client
            .delete_objects(&none, Retry::within(Duration::from_secs(5)))
            .await
            .unwrap();
        assert!(failed.is_empty());
    }

    #[test]
    fn object_data_reserves_the_declared_length_up_to_the_range() {
        assert_eq!(object_capacity(&SizeHint::with_exact(10), 100), 10);
        assert_eq!(object_capacity(&SizeHint::with_exact(100), 100), 100);
        assert_eq!(object_capacity(&SizeHint::with_exact(1000), 100), 100);
        assert_eq!(object_capacity(&SizeHint::with_exact(u64::MAX), 100), 100);
        assert_eq!(object_capacity(&SizeHint::new(), 100), 100);
        let mut unsure = SizeHint::new();
        unsure.set_lower(5);
        unsure.set_upper(50);
        assert_eq!(object_capacity(&unsure, 100), 100);
    }
}
