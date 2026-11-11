//! The settings of an [`S3Backend`] and the check that the bucket is there.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::backend::{S3Backend, Shared};
use super::cache::MetaCache;
use super::client::{ListRequest, Location, S3Client, Settings};
use super::error::S3Error;
use super::keys::{MAX_KEY_LEN, dir_prefix};
use super::retry::Retry;
use super::sigv4::Credentials;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_METADATA_TTL: Duration = Duration::from_secs(30);
const DEFAULT_LISTING_METADATA_MAX: usize = 1000;
const DEFAULT_UPLOAD_CONCURRENCY: usize = 4;

/// Settings of an [`S3Backend`], set through the methods below and applied by
/// [`build`](S3BackendBuilder::build).
pub struct S3BackendBuilder {
    endpoint: String,
    region: String,
    bucket: String,
    credentials: Option<Credentials>,
    prefix: String,
    path_style: Option<bool>,
    read_only: bool,
    case_insensitive: bool,
    request_timeout: Duration,
    metadata_ttl: Duration,
    listing_metadata_max: usize,
    upload_concurrency: usize,
}

impl fmt::Debug for S3BackendBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BackendBuilder")
            .field("endpoint", &origin(&self.endpoint))
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// The scheme, host and port of `endpoint`: no user name, password, path or
/// query.
fn origin(endpoint: &str) -> String {
    let start = endpoint.find("://").map_or(0, |at| at + 3);
    let end = endpoint[start..]
        .find(['/', '?', '#'])
        .map_or(endpoint.len(), |at| start + at);
    let host = endpoint[start..end]
        .rsplit_once('@')
        .map_or(&endpoint[start..end], |(_, host)| host);
    format!("{}{host}", &endpoint[..start])
}

impl S3Backend {
    /// Settings for the bucket `bucket` of the store at `endpoint`, an
    /// `https://` or `http://` URL with a host, an optional port and no
    /// path. `region` is the region requests are signed for.
    pub fn builder(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        bucket: impl Into<String>,
    ) -> S3BackendBuilder {
        S3BackendBuilder {
            endpoint: endpoint.into(),
            region: region.into(),
            bucket: bucket.into(),
            credentials: None,
            prefix: String::new(),
            path_style: None,
            read_only: false,
            case_insensitive: true,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            metadata_ttl: DEFAULT_METADATA_TTL,
            listing_metadata_max: DEFAULT_LISTING_METADATA_MAX,
            upload_concurrency: DEFAULT_UPLOAD_CONCURRENCY,
        }
    }
}

impl S3BackendBuilder {
    /// Sets the access key and secret key that sign requests. Required.
    #[must_use]
    pub fn credentials(
        mut self,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        let session_token = self.credentials.take().and_then(|c| c.session_token);
        self.credentials = Some(Credentials {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            session_token,
        });
        self
    }

    /// Sets the session token of temporary credentials.
    #[must_use]
    pub fn session_token(mut self, token: impl Into<String>) -> Self {
        let token = Some(token.into());
        match &mut self.credentials {
            Some(credentials) => credentials.session_token = token,
            None => {
                self.credentials = Some(Credentials {
                    access_key: String::new(),
                    secret_key: String::new(),
                    session_token: token,
                });
            }
        }
        self
    }

    /// Serves the keys below `prefix` as the share root. Leading and trailing
    /// `/` are dropped. The default is the whole bucket.
    #[must_use]
    pub fn prefix(mut self, prefix: impl AsRef<str>) -> Self {
        self.prefix = prefix.as_ref().trim_matches('/').to_owned();
        self
    }

    /// Puts the bucket name in the URL path (`true`) or in the host name
    /// (`false`). By default an `amazonaws.com` endpoint with a bucket name
    /// that is a DNS label uses the host name, and every other endpoint the
    /// path.
    #[must_use]
    pub fn path_style(mut self, path_style: bool) -> Self {
        self.path_style = Some(path_style);
        self
    }

    /// Refuses every change to the share. [`build`](Self::build) fails
    /// without it.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Sets whether names match without regard to case. On by default: a name
    /// that no key spells exactly opens the first key that differs only in
    /// case. Off, every name is exactly a key.
    #[must_use]
    pub fn case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.case_insensitive = case_insensitive;
        self
    }

    /// Sets how long the store requests for one call from a client may take in
    /// all, retries included. The default is 30 seconds.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets how long the backend trusts what it read from the store, such as
    /// a listing or the size of a file. The default is 30 seconds.
    #[must_use]
    pub fn metadata_ttl(mut self, ttl: Duration) -> Self {
        self.metadata_ttl = ttl;
        self
    }

    /// Sets how many entries of one listing get the times stored with them,
    /// read with one request each. Entries whose metadata the backend already
    /// holds do not count: they report their stored times whatever this is.
    /// Past the cap, or when its request fails or runs out of time, a file
    /// reports the time the store modified it and a directory the time the
    /// backend was built. The default is 1000; 0 reads none.
    #[must_use]
    pub fn listing_metadata_max(mut self, max: usize) -> Self {
        self.listing_metadata_max = max;
        self
    }

    /// Sets only how many HEAD requests a listing keeps in flight: four times
    /// this value, at most 64. The default is 4.
    #[must_use]
    pub fn upload_concurrency(mut self, concurrency: usize) -> Self {
        self.upload_concurrency = concurrency;
        self
    }

    /// Checks the settings and the bucket, and returns the backend.
    ///
    /// # Errors
    ///
    /// Fails for settings that cannot be used, for a platform without root
    /// certificates, and when one request for the keys below the prefix
    /// fails: the store answers with an error, as for a bucket that does not
    /// exist or credentials it refuses, or does not answer, as for an
    /// unreachable endpoint or a timeout.
    pub async fn build(self) -> Result<S3Backend, S3Error> {
        let credentials = self.check()?;
        let mut settings = Settings::new(
            Location {
                endpoint: self.endpoint,
                region: self.region,
                bucket: self.bucket,
            },
            credentials,
        );
        settings.path_style = self.path_style;
        // Building the client reads the platform's root certificates.
        let client = tokio::task::spawn_blocking(move || S3Client::new(settings))
            .await
            .map_err(S3Error::transport)??;

        let root = dir_prefix(&self.prefix);
        let request = ListRequest {
            prefix: &root,
            delimited: false,
            continuation_token: None,
            max_keys: Some(1),
        };
        client
            .list_objects(&request, Retry::within(self.request_timeout))
            .await?;

        Ok(S3Backend {
            shared: Arc::new(Shared {
                client,
                prefix: self.prefix,
                case_insensitive: self.case_insensitive,
                request_timeout: self.request_timeout,
                listing_metadata_max: self.listing_metadata_max,
                head_concurrency: head_concurrency(self.upload_concurrency),
                built: SystemTime::now(),
                cache: Mutex::new(MetaCache::new(self.metadata_ttl)),
            }),
        })
    }

    fn check(&self) -> Result<Credentials, S3Error> {
        let credentials = match &self.credentials {
            Some(credentials) if !credentials.access_key.is_empty() => credentials,
            Some(_) => {
                return Err(S3Error::InvalidArgument("the access key is empty"));
            }
            None => return Err(S3Error::InvalidArgument("the credentials are not set")),
        };
        if credentials.secret_key.is_empty() {
            return Err(S3Error::InvalidArgument("the secret key is empty"));
        }
        if credentials.session_token.as_deref() == Some("") {
            return Err(S3Error::InvalidArgument("the session token is empty"));
        }
        if self.request_timeout.is_zero() {
            return Err(S3Error::InvalidArgument("the request timeout is zero"));
        }
        if self.upload_concurrency == 0 {
            return Err(S3Error::InvalidArgument("the upload concurrency is zero"));
        }
        if self
            .prefix
            .split('/')
            .any(|name| name.is_empty() && !self.prefix.is_empty() || matches!(name, "." | ".."))
        {
            return Err(S3Error::InvalidArgument(
                "the prefix has an empty, . or .. component",
            ));
        }
        if dir_prefix(&self.prefix).len() >= MAX_KEY_LEN {
            return Err(S3Error::InvalidArgument(
                "the prefix is too long to leave room for a name",
            ));
        }
        if !self.read_only {
            return Err(S3Error::InvalidArgument(
                "the backend serves a read-only share; call read_only()",
            ));
        }
        Ok(credentials.clone())
    }
}

/// Most requests a listing keeps in flight.
const MAX_HEAD_CONCURRENCY: usize = 64;

/// The requests a listing keeps in flight for an upload concurrency of
/// `upload_concurrency`.
fn head_concurrency(upload_concurrency: usize) -> usize {
    upload_concurrency
        .saturating_mul(4)
        .min(MAX_HEAD_CONCURRENCY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builder() -> S3BackendBuilder {
        S3Backend::builder("http://127.0.0.1:1", "us-east-1", "bucket")
            .credentials("access-key-id", "secret-key-value")
            .read_only()
    }

    fn refusal(builder: S3BackendBuilder) -> &'static str {
        match builder.check() {
            Err(S3Error::InvalidArgument(why)) => why,
            other => panic!("not refused: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn the_defaults_are_valid() {
        let credentials = builder().check().unwrap();
        assert_eq!(credentials.access_key, "access-key-id");
        assert_eq!(credentials.session_token, None);
    }

    #[test]
    fn a_prefix_loses_its_outer_slashes() {
        for (given, kept) in [
            ("photos", "photos"),
            ("/photos/", "photos"),
            ("///a/b///", "a/b"),
            ("a/b", "a/b"),
            ("", ""),
            ("/", ""),
        ] {
            assert_eq!(builder().prefix(given).prefix, kept, "{given:?}");
            assert!(builder().prefix(given).check().is_ok(), "{given:?}");
        }
    }

    #[test]
    fn a_prefix_with_an_empty_or_dot_component_is_refused() {
        for prefix in ["a//b", "a/./b", "a/../b", "./a", "a/..", "."] {
            assert!(
                refusal(builder().prefix(prefix)).contains("prefix"),
                "{prefix:?}"
            );
        }
        assert!(builder().prefix("a.b/..c/d..").check().is_ok());
    }

    #[test]
    fn a_prefix_that_leaves_no_room_for_a_name_is_refused() {
        let longest = "p".repeat(MAX_KEY_LEN - 2);
        assert!(builder().prefix(&longest).check().is_ok());
        let nested = format!("{}/{}", "p".repeat(500), "q".repeat(MAX_KEY_LEN - 2 - 501));
        assert!(builder().prefix(&nested).check().is_ok());

        let too_long = "p".repeat(MAX_KEY_LEN - 1);
        assert!(refusal(builder().prefix(&too_long)).contains("prefix"));
        let nested = format!("{}/{}", "p".repeat(500), "q".repeat(MAX_KEY_LEN - 1 - 501));
        assert!(refusal(builder().prefix(&nested)).contains("prefix"));
    }

    #[test]
    fn credentials_are_required_and_not_empty() {
        let bare = S3Backend::builder("http://127.0.0.1:1", "r", "b").read_only();
        assert!(refusal(bare).contains("credentials"));
        assert!(refusal(builder().credentials("", "s")).contains("access key"));
        assert!(refusal(builder().credentials("a", "")).contains("secret key"));
        assert!(refusal(builder().session_token("")).contains("session token"));
        let token_alone = S3Backend::builder("http://x", "r", "b")
            .session_token("t")
            .read_only();
        assert!(refusal(token_alone).contains("access key"));
    }

    #[test]
    fn a_session_token_survives_credentials_set_after_it() {
        let set = builder().session_token("t").credentials("a", "s");
        let credentials = set.check().unwrap();
        assert_eq!(credentials.session_token.as_deref(), Some("t"));
        assert_eq!(credentials.access_key, "a");
        let before = builder().credentials("a", "s").session_token("t");
        assert_eq!(before.check().unwrap().session_token.as_deref(), Some("t"));
    }

    #[test]
    fn zero_limits_are_refused() {
        assert!(refusal(builder().request_timeout(Duration::ZERO)).contains("timeout"));
        assert!(refusal(builder().upload_concurrency(0)).contains("concurrency"));
        assert!(
            builder()
                .metadata_ttl(Duration::ZERO)
                .listing_metadata_max(0)
                .check()
                .is_ok()
        );
    }

    #[test]
    fn a_backend_that_is_not_read_only_is_refused_by_name() {
        let writable = S3Backend::builder("http://127.0.0.1:1", "r", "b").credentials("a", "s");
        let why = refusal(writable);
        assert!(why.contains("read_only()"), "{why}");
    }

    #[test]
    fn head_requests_follow_the_upload_concurrency_within_a_bound() {
        assert_eq!(head_concurrency(1), 4);
        assert_eq!(head_concurrency(4), 16);
        assert_eq!(head_concurrency(16), 64);
        assert_eq!(head_concurrency(17), 64);
        assert_eq!(head_concurrency(usize::MAX), 64);
    }

    #[test]
    fn the_origin_of_an_endpoint_has_no_user_name_password_path_or_query() {
        for (endpoint, shown) in [
            ("https://store.example", "https://store.example"),
            ("http://127.0.0.1:9000", "http://127.0.0.1:9000"),
            (
                "https://user:pass@store.example:9000",
                "https://store.example:9000",
            ),
            (
                "https://user@store.example/path?a=b@c",
                "https://store.example",
            ),
            ("https://a@b@store.example", "https://store.example"),
            ("https://store.example/a@b", "https://store.example"),
            ("https://store.example?token=x#y", "https://store.example"),
            ("user:pass@store.example", "store.example"),
            ("", ""),
        ] {
            assert_eq!(origin(endpoint), shown, "{endpoint}");
        }
    }

    #[test]
    fn debug_output_hides_the_credentials() {
        let shown = format!(
            "{:?}",
            builder().session_token("token-value").prefix("photos")
        );
        for secret in ["access-key-id", "secret-key-value", "token-value"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(shown.contains("photos"), "{shown}");

        let shown = format!(
            "{:?}",
            S3Backend::builder(
                "https://endpoint-user:endpoint-pass@store.example",
                "r",
                "b"
            )
        );
        for secret in ["endpoint-user", "endpoint-pass"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(shown.contains("https://store.example"), "{shown}");
    }

    #[tokio::test]
    async fn the_endpoint_the_region_and_the_bucket_are_checked() {
        for (endpoint, region, bucket) in [
            ("ftp://store.example", "us-east-1", "b"),
            ("https://user:pass@store.example", "us-east-1", "b"),
            ("https://store.example/path", "us-east-1", "b"),
            ("store.example", "us-east-1", "b"),
            ("https://store.example", "", "b"),
            ("https://store.example", "us east", "b"),
            ("https://store.example", "us-east-1", ""),
            ("https://store.example", "us-east-1", "a/b"),
        ] {
            let built = S3Backend::builder(endpoint, region, bucket)
                .credentials("a", "s")
                .read_only()
                .build()
                .await;
            assert!(
                matches!(built, Err(S3Error::InvalidArgument(_))),
                "{endpoint} {region} {bucket}"
            );
        }
    }
}
