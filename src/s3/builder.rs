//! The settings of an [`S3Backend`] and the check that the bucket is there.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tracing::info;

use super::backend::{S3Backend, Shared};
use super::cache::MetaCache;
use super::cachedir::{CacheDir, Recovered, cache_error, identity};
use super::client::{ListRequest, Location, S3Client, Settings};
use super::entry::{Entry, Own};
use super::error::S3Error;
use super::jobs::{Guard, Jobs};
use super::keys::{MAX_KEY_LEN, dir_prefix};
use super::meta::same_times;
use super::overlay::Overlay;
use super::parts::{MAX_PART_SIZE, MIN_PART_SIZE};
use super::readahead::{MAX_CHUNK, MIN_CHUNK, ReadAhead};
use super::retry::Retry;
use super::sigv4::Credentials;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_METADATA_TTL: Duration = Duration::from_secs(30);
const DEFAULT_LISTING_METADATA_MAX: usize = 1000;
const DEFAULT_UPLOAD_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_PART_SIZE: u64 = 16 << 20;
const DEFAULT_UPLOAD_CONCURRENCY: usize = 4;
const DEFAULT_READ_CHUNK: u32 = 8 << 20;
const DEFAULT_MAX_DIR_RENAME_OBJECTS: usize = 10_000;

/// Settings of an [`S3Backend`], set through the methods below and applied by
/// [`build`](S3BackendBuilder::build).
pub struct S3BackendBuilder {
    endpoint: String,
    region: String,
    bucket: String,
    credentials: Option<Credentials>,
    prefix: String,
    path_style: Option<bool>,
    cache_dir: Option<PathBuf>,
    read_only: bool,
    case_insensitive: bool,
    request_timeout: Duration,
    metadata_ttl: Duration,
    listing_metadata_max: usize,
    upload_delay: Duration,
    part_size: u64,
    upload_concurrency: usize,
    read_chunk: u32,
    max_dir_rename_objects: usize,
    /// Keeps the worker from starting jobs until a test lets it.
    #[cfg(test)]
    held_uploads: bool,
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
            cache_dir: None,
            read_only: false,
            case_insensitive: true,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            metadata_ttl: DEFAULT_METADATA_TTL,
            listing_metadata_max: DEFAULT_LISTING_METADATA_MAX,
            upload_delay: DEFAULT_UPLOAD_DELAY,
            part_size: DEFAULT_PART_SIZE,
            upload_concurrency: DEFAULT_UPLOAD_CONCURRENCY,
            read_chunk: DEFAULT_READ_CHUNK,
            max_dir_rename_objects: DEFAULT_MAX_DIR_RENAME_OBJECTS,
            #[cfg(test)]
            held_uploads: false,
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

    /// Keeps what clients change in `dir`. The backend makes `dir` if it is
    /// missing and locks it until every clone of the backend is dropped, the
    /// handles opened through it are closed and the requests in flight have
    /// ended. The directory must belong to this endpoint, bucket, prefix and
    /// [case setting](Self::case_insensitive), and be on storage that
    /// survives a restart: what it holds is not in the bucket.
    ///
    /// Required unless the backend is [`read_only`](Self::read_only), and
    /// refused with it.
    #[must_use]
    pub fn cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }

    /// Refuses every change to the share. The backend then needs no
    /// [`cache_dir`](Self::cache_dir), and one is refused.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Sets whether names match without regard to case. On by default: a name
    /// that no key spells exactly opens the first key that differs only in
    /// case, and a job that stores a file waits while another job stores, or a
    /// request deletes, a key that differs from its own only in case. Off,
    /// every name is exactly a key, so the store has to keep case: on a store
    /// that holds `Doc` and `doc` as one object, a change to one overwrites
    /// or deletes the other. A [cache directory](Self::cache_dir) is used with
    /// one setting only.
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

    /// Sets how long a file rests after its last change before the backend
    /// stores it in the bucket. A file that is open and left alone is stored
    /// too. Opening a file without overwriting it, or closing it, is not a
    /// change. A change to a file that is being stored stops the upload, and
    /// the file rests this long again. Renames, and times and attributes set
    /// on a file or directory, are stored after the same rest. The old key of
    /// a renamed file is deleted once the new key holds its content.
    /// The objects of deleted files are deleted in batches once nothing has
    /// been deleted for this long, at most a minute after the first of them
    /// was due.
    /// The default is 5 seconds.
    #[must_use]
    pub fn upload_delay(mut self, delay: Duration) -> Self {
        self.upload_delay = delay;
        self
    }

    /// Sets the size of the parts of a multipart upload, from 5 MiB to 5 GiB.
    /// A file of up to this many bytes is stored with one request; a larger
    /// one is stored in parts of this size. A file that would take more than
    /// 10,000 parts is stored in larger parts. The default is 16 MiB.
    #[must_use]
    pub fn part_size(mut self, bytes: u64) -> Self {
        self.part_size = bytes;
        self
    }

    /// Sets how many uploads run at once, and how many parts of a multipart
    /// upload are in flight at once for each. A listing keeps four times this
    /// many HEAD requests in flight, at most 64. The default is 4.
    #[must_use]
    pub fn upload_concurrency(mut self, concurrency: usize) -> Self {
        self.upload_concurrency = concurrency;
        self
    }

    /// Sets the size of the chunks that reads of objects with an ETag
    /// request, from 64 KiB to 32 MiB. Chunks are counted from the start of
    /// the object, and a read requests those that hold its bytes. A read of an
    /// object without an ETag requests the bytes it asks for. The backend
    /// keeps chunks for later reads while a handle that reads their version of
    /// the object is open: up to 4 chunks of each version, and 128 MiB of
    /// chunks over all versions. The default is 8 MiB.
    #[must_use]
    pub fn read_chunk(mut self, bytes: u32) -> Self {
        self.read_chunk = bytes;
        self
    }

    /// Sets the most objects a renamed directory may hold: the objects below
    /// it in the bucket and the entries the backend holds for it. A rename of
    /// a directory with more fails with
    /// [`AccessDenied`](crate::SmbError::AccessDenied) and changes nothing.
    /// The objects move after the rename answers. The cap bounds the memory
    /// and the cache directory space a move takes. The default is 10,000.
    #[must_use]
    pub fn max_dir_rename_objects(mut self, max: usize) -> Self {
        self.max_dir_rename_objects = max;
        self
    }

    /// Keeps the backend from starting uploads until
    /// [`hold_uploads`](S3Backend::hold_uploads) lets it.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn held_uploads(mut self, held: bool) -> Self {
        self.held_uploads = held;
        self
    }

    /// Checks the settings and the bucket, and returns the backend.
    ///
    /// # Errors
    ///
    /// Fails for settings that cannot be used and for a platform without root
    /// certificates.
    ///
    /// Fails for a cache directory that cannot be used, is locked by another
    /// backend, belongs to another endpoint, bucket, prefix or case setting,
    /// or has files and no identity.
    ///
    /// Fails when one request for the keys below the prefix fails: the store
    /// answers with an error, as for a bucket that does not exist or
    /// credentials it refuses, or does not answer, as for an unreachable
    /// endpoint or a timeout. The request runs before the cache directory is
    /// read back.
    ///
    /// Files an earlier backend recorded come back into the share with their
    /// times and attributes. The backend stores them, and the directory
    /// markers, renames and deletes an earlier one left, without waiting for
    /// the upload delay, including those whose upload failed. A file comes
    /// back as last recorded: one made and never recorded is gone, and an
    /// object changed and never recorded reads as the bucket has it. A file in
    /// the cache directory that cannot be read back moves to its `conflicts`
    /// directory, with an error in the log.
    pub async fn build(self) -> Result<S3Backend, S3Error> {
        let credentials = self.check()?;
        let local = match &self.cache_dir {
            None => None,
            Some(dir) => {
                let dir = dir.clone();
                let who = identity(
                    &origin(&self.endpoint),
                    &self.bucket,
                    &self.prefix,
                    self.case_insensitive,
                );
                let opened = tokio::task::spawn_blocking(move || CacheDir::open(&dir, &who))
                    .await
                    .map_err(|e| cache_error(io::Error::other(e)))??;
                Some(Arc::new(opened))
            }
        };
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

        let recovered = match &local {
            None => Recovered::default(),
            Some(local) => {
                let local = Arc::clone(local);
                let (prefix, fold) = (self.prefix.clone(), self.case_insensitive);
                tokio::task::spawn_blocking(move || local.recover(&prefix, fold))
                    .await
                    .map_err(|e| cache_error(io::Error::other(e)))?
                    .map_err(cache_error)?
            }
        };

        let built = SystemTime::now();
        let ahead = Arc::new(ReadAhead::new());
        let overlay = Overlay::new(self.case_insensitive, self.upload_delay);
        let entries = recovered
            .entries
            .into_iter()
            .map(|(record, file)| Entry::recovered(record, file, &ahead))
            .collect();
        let restored = overlay.install(entries, recovered.tombstones);
        if restored > 0 {
            info!(
                entries = restored,
                "entries restored from the cache directory"
            );
        }

        let jobs = Jobs::new(self.part_size, self.upload_concurrency);
        #[cfg(test)]
        jobs.held
            .store(self.held_uploads, std::sync::atomic::Ordering::SeqCst);
        let shared = Arc::new(Shared {
            client,
            prefix: self.prefix,
            case_insensitive: self.case_insensitive,
            request_timeout: self.request_timeout,
            listing_metadata_max: self.listing_metadata_max,
            head_concurrency: head_concurrency(self.upload_concurrency),
            built,
            cache: Mutex::new(MetaCache::new(self.metadata_ttl)),
            read_chunk: u64::from(self.read_chunk),
            max_dir_rename_objects: self.max_dir_rename_objects,
            ahead,
            read_only: self.read_only,
            overlay,
            local,
            root_own: Mutex::new(Own {
                times: same_times(built),
                attributes: 0,
            }),
            jobs,
        });
        let worker = Arc::new(Guard::start(&shared));
        Ok(S3Backend {
            shared,
            _worker: worker,
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
        if !(MIN_PART_SIZE..=MAX_PART_SIZE).contains(&self.part_size) {
            return Err(S3Error::InvalidArgument(
                "the part size is not between 5 MiB and 5 GiB",
            ));
        }
        if !(MIN_CHUNK..=MAX_CHUNK).contains(&self.read_chunk) {
            return Err(S3Error::InvalidArgument(
                "the read chunk is not between 64 KiB and 32 MiB",
            ));
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
        match (self.read_only, &self.cache_dir) {
            (false, None) => {
                return Err(S3Error::InvalidArgument(
                    "the cache directory is not set; call cache_dir() or read_only()",
                ));
            }
            (true, Some(_)) => {
                return Err(S3Error::InvalidArgument(
                    "a read-only backend has no use for a cache directory",
                ));
            }
            _ => {}
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
    fn the_read_chunk_is_between_64_kib_and_32_mib() {
        for bytes in [0, 1, MIN_CHUNK - 1, MAX_CHUNK + 1, u32::MAX] {
            assert!(
                refusal(builder().read_chunk(bytes)).contains("read chunk"),
                "{bytes}"
            );
        }
        for bytes in [MIN_CHUNK, DEFAULT_READ_CHUNK, MAX_CHUNK] {
            assert!(builder().read_chunk(bytes).check().is_ok(), "{bytes}");
        }
    }

    #[test]
    fn a_writable_backend_needs_a_cache_directory_and_a_read_only_one_refuses_it() {
        let writable = S3Backend::builder("http://127.0.0.1:1", "r", "b").credentials("a", "s");
        let why = refusal(writable);
        assert!(why.contains("cache_dir()"), "{why}");
        assert!(why.contains("read_only()"), "{why}");

        let both = builder().cache_dir("cache");
        assert!(refusal(both).contains("read-only"));

        let writable = S3Backend::builder("http://127.0.0.1:1", "r", "b")
            .credentials("a", "s")
            .cache_dir("cache");
        assert!(writable.check().is_ok());
    }

    #[test]
    fn the_part_size_is_between_5_mib_and_5_gib() {
        assert!(builder().check().is_ok(), "the default");
        for ok in [5 << 20, (5 << 20) + 1, 64 << 20, 5 << 30] {
            assert!(builder().part_size(ok).check().is_ok(), "{ok}");
        }
        for refused in [0, 1, (5 << 20) - 1, (5 << 30) + 1, u64::MAX] {
            assert!(
                refusal(builder().part_size(refused)).contains("part size"),
                "{refused}"
            );
        }
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
