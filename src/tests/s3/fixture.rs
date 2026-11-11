//! A bucket on the gateway, clients for it, and object contents for tests.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use super::gateway::{Gateway, REGION, gateway};
use crate::s3::client::{Location, S3Client, Settings};
use crate::s3::encode::hex;
use crate::s3::object::{ByteRange, Metadata};
use crate::s3::payload::Payload;
use crate::s3::retry::Retry;
use crate::s3::sigv4::Credentials;

pub(super) const MIB: usize = 1024 * 1024;

/// A `Last-Modified` value in the past.
pub(super) const OLD: &str = "Fri, 24 May 2013 00:00:00 GMT";

/// A bucket made for one test.
pub(super) struct TestBucket {
    pub(super) gateway: &'static Gateway,
    pub(super) name: String,
    /// A client that reaches the gateway directly.
    pub(super) client: S3Client,
}

impl TestBucket {
    /// Starts the gateway if no test has, and makes a bucket on it.
    pub(super) async fn new() -> Self {
        let gateway = tokio::task::spawn_blocking(gateway).await.unwrap();
        let name = gateway.bucket_name();
        let client = S3Client::new(settings(gateway, gateway.addr, &name)).unwrap();
        client.create_bucket().await.unwrap();
        TestBucket {
            gateway,
            name,
            client,
        }
    }

    /// A client for this bucket that connects to `addr`, with `adjust` applied
    /// to its settings.
    pub(super) fn client_at(
        &self,
        addr: SocketAddr,
        adjust: impl FnOnce(&mut Settings),
    ) -> S3Client {
        let mut settings = settings(self.gateway, addr, &self.name);
        adjust(&mut settings);
        S3Client::new(settings).unwrap()
    }
}

/// A client for a bucket at `addr` with made-up credentials, for a server that
/// is not the gateway.
pub(super) fn offline_client(addr: SocketAddr, adjust: impl FnOnce(&mut Settings)) -> S3Client {
    let mut settings = Settings::new(
        location(addr, REGION, "offline-bucket"),
        credentials("AKIDEXAMPLE", "SECRETEXAMPLE"),
    );
    adjust(&mut settings);
    S3Client::new(settings).unwrap()
}

/// A bucket at the plain HTTP endpoint `addr`.
pub(super) fn location(addr: SocketAddr, region: &str, bucket: &str) -> Location {
    Location {
        endpoint: format!("http://{addr}"),
        region: region.into(),
        bucket: bucket.into(),
    }
}

pub(super) fn credentials(access_key: &str, secret_key: &str) -> Credentials {
    Credentials {
        access_key: access_key.into(),
        secret_key: secret_key.into(),
        session_token: None,
    }
}

fn settings(gateway: &Gateway, addr: SocketAddr, bucket: &str) -> Settings {
    Settings::new(
        location(addr, REGION, bucket),
        credentials(&gateway.access_key, &gateway.secret_key),
    )
}

pub(super) fn range(start: u64, len: u64) -> ByteRange {
    ByteRange::new(start, len).unwrap()
}

/// A file holding `data`, shared as the client takes it.
pub(super) fn file_with(data: &[u8]) -> Arc<File> {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(data).unwrap();
    Arc::new(file)
}

/// Writes `data` at byte `at` of `file`.
pub(super) fn overwrite(file: &Arc<File>, at: u64, data: &[u8]) {
    let mut file: &File = file;
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(data).unwrap();
}

/// A payload of the bytes `file` holds from `offset`, which are `data`.
pub(super) fn file_payload(file: &Arc<File>, offset: u64, data: &[u8]) -> Payload {
    let hash = hex(&Sha256::digest(data));
    Payload::file(file.clone(), offset, data.len() as u64, &hash).unwrap()
}

/// A foreground deadline that no call that works comes near.
pub(super) fn foreground() -> Retry {
    Retry::within(Duration::from_secs(60))
}

/// Stores `body` under `key` and returns the ETag of the object.
pub(super) async fn put(client: &S3Client, key: &str, body: impl AsRef<[u8]>) -> String {
    client
        .put_object(
            key,
            Bytes::copy_from_slice(body.as_ref()),
            &Metadata::default(),
            foreground(),
        )
        .await
        .unwrap()
}

/// Whether a HEAD for `key` finds no object. Panics if it finds one.
pub(super) async fn is_missing(client: &S3Client, key: &str) -> bool {
    client
        .head_object(key, foreground())
        .await
        .unwrap_err()
        .is_no_such_key()
}

/// `len` bytes of a pattern that never repeats within 251 bytes, starting at
/// byte `offset` of it. Ranges of one pattern show a shifted or swapped part.
pub(super) fn pattern(offset: usize, len: usize) -> Bytes {
    (0..len)
        .map(|i| ((offset + i) % 251) as u8)
        .collect::<Vec<_>>()
        .into()
}

/// Metadata with these user keys and nothing else.
pub(super) fn user_metadata(pairs: &[(&str, &str)]) -> Metadata {
    Metadata {
        user: pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<BTreeMap<_, _>>(),
        ..Metadata::default()
    }
}
