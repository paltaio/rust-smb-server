//! The factories of the backends the suite runs over.

#[cfg(feature = "s3")]
use std::path::Path;

#[cfg(feature = "s3")]
use tokio::sync::watch;

#[cfg(feature = "encryption")]
use crate::encrypted::testing::names_over;
#[cfg(all(feature = "encryption", feature = "localfs"))]
use crate::encrypted::testing::{clear_over, names_with};
#[cfg(feature = "localfs")]
use crate::fs::LocalFsBackend;
use crate::tests::memfs::MemFsBackend;
#[cfg(feature = "s3")]
use crate::tests::s3::fixture::TestBucket;
#[cfg(feature = "s3")]
use crate::tests::s3::share::{worker_ended, writable_builder};
#[cfg(feature = "s3")]
use crate::{S3Backend, S3BackendBuilder};

#[cfg(feature = "s3")]
use super::BoxFuture;
use super::{Error, Fixture};

pub(super) async fn memfs() -> Result<Fixture, Error> {
    Ok(Fixture::new(MemFsBackend::new()))
}

/// A backend over a new directory, and the directory.
#[cfg(feature = "localfs")]
fn local() -> Result<(LocalFsBackend, tempfile::TempDir), Error> {
    let dir = tempfile::tempdir()?;
    Ok((LocalFsBackend::new(dir.path())?, dir))
}

/// `backend`, with `dir` removed once the test is over.
#[cfg(feature = "localfs")]
fn over(backend: impl crate::backend::ShareBackend, dir: tempfile::TempDir) -> Fixture {
    Fixture {
        after: Some(Box::pin(async move { drop(dir) })),
        ..Fixture::new(backend)
    }
}

#[cfg(feature = "localfs")]
pub(super) async fn localfs() -> Result<Fixture, Error> {
    let (backend, dir) = local()?;
    Ok(over(backend, dir))
}

#[cfg(feature = "encryption")]
pub(super) async fn layer_memfs() -> Result<Fixture, Error> {
    Ok(Fixture::new(names_over(MemFsBackend::new()).await))
}

#[cfg(all(feature = "encryption", feature = "localfs"))]
pub(super) async fn layer_localfs() -> Result<Fixture, Error> {
    let (backend, dir) = local()?;
    Ok(over(names_over(backend).await, dir))
}

/// The layer with names in the clear.
#[cfg(all(feature = "encryption", feature = "localfs"))]
pub(super) async fn layer_clear_localfs() -> Result<Fixture, Error> {
    let (backend, dir) = local()?;
    Ok(over(clear_over(backend).await, dir))
}

/// The layer with encrypted names that match exactly.
#[cfg(all(feature = "encryption", feature = "localfs"))]
pub(super) async fn layer_exact_localfs() -> Result<Fixture, Error> {
    let (backend, dir) = local()?;
    let layer = names_with(backend, |builder| builder.case_insensitive(false)).await;
    Ok(over(layer, dir))
}

/// Raises the soft limit on open files. A backend keeps open every file it
/// has made and not yet stored, and a process on macOS starts with room for
/// 256.
#[cfg(all(feature = "s3", unix))]
fn raise_file_limit() {
    static RAISED: std::sync::Once = std::sync::Once::new();
    RAISED.call_once(|| {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid rlimit for both calls to read and write.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                limit.rlim_cur = limit.rlim_cur.max(limit.rlim_max.min(8192));
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }
    });
}

/// A backend of the bucket that keeps its changes in `cache`, built with the
/// settings `configure` makes, and the signal that its worker has ended.
#[cfg(feature = "s3")]
pub(super) async fn s3_backend(
    bucket: &TestBucket,
    cache: &Path,
    configure: impl FnOnce(S3BackendBuilder) -> S3BackendBuilder,
) -> Result<(S3Backend, watch::Receiver<bool>), Error> {
    #[cfg(unix)]
    raise_file_limit();
    let backend = configure(writable_builder(bucket, bucket.gateway.addr, cache))
        .build()
        .await?;
    let exited = backend.worker_exited();
    Ok((backend, exited))
}

/// Removes `cache` once the worker of the backend over it has ended.
#[cfg(feature = "s3")]
fn after_s3(exited: watch::Receiver<bool>, cache: tempfile::TempDir) -> BoxFuture<'static, ()> {
    Box::pin(async move {
        worker_ended(exited).await;
        drop(cache);
    })
}

#[cfg(feature = "s3")]
pub(super) async fn s3() -> Result<Fixture, Error> {
    let bucket = TestBucket::new().await;
    let cache = tempfile::tempdir()?;
    let (backend, exited) = s3_backend(&bucket, cache.path(), |builder| builder).await?;
    Ok(Fixture {
        after: Some(after_s3(exited, cache)),
        ..Fixture::new(backend)
    })
}

/// The layer with encrypted names over a backend whose names match exactly.
#[cfg(all(feature = "encryption", feature = "s3"))]
pub(super) async fn layer_s3() -> Result<Fixture, Error> {
    let bucket = TestBucket::new().await;
    let cache = tempfile::tempdir()?;
    let (backend, exited) = s3_backend(&bucket, cache.path(), |builder| {
        builder.case_insensitive(false)
    })
    .await?;
    Ok(Fixture {
        after: Some(after_s3(exited, cache)),
        ..Fixture::new(names_over(backend).await)
    })
}
