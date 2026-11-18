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
#[cfg(any(feature = "s3", all(windows, feature = "localfs")))]
use crate::tests::util::scratch_dir;
#[cfg(all(windows, feature = "localfs"))]
use crate::tests::util::{Contender, on_admin_share};
#[cfg(feature = "s3")]
use crate::{S3Backend, S3BackendBuilder};

#[cfg(feature = "s3")]
use super::BoxFuture;
use super::{Error, Fixture};

pub(super) async fn memfs() -> Result<Fixture, Error> {
    Ok(Fixture::new(MemFsBackend::new()))
}

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

/// A backend whose share root is a new directory beside the test binary,
/// reached through the administrative share of its drive on this host.
#[cfg(all(windows, feature = "localfs"))]
fn local_unc() -> Result<(LocalFsBackend, tempfile::TempDir), Error> {
    let dir = scratch_dir();
    Ok((LocalFsBackend::new(on_admin_share(dir.path()))?, dir))
}

#[cfg(all(windows, feature = "localfs"))]
pub(super) async fn localfs_unc() -> Result<Fixture, Error> {
    let (backend, dir) = local_unc()?;
    Ok(over(backend, dir))
}

#[cfg(all(windows, feature = "encryption", feature = "localfs"))]
pub(super) async fn layer_localfs_unc() -> Result<Fixture, Error> {
    let (backend, dir) = local_unc()?;
    Ok(over(names_over(backend).await, dir))
}

/// The names of the model run in `namespace`, which the contender opens in
/// the other case in every directory.
#[cfg(all(windows, feature = "localfs"))]
fn contended_names() -> Vec<String> {
    ["f", "F", "g.txt", "G.TXT", "d", "D", "e"]
        .into_iter()
        .map(str::to_string)
        .chain(["x".repeat(150), "X".repeat(150)])
        .collect()
}

/// `backend` over the share root `dir`, whose names a [`Contender`] opens
/// in the other case through the administrative share until the test is
/// over; `after` checks it made a whole pass over the tree.
#[cfg(all(windows, feature = "localfs"))]
fn contended(backend: impl crate::backend::ShareBackend, dir: tempfile::TempDir) -> Fixture {
    let contender = Contender::start(on_admin_share(dir.path()), &contended_names());
    Fixture {
        after: Some(Box::pin(async move {
            let passes = tokio::task::spawn_blocking(move || contender.stop())
                .await
                .expect("the contender stopped");
            drop(dir);
            assert!(passes > 0, "the contender made no pass over the tree");
        })),
        ..Fixture::new(backend)
    }
}

/// [`localfs_unc`] with a [`Contender`] on its names.
#[cfg(all(windows, feature = "localfs"))]
pub(super) async fn localfs_unc_contended() -> Result<Fixture, Error> {
    let (backend, dir) = local_unc()?;
    Ok(contended(backend, dir))
}

/// [`layer_localfs_unc`] with a [`Contender`] on its names.
#[cfg(all(windows, feature = "encryption", feature = "localfs"))]
pub(super) async fn layer_localfs_unc_contended() -> Result<Fixture, Error> {
    let (backend, dir) = local_unc()?;
    Ok(contended(names_over(backend).await, dir))
}

/// A backend of the bucket that keeps its changes in `cache`, built with the
/// settings `configure` makes, and the signal that its worker has ended.
#[cfg(feature = "s3")]
pub(super) async fn s3_backend(
    bucket: &TestBucket,
    cache: &Path,
    configure: impl FnOnce(S3BackendBuilder) -> S3BackendBuilder,
) -> Result<(S3Backend, watch::Receiver<bool>), Error> {
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
    let cache = scratch_dir();
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
    let cache = scratch_dir();
    let (backend, exited) = s3_backend(&bucket, cache.path(), |builder| {
        builder.case_insensitive(false)
    })
    .await?;
    Ok(Fixture {
        after: Some(after_s3(exited, cache)),
        ..Fixture::new(names_over(backend).await)
    })
}
