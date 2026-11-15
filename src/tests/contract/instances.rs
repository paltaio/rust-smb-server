//! The factories of the backends the suite runs over.

#[cfg(feature = "encryption")]
use crate::encrypted::testing::names_over;
#[cfg(all(feature = "encryption", feature = "localfs"))]
use crate::encrypted::testing::{clear_over, names_with};
#[cfg(feature = "localfs")]
use crate::fs::LocalFsBackend;
use crate::tests::memfs::MemFsBackend;

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
