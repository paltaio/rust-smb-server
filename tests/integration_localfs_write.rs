//! The tests in `suites/integration_localfs_write.rs`, over `LocalFsBackend`.
//! With the `encryption` feature, `integration_encrypted` runs them.
#![cfg(not(feature = "encryption"))]

mod common;

#[path = "suites/integration_localfs_write.rs"]
mod integration_localfs_write;
