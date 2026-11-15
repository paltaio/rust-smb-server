//! The tests in `suites/queries_directory.rs`, over `LocalFsBackend`.
//! With the `encryption` feature, `integration_encrypted` runs them.
#![cfg(all(feature = "localfs", not(feature = "encryption")))]

mod common;

#[path = "suites/queries_directory.rs"]
mod queries_directory;
