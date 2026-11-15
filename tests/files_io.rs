//! The tests in `suites/files_io.rs`, over `LocalFsBackend`.
//! With the `encryption` feature, `integration_encrypted` runs them.
#![cfg(not(feature = "encryption"))]

mod common;

#[path = "suites/files_io.rs"]
mod files_io;
