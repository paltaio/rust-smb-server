//! The tests in `suites/files_delete_pending.rs`, over `LocalFsBackend`.
//! With the `encryption` feature, `integration_encrypted` runs them.
#![cfg(not(feature = "encryption"))]

mod common;

#[path = "suites/files_delete_pending.rs"]
mod files_delete_pending;
