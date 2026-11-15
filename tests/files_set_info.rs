//! The tests in `suites/files_set_info.rs`, over `LocalFsBackend`.
//! With the `encryption` feature, `integration_encrypted` runs them.
#![cfg(not(feature = "encryption"))]

mod common;

#[path = "suites/files_set_info.rs"]
mod files_set_info;
