//! The tests in `suites/files_create_action.rs`, over `LocalFsBackend`.
//! With the `encryption` feature, `integration_encrypted` runs them.
#![cfg(not(feature = "encryption"))]

mod common;

#[path = "suites/files_create_action.rs"]
mod files_create_action;
