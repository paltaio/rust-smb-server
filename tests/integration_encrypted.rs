//! The file and query tests over `LocalFsBackend` and over the encrypted
//! layer on top of it.

mod common;

#[path = "suites/files_create_action.rs"]
mod files_create_action;
#[path = "suites/files_delete_pending.rs"]
mod files_delete_pending;
#[path = "suites/files_io.rs"]
mod files_io;
#[path = "suites/files_set_info.rs"]
mod files_set_info;
#[path = "suites/integration_localfs_write.rs"]
mod integration_localfs_write;
#[path = "suites/queries_directory.rs"]
mod queries_directory;
