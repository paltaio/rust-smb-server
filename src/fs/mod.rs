//! Local-filesystem [`ShareBackend`] for `smb-server`, sandboxed at the
//! share root: every name is looked up from a directory handle inside it.

mod dir;
#[cfg(target_os = "linux")]
mod eas;
#[cfg(target_os = "linux")]
mod inotify;
mod local;
#[cfg(target_os = "macos")]
mod macos_streams;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod open_streams;
#[cfg(target_os = "linux")]
mod reflink;
#[cfg(target_os = "linux")]
mod streams;
#[cfg(windows)]
mod windows_clone;
#[cfg(windows)]
mod windows_dir;
#[cfg(windows)]
mod windows_eas;
#[cfg(windows)]
mod windows_streams;
#[cfg(windows)]
mod windows_trash;

pub use local::LocalFsBackend;

mod volume;
