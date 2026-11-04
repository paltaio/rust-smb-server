//! Local-filesystem [`ShareBackend`] for `smb-server`, sandboxed via `cap-std`.

#[cfg(target_os = "linux")]
mod inotify;
mod local;
#[cfg(target_os = "macos")]
mod macos_streams;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod open_streams;
#[cfg(target_os = "linux")]
mod streams;

pub use local::LocalFsBackend;

mod volume;
