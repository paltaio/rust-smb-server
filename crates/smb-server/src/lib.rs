//! SMB2/3 file-sharing server with pluggable storage backends.
//!
//! See `docs/superpowers/specs/2026-04-27-rust-smb-server-design.md` for the
//! v1 design. The public API is small on purpose:
//!
//! ```no_run
//! use smb_server::{SmbServer, Share, Access, ShareBackend};
//! # async fn run<B: ShareBackend>(backend: B) -> Result<(), Box<dyn std::error::Error>> {
//! SmbServer::builder()
//!     .listen("0.0.0.0:4445".parse()?)
//!     .user("alice", "password")
//!     .share(Share::new("home", backend).user("alice", Access::ReadWrite))
//!     .build()?
//!     .serve()
//!     .await?;
//! # Ok(()) }
//! ```

pub mod backend;
pub mod builder;
pub mod conn;
pub mod dispatch;
pub mod error;
pub mod handlers;
pub mod info_class;
pub mod ntstatus;
pub mod path;
pub mod server;
pub mod utils;

pub use backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenIntent, OpenOptions,
    ShareBackend,
};
pub use builder::{Access, BuildError, Share, SmbServerBuilder};
pub use error::{SmbError, SmbResult};
pub use path::SmbPath;
pub use server::{ServerConfig, ShutdownHandle, SmbServer};
