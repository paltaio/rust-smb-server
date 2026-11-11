//! S3 storage backend.

mod backend;
mod builder;
mod cache;
pub(crate) mod client;
pub(crate) mod date;
pub(crate) mod encode;
pub(crate) mod error;
mod handle;
mod keys;
mod list;
mod lookup;
mod meta;
pub(crate) mod object;
pub(crate) mod payload;
mod read;
mod readahead;
pub(crate) mod retry;
pub(crate) mod sigv4;
pub(crate) mod transport;
pub(crate) mod xml;

pub use backend::S3Backend;
pub use builder::S3BackendBuilder;
pub use error::S3Error;
