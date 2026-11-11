//! S3 storage backend.

mod backend;
mod builder;
mod cache;
pub(crate) mod cachedir;
mod change;
pub(crate) mod client;
mod data;
pub(crate) mod date;
pub(crate) mod encode;
mod entry;
pub(crate) mod error;
mod handle;
mod keys;
mod list;
mod lookup;
mod merge;
mod meta;
pub(crate) mod object;
mod open;
mod overlay;
pub(crate) mod payload;
mod ranges;
mod read;
mod readahead;
pub(crate) mod record;
pub(crate) mod retry;
pub(crate) mod sigv4;
pub(crate) mod transport;
pub(crate) mod xml;

pub use backend::S3Backend;
pub use builder::S3BackendBuilder;
pub use error::S3Error;
