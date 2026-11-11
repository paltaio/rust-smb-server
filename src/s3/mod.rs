//! S3 storage backend.

#![cfg_attr(not(test), expect(dead_code, reason = "called by tests only"))]

pub(crate) mod client;
pub(crate) mod date;
pub(crate) mod encode;
pub(crate) mod error;
pub(crate) mod object;
pub(crate) mod payload;
pub(crate) mod retry;
pub(crate) mod sigv4;
pub(crate) mod transport;
pub(crate) mod xml;
