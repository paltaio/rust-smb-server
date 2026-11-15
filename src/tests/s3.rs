//! Tests that need an S3 endpoint, served by a local Versity Gateway.

mod client;
mod closes;
mod dirs;
mod faults;
pub(super) mod fixture;
mod gateway;
mod listings;
mod lookups;
mod moves;
mod proxy;
mod readonly;
mod reads;
mod recovery;
pub(super) mod share;
pub(super) mod uploads;
mod wire;
mod writes;
