//! The reply to Apple's `AAPL` server query, which macOS clients put in
//! the CREATE of a share's root when they mount it.

use crate::proto::messages::aapl::{AAPL_CASE_SENSITIVE, AAPL_UNIX_BASED};
use crate::proto::messages::{AaplQuery, AaplReply, CreateContext};
use crate::server::ShareBindings;

/// The server caps of a reply. With UNIX_BASED the client relies on the
/// server to zero-fill gaps past the end of a file.
const SERVER_CAPS: u64 = if cfg!(unix) { AAPL_UNIX_BASED } else { 0 };

/// The `AAPL` response context to `query` on `share`, with `model`.
pub(super) fn reply(share: &ShareBindings, query: &AaplQuery, model: &str) -> CreateContext {
    let volume_caps = if share.backend.capabilities().case_sensitive {
        AAPL_CASE_SENSITIVE
    } else {
        0
    };
    CreateContext {
        name: CreateContext::NAME_AAPL.to_vec(),
        data: AaplReply {
            bitmap: query.bitmap,
            server_caps: SERVER_CAPS,
            volume_caps,
            model,
        }
        .encode(),
    }
}
