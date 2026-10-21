//! OPLOCK_BREAK handler (MS-SMB2 3.3.5.22). The server grants no oplocks,
//! and the read leases it grants break without an acknowledgment, so no
//! acknowledgment matches a break in progress.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::oplock_break::OplockBreakAck;
use crate::proto::messages::{Dialect, LeaseBreakAck};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::files::LeaseId;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

/// StructureSize of an oplock break acknowledgment.
const OPLOCK_ACK_SIZE: u16 = 24;
/// StructureSize of a lease break acknowledgment.
const LEASE_ACK_SIZE: u16 = 36;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let tree = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(status) => return HandlerResponse::err(status),
    };
    let structure_size = body.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let dialect = *conn.dialect.read().await;
    match structure_size {
        // MS-SMB2 3.3.5.22.2: the lease is not found, or no break of it is
        // in progress.
        Some(LEASE_ACK_SIZE) if dialect != Some(Dialect::Smb202) => {
            let Ok(ack) = LeaseBreakAck::parse(body) else {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            };
            let id = LeaseId {
                client: *conn.client_guid.read().await,
                key: ack.lease_key,
            };
            if server.leases.exists(id) {
                HandlerResponse::err(ntstatus::STATUS_UNSUCCESSFUL)
            } else {
                HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
            }
        }
        // MS-SMB2 3.3.5.22.1: no open, or an open with no break pending.
        Some(OPLOCK_ACK_SIZE | LEASE_ACK_SIZE) => {
            let Ok(ack) = OplockBreakAck::parse(body) else {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            };
            if lookup_open(&tree, ack.file_id).await.is_none() {
                return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
            }
            HandlerResponse::err(ntstatus::STATUS_INVALID_DEVICE_STATE)
        }
        _ => HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    }
}
