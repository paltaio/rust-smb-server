//! IOCTL handler (MS-SMB2 3.3.5.15): FSCTL_VALIDATE_NEGOTIATE_INFO,
//! FSCTL_SRV_ENUMERATE_SNAPSHOTS with no snapshots, STATUS_FS_DRIVER_REQUIRED
//! for DFS referrals and STATUS_NOT_SUPPORTED for the rest.

use std::sync::Arc;

use crate::proto::header::{SMB2_HEADER_LEN, Smb2Header};
use crate::proto::messages::{Dialect, FileId, Fsctl, IoctlRequest, IoctlResponse};
use tracing::warn;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::negotiate::{select_dialect, server_capabilities, server_security_mode};
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

/// Size of the fixed part of an IOCTL request, before Buffer.
const IOCTL_FIXED_LEN: usize = 56;

/// Size of a VALIDATE_NEGOTIATE_INFO response (MS-SMB2 2.2.32.6).
const VALIDATE_NEGOTIATE_RESPONSE_LEN: u32 = 24;

/// Offset of the response Buffer from the start of the SMB2 header.
const RESPONSE_BUFFER_OFFSET: u32 = 0x70;

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
    let req = match IoctlRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    if req.flags != IoctlRequest::FLAG_IS_FSCTL {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }

    let fsctl = req.fsctl();
    let no_file = matches!(
        fsctl,
        Fsctl::DfsGetReferrals
            | Fsctl::DfsGetReferralsEx
            | Fsctl::QueryNetworkInterfaceInfo
            | Fsctl::ValidateNegotiateInfo
            | Fsctl::PipeWait
    );
    let open = if no_file {
        if req.file_id != FileId::any() {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        None
    } else {
        match lookup_open(&tree, req.file_id).await {
            Some(open) => Some(open),
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };

    let max_transact = *conn.max_read_size.read().await;
    if req.input_count > max_transact
        || req.max_input_response > max_transact
        || req.max_output_response > max_transact
    {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let Some(input) = input_buffer(&req, body) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };

    match fsctl {
        Fsctl::ValidateNegotiateInfo => validate_negotiate_info(server, conn, &req, input).await,
        Fsctl::SrvEnumerateSnapshots => {
            if req.max_output_response < 16 {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            let file_id = match open {
                Some(open) => open.read().await.file_id,
                None => req.file_id,
            };
            // SRV_SNAPSHOT_ARRAY with no snapshots: NumberOfSnapShots,
            // NumberOfSnapShotsReturned and SnapShotArraySize all 0.
            response(req.ctl_code, file_id, vec![0u8; 12])
        }
        Fsctl::DfsGetReferrals | Fsctl::DfsGetReferralsEx => {
            HandlerResponse::err(ntstatus::STATUS_FS_DRIVER_REQUIRED)
        }
        _ => HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    }
}

/// The request's input buffer, located by InputOffset, or `None` when the
/// offset and count break the rules of MS-SMB2 3.3.5.15.
fn input_buffer<'a>(req: &IoctlRequest, body: &'a [u8]) -> Option<&'a [u8]> {
    if req.input_count == 0 {
        return Some(&[]);
    }
    let offset = req.input_offset as usize;
    if offset < SMB2_HEADER_LEN + IOCTL_FIXED_LEN || !offset.is_multiple_of(8) {
        return None;
    }
    let start = offset - SMB2_HEADER_LEN;
    let end = start.checked_add(req.input_count as usize)?;
    body.get(start..end)
}

fn response(ctl_code: u32, file_id: FileId, output: Vec<u8>) -> HandlerResponse {
    let resp = IoctlResponse {
        structure_size: 49,
        reserved: 0,
        ctl_code,
        file_id,
        input_offset: RESPONSE_BUFFER_OFFSET,
        input_count: 0,
        output_offset: RESPONSE_BUFFER_OFFSET,
        output_count: output.len() as u32,
        flags: 0,
        reserved2: 0,
        output,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("IOCTL response encodes");
    HandlerResponse::ok(buf)
}

/// MS-SMB2 3.3.5.15.12. Every mismatch with the NEGOTIATE the client sent
/// closes the connection: it means the negotiation was tampered with.
async fn validate_negotiate_info(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    req: &IoctlRequest,
    input: &[u8],
) -> HandlerResponse {
    let dialect = *conn.dialect.read().await;
    let client = conn
        .client_negotiate
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let terminate = |reason: &str| {
        warn!(
            reason,
            "VALIDATE_NEGOTIATE_INFO failed; closing the connection"
        );
        conn.request_disconnect();
        HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED)
    };

    let (Some(dialect), Some(client)) = (dialect, client) else {
        return terminate("no negotiated dialect");
    };
    if dialect == Dialect::Smb311 {
        return terminate("not used with SMB 3.1.1");
    }
    if req.max_output_response < VALIDATE_NEGOTIATE_RESPONSE_LEN {
        return terminate("MaxOutputResponse too small");
    }
    let Some(request) = ValidateNegotiateRequest::parse(input) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    if request.dialects != client.dialects {
        return terminate("dialects differ");
    }
    if select_dialect(&request.dialects) != Some(dialect) {
        return terminate("dialect differs");
    }
    if request.guid != client.guid {
        return terminate("client GUID differs");
    }
    if request.security_mode != client.security_mode {
        return terminate("security mode differs");
    }
    if request.capabilities != client.capabilities {
        return terminate("capabilities differ");
    }

    let mut out = Vec::with_capacity(VALIDATE_NEGOTIATE_RESPONSE_LEN as usize);
    out.extend_from_slice(&server_capabilities(dialect).to_le_bytes());
    out.extend_from_slice(conn.server_guid.as_bytes());
    out.extend_from_slice(&server_security_mode(server).to_le_bytes());
    out.extend_from_slice(&dialect.as_u16().to_le_bytes());
    response(Fsctl::VALIDATE_NEGOTIATE_INFO, FileId::any(), out)
}

/// VALIDATE_NEGOTIATE_INFO request (MS-SMB2 2.2.31.4).
struct ValidateNegotiateRequest {
    capabilities: u32,
    guid: [u8; 16],
    security_mode: u16,
    dialects: Vec<u16>,
}

impl ValidateNegotiateRequest {
    fn parse(input: &[u8]) -> Option<Self> {
        let fixed = input.get(..24)?;
        let count = u16::from_le_bytes([fixed[22], fixed[23]]) as usize;
        let list = input.get(24..24 + 2 * count)?;
        Some(Self {
            capabilities: u32::from_le_bytes(fixed[0..4].try_into().ok()?),
            guid: fixed[4..20].try_into().ok()?,
            security_mode: u16::from_le_bytes([fixed[20], fixed[21]]),
            dialects: list
                .chunks_exact(2)
                .map(|d| u16::from_le_bytes([d[0], d[1]]))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::Access;
    use crate::conn::state::{Session, TreeConnect};
    use crate::handlers::negotiate::ClientNegotiate;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail};
    use crate::server::ShareBindings;
    use tokio::sync::RwLock;

    const GUID: [u8; 16] = [0xCD; 16];
    const DIALECTS: [u16; 2] = [0x0300, 0x0302];

    async fn connection(dialect: Dialect) -> (Arc<ServerState>, Arc<Connection>) {
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("build")
            .state();
        let conn = Arc::new(Connection::new(server.config.server_guid, 65536, 65536));
        *conn.dialect.write().await = Some(dialect);
        *conn.client_negotiate.lock().unwrap() = Some(ClientNegotiate {
            capabilities: 0x44,
            security_mode: 0x0001,
            guid: GUID,
            dialects: DIALECTS.to_vec(),
        });
        let session = Session::new(Identity::Anonymous, [0; 16], [0; 16], false, None);
        let tree = TreeConnect::new(1, ShareBindings::ipc(), Access::Read);
        session
            .trees
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(tree)));
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(RwLock::new(session)));
        (server, conn)
    }

    fn header() -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: Command::Ioctl,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id: 5,
            tail: HeaderTail::sync(1),
            session_id: 7,
            signature: [0; 16],
        }
    }

    fn validate_body(caps: u32, guid: [u8; 16], mode: u16, dialects: &[u16], max: u32) -> Vec<u8> {
        let mut input = caps.to_le_bytes().to_vec();
        input.extend_from_slice(&guid);
        input.extend_from_slice(&mode.to_le_bytes());
        input.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
        for d in dialects {
            input.extend_from_slice(&d.to_le_bytes());
        }
        let mut body = Vec::new();
        IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
            file_id: FileId::any(),
            input_offset: 0x78,
            input_count: input.len() as u32,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: max,
            flags: IoctlRequest::FLAG_IS_FSCTL,
            reserved2: 0,
            input,
        }
        .write_to(&mut body)
        .unwrap();
        body
    }

    #[tokio::test]
    async fn validate_negotiate_info_mismatch_requests_a_disconnect() {
        let cases = [
            (0x7F, GUID, 0x0001, &DIALECTS[..], 24),
            (0x44, [0xEE; 16], 0x0001, &DIALECTS[..], 24),
            (0x44, GUID, 0x0003, &DIALECTS[..], 24),
            (0x44, GUID, 0x0001, &[0x0300][..], 24),
            (0x44, GUID, 0x0001, &DIALECTS[..], 23),
        ];
        for (caps, guid, mode, dialects, max) in cases {
            let (server, conn) = connection(Dialect::Smb302).await;
            let body = validate_body(caps, guid, mode, dialects, max);
            let resp = handle(&server, &conn, &header(), &body).await;
            assert_ne!(resp.status, ntstatus::STATUS_SUCCESS);
            assert!(conn.disconnect_requested(), "{caps:x} {mode} {dialects:?}");
        }

        let (server, conn) = connection(Dialect::Smb302).await;
        let body = validate_body(0x44, GUID, 0x0001, &DIALECTS, 24);
        let resp = handle(&server, &conn, &header(), &body).await;
        assert_eq!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(!conn.disconnect_requested());
    }

    #[tokio::test]
    async fn validate_negotiate_info_on_smb311_requests_a_disconnect() {
        let (server, conn) = connection(Dialect::Smb311).await;
        let dialects = [0x0300, 0x0302, 0x0311];
        conn.client_negotiate
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .dialects = dialects.to_vec();
        let body = validate_body(0x44, GUID, 0x0001, &dialects, 24);
        handle(&server, &conn, &header(), &body).await;
        assert!(conn.disconnect_requested());
    }
}
