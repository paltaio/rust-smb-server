//! NEGOTIATE handler.

use std::sync::Arc;

use crate::proto::auth::spnego::encode_init_response;
use crate::proto::crypto::SigningAlgo;
use crate::proto::header::{SMB2_HEADER_LEN, Smb2Header};
use crate::proto::messages::{
    Dialect, NegotiateContext, NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities,
    SigningCapabilities,
};
use binrw::BinRead;
use tracing::info;
use uuid::Uuid;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;
use crate::utils::{fill_random, now_filetime};

// MS-SMB2 2.2.4 SecurityMode bits. SIGNING_REQUIRED is set only when the
// server requires signing: anonymous Linux cifs mounts do not send enough
// NTLM material for the server to derive matching SMB3 signing keys.
const SIGNING_ENABLED: u16 = 0x0001;
const SIGNING_REQUIRED: u16 = 0x0002;

const CAP_LARGE_MTU: u32 = 0x0000_0004;

/// Size of the fixed part of a NEGOTIATE request, before Dialects.
const NEGOTIATE_FIXED_LEN: usize = 36;

/// Values from the client's NEGOTIATE request (MS-SMB2 3.3.5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNegotiate {
    pub capabilities: u32,
    pub security_mode: u16,
    pub guid: [u8; 16],
    pub dialects: Vec<u16>,
}

impl ClientNegotiate {
    /// Connection.ShouldSign: the client set SMB2_NEGOTIATE_SIGNING_REQUIRED.
    pub fn should_sign(&self) -> bool {
        self.security_mode & SIGNING_REQUIRED != 0
    }
}

/// SecurityMode the server sends (Connection.ServerSecurityMode).
pub(crate) fn server_security_mode(server: &ServerState) -> u16 {
    if server.auth.settings.require_signing {
        SIGNING_ENABLED | SIGNING_REQUIRED
    } else {
        SIGNING_ENABLED
    }
}

/// Capabilities the server sends for `dialect` (Connection.ServerCapabilities).
/// LARGE_MTU needs multi-credit support, which SMB 2.0.2 lacks.
pub(crate) fn server_capabilities(dialect: Dialect) -> u32 {
    match dialect {
        Dialect::Smb202 => 0,
        _ => CAP_LARGE_MTU,
    }
}

/// What the client's 3.1.1 NegotiateContextList asks of the response.
struct ClientContexts {
    /// The signing algorithm picked from the client's
    /// SMB2_SIGNING_CAPABILITIES, when it sent one.
    signing_algorithm: Option<u16>,
}

/// Checks the 3.1.1 NegotiateContextList of `req` (MS-SMB2 3.3.5.4).
/// `body` is the request after the SMB2 header.
fn read_contexts(body: &[u8], req: &NegotiateRequest) -> Result<ClientContexts, u32> {
    let invalid = ntstatus::STATUS_INVALID_PARAMETER;
    let field = req.negotiate_context_offset_or_client_start_time;
    let offset = (field & 0xFFFF_FFFF) as usize;
    let count = ((field >> 32) & 0xFFFF) as u16;
    let dialects_end = NEGOTIATE_FIXED_LEN + 2 * req.dialects.len();
    let start = offset.checked_sub(SMB2_HEADER_LEN).ok_or(invalid)?;
    if start < dialects_end || start > body.len() {
        return Err(invalid);
    }
    let list = NegotiateContext::parse_list(&body[start..], count).map_err(|_| invalid)?;

    let of_type = |t: u16| list.iter().filter(move |c| c.context_type == t);
    let mut preauth = of_type(NegotiateContext::TYPE_PREAUTH_INTEGRITY);
    let (Some(preauth), None) = (preauth.next(), preauth.next()) else {
        return Err(invalid);
    };
    for t in [
        NegotiateContext::TYPE_ENCRYPTION,
        NegotiateContext::TYPE_COMPRESSION,
        NegotiateContext::TYPE_RDMA_TRANSFORM,
        NegotiateContext::TYPE_SIGNING,
    ] {
        if of_type(t).count() > 1 {
            return Err(invalid);
        }
    }

    let caps = PreauthIntegrityCapabilities::read(&mut std::io::Cursor::new(&preauth.data))
        .map_err(|_| invalid)?;
    if !caps
        .hash_algorithms
        .contains(&PreauthIntegrityCapabilities::HASH_SHA512)
    {
        return Err(ntstatus::STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
    }

    let signing_algorithm = match of_type(NegotiateContext::TYPE_SIGNING).next() {
        Some(ctx) => {
            let caps = SigningCapabilities::read(&mut std::io::Cursor::new(&ctx.data))
                .map_err(|_| invalid)?;
            if caps.signing_algorithm_count == 0 {
                return Err(invalid);
            }
            // AES-CMAC is the one 3.1.1 algorithm implemented, and the
            // answer when the client lists none of the server's.
            Some(SigningCapabilities::ALGORITHM_AES_CMAC)
        }
        None => None,
    };
    Ok(ClientContexts { signing_algorithm })
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    _hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match NegotiateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    *conn
        .client_negotiate
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ClientNegotiate {
        capabilities: req.capabilities,
        security_mode: req.security_mode,
        guid: req.client_guid,
        dialects: req.dialects.clone(),
    });
    if req.dialects.is_empty() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }

    let Some(dialect) = select_dialect(&req.dialects) else {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };
    let chosen = dialect.as_u16();
    let contexts = if dialect == Dialect::Smb311 {
        match read_contexts(body, &req) {
            Ok(c) => Some(c),
            Err(status) => return HandlerResponse::err(status),
        }
    } else {
        None
    };

    *conn.dialect.write().await = Some(dialect);
    *conn.client_guid.write().await = Uuid::from_bytes(req.client_guid);
    *conn.signing_algo.write().await = match dialect {
        Dialect::Smb202 | Dialect::Smb210 => SigningAlgo::HmacSha256,
        _ => SigningAlgo::AesCmac,
    };

    // Build SPNEGO security blob (mech-list-only, advertising NTLMSSP).
    let security_blob = encode_init_response();
    let security_buffer_offset: u16 = 64 + 64; // SMB2 header + fixed NEG response (64 bytes)
    let security_buffer_length: u16 = security_blob.len() as u16;

    // For 3.1.1 build negotiate contexts.
    let mut contexts_bytes: Vec<u8> = Vec::new();
    let mut context_count: u16 = 0;
    let mut negotiate_context_offset: u32 = 0;

    if let Some(client_contexts) = contexts {
        // PREAUTH_INTEGRITY_CAPABILITIES
        let mut salt = [0u8; 32];
        if let Err(e) = fill_random(&mut salt) {
            tracing::error!(error = %e, "OS RNG failed; cannot generate preauth salt");
            return HandlerResponse::err(ntstatus::STATUS_INTERNAL_ERROR);
        }
        let preauth_caps = PreauthIntegrityCapabilities {
            hash_algorithm_count: 1,
            salt_length: 32,
            hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
            salt: salt.to_vec(),
        };
        let preauth_data = {
            use binrw::BinWrite;
            let mut c = std::io::Cursor::new(Vec::new());
            BinWrite::write(&preauth_caps, &mut c).expect("preauth negotiate context encodes");
            c.into_inner()
        };
        let preauth_ctx = NegotiateContext {
            context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
            data_length: preauth_data.len() as u16,
            reserved: 0,
            data: preauth_data,
        };

        let mut ctxs = vec![preauth_ctx];
        // SIGNING_CAPABILITIES goes back only to a client that sent one.
        if let Some(algorithm) = client_contexts.signing_algorithm {
            let signing_caps = SigningCapabilities {
                signing_algorithm_count: 1,
                signing_algorithms: vec![algorithm],
            };
            let signing_data = {
                use binrw::BinWrite;
                let mut c = std::io::Cursor::new(Vec::new());
                BinWrite::write(&signing_caps, &mut c).expect("signing negotiate context encodes");
                c.into_inner()
            };
            ctxs.push(NegotiateContext {
                context_type: NegotiateContext::TYPE_SIGNING,
                data_length: signing_data.len() as u16,
                reserved: 0,
                data: signing_data,
            });
        }
        if let Err(e) = NegotiateContext::encode_list(&ctxs, &mut contexts_bytes) {
            tracing::error!(error = %e, "encode_list failed");
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        context_count = ctxs.len() as u16;

        // The contexts go after security buffer, 8-byte aligned.
        let post_security = security_buffer_offset as u32 + security_buffer_length as u32;
        // Round up to next multiple of 8 from the start of the SMB2 header.
        negotiate_context_offset = (post_security + 7) & !7;
    }

    let max_read_size = *conn.max_read_size.read().await;
    let max_write_size = *conn.max_write_size.read().await;
    let max_transact_size = max_read_size;

    let resp = NegotiateResponse {
        structure_size: 65,
        security_mode: server_security_mode(server),
        dialect_revision: chosen,
        negotiate_context_count_or_reserved: context_count,
        server_guid: *server.config.server_guid.as_bytes(),
        capabilities: server_capabilities(dialect),
        max_transact_size,
        max_read_size,
        max_write_size,
        system_time: now_filetime(),
        server_start_time: 0,
        security_buffer_offset,
        security_buffer_length,
        negotiate_context_offset_or_reserved2: negotiate_context_offset,
        security_buffer: security_blob,
    };

    let mut body_out = Vec::new();
    if let Err(e) = resp.write_to(&mut body_out) {
        tracing::error!(error = %e, "encode NEGOTIATE response");
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // Append padding to align contexts at `negotiate_context_offset`.
    if dialect == Dialect::Smb311 && context_count > 0 {
        let cur = 64 + body_out.len() as u32; // header + body so far
        if cur < negotiate_context_offset {
            let pad = (negotiate_context_offset - cur) as usize;
            body_out.extend(std::iter::repeat_n(0u8, pad));
        }
        body_out.extend_from_slice(&contexts_bytes);
    }
    info!(?dialect, "NEGOTIATE complete");
    let mut hr = HandlerResponse::ok(body_out);
    hr.skip_signing = true;
    hr
}

/// The greatest dialect in `offered` that the server implements.
pub(crate) fn select_dialect(offered: &[u16]) -> Option<Dialect> {
    const SUPPORTED: &[u16] = &[0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    offered
        .iter()
        .copied()
        .filter(|d| SUPPORTED.contains(d))
        .max()
        .and_then(Dialect::from_u16)
}

/// Build the SMB2 NEGOTIATE response sent in reply to an SMB1 multi-protocol
/// NEGOTIATE_REQUEST that listed an SMB2 dialect (MS-SMB2 §3.3.5.3.1).
///
/// Leaves the connection dialect unset. The client follows up with an SMB2
/// NEGOTIATE, which goes through [`handle`].
pub async fn multi_protocol_response(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    chosen: u16,
) -> HandlerResponse {
    let security_blob = encode_init_response();
    let security_buffer_offset: u16 = 64 + 64;
    let security_buffer_length: u16 = security_blob.len() as u16;
    let max_read_size = *conn.max_read_size.read().await;
    let max_write_size = *conn.max_write_size.read().await;
    let max_transact_size = max_read_size;

    let resp = NegotiateResponse {
        structure_size: 65,
        security_mode: server_security_mode(server),
        dialect_revision: chosen,
        negotiate_context_count_or_reserved: 0,
        server_guid: *server.config.server_guid.as_bytes(),
        capabilities: 0,
        max_transact_size,
        max_read_size,
        max_write_size,
        system_time: now_filetime(),
        server_start_time: 0,
        security_buffer_offset,
        security_buffer_length,
        negotiate_context_offset_or_reserved2: 0,
        security_buffer: security_blob,
    };

    let mut body_out = Vec::new();
    if let Err(e) = resp.write_to(&mut body_out) {
        tracing::error!(error = %e, "encode multi-protocol NEGOTIATE response");
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    info!(
        chosen = %format_args!("0x{chosen:04X}"),
        "SMB1 multi-protocol -> SMB2"
    );
    let mut hr = HandlerResponse::ok(body_out);
    hr.skip_signing = true;
    hr
}
