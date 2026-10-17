//! Per-frame dispatch: parse header, route to handler, sign response, encode.

use std::sync::Arc;

use crate::proto::auth::ntlm::Identity;
use crate::proto::crypto::{PreauthIntegrity, sign};
use crate::proto::framing::MAX_FRAME_PAYLOAD;
use crate::proto::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_RELATED_OPERATIONS,
    SMB2_FLAGS_SERVER_TO_REDIR, SMB2_FLAGS_SIGNED, SMB2_HEADER_LEN, Smb2Header,
};
use crate::proto::messages::{Dialect, ErrorResponse};
use tracing::{Instrument, debug, debug_span, error, warn};

use crate::conn::chain;
use crate::conn::credits::{CreditWindow, charge_covers};
use crate::conn::limits::supports_multi_credit;
use crate::conn::related::RelatedContext;
use crate::conn::state::Connection;
use crate::handlers;
use crate::ntstatus;
use crate::server::ServerState;

/// Result of a handler: a complete (unsigned) response payload + the NTSTATUS
/// to set in the header. The dispatcher patches the header, applies signing
/// (if required), and ships the bytes.
pub struct HandlerResponse {
    /// Bytes after the SMB2 header - the body. The handler owns body
    /// construction.
    pub body: Vec<u8>,
    /// NTSTATUS for the response header.
    pub status: u32,
    /// Optional override for `tree_id` on the response header (e.g.
    /// TREE_CONNECT returns the freshly minted tree id).
    pub override_tree_id: Option<u32>,
    /// Optional override for `session_id` on the response header (e.g.
    /// SESSION_SETUP returns the freshly minted session id).
    pub override_session_id: Option<u64>,
    /// If true, the dispatcher will not sign the response. Used for
    /// pre-session-setup messages where no key exists yet.
    pub skip_signing: bool,
    /// If set, take the per-session 3.1.1 preauth snapshot after hashing the
    /// SESSION_SETUP request but before hashing the response. Set by
    /// SESSION_SETUP on the round that produces STATUS_SUCCESS, so the
    /// session's KDF context can use the snapshot.
    pub take_preauth_snapshot_for_session: Option<u64>,
}

impl HandlerResponse {
    pub fn ok(body: Vec<u8>) -> Self {
        Self {
            body,
            status: ntstatus::STATUS_SUCCESS,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
        }
    }

    pub fn err(status: u32) -> Self {
        let er = ErrorResponse::status(status);
        let mut buf = Vec::new();
        er.write_to(&mut buf).expect("error response encodes");
        Self {
            body: buf,
            status,
            override_tree_id: None,
            override_session_id: None,
            skip_signing: false,
            take_preauth_snapshot_for_session: None,
        }
    }
}

/// Top-level frame dispatch. Returns the bytes to push into the writer
/// channel, or `None` if the request elicits no response (CANCEL).
pub async fn dispatch_frame(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Option<Vec<u8>> {
    // SMB1 multi-protocol bootstrap (MS-SMB2 §3.3.5.3.1). The only SMB1 we
    // accept: a NEGOTIATE_REQUEST listing "SMB 2.???" or "SMB 2.002", as the
    // first request on the connection (3.3.5.3).
    if is_smb1_negotiate(frame) {
        // Its MessageId counts as 0 (MS-SMB2 3.3.5.2.3).
        if conn.dialect.read().await.is_some() || !lock_credits(conn).consume(0, 1) {
            warn!("SMB1 NEGOTIATE is not the first request; closing connection");
            conn.request_disconnect();
            return None;
        }
        let reply = handle_smb1_multi_protocol(server, conn, frame).await;
        if reply.is_none() {
            warn!("SMB1 NEGOTIATE without an SMB2 dialect; closing connection");
            conn.request_disconnect();
        }
        return reply;
    }
    let dialect = *conn.dialect.read().await;
    let requests = match chain::split(frame, dialect) {
        Ok(requests) => requests,
        Err(reason) => {
            warn!(%reason, "malformed frame; closing connection");
            conn.request_disconnect();
            return None;
        }
    };
    if let Err(message_id) = consume_message_ids(conn, &requests, dialect) {
        warn!(
            message_id,
            "MessageId outside the window; closing connection"
        );
        conn.request_disconnect();
        return None;
    }

    let mut responses = Vec::new();
    let mut related = RelatedContext::default();
    let mut response_len = 0;
    // A chain whose first request is marked related fails as a whole
    // (MS-SMB2 3.3.5.2.7.2).
    let mut chain_failure = (requests[0].header.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0)
        .then_some(ntstatus::STATUS_INVALID_PARAMETER);

    for request in requests {
        let mut req_hdr = request.header;
        let received = &frame[request.range];
        let mut sub_frame = received.to_vec();
        let mut failure = chain_failure;
        if failure.is_none()
            && req_hdr.flags & SMB2_FLAGS_RELATED_OPERATIONS != 0
            && let Err(f) = related.apply(&mut sub_frame, &mut req_hdr)
        {
            failure = Some(f.status);
            if f.rest_of_chain {
                chain_failure = Some(f.status);
            }
        }

        let response = match failure {
            Some(_) if req_hdr.command == Command::Cancel => None,
            Some(status) => {
                debug!(
                    command = ?req_hdr.command,
                    status,
                    "related request fails without running"
                );
                let granted = grant_credits(conn, &req_hdr);
                let error = HandlerResponse::err(status);
                Some(build_response_bytes(conn, &req_hdr, error, None, granted).await)
            }
            None => {
                let response = dispatch_one(server, conn, &sub_frame, received).await;
                if let Some((bytes, _)) = &response {
                    related.update(req_hdr.command, &sub_frame, bytes);
                }
                response
            }
        };
        if let Some(mut response) = response {
            // Keep room for an error response to every request in the frame.
            if align_8(response_len) + response.0.len() + 2 * frame.len()
                > MAX_FRAME_PAYLOAD as usize
            {
                warn!(len = response.0.len(), "response does not fit in one frame");
                let error = HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
                let granted = read_u16(&response.0, 0x0E);
                response = build_response_bytes(conn, &req_hdr, error, None, granted).await;
            }
            response_len = align_8(response_len) + response.0.len();
            responses.push(response);
        }
    }

    if responses.is_empty() {
        return None;
    }

    Some(stitch_responses(conn, responses).await)
}

/// Takes each request's MessageIds out of the connection's window: one id,
/// or CreditCharge ids for a multi-credit request on SMB 2.1 and 3.x. CANCEL
/// takes none (MS-SMB2 3.3.5.2.3). Fails with the first MessageId that is not
/// available.
fn consume_message_ids(
    conn: &Connection,
    requests: &[chain::Request],
    dialect: Option<Dialect>,
) -> Result<(), u64> {
    let mut window = lock_credits(conn);
    for request in requests {
        let hdr = &request.header;
        if hdr.command == Command::Cancel {
            continue;
        }
        let count = if supports_multi_credit(dialect) {
            u64::from(hdr.credit_charge.max(1))
        } else {
            1
        };
        if !window.consume(hdr.message_id, count) {
            return Err(hdr.message_id);
        }
    }
    Ok(())
}

fn lock_credits(conn: &Connection) -> std::sync::MutexGuard<'_, CreditWindow> {
    conn.credits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Credits to grant in the response to `req_hdr`.
fn grant_credits(conn: &Connection, req_hdr: &Smb2Header) -> u16 {
    lock_credits(conn).grant(
        req_hdr.credit_request_response,
        req_hdr.command == Command::Negotiate,
    )
}

/// Joins compound responses into one frame. Each response but the last is
/// padded to 8 bytes and signed over its padding (MS-SMB2 3.1.4.1).
async fn stitch_responses(
    conn: &Arc<Connection>,
    responses: Vec<(Vec<u8>, Option<[u8; 16]>)>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut signed = Vec::with_capacity(responses.len());
    let response_count = responses.len();

    for (index, (mut response, key)) in responses.into_iter().enumerate() {
        let start = out.len();
        let mut len = response.len();
        if index + 1 < response_count {
            len = align_8(len);
            response[0x14..0x18].copy_from_slice(&(len as u32).to_le_bytes());
        }
        out.extend_from_slice(&response);
        out.resize(start + len, 0);
        if let Some(key) = key {
            signed.push((start, len, key));
        }
    }

    let algo = *conn.signing_algo.read().await;
    for (start, len, key) in signed {
        if let Err(e) = sign(&mut out[start..start + len], &key, algo) {
            error!(error = %e, "failed to sign compound response");
        }
    }

    out
}

const fn align_8(n: usize) -> usize {
    (n + 7) & !7
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Handles one request. `frame` is the request with related-operation ids
/// filled in; `received` is the same request as it arrived, which is what
/// the client signed and hashed. Returns the response and the key it was
/// signed with.
async fn dispatch_one(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
    received: &[u8],
) -> Option<(Vec<u8>, Option<[u8; 16]>)> {
    let (req_hdr, body_bytes) = match Smb2Header::parse(frame) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to parse header");
            return None;
        }
    };

    let cmd = req_hdr.command;
    let mid = req_hdr.message_id;
    let sid = req_hdr.session_id;
    let tid = req_hdr.tree_id().unwrap_or(0);

    let span = debug_span!("dispatch", cmd = ?cmd, mid, sid, tid);
    async move {
        debug!("dispatch start");

        // The request's session, kept so LOGOFF's response can still be
        // signed with its key after the handler removes it.
        let request_session = conn.sessions.read().await.get(&sid).cloned();

        // Verify signature on incoming request (when applicable).
        if let Err(status) = verify_request_signature(server, conn, &req_hdr, received).await {
            let resp = HandlerResponse::err(status);
            let granted = grant_credits(conn, &req_hdr);
            return Some(
                build_response_bytes(conn, &req_hdr, resp, request_session.as_ref(), granted).await,
            );
        }

        // CANCEL is fire-and-forget - no response.
        if cmd == Command::Cancel {
            debug!("CANCEL received; no response");
            return None;
        }

        let dialect = *conn.dialect.read().await;
        let malformed = !chain::body_is_well_formed(cmd, body_bytes);
        if malformed {
            warn!("request body does not match its StructureSize");
        }
        let undercharged = supports_multi_credit(dialect)
            && !charge_covers(req_hdr.credit_charge, chain::payload_size(cmd, body_bytes));
        if undercharged {
            warn!(
                credit_charge = req_hdr.credit_charge,
                "CreditCharge does not cover the payload"
            );
        }
        if malformed || undercharged {
            let resp = HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
            let granted = grant_credits(conn, &req_hdr);
            return Some(
                build_response_bytes(conn, &req_hdr, resp, request_session.as_ref(), granted).await,
            );
        }

        let mut session_preauth = None;

        // 3.1.1 preauth is connection-scoped for NEGOTIATE, then per
        // SESSION_SETUP authentication exchange.
        if cmd == Command::Negotiate {
            let mut p = conn
                .preauth
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            p.update(received);
        } else if cmd == Command::SessionSetup
            && dialect == Some(crate::proto::messages::Dialect::Smb311)
        {
            let mut p = take_session_preauth(conn, req_hdr.session_id).await;
            p.update(received);
            session_preauth = Some(p);
        }

        if cmd == Command::SessionSetup {
            drop_stale_auths(conn, server.config.limits.handshake_timeout).await;
        }
        let resp = handlers::dispatch_command(server, conn, &req_hdr, body_bytes).await;
        if cmd == Command::SessionSetup {
            track_pending_auth(conn, &req_hdr, &resp);
        }

        // If the handler asked for a preauth snapshot (3.1.1), take it now.
        if let Some(sid) = resp.take_preauth_snapshot_for_session {
            let snap = session_preauth
                .as_ref()
                .expect("SMB 3.1.1 SessionSetup snapshot requires per-session preauth")
                .snapshot();
            // Stash on the session - the handler already created it.
            let sessions = conn.sessions.read().await;
            if let Some(sess_arc) = sessions.get(&sid) {
                let mut sess = sess_arc.write().await;
                sess.preauth_snapshot = Some(snap);
                // For 3.1.1, recompute signing key now that we have the snapshot.
                let dialect = *conn.dialect.read().await;
                if dialect == Some(crate::proto::messages::Dialect::Smb311) {
                    sess.signing_key =
                        crate::proto::crypto::signing_key_311(&sess.session_base_key, &snap);
                }
            }
        }

        let granted = grant_credits(conn, &req_hdr);
        let (bytes, key) =
            build_response_bytes(conn, &req_hdr, resp, request_session.as_ref(), granted).await;

        if cmd == Command::Negotiate {
            let mut p = conn
                .preauth
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            p.update(&bytes);
        } else if cmd == Command::SessionSetup
            && dialect == Some(crate::proto::messages::Dialect::Smb311)
        {
            if read_u32(&bytes, 0x08) == ntstatus::STATUS_MORE_PROCESSING_REQUIRED {
                if let Some(mut p) = session_preauth {
                    p.update(&bytes);
                    let sid = read_u64(&bytes, 0x28);
                    conn.session_preauth.write().await.insert(sid, p);
                }
            } else {
                conn.session_preauth
                    .write()
                    .await
                    .remove(&req_hdr.session_id);
            }
        }

        Some((bytes, key))
    }
    .instrument(span)
    .await
}

/// Drops SESSION_SETUP exchanges that started more than `timeout` ago, so
/// abandoned ones do not use up the connection's pending slots.
async fn drop_stale_auths(conn: &Connection, timeout: std::time::Duration) {
    let stale: Vec<u64> = {
        let mut started = conn
            .pending_auth_started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stale = started
            .iter()
            .filter(|(_, at)| at.elapsed() >= timeout)
            .map(|(&id, _)| id)
            .collect();
        for id in &stale {
            started.remove(id);
        }
        stale
    };
    if stale.is_empty() {
        return;
    }
    debug!(
        count = stale.len(),
        "dropping unfinished SESSION_SETUP exchanges"
    );
    let mut pending = conn.pending_auths.write().await;
    let mut preauth = conn.session_preauth.write().await;
    for id in stale {
        pending.remove(&id);
        preauth.remove(&id);
    }
}

/// Notes when a SESSION_SETUP exchange starts, and forgets it once it ends.
fn track_pending_auth(conn: &Connection, req_hdr: &Smb2Header, resp: &HandlerResponse) {
    let mut started = conn
        .pending_auth_started
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if resp.status == ntstatus::STATUS_MORE_PROCESSING_REQUIRED {
        let id = resp.override_session_id.unwrap_or(req_hdr.session_id);
        started.entry(id).or_insert_with(std::time::Instant::now);
    } else {
        started.remove(&req_hdr.session_id);
    }
}

async fn take_session_preauth(conn: &Arc<Connection>, session_id: u64) -> PreauthIntegrity {
    if session_id != 0
        && let Some(preauth) = conn.session_preauth.write().await.remove(&session_id)
    {
        return preauth;
    }

    conn.preauth
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

async fn verify_request_signature(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    frame: &[u8],
) -> Result<(), u32> {
    if hdr.command == Command::Negotiate {
        if hdr.flags & SMB2_FLAGS_SIGNED != 0 {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        return Ok(());
    }
    if hdr.session_id == 0 {
        return Ok(());
    }
    let sessions = conn.sessions.read().await;
    let sess_arc = match sessions.get(&hdr.session_id) {
        Some(s) => s.clone(),
        None => {
            // Unknown session.
            if hdr.flags & SMB2_FLAGS_SIGNED == 0 {
                return Ok(());
            }
            return Err(ntstatus::STATUS_USER_SESSION_DELETED);
        }
    };
    drop(sessions);

    if hdr.flags & SMB2_FLAGS_SIGNED != 0 {
        let sess = sess_arc.read().await;
        if matches!(sess.identity, Identity::Anonymous) {
            return Ok(());
        }
        let key = sess.signing_key;
        drop(sess);
        let algo = *conn.signing_algo.read().await;
        if let Err(e) = crate::proto::crypto::verify(frame, &key, algo) {
            warn!(error = %e, "request signature verification failed");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
    } else if hdr.command != Command::SessionSetup {
        let sess = sess_arc.read().await;
        let need = sess.signing_required && !matches!(sess.identity, Identity::Anonymous);
        drop(sess);
        if need {
            warn!(?hdr.command, "missing required signature on request");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
    }
    Ok(())
}

/// Build the final on-the-wire bytes: header + body, granting `granted`
/// credits, with signing applied when the session has a key.
/// `request_session` is used when LOGOFF has already removed the session
/// from the table. Returns the bytes and the signing key used.
async fn build_response_bytes(
    conn: &Arc<Connection>,
    req_hdr: &Smb2Header,
    handler_resp: HandlerResponse,
    request_session: Option<&Arc<tokio::sync::RwLock<crate::conn::state::Session>>>,
    granted: u16,
) -> (Vec<u8>, Option<[u8; 16]>) {
    let mut hdr = *req_hdr;
    hdr.credit_request_response = granted;
    hdr.flags |= SMB2_FLAGS_SERVER_TO_REDIR;
    hdr.flags &= !SMB2_FLAGS_ASYNC_COMMAND;
    hdr.next_command = 0;
    hdr.channel_sequence_status = handler_resp.status;
    hdr.tail = HeaderTail::sync(
        handler_resp
            .override_tree_id
            .unwrap_or_else(|| req_hdr.tree_id().unwrap_or(0)),
    );
    if let Some(sid) = handler_resp.override_session_id {
        hdr.session_id = sid;
    }
    hdr.signature = [0u8; 16];

    let request_was_signed = req_hdr.flags & SMB2_FLAGS_SIGNED != 0;
    // MS-SMB2 §3.3.5.5.3 step 12: SessionSetup SUCCESS must be signed for
    // non-anon/non-guest sessions even though the request cannot be signed yet.
    let is_session_setup_success =
        req_hdr.command == Command::SessionSetup && handler_resp.status == ntstatus::STATUS_SUCCESS;
    let mut should_sign = false;
    let mut key = [0u8; 16];
    let algo = *conn.signing_algo.read().await;
    if !handler_resp.skip_signing
        && hdr.session_id != 0
        && (request_was_signed || is_session_setup_success)
    {
        let current = conn.sessions.read().await.get(&hdr.session_id).cloned();
        let session = current.or_else(|| {
            request_session
                .filter(|_| hdr.session_id == req_hdr.session_id)
                .cloned()
        });
        if let Some(sess_arc) = session {
            let sess = sess_arc.read().await;
            let is_anon = matches!(sess.identity, Identity::Anonymous);
            if !is_anon && sess.signing_key != [0u8; 16] {
                key = sess.signing_key;
                should_sign = true;
            }
        }
    }
    if should_sign {
        hdr.flags |= SMB2_FLAGS_SIGNED;
    } else {
        hdr.flags &= !SMB2_FLAGS_SIGNED;
    }
    let mut out = Vec::with_capacity(SMB2_HEADER_LEN + handler_resp.body.len());
    if let Err(e) = hdr.write(&mut out) {
        error!(error = %e, "failed to encode response header");
        return (Vec::new(), None);
    }
    out.extend_from_slice(&handler_resp.body);

    if should_sign && let Err(e) = sign(&mut out, &key, algo) {
        error!(error = %e, "failed to sign response");
    }
    (out, should_sign.then_some(key))
}

/// Detect and answer an SMB1 multi-protocol NEGOTIATE_REQUEST.
///
/// SMB1 frame layout for the request we accept:
/// * `[0..4]`  - magic `0xFF 'S' 'M' 'B'`
/// * `[4]`     - command (0x72 = SMB_COM_NEGOTIATE)
/// * `[5..32]` - rest of SMB1 header (status, flags, pid, tid, mid ...)
/// * `[32]`    - `WordCount` (0 for NEGOTIATE)
/// * `[33..35]` - `ByteCount` (u16 LE)
/// * `[35..]`  - dialect strings, each `0x02 <ASCII> 0x00`.
///
/// Returns `Some(reply_bytes)` only for a SMB1 NEGOTIATE that lists at least
/// one SMB2 dialect we recognise, and sets Connection.NegotiateDialect to
/// 0x02FF ("SMB 2.???") or 0x0202 ("SMB 2.002" alone).
async fn handle_smb1_multi_protocol(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Option<Vec<u8>> {
    if frame.len() < 35 {
        return None;
    }
    let body_start = 33; // 32-byte header + 1-byte WordCount(=0)
    let byte_count = u16::from_le_bytes([frame[body_start], frame[body_start + 1]]) as usize;
    let blob_start = body_start + 2;
    let blob_end = (blob_start + byte_count).min(frame.len());
    let blob = &frame[blob_start..blob_end];

    let mut wants_wildcard = false;
    let mut wants_smb202 = false;
    let mut i = 0;
    while i < blob.len() {
        if blob[i] != 0x02 {
            break;
        }
        i += 1;
        let nul = match blob[i..].iter().position(|&b| b == 0) {
            Some(p) => p,
            None => break,
        };
        let s = std::str::from_utf8(&blob[i..i + nul]).unwrap_or("");
        match s {
            "SMB 2.???" => wants_wildcard = true,
            "SMB 2.002" => wants_smb202 = true,
            _ => {}
        }
        i += nul + 1;
    }

    let dialect = if wants_wildcard {
        Dialect::Smb2Wildcard
    } else if wants_smb202 {
        Dialect::Smb202
    } else {
        return None;
    };
    let chosen = dialect.as_u16();

    debug!(
        chosen = %format_args!("0x{chosen:04X}"),
        "SMB1 multi-protocol negotiate"
    );

    // Synthesize a request header so build_response_bytes can mint the
    // SERVER_TO_REDIR response. Per MS-SMB2 §3.3.5.3.1 the response uses
    // message_id=0, tree_id=0xFFFF, session_id=0.
    let req_hdr = Smb2Header {
        command: Command::Negotiate,
        message_id: 0,
        session_id: 0,
        tail: HeaderTail::Sync {
            reserved: 0,
            tree_id: 0xFFFF,
        },
        ..Default::default()
    };
    let resp = handlers::negotiate::multi_protocol_response(server, conn, chosen).await;
    if resp.status == ntstatus::STATUS_SUCCESS {
        *conn.dialect.write().await = Some(dialect);
    }
    let granted = grant_credits(conn, &req_hdr);
    Some(
        build_response_bytes(conn, &req_hdr, resp, None, granted)
            .await
            .0,
    )
}

fn is_smb1_negotiate(frame: &[u8]) -> bool {
    frame.len() >= 5 && frame[0..4] == [0xFF, b'S', b'M', b'B'] && frame[4] == 0x72
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::state::{Session, TreeConnect};
    use crate::proto::crypto::{SigningAlgo, verify};
    use crate::proto::messages::{
        CloseRequest, CreateRequest, Dialect, FileId, LogoffRequest, QueryInfoRequest,
    };
    use crate::tests::memfs::MemFsBackend;
    use crate::{Access, Share, SmbServer};
    use tokio::sync::RwLock;
    use uuid::Uuid;

    fn test_conn() -> Arc<Connection> {
        Arc::new(Connection::new(Uuid::nil(), 1024 * 1024, 1024 * 1024))
    }

    const KEY: [u8; 16] = [0x42; 16];
    const RELATED_FILE_ID: FileId = FileId::new(u64::MAX, u64::MAX);

    /// Server with alice signed in on session 1 and connected to `home` on
    /// tree 1, signing with `KEY`.
    async fn signed_session() -> (Arc<ServerState>, Arc<Connection>) {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("alice", "password")
            .share(
                Share::new("home", MemFsBackend::new().with_file("f.txt", b"data"))
                    .user("alice", Access::ReadWrite),
            )
            .build()
            .expect("build");
        let state = server.state();
        let conn = test_conn();
        *conn.dialect.write().await = Some(Dialect::Smb300);
        *conn.signing_algo.write().await = SigningAlgo::AesCmac;
        {
            let mut credits = conn.credits.lock().expect("credits");
            assert!(credits.consume(0, 1));
            credits.grant(64, false);
        }

        let identity = Identity::User {
            user: "alice".to_string(),
            domain: String::new(),
        };
        let session = Session::new(1, identity, [0; 16], KEY, true, None);
        let share = state.find_share("home").await.expect("share");
        let tree = TreeConnect::new(1, share, Access::ReadWrite);
        session
            .trees
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(tree)));
        conn.sessions
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(session)));
        (state, conn)
    }

    /// Signed requests chained into one compound frame; every request after
    /// the first is related.
    fn signed_compound(requests: &[(Command, Vec<u8>)]) -> Vec<u8> {
        let mut frame = Vec::new();
        for (index, (command, body)) in requests.iter().enumerate() {
            let last = index + 1 == requests.len();
            let mut flags = SMB2_FLAGS_SIGNED;
            if index > 0 {
                flags |= SMB2_FLAGS_RELATED_OPERATIONS;
            }
            let hdr = Smb2Header {
                credit_charge: 1,
                command: *command,
                credit_request_response: 1,
                flags,
                message_id: index as u64 + 10,
                tail: HeaderTail::sync(1),
                session_id: 1,
                ..Default::default()
            };
            let mut msg = Vec::new();
            hdr.write(&mut msg).expect("header");
            msg.extend_from_slice(body);
            if !last {
                msg.resize(align_8(msg.len()), 0);
                let next = msg.len() as u32;
                msg[0x14..0x18].copy_from_slice(&next.to_le_bytes());
            }
            sign(&mut msg, &KEY, SigningAlgo::AesCmac).expect("sign");
            frame.extend_from_slice(&msg);
        }
        frame
    }

    /// CREATE f.txt, then related QUERY_INFO and CLOSE on the new FileId.
    /// The QUERY_INFO response, 76 bytes, is padded in the compound.
    fn create_query_close() -> Vec<u8> {
        let name = crate::utils::utf16le("f.txt");
        let mut create = Vec::new();
        CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0012_0089,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: 1,
            create_options: 0,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: vec![],
        }
        .write_to(&mut create)
        .expect("create");
        let mut query = Vec::new();
        QueryInfoRequest {
            structure_size: 41,
            info_type: 1,
            file_information_class: crate::info_class::FILE_EA_INFORMATION,
            output_buffer_length: 4096,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id: RELATED_FILE_ID,
            input_buffer: vec![],
        }
        .write_to(&mut query)
        .expect("query");
        let mut close = Vec::new();
        CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id: RELATED_FILE_ID,
        }
        .write_to(&mut close)
        .expect("close");
        signed_compound(&[
            (Command::Create, create),
            (Command::QueryInfo, query),
            (Command::Close, close),
        ])
    }

    /// Each response in a compound frame: (status, bytes up to the next).
    fn split_responses(frame: &[u8]) -> Vec<(u32, &[u8])> {
        let mut out = Vec::new();
        let mut rest = frame;
        loop {
            let next = read_u32(rest, 0x14) as usize;
            let len = if next == 0 { rest.len() } else { next };
            out.push((read_u32(rest, 0x08), &rest[..len]));
            if next == 0 {
                return out;
            }
            rest = &rest[next..];
        }
    }

    #[tokio::test]
    async fn signed_related_compound_requests_are_accepted() {
        let (state, conn) = signed_session().await;
        let frame = dispatch_frame(&state, &conn, &create_query_close())
            .await
            .expect("response");
        let statuses: Vec<u32> = split_responses(&frame).iter().map(|r| r.0).collect();
        assert_eq!(statuses, [ntstatus::STATUS_SUCCESS; 3]);
    }

    #[tokio::test]
    async fn compound_responses_are_signed_over_their_padding() {
        let (state, conn) = signed_session().await;
        let frame = dispatch_frame(&state, &conn, &create_query_close())
            .await
            .expect("response");
        for (index, (_, response)) in split_responses(&frame).into_iter().enumerate() {
            assert_ne!(read_u32(response, 0x10) & SMB2_FLAGS_SIGNED, 0);
            assert!(
                verify(response, &KEY, SigningAlgo::AesCmac).is_ok(),
                "response {index} signature"
            );
        }
    }

    #[tokio::test]
    async fn logoff_response_is_signed() {
        let (state, conn) = signed_session().await;
        let mut body = Vec::new();
        LogoffRequest::default()
            .write_to(&mut body)
            .expect("logoff");
        let request = signed_compound(&[(Command::Logoff, body)]);
        let response = dispatch_frame(&state, &conn, &request)
            .await
            .expect("response");
        assert_eq!(read_u32(&response, 0x08), ntstatus::STATUS_SUCCESS);
        assert_ne!(read_u32(&response, 0x10) & SMB2_FLAGS_SIGNED, 0);
        assert!(verify(&response, &KEY, SigningAlgo::AesCmac).is_ok());
        assert!(conn.sessions.read().await.is_empty());
    }

    fn negotiated_preauth() -> PreauthIntegrity {
        let mut preauth = PreauthIntegrity::new();
        preauth.update(b"negotiate request");
        preauth.update(b"negotiate response");
        preauth
    }

    #[tokio::test]
    async fn new_session_setup_preauth_starts_from_negotiate_base() {
        let conn = test_conn();
        let base = negotiated_preauth();
        *conn.preauth.lock().expect("preauth lock") = base.clone();

        let mut first_session = take_session_preauth(&conn, 0).await;
        first_session.update(b"session one request");
        first_session.update(b"session one response");
        conn.session_preauth.write().await.insert(1, first_session);

        let mut second_session = take_session_preauth(&conn, 0).await;
        second_session.update(b"session two request");

        let mut expected = base.clone();
        expected.update(b"session two request");

        let mut polluted = base;
        polluted.update(b"session one request");
        polluted.update(b"session one response");
        polluted.update(b"session two request");

        assert_eq!(second_session.snapshot(), expected.snapshot());
        assert_ne!(second_session.snapshot(), polluted.snapshot());
    }

    #[tokio::test]
    async fn followup_session_setup_consumes_stored_session_preauth() {
        let conn = test_conn();
        let mut stored = negotiated_preauth();
        stored.update(b"session setup request");
        stored.update(b"session setup more-processing response");
        let expected = stored.snapshot();
        conn.session_preauth.write().await.insert(7, stored);

        let got = take_session_preauth(&conn, 7).await;

        assert_eq!(got.snapshot(), expected);
        assert!(!conn.session_preauth.read().await.contains_key(&7));
    }
}
