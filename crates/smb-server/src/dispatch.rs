//! Per-frame dispatch: parse header, route to handler, sign response, encode.

use std::sync::Arc;

use smb_proto::auth::ntlm::Identity;
use smb_proto::crypto::sign;
use smb_proto::header::{
    Command, HeaderTail, Smb2Header, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_SERVER_TO_REDIR,
    SMB2_FLAGS_SIGNED, SMB2_HEADER_LEN,
};
use smb_proto::messages::ErrorResponse;
use tracing::{debug, debug_span, error, warn, Instrument};

use crate::conn::state::Connection;
use crate::handlers;
use crate::ntstatus;
use crate::server::ServerState;

/// Result of a handler: a complete (unsigned) response payload + the NTSTATUS
/// to set in the header. The dispatcher patches the header, applies signing
/// (if required), and ships the bytes.
pub struct HandlerResponse {
    /// Bytes after the SMB2 header — the body. The handler owns body
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
    /// If true, take the per-session 3.1.1 preauth snapshot from the
    /// connection-level preauth hash *after* hashing the request but *before*
    /// hashing the response. Set by SESSION_SETUP on the round that produces
    /// STATUS_SUCCESS, so the session's KDF context can use the snapshot.
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
    // accept: a NEGOTIATE_REQUEST listing "SMB 2.???" or "SMB 2.002".
    // Reply with an SMB2 NEGOTIATE response and the client follows up with
    // a real SMB2 NEGOTIATE.
    if let Some(bytes) = handle_smb1_multi_protocol(server, conn, frame).await {
        return Some(bytes);
    }
    if frame.len() < SMB2_HEADER_LEN {
        warn!(len = frame.len(), "frame too short for SMB2 header");
        return None;
    }
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

        // Verify signature on incoming request (when applicable).
        if let Err(status) = verify_request_signature(server, conn, &req_hdr, frame).await {
            return Some(build_response_bytes(conn, &req_hdr, HandlerResponse::err(status)).await);
        }

        // CANCEL is fire-and-forget — no response.
        if cmd == Command::Cancel {
            debug!("CANCEL received; no response");
            return None;
        }

        // Pre-auth integrity (3.1.1): hash the request before processing.
        if matches!(cmd, Command::Negotiate | Command::SessionSetup) {
            let mut p = conn.preauth.lock().await;
            p.update(frame);
        }

        let resp = handlers::dispatch_command(server, conn, &req_hdr, body_bytes).await;

        // If the handler asked for a preauth snapshot (3.1.1), take it now.
        if let Some(sid) = resp.take_preauth_snapshot_for_session {
            let snap = conn.preauth.lock().await.snapshot();
            // Stash on the session — the handler already created it.
            let sessions = conn.sessions.read().await;
            if let Some(sess_arc) = sessions.get(&sid) {
                let mut sess = sess_arc.write().await;
                sess.preauth_snapshot = Some(snap);
                // For 3.1.1, recompute signing key now that we have the snapshot.
                let dialect = *conn.dialect.read().await;
                if dialect == Some(smb_proto::messages::Dialect::Smb311) {
                    sess.signing_key =
                        smb_proto::crypto::signing_key_311(&sess.session_base_key, &snap);
                }
            }
        }

        let bytes = build_response_bytes(conn, &req_hdr, resp).await;

        // 3.1.1 preauth: hash response too (after signing).
        if matches!(cmd, Command::Negotiate | Command::SessionSetup) {
            let mut p = conn.preauth.lock().await;
            p.update(&bytes);
        }

        Some(bytes)
    }
    .instrument(span)
    .await
}

async fn verify_request_signature(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    frame: &[u8],
) -> Result<(), u32> {
    if hdr.command == Command::Negotiate {
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
        let key = sess.signing_key;
        drop(sess);
        let algo = *conn.signing_algo.read().await;
        if let Err(e) = smb_proto::crypto::verify(frame, &key, algo) {
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

/// Build the final on-the-wire bytes: header + body, with signing applied
/// when the session has a key.
async fn build_response_bytes(
    conn: &Arc<Connection>,
    req_hdr: &Smb2Header,
    handler_resp: HandlerResponse,
) -> Vec<u8> {
    let mut hdr = *req_hdr;
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

    // Decide signing.
    let mut should_sign = false;
    let mut key = [0u8; 16];
    let algo = *conn.signing_algo.read().await;
    if !handler_resp.skip_signing && hdr.session_id != 0 {
        let sessions = conn.sessions.read().await;
        if let Some(sess_arc) = sessions.get(&hdr.session_id) {
            let sess = sess_arc.read().await;
            let is_anon = matches!(sess.identity, Identity::Anonymous);
            // Sign whenever the session has an identity (i.e. not anonymous).
            // SESSION_SETUP success responses *are* signed once a key is set.
            if !is_anon {
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
        return Vec::new();
    }
    out.extend_from_slice(&handler_resp.body);

    if should_sign {
        if let Err(e) = sign(&mut out, &key, algo) {
            error!(error = %e, "failed to sign response");
        }
    }
    out
}

/// Detect and answer an SMB1 multi-protocol NEGOTIATE_REQUEST.
///
/// SMB1 frame layout for the request we accept:
/// * `[0..4]`  — magic `0xFF 'S' 'M' 'B'`
/// * `[4]`     — command (0x72 = SMB_COM_NEGOTIATE)
/// * `[5..32]` — rest of SMB1 header (status, flags, pid, tid, mid …)
/// * `[32]`    — `WordCount` (0 for NEGOTIATE)
/// * `[33..35]`— `ByteCount` (u16 LE)
/// * `[35..]`  — dialect strings, each `0x02 <ASCII> 0x00`.
///
/// Returns `Some(reply_bytes)` only for a SMB1 NEGOTIATE that lists at least
/// one SMB2 dialect we recognise; otherwise `None` so the caller can fall
/// through to the normal SMB2 path.
async fn handle_smb1_multi_protocol(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    frame: &[u8],
) -> Option<Vec<u8>> {
    if frame.len() < 35 || frame[0..4] != [0xFF, b'S', b'M', b'B'] || frame[4] != 0x72 {
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

    let chosen = if wants_wildcard {
        smb_proto::messages::Dialect::Smb2Wildcard.as_u16()
    } else if wants_smb202 {
        smb_proto::messages::Dialect::Smb202.as_u16()
    } else {
        return None;
    };

    debug!(
        chosen = format!("0x{chosen:04X}"),
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
    Some(build_response_bytes(conn, &req_hdr, resp).await)
}
