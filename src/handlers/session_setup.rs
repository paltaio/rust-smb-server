//! SESSION_SETUP handler: drives the SPNEGO + NTLMv2 state machine.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::proto::auth::ntlm::{
    AuthOutcome, Direction, Identity, NTLMSSP_SIGNATURE, NtlmAuthenticate, NtlmMac, NtlmServer,
    NtlmTargetInfo, UserCreds,
};
#[cfg(feature = "krb5")]
use crate::proto::auth::spnego::OID_KRB5;
use crate::proto::auth::spnego::{
    NegState, NegTokenInit, OID_NTLMSSP, decode_init_token, decode_resp_token, encode_resp_token,
};
use crate::proto::crypto::{SessionCipher, signing_key_30};
use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, SessionSetupRequest, SessionSetupResponse};
use tracing::{debug, info, warn};

use crate::conn::state::{Connection, MAX_PENDING_AUTHS, PendingAuth, Session};
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;
use crate::utils::{fill_random, now_filetime};

/// A SESSION_SETUP security token, by form.
enum Token {
    /// Raw NTLMSSP. RFC 4178 section 4.2.1 lets the client skip SPNEGO once
    /// the mechanism is settled.
    Raw { msg_type: u32, ntlm: Vec<u8> },
    /// GSS-API NegTokenInit (starts with 0x60).
    Init(NegTokenInit),
    /// SPNEGO NegTokenResp: the inner token and the client's mechListMIC.
    Resp {
        ntlm: Vec<u8>,
        mech_list_mic: Option<Vec<u8>>,
    },
}

impl Token {
    fn decode(blob: &[u8]) -> Result<Self, u32> {
        if blob.starts_with(NTLMSSP_SIGNATURE) {
            let msg_type = blob
                .get(8..12)
                .map_or(0, |t| u32::from_le_bytes([t[0], t[1], t[2], t[3]]));
            return Ok(Token::Raw {
                msg_type,
                ntlm: blob.to_vec(),
            });
        }
        if blob[0] == 0x60 {
            return match decode_init_token(blob) {
                Ok(init) => Ok(Token::Init(init)),
                Err(e) => {
                    warn!(error = %e, "SPNEGO init decode failed");
                    Err(ntstatus::STATUS_LOGON_FAILURE)
                }
            };
        }
        match decode_resp_token(blob) {
            Ok(resp) => Ok(Token::Resp {
                ntlm: resp.response_token.unwrap_or_default(),
                mech_list_mic: resp.mech_list_mic,
            }),
            Err(e) => {
                warn!(error = %e, "SPNEGO resp decode failed");
                Err(ntstatus::STATUS_LOGON_FAILURE)
            }
        }
    }
}

/// The token that opens an exchange.
enum Opening {
    /// Raw NTLM NEGOTIATE_MESSAGE.
    Raw(Vec<u8>),
    Spnego(NegTokenInit),
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match SessionSetupRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    let blob = &req.security_buffer;
    if blob.is_empty() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // MS-SMB2 3.3.5.5: while every session is encrypted and unencrypted
    // access is rejected, a client that cannot encrypt gets no session.
    let settings = &server.auth.settings;
    if settings.encrypt_data
        && settings.reject_unencrypted_access
        && conn.cipher.read().await.is_none()
    {
        info!("session setup refused: the server encrypts and the client cannot");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if tracing::enabled!(tracing::Level::DEBUG) {
        let mut first8 = String::with_capacity(16);
        for b in blob.iter().take(8) {
            use std::fmt::Write as _;
            write!(&mut first8, "{b:02x}").expect("writing to String cannot fail");
        }
        tracing::debug!(
            first8 = %first8,
            len = blob.len(),
            sid = hdr.session_id,
            "session setup blob"
        );
    }

    let sid = hdr.session_id;
    // MS-SMB2 3.3.5.5: multichannel is not supported, so binding fails.
    if sid != 0 && req.flags & SessionSetupRequest::FLAG_BINDING != 0 {
        return HandlerResponse::err(ntstatus::STATUS_REQUEST_NOT_ACCEPTED);
    }

    let token = match Token::decode(blob) {
        Ok(t) => t,
        Err(status) => return HandlerResponse::err(status),
    };

    let opening = match token {
        Token::Raw { msg_type: 1, ntlm } => Opening::Raw(ntlm),
        // Kerberos is offered first in the server's mechanism list, so a domain client sends an
        // AP-REQ already wrapped in SPNEGO and the exchange ends in this one round. It is checked
        // before the NTLM opening because there is no second message to fall back into: the ticket
        // is either good now or never.
        #[cfg(feature = "krb5")]
        Token::Init(init)
            if server.kerberos.is_some() && init.mech_types.iter().any(|mech| mech == OID_KRB5) =>
        {
            return accept_kerberos(server, conn, &req, sid, &init).await;
        }
        Token::Init(init) => Opening::Spnego(init),
        Token::Raw { ntlm, .. } => {
            return continue_or_reject(server, conn, &req, sid, ntlm, None).await;
        }
        Token::Resp {
            ntlm,
            mech_list_mic,
        } => {
            return continue_or_reject(server, conn, &req, sid, ntlm, mech_list_mic).await;
        }
    };

    if sid == 0 {
        if session_limit_reached(server, &*conn.sessions.read().await) {
            warn!("session limit reached on connection");
            return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        let new_sid = server.auth.alloc_session_id();
        return begin_exchange(server, conn, new_sid, opening).await;
    }
    // A first token for a known session starts over: reauthentication of
    // an established session (MS-SMB2 3.3.5.5.2), or a restart of one in
    // progress.
    let known = conn.sessions.read().await.contains_key(&sid)
        || conn.pending_auths.write().await.remove(&sid).is_some();
    if !known {
        return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED);
    }
    begin_exchange(server, conn, sid, opening).await
}

/// Accepts a Kerberos AP-REQ and establishes the session, in one round.
///
/// Mirrors the session construction `continue_exchange` does after NTLM succeeds, because the shape
/// of a session does not depend on how the client proved who it is: the key, the signing policy, the
/// cipher and the flags are the same either way. What it does not mirror is the message exchange -
/// there is no challenge, so a failure here is final and a success needs no second round trip.
#[cfg(feature = "krb5")]
async fn accept_kerberos(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    req: &SessionSetupRequest,
    sid: u64,
    init: &NegTokenInit,
) -> HandlerResponse {
    let Some(acceptor) = server.kerberos.as_ref() else {
        // Unreachable: the caller checked. Refusing beats panicking, and the status says what a
        // client can act on.
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };

    // The AP-REQ travels as the mechanism token of the first SPNEGO message.
    let Some(ap_req) = init.mech_token.as_deref() else {
        info!("kerberos offered without a ticket");
        return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
    };

    if tracing::enabled!(tracing::Level::DEBUG) {
        let mut head = String::with_capacity(48);
        for byte in ap_req.iter().take(24) {
            use std::fmt::Write as _;
            write!(&mut head, "{byte:02x}").expect("writing to String cannot fail");
        }
        tracing::debug!(len = ap_req.len(), head = %head, "kerberos ticket bytes");
    }

    let identity = match acceptor.accept(ap_req) {
        Ok(identity) => identity,
        Err(error) => {
            // The reason is logged, never returned: an attacker learns from the difference between
            // "no such principal" and "bad key", and a client learns nothing it can use.
            info!(reason = %error, "kerberos ticket refused");
            let peer = conn.peer_addr.map(|a| a.ip());
            server.auth.record_failure("", peer);
            return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
        }
    };

    // A realm is not a share ACL: the identity is the user, and what it may reach is decided by the
    // share and the session, exactly as for an NTLM logon of the same name.
    let smb_identity = Identity::User {
        user: identity.user.clone(),
        domain: identity.realm.clone(),
    };

    let new_sid = if sid == 0 {
        if session_limit_reached(server, &*conn.sessions.read().await) {
            warn!("session limit reached on connection");
            return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        server.auth.alloc_session_id()
    } else {
        sid
    };

    // Reauthentication keeps the session and its trees, for the same user only (MS-SMB2 3.3.5.5.2).
    let existing = conn.sessions.read().await.get(&new_sid).cloned();
    if let Some(existing) = &existing
        && !same_user(&existing.read().await.identity, &smb_identity)
    {
        info!(%identity.realm, "kerberos reauthentication as another user refused");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let dialect = *conn.dialect.read().await;
    let Some(dialect) = dialect else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };

    let session_base_key = identity.session_key;
    let cipher = *conn.cipher.read().await;
    let encrypt_data = server.auth.settings.encrypt_data && cipher.is_some();
    let session_flags = if encrypt_data {
        SessionSetupResponse::FLAG_ENCRYPT_DATA
    } else {
        0
    };

    // The reply carries the AP-REP when the client asked for mutual authentication: Windows always
    // does, and a client that asked and got none refuses the session even though the ticket was good.
    let response_token = encode_resp_token(
        NegState::AcceptCompleted,
        Some(OID_KRB5),
        identity.ap_rep.as_deref(),
        None,
    );
    if tracing::enabled!(tracing::Level::DEBUG) {
        let mut head = String::with_capacity(96);
        for byte in response_token.iter().take(48) {
            use std::fmt::Write as _;
            write!(&mut head, "{byte:02x}").expect("writing to String cannot fail");
        }
        tracing::debug!(len = response_token.len(), head = %head, "kerberos reply bytes");
    }

    let body_out =
        build_session_setup_response(ntstatus::STATUS_SUCCESS, &response_token, session_flags);

    let mut response = HandlerResponse {
        body: body_out,
        status: ntstatus::STATUS_SUCCESS,
        override_tree_id: None,
        override_session_id: Some(new_sid),
        skip_signing: false,
        take_preauth_snapshot_for_session: None,
        after_send: Vec::new(),
    };

    if existing.is_some() {
        info!("session reauthenticated by kerberos");
        return response;
    }

    let signing_key = signing_key(dialect, &session_base_key);
    let signing_required = signing_required(server, conn, req, &smb_identity);
    let mut session = Session::new(
        smb_identity.clone(),
        session_base_key,
        signing_key,
        signing_required,
        None,
    );
    session.encrypt_data = encrypt_data;
    // SMB 3.1.1 keys come from the preauth hash, once it is known.
    if dialect != Dialect::Smb311
        && let Some(cipher) = cipher
    {
        session.cipher = Some(Arc::new(SessionCipher::derive(
            cipher,
            &session_base_key,
            None,
        )));
    }

    let session_arc = Arc::new(tokio::sync::RwLock::new(session));
    {
        let mut sessions = conn.sessions.write().await;
        if session_limit_reached(server, &sessions) {
            warn!("session limit reached on connection");
            return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        sessions.insert(new_sid, session_arc);
    }

    if req.previous_session_id != 0 && req.previous_session_id != new_sid {
        close_previous_session(server, req.previous_session_id, &smb_identity).await;
    }
    if dialect == Dialect::Smb311 {
        response.take_preauth_snapshot_for_session = Some(new_sid);
    }

    server.auth.record_success(&identity.user);
    info!(
        user = %identity.user,
        realm = %identity.realm,
        mutual = identity.ap_rep.is_some(),
        "session established by kerberos"
    );
    response
}

/// A token that continues the exchange of `sid`.
async fn continue_or_reject(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    req: &SessionSetupRequest,
    sid: u64,
    ntlm: Vec<u8>,
    client_mic: Option<Vec<u8>>,
) -> HandlerResponse {
    if sid == 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let pending = conn.pending_auths.write().await.remove(&sid);
    let Some(pending) = pending else {
        return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED);
    };
    continue_exchange(server, conn, req, sid, pending, ntlm, client_mic).await
}

/// First round: start an NTLM acceptor for `sid` and answer with the
/// CHALLENGE_MESSAGE, or with an SPNEGO counter-proposal for NTLM.
async fn begin_exchange(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    sid: u64,
    opening: Opening,
) -> HandlerResponse {
    let mut server_challenge = [0u8; 8];
    if let Err(e) = fill_random(&mut server_challenge) {
        tracing::error!(error = %e, "OS RNG failed; cannot generate NTLM challenge");
        return HandlerResponse::err(ntstatus::STATUS_INTERNAL_ERROR);
    }
    let netbios = server.config.netbios_name.clone();
    let mut acceptor = NtlmServer::new(
        server_challenge,
        NtlmTargetInfo::new(netbios.clone(), netbios.clone(), netbios, "", ""),
        now_filetime(),
    );

    let (outbound, raw) = match opening {
        Opening::Raw(ntlm) => match accept_negotiate(&mut acceptor, &ntlm) {
            Ok(challenge) => (challenge, true),
            Err(status) => return HandlerResponse::err(status),
        },
        Opening::Spnego(init) => {
            let Some(pos) = init.mech_types.iter().position(|m| m == OID_NTLMSSP) else {
                return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
            };
            acceptor.mech_list = Some(init.mech_types_der);
            acceptor.mech_list_mic_required = pos != 0;
            // An optimistic mechToken is for the client's first mechanism,
            // so it is used only when that mechanism is NTLM. Otherwise the
            // reply selects NTLM and waits for its NEGOTIATE_MESSAGE.
            match init.mech_token.filter(|_| pos == 0) {
                Some(ntlm) => match accept_negotiate(&mut acceptor, &ntlm) {
                    Ok(challenge) => (
                        encode_resp_token(
                            NegState::AcceptIncomplete,
                            Some(OID_NTLMSSP),
                            Some(&challenge),
                            None,
                        ),
                        false,
                    ),
                    Err(status) => return HandlerResponse::err(status),
                },
                None => {
                    let state = if pos == 0 {
                        NegState::AcceptIncomplete
                    } else {
                        NegState::RequestMic
                    };
                    (
                        encode_resp_token(state, Some(OID_NTLMSSP), None, None),
                        false,
                    )
                }
            }
        }
    };

    {
        let mut pa = conn.pending_auths.write().await;
        if pa.len() >= MAX_PENDING_AUTHS {
            warn!(
                pending = pa.len(),
                "too many pending NTLM exchanges on connection"
            );
            return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        pa.insert(sid, Arc::new(std::sync::Mutex::new((acceptor, raw))));
    }
    more_processing(sid, &outbound)
}

/// Feeds the client's NEGOTIATE_MESSAGE to `acceptor` and returns the
/// CHALLENGE_MESSAGE.
fn accept_negotiate(acceptor: &mut NtlmServer, ntlm: &[u8]) -> Result<Vec<u8>, u32> {
    if let Err(e) = acceptor.step1_negotiate(ntlm) {
        warn!(error = %e, "NTLM step1 failed");
        return Err(ntstatus::STATUS_LOGON_FAILURE);
    }
    Ok(acceptor.challenge())
}

fn more_processing(sid: u64, outbound: &[u8]) -> HandlerResponse {
    let body_out =
        build_session_setup_response(ntstatus::STATUS_MORE_PROCESSING_REQUIRED, outbound, 0);
    HandlerResponse {
        body: body_out,
        status: ntstatus::STATUS_MORE_PROCESSING_REQUIRED,
        override_tree_id: None,
        override_session_id: Some(sid),
        skip_signing: true, // no key yet
        take_preauth_snapshot_for_session: None,
        after_send: Vec::new(),
    }
}

/// Later rounds of the exchange for `sid`.
async fn continue_exchange(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    req: &SessionSetupRequest,
    sid: u64,
    pending: PendingAuth,
    ntlm: Vec<u8>,
    client_mic: Option<Vec<u8>>,
) -> HandlerResponse {
    // After a counter-proposal the client's next token is the NTLM
    // NEGOTIATE_MESSAGE.
    let challenge = {
        let mut pair = pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pair.0.has_negotiate() {
            None
        } else {
            match accept_negotiate(&mut pair.0, &ntlm) {
                Ok(challenge) => Some(challenge),
                Err(status) => return HandlerResponse::err(status),
            }
        }
    };
    if let Some(challenge) = challenge {
        let outbound = encode_resp_token(NegState::AcceptIncomplete, None, Some(&challenge), None);
        conn.pending_auths.write().await.insert(sid, pending);
        return more_processing(sid, &outbound);
    }

    // A session that already exists is being reauthenticated.
    let existing = conn.sessions.read().await.get(&sid).cloned();

    // The failed-logon throttle counts by the user name the client sent and
    // by the client's address. The guest password is empty and known to
    // everyone, so guest logons count by address only: a lockout of the
    // name would shut every client out of guest access.
    let claimed_user = NtlmAuthenticate::parse(&ntlm)
        .map(|a| a.user)
        .unwrap_or_default();
    let throttled_user = if is_guest(&*server.users.table.read().await, &claimed_user) {
        ""
    } else {
        claimed_user.as_str()
    };
    let peer = conn.peer_addr.map(|a| a.ip());
    if server.auth.is_locked_out(throttled_user, peer) {
        info!("logon refused: too many failed logons for this user name or address");
        return logon_failed(
            server,
            conn,
            sid,
            existing.is_some(),
            None,
            ntstatus::STATUS_ACCOUNT_LOCKED_OUT,
        )
        .await;
    }

    // A guest logon is checked against the empty password, and only while
    // a share is public.
    let public = eq_ignore_case(&claimed_user, GUEST) && server.anonymous_allowed().await;
    let users = server.users.table.read().await;
    let result = {
        let pair = pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (acceptor, raw_form) = (&pair.0, pair.1);
        let lookup = |u: &str, _d: &str| match configured_user(&users, u) {
            Some((_, creds)) => Some(creds.clone()),
            None => (public && is_guest(&users, u)).then(|| UserCreds::from_password("")),
        };
        acceptor
            .authenticate(&ntlm, lookup)
            .map_err(|e| {
                info!(error = %e, "NTLM authenticate failed");
                ntstatus::STATUS_LOGON_FAILURE
            })
            .and_then(|mut outcome| {
                // The session carries the configured spelling of the name,
                // which share access is granted to.
                let mut nt_hash = None;
                let mut guest = false;
                if let Identity::User { user, .. } = &mut outcome.identity {
                    match configured_user(&users, user) {
                        Some((name, creds)) => {
                            *user = name.clone();
                            nt_hash = Some(creds.nt_hash);
                        }
                        None => guest = public && is_guest(&users, user),
                    }
                }
                let mic = if raw_form {
                    None
                } else {
                    mech_list_mic(acceptor, &outcome, client_mic.as_deref())?
                };
                // A guest gets an anonymous session: the public shares and
                // no key.
                if guest {
                    outcome.identity = Identity::Anonymous;
                    outcome.session_key = [0; 16];
                }
                Ok((outcome, raw_form, mic, nt_hash, guest))
            })
    };
    drop(users);
    let (outcome, raw_form, server_mic, nt_hash, guest) = match result {
        Ok(r) => r,
        Err(status) => {
            return logon_failed(
                server,
                conn,
                sid,
                existing.is_some(),
                Some(throttled_user),
                status,
            )
            .await;
        }
    };
    if !throttled_user.is_empty() {
        server.auth.record_success(throttled_user);
    }

    // Anonymous gating.
    if matches!(outcome.identity, Identity::Anonymous) && !server.anonymous_allowed().await {
        return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
    }
    // MS-SMB2 3.3.5.5.3 sets Session.SigningRequired when the request's
    // SecurityMode has SIGNING_REQUIRED, guests included, and a guest
    // session has no key to sign with. The spec names no status for this;
    // MS-SMB2 3.3.5.5 refuses a session that cannot be encrypted as the
    // server requires with STATUS_ACCESS_DENIED, and the same status is used
    // here.
    if guest && req.security_mode & SessionSetupRequest::SECURITY_SIGNING_REQUIRED != 0 {
        info!("guest logon refused: the client requires signing");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let session_base_key = outcome.session_key;
    let dialect = *conn.dialect.read().await;
    let Some(dialect) = dialect else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };

    // MS-SMB2 3.3.5.5.3: anonymous sessions are flagged IS_NULL, guest
    // sessions IS_GUEST. Authenticated sessions on a connection with a
    // cipher get encryption keys, and are encrypted when the server
    // encrypts every session.
    let anonymous = matches!(outcome.identity, Identity::Anonymous);
    let cipher = (*conn.cipher.read().await).filter(|_| !anonymous);
    let encrypt_data = server.auth.settings.encrypt_data && cipher.is_some();
    let session_flags = if guest {
        SessionSetupResponse::FLAG_IS_GUEST
    } else if anonymous {
        SessionSetupResponse::FLAG_IS_NULL
    } else if encrypt_data {
        SessionSetupResponse::FLAG_ENCRYPT_DATA
    } else {
        0
    };
    let success_buf: Vec<u8> = if raw_form {
        Vec::new()
    } else {
        encode_resp_token(NegState::AcceptCompleted, None, None, server_mic.as_deref())
    };
    let body_out =
        build_session_setup_response(ntstatus::STATUS_SUCCESS, &success_buf, session_flags);
    let mut response = HandlerResponse {
        body: body_out,
        status: ntstatus::STATUS_SUCCESS,
        override_tree_id: None,
        override_session_id: Some(sid),
        // Anonymous and guest sessions have no key; the dispatcher signs
        // the rest.
        skip_signing: anonymous,
        take_preauth_snapshot_for_session: None,
        after_send: Vec::new(),
    };

    // Reauthentication keeps the session, its key and its trees
    // (MS-SMB2 3.3.5.5.2), for the same user only.
    // Guest sessions are anonymous sessions flagged IS_GUEST; the log
    // names them as guests.
    let identity = if guest {
        "Guest".to_string()
    } else {
        format!("{:?}", outcome.identity)
    };
    if let Some(existing) = existing {
        if !same_user(&existing.read().await.identity, &outcome.identity) {
            info!(%identity, "reauthentication as another user refused");
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        info!(%identity, "session reauthenticated");
        return response;
    }

    let signing_key = signing_key(dialect, &session_base_key);
    let signing_required = signing_required(server, conn, req, &outcome.identity);
    let mut session = Session::new(
        outcome.identity.clone(),
        session_base_key,
        signing_key,
        signing_required,
        None,
    );
    session.encrypt_data = encrypt_data;
    // SMB 3.1.1 keys come from the preauth hash, once it is known.
    if dialect != Dialect::Smb311
        && let Some(cipher) = cipher
    {
        session.cipher = Some(Arc::new(SessionCipher::derive(
            cipher,
            &session_base_key,
            None,
        )));
    }
    let session_arc = Arc::new(tokio::sync::RwLock::new(session));
    {
        let mut sessions = conn.sessions.write().await;
        if session_limit_reached(server, &sessions) {
            warn!("session limit reached on connection");
            return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        // ConfigHandle::remove_user drops the user before it closes the
        // user's sessions, and that sweep waits for this lock. A user that is
        // gone, or whose password changed, since it authenticated gets no
        // session.
        if let (Identity::User { user, .. }, Some(nt_hash)) = (&outcome.identity, nt_hash)
            && server
                .lookup_user(user)
                .await
                .is_none_or(|c| c.nt_hash != nt_hash)
        {
            info!("user removed or changed during logon");
            return HandlerResponse::err(ntstatus::STATUS_LOGON_FAILURE);
        }
        sessions.insert(sid, session_arc);
    }

    if req.previous_session_id != 0 && req.previous_session_id != sid {
        close_previous_session(server, req.previous_session_id, &outcome.identity).await;
    }

    if dialect == Dialect::Smb311 {
        response.take_preauth_snapshot_for_session = Some(sid);
    }
    info!(%identity, "session established");
    response
}

fn session_limit_reached<T>(server: &ServerState, sessions: &HashMap<u64, T>) -> bool {
    sessions.len() >= server.auth.settings.max_sessions_per_connection
}

/// Ends a logon that failed with `status`: counts it against the connection
/// and, with `user` set, against that name and the client's address. Closes
/// the connection once it has failed too often, and removes a session that
/// was being reauthenticated (MS-SMB2 3.3.5.5.3), keeping its durable opens
/// as LOGOFF does.
async fn logon_failed(
    server: &ServerState,
    conn: &Connection,
    sid: u64,
    reauth: bool,
    user: Option<&str>,
    status: u32,
) -> HandlerResponse {
    if let Some(user) = user {
        server
            .auth
            .record_failure(user, conn.peer_addr.map(|a| a.ip()));
    }
    let failures = conn.logon_failures.fetch_add(1, Ordering::Relaxed) + 1;
    if server.auth.connection_exhausted(failures) {
        warn!(failures, "too many failed logons; closing the connection");
        conn.request_disconnect();
    }
    if reauth {
        conn.close_session(sid, Some(&server.durable)).await;
    }
    HandlerResponse::err(status)
}

/// True when both identities are the same configured user, or both are
/// anonymous.
fn same_user(a: &Identity, b: &Identity) -> bool {
    match (a, b) {
        (Identity::Anonymous, Identity::Anonymous) => true,
        (Identity::User { user: a, .. }, Identity::User { user: b, .. }) => a == b,
        _ => false,
    }
}

/// MS-SMB2 3.3.5.5.3: a logon that names a PreviousSessionId of the same
/// user ends that session, on whichever connection holds it, as if that
/// connection were lost (MS-SMB2 3.3.7.1): its durable opens are kept.
async fn close_previous_session(server: &ServerState, previous: u64, identity: &Identity) {
    if matches!(identity, Identity::Anonymous) {
        return;
    }
    for conn in server.active_connections.live().await {
        let old = conn.sessions.read().await.get(&previous).cloned();
        let Some(old) = old else {
            continue;
        };
        if same_user(&old.read().await.identity, identity) {
            info!(previous, "closing the session the client reconnected from");
            conn.close_session(previous, Some(&server.durable)).await;
        }
        return;
    }
}

/// Checks the client's mechListMIC and returns the server's, for an SPNEGO
/// exchange (RFC 4178 section 5, MS-SPNG 3.1.5.1). The MIC is exchanged
/// when the client sends one, when the AUTHENTICATE_MESSAGE carried an NTLM
/// MIC, or when NTLM was not the client's first choice; in the last case the
/// client's MIC is required. Anonymous logons have no key and exchange none.
fn mech_list_mic(
    acceptor: &NtlmServer,
    outcome: &AuthOutcome,
    client_mic: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, u32> {
    let required = acceptor.mech_list_mic_required;
    let wanted = required || client_mic.is_some() || outcome.mic_present;
    let (Some(mech_list), false) = (
        acceptor.mech_list.as_deref(),
        matches!(outcome.identity, Identity::Anonymous),
    ) else {
        return Ok(None);
    };
    if !wanted {
        return Ok(None);
    }
    let key = &outcome.session_key;
    let client = NtlmMac::new(outcome.flags, key, Direction::ClientToServer);
    let server = NtlmMac::new(outcome.flags, key, Direction::ServerToClient);
    let (Some(mut client), Some(mut server)) = (client, server) else {
        if required || client_mic.is_some() {
            info!("mechListMIC needed but NTLM signing was not negotiated");
            return Err(ntstatus::STATUS_LOGON_FAILURE);
        }
        return Ok(None);
    };
    match client_mic {
        Some(mic) if !client.verify(mech_list, mic) => {
            info!("SPNEGO mechListMIC mismatch");
            return Err(ntstatus::STATUS_LOGON_FAILURE);
        }
        None if required => {
            info!("SPNEGO mechListMIC missing");
            return Err(ntstatus::STATUS_LOGON_FAILURE);
        }
        _ => {}
    }
    Ok(Some(server.mac(mech_list).to_vec()))
}

/// Session.SigningRequired (MS-SMB2 3.3.5.5.3): the client asked for
/// signing in SESSION_SETUP or NEGOTIATE, or the server requires it.
/// Anonymous sessions have no key and are never signed.
fn signing_required(
    server: &ServerState,
    conn: &Connection,
    req: &SessionSetupRequest,
    identity: &Identity,
) -> bool {
    if matches!(identity, Identity::Anonymous) {
        return false;
    }
    let should_sign = conn
        .client_negotiate
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .is_some_and(|n| n.should_sign());
    req.security_mode & SessionSetupRequest::SECURITY_SIGNING_REQUIRED != 0
        || should_sign
        || server.auth.settings.require_signing
}

/// The configured user an NTLM user name refers to. NTLM user names are not
/// case sensitive: an exact match wins, then the one name that matches
/// ignoring case. A name that matches several users only by case matches
/// none of them. Every entry is compared, so the time taken does not show
/// whether or how the name matched.
fn configured_user<'a>(
    users: &'a HashMap<String, UserCreds>,
    name: &str,
) -> Option<(&'a String, &'a UserCreds)> {
    let mut exact = None;
    let mut folded = None;
    let mut folded_count = 0usize;
    for user in users {
        if user.0 == name {
            exact = Some(user);
        }
        if eq_ignore_case(user.0, name) {
            folded = Some(user);
            folded_count += 1;
        }
    }
    exact.or(folded.filter(|_| folded_count == 1))
}

/// The user name of a guest logon.
const GUEST: &str = "guest";

/// True when a logon as `name` is a guest logon: the name is `guest` in any
/// case and no configured user has that name.
fn is_guest(users: &HashMap<String, UserCreds>, name: &str) -> bool {
    eq_ignore_case(name, GUEST) && !users.keys().any(|user| eq_ignore_case(user, GUEST))
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_uppercase)
        .eq(b.chars().flat_map(char::to_uppercase))
}

/// Session.SigningKey for `dialect` (MS-SMB2 3.3.5.5.3). SMB 2.x signs with
/// the session key itself. For 3.1.1 the key is derived later, once the
/// preauth hash of this exchange is known.
fn signing_key(dialect: Dialect, session_key: &[u8; 16]) -> [u8; 16] {
    match dialect {
        Dialect::Smb311 => [0u8; 16],
        Dialect::Smb202 | Dialect::Smb210 | Dialect::Smb2Wildcard => *session_key,
        Dialect::Smb300 | Dialect::Smb302 => signing_key_30(session_key),
    }
}

fn build_session_setup_response(_status: u32, spnego_blob: &[u8], session_flags: u16) -> Vec<u8> {
    let resp = SessionSetupResponse {
        structure_size: 9,
        session_flags,
        security_buffer_offset: 64 + 8, // SMB2 header + fixed prefix
        security_buffer_length: spnego_blob.len() as u16,
        security_buffer: spnego_blob.to_vec(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf)
        .expect("SESSION_SETUP response encodes");
    debug!(len = buf.len(), "SESSION_SETUP response built");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_per_dialect() {
        let key = [0x5A; 16];
        assert_eq!(signing_key(Dialect::Smb202, &key), key);
        assert_eq!(signing_key(Dialect::Smb210, &key), key);
        assert_eq!(signing_key(Dialect::Smb300, &key), signing_key_30(&key));
        assert_eq!(signing_key(Dialect::Smb302, &key), signing_key_30(&key));
    }

    #[test]
    fn configured_user_matches_case_insensitively_once() {
        let mut users = HashMap::new();
        users.insert("Alice".to_string(), UserCreds::from_password("a"));
        users.insert("bob".to_string(), UserCreds::from_password("b"));
        users.insert("BOB".to_string(), UserCreds::from_password("c"));
        assert_eq!(configured_user(&users, "alice").unwrap().0, "Alice");
        assert_eq!(configured_user(&users, "bob").unwrap().0, "bob");
        assert_eq!(configured_user(&users, "BOB").unwrap().0, "BOB");
        assert!(configured_user(&users, "Bob").is_none());
        assert!(configured_user(&users, "carol").is_none());
    }

    #[test]
    fn guest_is_the_name_guest_when_no_user_has_it() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), UserCreds::from_password("a"));
        for name in ["guest", "GUEST", "Guest"] {
            assert!(is_guest(&users, name), "{name}");
        }
        assert!(!is_guest(&users, "alice"));
        assert!(!is_guest(&users, "guests"));
        assert!(!is_guest(&users, ""));
        users.insert("Guest".to_string(), UserCreds::from_password("g"));
        assert!(!is_guest(&users, "guest"));
    }

    use crate::proto::auth::ntlm::testing::{AuthMsg, build_auth};
    use crate::proto::header::{Command, HeaderTail};
    use std::time::Duration;

    fn header(session_id: u64) -> Smb2Header {
        Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: Command::SessionSetup,
            credit_request_response: 1,
            flags: 0,
            next_command: 0,
            message_id: 1,
            tail: HeaderTail::sync(0),
            session_id,
            signature: [0; 16],
        }
    }

    fn body(token: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        SessionSetupRequest {
            structure_size: 25,
            flags: 0,
            security_mode: 1,
            capabilities: 0,
            channel: 0,
            security_buffer_offset: 88,
            security_buffer_length: token.len() as u16,
            previous_session_id: 0,
            security_buffer: token.to_vec(),
        }
        .write_to(&mut body)
        .unwrap();
        body
    }

    fn ntlm_negotiate() -> Vec<u8> {
        let mut msg = NTLMSSP_SIGNATURE.to_vec();
        msg.extend_from_slice(&1u32.to_le_bytes());
        msg.extend_from_slice(&0x0008_0201u32.to_le_bytes());
        msg.extend_from_slice(&[0u8; 16]);
        msg
    }

    /// NTLMv2 AUTHENTICATE_MESSAGE answering the CHALLENGE_MESSAGE
    /// `challenge`, without a MIC or key exchange.
    fn ntlm_authenticate(challenge: &[u8], user: &str, password: &str) -> Vec<u8> {
        let m = AuthMsg {
            user,
            password,
            challenge: challenge[24..32].try_into().unwrap(),
            ..AuthMsg::default()
        };
        build_auth(&m).0
    }

    fn server(builder: crate::SmbServerBuilder) -> crate::SmbServer {
        builder
            .listen("127.0.0.1:0".parse().unwrap())
            .user("alice", "password")
            .build()
            .expect("build")
    }

    async fn connection(state: &Arc<ServerState>) -> Arc<Connection> {
        let conn = Arc::new(Connection::new(state.config.server_guid, 65536, 65536));
        state.active_connections.register(&conn).await;
        *conn.dialect.write().await = Some(Dialect::Smb210);
        conn
    }

    /// First round; returns the SessionId and the CHALLENGE_MESSAGE.
    async fn first_round(state: &Arc<ServerState>, conn: &Arc<Connection>) -> (u64, Vec<u8>) {
        let resp = handle(state, conn, &header(0), &body(&ntlm_negotiate())).await;
        assert_eq!(resp.status, ntstatus::STATUS_MORE_PROCESSING_REQUIRED);
        let sid = resp.override_session_id.unwrap();
        let challenge = SessionSetupResponse::parse(&resp.body)
            .unwrap()
            .security_buffer;
        (sid, challenge)
    }

    async fn logon(
        state: &Arc<ServerState>,
        conn: &Arc<Connection>,
        user: &str,
        password: &str,
    ) -> u32 {
        let (sid, challenge) = first_round(state, conn).await;
        let auth = ntlm_authenticate(&challenge, user, password);
        handle(state, conn, &header(sid), &body(&auth)).await.status
    }

    #[tokio::test]
    async fn repeated_failures_close_the_connection() {
        let server = server(crate::SmbServer::builder().logon_throttle(2, Duration::from_secs(60)));
        let state = server.state();
        let conn = connection(&state).await;
        assert_eq!(
            logon(&state, &conn, "alice", "wrong").await,
            ntstatus::STATUS_LOGON_FAILURE
        );
        assert!(!conn.disconnect_requested());
        assert_eq!(
            logon(&state, &conn, "nobody", "wrong").await,
            ntstatus::STATUS_LOGON_FAILURE
        );
        assert!(conn.disconnect_requested());
    }

    #[tokio::test]
    async fn sessions_per_connection_are_capped() {
        let server = server(crate::SmbServer::builder().max_sessions_per_connection(1));
        let state = server.state();
        let conn = connection(&state).await;
        assert_eq!(logon(&state, &conn, "alice", "password").await, 0);
        let resp = handle(&state, &conn, &header(0), &body(&ntlm_negotiate())).await;
        assert_eq!(resp.status, ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    }

    /// A logon that authenticated before `remove_user` and inserts its
    /// session after the sweep does not leave a session behind.
    #[tokio::test]
    async fn logon_racing_remove_user_leaves_no_session() {
        let server = server(crate::SmbServer::builder());
        let state = server.state();
        let config = server.config_handle();
        let conn = connection(&state).await;
        let (sid, challenge) = first_round(&state, &conn).await;
        let auth = ntlm_authenticate(&challenge, "alice", "password");

        // Hold the dialect so the logon stops after authenticating.
        let dialect = conn.dialect.write().await;
        let logon = tokio::spawn({
            let (state, conn) = (state.clone(), conn.clone());
            async move {
                handle(&state, &conn, &header(sid), &body(&auth))
                    .await
                    .status
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        config.remove_user("alice").await.unwrap();
        drop(dialect);
        assert_ne!(logon.await.unwrap(), ntstatus::STATUS_SUCCESS);
        assert!(conn.sessions.read().await.is_empty());
    }
}
