//! Client-side NTLM, SPNEGO and SMB2 pieces for the authentication tests.

#![allow(dead_code, reason = "each test crate uses part of the helpers")]

use hmac::Mac as _;
use md4::Digest as _;
use rc4::{KeyInit as _, StreamCipher as _};
use smb_server::wire::header::{
    Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, SMB2_FLAGS_SIGNED, Smb2Header,
};
use smb_server::wire::messages::{
    FileId, IoctlRequest, NegotiateRequest, SessionSetupRequest, SessionSetupResponse,
    TreeConnectRequest,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

pub const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
pub const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

pub const OID_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

pub const NTLM_UNICODE: u32 = 0x0000_0001;
pub const NTLM_REQUEST_TARGET: u32 = 0x0000_0004;
pub const NTLM_SIGN: u32 = 0x0000_0010;
pub const NTLM_NTLM: u32 = 0x0000_0200;
pub const NTLM_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NTLM_ESS: u32 = 0x0008_0000;
pub const NTLM_TARGET_INFO: u32 = 0x0080_0000;
pub const NTLM_VERSION: u32 = 0x0200_0000;
pub const NTLM_128: u32 = 0x2000_0000;
pub const NTLM_KEY_EXCH: u32 = 0x4000_0000;
pub const NTLM_56: u32 = 0x8000_0000;

/// NTLMv2 client flags with signing, key exchange, 128-bit keys and TargetInfo.
pub const CLIENT_FLAGS: u32 = NTLM_UNICODE
    | NTLM_REQUEST_TARGET
    | NTLM_SIGN
    | NTLM_NTLM
    | NTLM_ALWAYS_SIGN
    | NTLM_ESS
    | NTLM_TARGET_INFO
    | NTLM_VERSION
    | NTLM_128
    | NTLM_KEY_EXCH
    | NTLM_56;

pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
pub const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
pub const STATUS_REQUEST_NOT_ACCEPTED: u32 = 0xC000_00D0;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xC000_0234;
pub const STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
pub const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;

// --- DER --------------------------------------------------------------------

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// Splits one TLV off `buf`: (tag, content, rest).
pub fn split_tlv(buf: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = buf[0];
    let (len, at) = if buf[1] < 0x80 {
        (buf[1] as usize, 2)
    } else {
        let nb = (buf[1] & 0x7f) as usize;
        let len = buf[2..2 + nb]
            .iter()
            .fold(0usize, |v, &b| (v << 8) | b as usize);
        (len, 2 + nb)
    };
    (tag, &buf[at..at + len], &buf[at + len..])
}

/// DER MechTypeList for `mechs`.
pub fn mech_type_list(mechs: &[&[u8]]) -> Vec<u8> {
    let oids: Vec<u8> = mechs.iter().flat_map(|m| tlv(0x06, m)).collect();
    tlv(0x30, &oids)
}

/// GSS-API NegTokenInit with the given MechTypeList and optional mechToken.
pub fn spnego_init(mech_list: &[u8], token: Option<&[u8]>) -> Vec<u8> {
    let mut seq = tlv(0xa0, mech_list);
    if let Some(t) = token {
        seq.extend(tlv(0xa2, &tlv(0x04, t)));
    }
    let inner = [tlv(0x06, OID_SPNEGO), tlv(0xa0, &tlv(0x30, &seq))].concat();
    tlv(0x60, &inner)
}

/// NegTokenResp with an optional responseToken and mechListMIC.
pub fn spnego_resp(token: Option<&[u8]>, mic: Option<&[u8]>) -> Vec<u8> {
    let mut seq = Vec::new();
    if let Some(t) = token {
        seq.extend(tlv(0xa2, &tlv(0x04, t)));
    }
    if let Some(m) = mic {
        seq.extend(tlv(0xa3, &tlv(0x04, m)));
    }
    tlv(0xa1, &tlv(0x30, &seq))
}

/// Fields of a server NegTokenResp.
#[derive(Debug, Default)]
pub struct NegResp {
    pub state: Option<u8>,
    pub mech: Option<Vec<u8>>,
    pub token: Option<Vec<u8>>,
    pub mic: Option<Vec<u8>>,
}

pub fn parse_neg_resp(buf: &[u8]) -> NegResp {
    let (tag, inner, _) = split_tlv(buf);
    assert_eq!(tag, 0xa1, "NegTokenResp");
    let (_, mut seq, _) = split_tlv(inner);
    let mut out = NegResp::default();
    while !seq.is_empty() {
        let (tag, content, rest) = split_tlv(seq);
        let (_, value, _) = split_tlv(content);
        match tag {
            0xa0 => out.state = Some(value[0]),
            0xa1 => out.mech = Some(value.to_vec()),
            0xa2 => out.token = Some(value.to_vec()),
            0xa3 => out.mic = Some(value.to_vec()),
            _ => {}
        }
        seq = rest;
    }
    out
}

// --- NTLM -------------------------------------------------------------------

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = hmac::Hmac::<md5::Md5>::new_from_slice(key).expect("hmac key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn md5_of(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = md5::Md5::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn rc4(key: &[u8], data: &mut [u8]) {
    rc4::Rc4::new_from_slice(key)
        .expect("rc4 key")
        .apply_keystream(data);
}

pub fn ntlm_negotiate(flags: u32) -> Vec<u8> {
    let mut msg = NTLMSSP_SIGNATURE.to_vec();
    msg.extend_from_slice(&1u32.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(&[0u8; 16]);
    msg.extend_from_slice(&[6, 1, 0, 0x1D, 0, 0, 0, 0x0F]);
    msg
}

/// Server challenge and TargetInfo of a CHALLENGE_MESSAGE.
pub fn parse_challenge(msg: &[u8]) -> ([u8; 8], Vec<u8>) {
    assert_eq!(&msg[..8], NTLMSSP_SIGNATURE);
    let challenge: [u8; 8] = msg[24..32].try_into().unwrap();
    let len = u16::from_le_bytes([msg[40], msg[41]]) as usize;
    let off = u32::from_le_bytes(msg[44..48].try_into().unwrap()) as usize;
    (challenge, msg[off..off + len].to_vec())
}

/// Options for [`ntlm_authenticate`].
#[derive(Clone, Copy)]
pub struct AuthOptions {
    pub flags: u32,
    /// Announce a MIC in MsvAvFlags and fill it in.
    pub mic: bool,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self {
            flags: CLIENT_FLAGS,
            mic: true,
        }
    }
}

/// NTLMv2 AUTHENTICATE_MESSAGE answering `challenge_msg`, and the
/// ExportedSessionKey.
pub fn ntlm_authenticate(
    user: &str,
    password: &str,
    negotiate_msg: &[u8],
    challenge_msg: &[u8],
    opts: AuthOptions,
) -> (Vec<u8>, [u8; 16]) {
    let (server_challenge, target_info) = parse_challenge(challenge_msg);
    let nt_hash: [u8; 16] = md4::Md4::digest(utf16le(password)).into();
    let response_key = hmac_md5(&nt_hash, &[&utf16le(&user.to_uppercase())]);

    // TargetInfo with its EOL removed, MsvAvFlags added, and a new EOL.
    let mut av = target_info[..target_info.len() - 4].to_vec();
    if opts.mic {
        av.extend_from_slice(&6u16.to_le_bytes());
        av.extend_from_slice(&4u16.to_le_bytes());
        av.extend_from_slice(&2u32.to_le_bytes());
    }
    av.extend_from_slice(&[0, 0, 0, 0]);
    let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
    blob.extend_from_slice(&[0; 8]);
    blob.extend_from_slice(&[0xAA; 8]);
    blob.extend_from_slice(&[0; 4]);
    blob.extend_from_slice(&av);
    blob.extend_from_slice(&[0; 4]);

    let proof = hmac_md5(&response_key, &[&server_challenge, &blob]);
    let kxkey = hmac_md5(&response_key, &[&proof]);
    let nt_response = [&proof[..], &blob].concat();
    let (exported, encrypted) = if opts.flags & NTLM_KEY_EXCH != 0 {
        let random = [0x42u8; 16];
        let mut enc = random;
        rc4(&kxkey, &mut enc);
        (random, enc.to_vec())
    } else {
        (kxkey, Vec::new())
    };

    let user = utf16le(user);
    let lm = [0u8; 24];
    let fields: [&[u8]; 6] = [&lm, &nt_response, &[], &user, &[], &encrypted];
    let header_len = if opts.mic { 88u32 } else { 72 };
    let mut msg = NTLMSSP_SIGNATURE.to_vec();
    msg.extend_from_slice(&3u32.to_le_bytes());
    let mut payload = Vec::new();
    for field in fields {
        let offset = header_len + payload.len() as u32;
        msg.extend_from_slice(&(field.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(field.len() as u16).to_le_bytes());
        msg.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(field);
    }
    msg.extend_from_slice(&opts.flags.to_le_bytes());
    msg.extend_from_slice(&[6, 1, 0, 0x1D, 0, 0, 0, 0x0F]);
    if opts.mic {
        msg.extend_from_slice(&[0u8; 16]);
    }
    msg.extend_from_slice(&payload);
    if opts.mic {
        let mic = hmac_md5(&exported, &[negotiate_msg, challenge_msg, &msg]);
        msg[72..88].copy_from_slice(&mic);
    }
    (msg, exported)
}

/// NTLMSSP_MESSAGE_SIGNATURE at sequence number 0, with extended session
/// security, 128-bit keys and key exchange.
pub fn ntlm_mac(exported: &[u8; 16], client_to_server: bool, message: &[u8]) -> [u8; 16] {
    let dir = if client_to_server {
        "client-to-server"
    } else {
        "server-to-client"
    };
    let sign_key = md5_of(&[
        exported,
        format!("session key to {dir} signing key magic constant\0").as_bytes(),
    ]);
    let seal_key = md5_of(&[
        exported,
        format!("session key to {dir} sealing key magic constant\0").as_bytes(),
    ]);
    let digest = hmac_md5(&sign_key, &[&0u32.to_le_bytes(), message]);
    let mut checksum = [0u8; 8];
    checksum.copy_from_slice(&digest[..8]);
    rc4(&seal_key, &mut checksum);
    let mut out = [0u8; 16];
    out[0] = 1;
    out[4..12].copy_from_slice(&checksum);
    out
}

// --- SMB2 -------------------------------------------------------------------

pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub fn build_header(
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
) -> Smb2Header {
    Smb2Header {
        credit_charge: 1,
        channel_sequence_status: 0,
        command,
        credit_request_response: 64,
        flags: 0,
        next_command: 0,
        message_id,
        tail: HeaderTail::sync(tree_id),
        session_id,
        signature: [0u8; 16],
    }
}

pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

pub async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.expect("frame header");
    let len = u32::from_be_bytes(hdr) as usize & 0x00FF_FFFF;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.expect("frame body");
    body
}

pub fn parse_response_header(frame: &[u8]) -> (Smb2Header, &[u8]) {
    let (h, rest) = Smb2Header::parse(frame).expect("response header");
    assert_ne!(h.flags & SMB2_FLAGS_SERVER_TO_REDIR, 0, "not a response");
    (h, rest)
}

/// SMB 2.x signature (HMAC-SHA256) of `msg` with its signature field zeroed.
pub fn smb2_signature(msg: &[u8], key: &[u8; 16]) -> [u8; 16] {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(&msg[..48]);
    mac.update(&[0; 16]);
    mac.update(&msg[64..]);
    mac.finalize().into_bytes()[..16]
        .try_into()
        .expect("16 bytes")
}

/// Sends `body` as `command` and returns the response frame.
pub async fn request(
    s: &mut TcpStream,
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    body: &[u8],
) -> Vec<u8> {
    let hdr = build_header(command, message_id, session_id, tree_id);
    send(s, hdr, body, None).await
}

/// Sends `hdr` and `body`, signed with an SMB 2.x `key` when one is given,
/// and returns the response frame.
pub async fn send(
    s: &mut TcpStream,
    mut hdr: Smb2Header,
    body: &[u8],
    key: Option<&[u8; 16]>,
) -> Vec<u8> {
    if key.is_some() {
        hdr.flags |= SMB2_FLAGS_SIGNED;
    }
    let mut msg = Vec::new();
    hdr.write(&mut msg).expect("header");
    msg.extend_from_slice(body);
    if let Some(key) = key {
        let sig = smb2_signature(&msg, key);
        msg[48..64].copy_from_slice(&sig);
    }
    let mut framed = Vec::new();
    encode_frame(&msg, &mut framed);
    s.write_all(&framed).await.expect("write");
    read_frame(s).await
}

pub fn status(frame: &[u8]) -> u32 {
    parse_response_header(frame).0.channel_sequence_status
}

pub fn response_session_id(frame: &[u8]) -> u64 {
    parse_response_header(frame).0.session_id
}

/// NEGOTIATE request body.
pub fn negotiate_body(dialects: &[u16], security_mode: u16, capabilities: u32) -> Vec<u8> {
    let req = NegotiateRequest {
        structure_size: 36,
        dialect_count: dialects.len() as u16,
        security_mode,
        reserved: 0,
        capabilities,
        client_guid: [0xCD; 16],
        negotiate_context_offset_or_client_start_time: 0,
        dialects: dialects.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("negotiate");
    body
}

pub const CTX_PREAUTH: u16 = 0x0001;
pub const CTX_ENCRYPTION: u16 = 0x0002;
pub const CTX_SIGNING: u16 = 0x0008;

/// SMB2_PREAUTH_INTEGRITY_CAPABILITIES data with the given hash ids.
pub fn preauth_context(hashes: &[u16]) -> (u16, Vec<u8>) {
    let mut data = (hashes.len() as u16).to_le_bytes().to_vec();
    data.extend_from_slice(&32u16.to_le_bytes());
    for h in hashes {
        data.extend_from_slice(&h.to_le_bytes());
    }
    data.extend_from_slice(&[0x11; 32]);
    (CTX_PREAUTH, data)
}

/// Context data made of a u16 count and u16 ids, as in
/// SMB2_SIGNING_CAPABILITIES and SMB2_ENCRYPTION_CAPABILITIES.
pub fn id_list_context(context_type: u16, ids: &[u16]) -> (u16, Vec<u8>) {
    let mut data = (ids.len() as u16).to_le_bytes().to_vec();
    for id in ids {
        data.extend_from_slice(&id.to_le_bytes());
    }
    (context_type, data)
}

/// SMB 3.1.1 NEGOTIATE request body with `contexts`.
pub fn negotiate_311_body(dialects: &[u16], contexts: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let fixed_end = 64 + 36 + 2 * dialects.len();
    let offset = (fixed_end + 7) & !7;
    let req = NegotiateRequest {
        structure_size: 36,
        dialect_count: dialects.len() as u16,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0xCD; 16],
        negotiate_context_offset_or_client_start_time: offset as u64
            | ((contexts.len() as u64) << 32),
        dialects: dialects.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("negotiate");
    for (i, (context_type, data)) in contexts.iter().enumerate() {
        let target = if i == 0 {
            offset - 64
        } else {
            (body.len() + 7) & !7
        };
        body.resize(target, 0);
        body.extend_from_slice(&context_type.to_le_bytes());
        body.extend_from_slice(&(data.len() as u16).to_le_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(data);
    }
    body
}

/// (type, data) of each negotiate context in a NEGOTIATE response frame.
pub fn response_contexts(frame: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let count = u16::from_le_bytes([frame[64 + 6], frame[64 + 7]]) as usize;
    let mut at = u32::from_le_bytes(frame[64 + 60..64 + 64].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        at = (at + 7) & !7;
        let context_type = u16::from_le_bytes([frame[at], frame[at + 1]]);
        let len = u16::from_le_bytes([frame[at + 2], frame[at + 3]]) as usize;
        out.push((context_type, frame[at + 8..at + 8 + len].to_vec()));
        at += 8 + len;
    }
    out
}

/// SESSION_SETUP request body.
pub fn session_setup_body(blob: &[u8], flags: u8, security_mode: u8, previous: u64) -> Vec<u8> {
    let req = SessionSetupRequest {
        structure_size: 25,
        flags,
        security_mode,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: blob.len() as u16,
        previous_session_id: previous,
        security_buffer: blob.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("session setup");
    body
}

/// Security buffer of a SESSION_SETUP response.
pub fn session_setup_token(frame: &[u8]) -> Vec<u8> {
    let (_, body) = parse_response_header(frame);
    SessionSetupResponse::parse(body)
        .expect("session setup response")
        .security_buffer
}

/// A finished NTLM login.
pub struct Login {
    pub status: u32,
    pub session_id: u64,
    pub key: [u8; 16],
    /// The final response frame.
    pub frame: Vec<u8>,
}

/// Two-round SPNEGO NTLM login as `user`, sending a mechListMIC. Uses
/// message ids `mid` and `mid + 1`.
pub async fn spnego_login(
    s: &mut TcpStream,
    mid: u64,
    session_id: u64,
    user: &str,
    password: &str,
) -> Login {
    login_with(s, mid, session_id, user, password, LoginOptions::default()).await
}

/// Knobs for [`login_with`].
#[derive(Clone, Copy)]
pub struct LoginOptions {
    pub raw: bool,
    pub security_mode: u8,
    pub flags: u8,
    pub previous_session_id: u64,
    pub auth: AuthOptions,
}

impl Default for LoginOptions {
    fn default() -> Self {
        Self {
            raw: false,
            security_mode: 0x01,
            flags: 0,
            previous_session_id: 0,
            auth: AuthOptions::default(),
        }
    }
}

pub async fn login_with(
    s: &mut TcpStream,
    mid: u64,
    session_id: u64,
    user: &str,
    password: &str,
    opts: LoginOptions,
) -> Login {
    let negotiate = ntlm_negotiate(opts.auth.flags);
    let mech_list = mech_type_list(&[OID_NTLMSSP]);
    let first = if opts.raw {
        negotiate.clone()
    } else {
        spnego_init(&mech_list, Some(&negotiate))
    };
    let body = session_setup_body(&first, opts.flags, opts.security_mode, 0);
    let frame = request(s, Command::SessionSetup, mid, session_id, 0, &body).await;
    let st = status(&frame);
    if st != 0xC000_0016 {
        return Login {
            status: st,
            session_id: response_session_id(&frame),
            key: [0; 16],
            frame,
        };
    }
    let sid = response_session_id(&frame);
    let token = session_setup_token(&frame);
    let challenge = if opts.raw {
        token
    } else {
        parse_neg_resp(&token).token.expect("challenge")
    };
    let (auth, key) = ntlm_authenticate(user, password, &negotiate, &challenge, opts.auth);
    let second = if opts.raw {
        auth
    } else {
        let mic = ntlm_mac(&key, true, &mech_list);
        spnego_resp(Some(&auth), Some(&mic))
    };
    let body = session_setup_body(
        &second,
        opts.flags,
        opts.security_mode,
        opts.previous_session_id,
    );
    let frame = request(s, Command::SessionSetup, mid + 1, sid, 0, &body).await;
    Login {
        status: status(&frame),
        session_id: sid,
        key,
        frame,
    }
}

/// TREE_CONNECT request body for `path`.
pub fn tree_connect_body(path: &str) -> Vec<u8> {
    let path = utf16le(path);
    let mut body = Vec::new();
    TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path.len() as u16,
        path,
    }
    .write_to(&mut body)
    .expect("tree connect");
    body
}

/// CREATE request body opening `name` (FILE_OPEN) with `access`.
pub fn create_body(name: &str, access: u32, options: u32) -> Vec<u8> {
    let name = utf16le(name);
    let req = smb_server::wire::messages::CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: access,
        file_attributes: 0,
        share_access: 7,
        create_disposition: 1,
        create_options: options,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: Vec::new(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("create");
    body
}

/// FileId of a successful CREATE response frame.
pub fn created_file_id(frame: &[u8]) -> FileId {
    assert_eq!(status(frame), 0, "CREATE failed");
    smb_server::wire::messages::CreateResponse::parse(&frame[64..])
        .expect("create response")
        .file_id
}

/// IOCTL request body.
pub fn ioctl_body(
    ctl_code: u32,
    file_id: FileId,
    input: &[u8],
    max_output: u32,
    flags: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code,
        file_id,
        input_offset: if input.is_empty() { 0 } else { 0x78 },
        input_count: input.len() as u32,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: max_output,
        flags,
        reserved2: 0,
        input: input.to_vec(),
    }
    .write_to(&mut body)
    .expect("ioctl");
    body
}

/// VALIDATE_NEGOTIATE_INFO request input.
pub fn validate_negotiate_input(
    capabilities: u32,
    guid: [u8; 16],
    security_mode: u16,
    dialects: &[u16],
) -> Vec<u8> {
    let mut out = capabilities.to_le_bytes().to_vec();
    out.extend_from_slice(&guid);
    out.extend_from_slice(&security_mode.to_le_bytes());
    out.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    for d in dialects {
        out.extend_from_slice(&d.to_le_bytes());
    }
    out
}

/// Reads a frame, or returns `None` once the server closes the connection.
pub async fn read_or_closed(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    match tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut hdr)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return None,
        Err(_) => panic!("server neither replied nor closed the connection"),
    }
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.ok()?;
    Some(body)
}
