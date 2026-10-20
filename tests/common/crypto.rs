//! Client-side SMB 3.x encryption: key derivation, the transform header and
//! a session that sends encrypted requests.

use std::net::SocketAddr;

use aes::{Aes128, Aes256};
use aes_gcm::aead::{AeadInPlace, KeyInit, Nonce, Tag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use ccm::Ccm;
use ccm::consts::{U11, U16};
use hmac::Mac;
use sha2::Digest as _;
use smb_server::ntstatus::{STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS};
use smb_server::wire::header::{Command, SMB2_FLAGS_SIGNED, Smb2Header};
use smb_server::wire::messages::{NegotiateResponse, SessionSetupResponse};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use super::auth::{
    AuthOptions, CTX_ENCRYPTION, Login, id_list_context, mech_type_list, negotiate_311_body,
    ntlm_authenticate, ntlm_mac, ntlm_negotiate, parse_neg_resp, preauth_context,
    response_contexts, response_session_id, session_setup_token, spnego_init, spnego_resp, status,
};
use super::{
    OID_NTLMSSP, build_header, framed, message, negotiate_body, read_frame, session_setup_body,
};

/// SMB2_GLOBAL_CAP_ENCRYPTION, the 3.0 and 3.0.2 way to offer encryption.
pub const CAP_ENCRYPTION: u32 = 0x0000_0040;
/// SHA-512, the only preauth integrity hash.
pub const PREAUTH_SHA512: u16 = 0x0001;

// --- Ciphers ----------------------------------------------------------------

/// SMB2 encryption cipher ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Cipher {
    Aes128Ccm = 1,
    Aes128Gcm = 2,
    Aes256Ccm = 3,
    Aes256Gcm = 4,
}

impl Cipher {
    pub const ALL: [Cipher; 4] = [
        Cipher::Aes128Ccm,
        Cipher::Aes128Gcm,
        Cipher::Aes256Ccm,
        Cipher::Aes256Gcm,
    ];

    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.id() == id)
    }

    pub fn id(self) -> u16 {
        self as u16
    }

    pub fn key_len(self) -> usize {
        match self {
            Cipher::Aes128Ccm | Cipher::Aes128Gcm => 16,
            Cipher::Aes256Ccm | Cipher::Aes256Gcm => 32,
        }
    }

    /// Bytes of the transform Nonce field the cipher uses.
    pub fn nonce_len(self) -> usize {
        match self {
            Cipher::Aes128Ccm | Cipher::Aes256Ccm => 11,
            Cipher::Aes128Gcm | Cipher::Aes256Gcm => 12,
        }
    }
}

type Ccm128 = Ccm<Aes128, U16, U11>;
type Ccm256 = Ccm<Aes256, U16, U11>;

fn seal(cipher: Cipher, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    match cipher {
        Cipher::Aes128Ccm => seal_with::<Ccm128>(key, nonce, aad, buf),
        Cipher::Aes128Gcm => seal_with::<Aes128Gcm>(key, nonce, aad, buf),
        Cipher::Aes256Ccm => seal_with::<Ccm256>(key, nonce, aad, buf),
        Cipher::Aes256Gcm => seal_with::<Aes256Gcm>(key, nonce, aad, buf),
    }
}

fn open(cipher: Cipher, key: &[u8], nonce: &[u8], aad: &[u8], tag: &[u8], buf: &mut [u8]) -> bool {
    match cipher {
        Cipher::Aes128Ccm => open_with::<Ccm128>(key, nonce, aad, tag, buf),
        Cipher::Aes128Gcm => open_with::<Aes128Gcm>(key, nonce, aad, tag, buf),
        Cipher::Aes256Ccm => open_with::<Ccm256>(key, nonce, aad, tag, buf),
        Cipher::Aes256Gcm => open_with::<Aes256Gcm>(key, nonce, aad, tag, buf),
    }
}

fn seal_with<A: AeadInPlace + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    A::new_from_slice(key)
        .expect("key length")
        .encrypt_in_place_detached(Nonce::<A>::from_slice(nonce), aad, buf)
        .expect("encrypt")
        .as_slice()
        .try_into()
        .expect("16-byte tag")
}

fn open_with<A: AeadInPlace + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    tag: &[u8],
    buf: &mut [u8],
) -> bool {
    A::new_from_slice(key)
        .expect("key length")
        .decrypt_in_place_detached(
            Nonce::<A>::from_slice(nonce),
            aad,
            buf,
            Tag::<A>::from_slice(tag),
        )
        .is_ok()
}

// --- Keys -------------------------------------------------------------------

/// SP 800-108 counter-mode KDF with HMAC-SHA-256 and L = `len * 8` bits.
/// `label` and `context` carry their own trailing NUL.
pub fn kdf(key: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 32, "one HMAC-SHA-256 block");
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(&1u32.to_be_bytes());
    mac.update(label);
    mac.update(&[0]);
    mac.update(context);
    mac.update(&(len as u32 * 8).to_be_bytes());
    mac.finalize().into_bytes()[..len].to_vec()
}

/// Client-side session keys.
#[derive(Clone, Debug)]
pub struct Keys {
    pub signing: [u8; 16],
    /// Client to server.
    pub encryption: Vec<u8>,
    /// Server to client.
    pub decryption: Vec<u8>,
}

/// SMB 3.0 and 3.0.2 keys. The cipher is always AES-128-CCM.
pub fn keys_30(session_key: &[u8]) -> Keys {
    Keys {
        signing: kdf(session_key, b"SMB2AESCMAC\0", b"SmbSign\0", 16)
            .try_into()
            .expect("16 bytes"),
        encryption: kdf(session_key, b"SMB2AESCCM\0", b"ServerIn \0", 16),
        decryption: kdf(session_key, b"SMB2AESCCM\0", b"ServerOut\0", 16),
    }
}

/// SMB 3.1.1 keys for `cipher`, bound to the session's preauth hash.
pub fn keys_311(session_key: &[u8], cipher: Cipher, preauth_hash: &[u8; 64]) -> Keys {
    let len = cipher.key_len();
    Keys {
        signing: kdf(session_key, b"SMBSigningKey\0", preauth_hash, 16)
            .try_into()
            .expect("16 bytes"),
        encryption: kdf(session_key, b"SMBC2SCipherKey\0", preauth_hash, len),
        decryption: kdf(session_key, b"SMBS2CCipherKey\0", preauth_hash, len),
    }
}

/// Folds `message`, an SMB2 message without its transport prefix, into a
/// SHA-512 preauth integrity hash.
pub fn preauth_update(hash: &mut [u8; 64], message: &[u8]) {
    let next = sha2::Sha512::new()
        .chain_update(&hash[..])
        .chain_update(message)
        .finalize();
    hash.copy_from_slice(&next);
}

// --- Transform header ---------------------------------------------------------

pub const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xFD, b'S', b'M', b'B'];
pub const TRANSFORM_HEADER_LEN: usize = 52;
const FLAG_ENCRYPTED: u16 = 0x0001;

pub fn is_transform(frame: &[u8]) -> bool {
    frame.starts_with(&TRANSFORM_PROTOCOL_ID)
}

/// SessionId of a transform header.
pub fn transform_session_id(frame: &[u8]) -> u64 {
    u64::from_le_bytes(frame[44..52].try_into().unwrap())
}

/// Transform header followed by `message` encrypted under `key`. `nonce`
/// fills the start of the Nonce field, the rest is zero; the cipher reads
/// the first 11 (CCM) or 12 (GCM) bytes.
pub fn encrypt(
    cipher: Cipher,
    key: &[u8],
    session_id: u64,
    nonce: &[u8],
    message: &[u8],
) -> Vec<u8> {
    encrypt_with_flags(cipher, key, session_id, nonce, FLAG_ENCRYPTED, message)
}

/// Like [`encrypt`], with `flags` in the transform header's Flags field.
pub fn encrypt_with_flags(
    cipher: Cipher,
    key: &[u8],
    session_id: u64,
    nonce: &[u8],
    flags: u16,
    message: &[u8],
) -> Vec<u8> {
    let mut field = [0u8; 16];
    field[..nonce.len()].copy_from_slice(nonce);
    let mut out = TRANSFORM_PROTOCOL_ID.to_vec();
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&field);
    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&session_id.to_le_bytes());
    let mut body = message.to_vec();
    let tag = seal(
        cipher,
        key,
        &field[..cipher.nonce_len()],
        &out[20..],
        &mut body,
    );
    out[4..20].copy_from_slice(&tag);
    out.extend_from_slice(&body);
    out
}

/// Plaintext of a transform `frame` (without the transport prefix), or
/// `None` if the header is malformed or the tag does not verify.
pub fn decrypt(cipher: Cipher, key: &[u8], frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < TRANSFORM_HEADER_LEN || !is_transform(frame) {
        return None;
    }
    let size = u32::from_le_bytes(frame[36..40].try_into().unwrap()) as usize;
    let flags = u16::from_le_bytes([frame[42], frame[43]]);
    if size != frame.len() - TRANSFORM_HEADER_LEN || flags != FLAG_ENCRYPTED {
        return None;
    }
    let mut body = frame[TRANSFORM_HEADER_LEN..].to_vec();
    let nonce = &frame[20..20 + cipher.nonce_len()];
    open(cipher, key, nonce, &frame[20..52], &frame[4..20], &mut body).then_some(body)
}

// --- Session ------------------------------------------------------------------

/// SMB 3.1.1 NEGOTIATE body offering SHA-512 preauth and `ciphers`.
pub fn negotiate_311_encryption_body(ciphers: &[Cipher]) -> Vec<u8> {
    let ids: Vec<u16> = ciphers.iter().map(|c| c.id()).collect();
    negotiate_311_cipher_ids_body(&ids)
}

/// SMB 3.1.1 NEGOTIATE body offering SHA-512 preauth and the cipher ids
/// `ids`, known or not.
pub fn negotiate_311_cipher_ids_body(ids: &[u16]) -> Vec<u8> {
    negotiate_311_body(
        &[0x0311],
        &[
            preauth_context(&[PREAUTH_SHA512]),
            id_list_context(CTX_ENCRYPTION, ids),
        ],
    )
}

/// Sets SMB2_FLAGS_SIGNED on `msg`, an SMB2 message without its transport
/// prefix, and signs it with AES-128-CMAC under `key`.
pub fn cmac_sign(msg: &mut [u8], key: &[u8; 16]) {
    let flags = u32::from_le_bytes(msg[16..20].try_into().unwrap()) | SMB2_FLAGS_SIGNED;
    msg[16..20].copy_from_slice(&flags.to_le_bytes());
    msg[48..64].fill(0);
    let mut mac = <cmac::Cmac<Aes128> as Mac>::new_from_slice(key).expect("cmac key");
    mac.update(msg);
    msg[48..64].copy_from_slice(&mac.finalize().into_bytes());
}

/// Cipher a 3.1.1 NEGOTIATE response frame selected, if any.
pub fn negotiated_cipher(frame: &[u8]) -> Option<Cipher> {
    let (_, data) = response_contexts(frame)
        .into_iter()
        .find(|(t, _)| *t == CTX_ENCRYPTION)?;
    assert_eq!(u16::from_le_bytes([data[0], data[1]]), 1, "CipherCount");
    Cipher::from_id(u16::from_le_bytes([data[2], data[3]]))
}

/// Writes `msg`, folds it into `hash`, and returns the response frame.
async fn hashed_exchange(s: &mut TcpStream, msg: &[u8], hash: &mut [u8; 64]) -> Vec<u8> {
    preauth_update(hash, msg);
    s.write_all(&framed(msg)).await.expect("write");
    read_frame(s).await
}

/// Sends NEGOTIATE with `body` and MessageId 0, folds the request and the
/// response into `hash`, and returns the response frame.
pub async fn hashed_negotiate(s: &mut TcpStream, body: &[u8], hash: &mut [u8; 64]) -> Vec<u8> {
    let req = message(&build_header(Command::Negotiate, 0, 0, 0), body);
    let frame = hashed_exchange(s, &req, hash).await;
    preauth_update(hash, &frame);
    frame
}

/// Two-round SPNEGO NTLM login like [`super::auth::spnego_login`], folding
/// every SESSION_SETUP message except a final STATUS_SUCCESS response into
/// `hash`. Uses message ids `mid` and `mid + 1`.
pub async fn hashed_login(
    s: &mut TcpStream,
    mid: u64,
    user: &str,
    password: &str,
    hash: &mut [u8; 64],
) -> Login {
    let opts = AuthOptions::default();
    let negotiate = ntlm_negotiate(opts.flags);
    let mech_list = mech_type_list(&[OID_NTLMSSP]);
    let body = session_setup_body(&spnego_init(&mech_list, Some(&negotiate)), 0, 0x01, 0);
    let req = message(&build_header(Command::SessionSetup, mid, 0, 0), &body);
    let frame = hashed_exchange(s, &req, hash).await;
    let sid = response_session_id(&frame);
    let st = status(&frame);
    if st != STATUS_MORE_PROCESSING_REQUIRED {
        return Login {
            status: st,
            session_id: sid,
            key: [0; 16],
            frame,
        };
    }
    preauth_update(hash, &frame);

    let challenge = parse_neg_resp(&session_setup_token(&frame))
        .token
        .expect("challenge");
    let (auth, key) = ntlm_authenticate(user, password, &negotiate, &challenge, opts);
    let mic = ntlm_mac(&key, true, &mech_list);
    let body = session_setup_body(&spnego_resp(Some(&auth), Some(&mic)), 0, 0x01, 0);
    let req = message(&build_header(Command::SessionSetup, mid + 1, sid, 0), &body);
    let frame = hashed_exchange(s, &req, hash).await;
    if status(&frame) != STATUS_SUCCESS {
        preauth_update(hash, &frame);
    }
    Login {
        status: status(&frame),
        session_id: sid,
        key,
        frame,
    }
}

/// A logged-in SMB 3.x session with encryption keys.
pub struct EncryptedSession {
    pub stream: TcpStream,
    pub dialect: u16,
    pub cipher: Cipher,
    pub session_id: u64,
    /// TreeId put in request headers.
    pub tree_id: u32,
    pub keys: Keys,
    /// Hash the 3.1.1 keys come from.
    pub preauth_hash: [u8; 64],
    pub negotiate_frame: Vec<u8>,
    /// Final SESSION_SETUP response frame.
    pub session_setup_frame: Vec<u8>,
    /// Last frame read from the server, as received.
    pub last_frame: Vec<u8>,
    next_message_id: u64,
    next_nonce: u64,
}

impl EncryptedSession {
    /// Negotiates 3.1.1 offering `ciphers` and logs in as `user`.
    pub async fn smb311(addr: SocketAddr, ciphers: &[Cipher], user: &str, password: &str) -> Self {
        Self::establish(addr, negotiate_311_encryption_body(ciphers), user, password).await
    }

    /// Negotiates `dialect` (3.0 or 3.0.2) with SMB2_GLOBAL_CAP_ENCRYPTION
    /// and logs in as `user`.
    pub async fn smb30(addr: SocketAddr, dialect: u16, user: &str, password: &str) -> Self {
        let body = negotiate_body(&[dialect], 0x0001, CAP_ENCRYPTION);
        Self::establish(addr, body, user, password).await
    }

    async fn establish(addr: SocketAddr, negotiate: Vec<u8>, user: &str, password: &str) -> Self {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let mut hash = [0u8; 64];
        let negotiate_frame = hashed_negotiate(&mut stream, &negotiate, &mut hash).await;
        assert_eq!(status(&negotiate_frame), STATUS_SUCCESS, "NEGOTIATE");
        let neg = NegotiateResponse::parse(&negotiate_frame[64..]).expect("negotiate response");
        let dialect = neg.dialect_revision;
        let cipher = if dialect == 0x0311 {
            negotiated_cipher(&negotiate_frame).expect("server selected no cipher")
        } else {
            assert_ne!(neg.capabilities & CAP_ENCRYPTION, 0, "CAP_ENCRYPTION");
            Cipher::Aes128Ccm
        };

        let login = hashed_login(&mut stream, 1, user, password, &mut hash).await;
        assert_eq!(login.status, STATUS_SUCCESS, "SESSION_SETUP");
        let keys = if dialect == 0x0311 {
            keys_311(&login.key, cipher, &hash)
        } else {
            keys_30(&login.key)
        };
        Self {
            stream,
            dialect,
            cipher,
            session_id: login.session_id,
            tree_id: 0,
            keys,
            preauth_hash: hash,
            negotiate_frame,
            last_frame: login.frame.clone(),
            session_setup_frame: login.frame,
            next_message_id: 3,
            next_nonce: 1,
        }
    }

    /// SessionFlags of the final SESSION_SETUP response.
    pub fn session_flags(&self) -> u16 {
        SessionSetupResponse::parse(&self.session_setup_frame[64..])
            .expect("session setup response")
            .session_flags
    }

    /// Header for `command` with the next MessageId, the SessionId and
    /// [`Self::tree_id`].
    pub fn header(&mut self, command: Command) -> Smb2Header {
        let hdr = build_header(command, self.next_message_id, self.session_id, self.tree_id);
        self.next_message_id += 1;
        hdr
    }

    /// `message` in a transform header with a fresh nonce.
    pub fn seal(&mut self, message: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce.to_le_bytes();
        self.next_nonce += 1;
        encrypt(
            self.cipher,
            &self.keys.encryption,
            self.session_id,
            &nonce,
            message,
        )
    }

    /// Plaintext of a transform frame from the server.
    pub fn open(&self, frame: &[u8]) -> Option<Vec<u8>> {
        decrypt(self.cipher, &self.keys.decryption, frame)
    }

    /// Writes `payload` as one frame and returns the next frame read.
    pub async fn exchange(&mut self, payload: &[u8]) -> Vec<u8> {
        self.stream
            .write_all(&framed(payload))
            .await
            .expect("write");
        self.last_frame = read_frame(&mut self.stream).await;
        self.last_frame.clone()
    }

    /// Sends `body` as an encrypted `command`; returns the decrypted
    /// response. Panics if the response is not a valid transform frame.
    pub async fn send_encrypted(&mut self, command: Command, body: &[u8]) -> Vec<u8> {
        let hdr = self.header(command);
        let sealed = self.seal(&message(&hdr, body));
        let frame = self.exchange(&sealed).await;
        assert!(is_transform(&frame), "response is not encrypted");
        self.open(&frame).expect("response decrypts")
    }

    /// Sends `body` as an unencrypted, unsigned `command`; returns the
    /// response frame as received.
    pub async fn send_plain(&mut self, command: Command, body: &[u8]) -> Vec<u8> {
        let hdr = self.header(command);
        self.exchange(&message(&hdr, body)).await
    }

    /// Encrypted TREE_CONNECT to `path`; on success the TreeId is kept for
    /// later requests. Returns the decrypted response.
    pub async fn tree_connect(&mut self, path: &str) -> Vec<u8> {
        let resp = self
            .send_encrypted(Command::TreeConnect, &super::tree_connect_body(path))
            .await;
        if status(&resp) == STATUS_SUCCESS {
            self.tree_id = super::parse_response_header(&resp)
                .0
                .tree_id()
                .expect("tree id");
        }
        resp
    }
}
