//! NTLMv2 server-side authentication.
//!
//! Spec references (all from MS-NLMP):
//! * §2.2.1 NTLM messages (NEGOTIATE, CHALLENGE, AUTHENTICATE)
//! * §2.2.2 Common structures (AV_PAIR, NTLMv2_RESPONSE, NTLMv2_CLIENT_CHALLENGE)
//! * §3.3.2 NTLM v2 Authentication algorithm
//! * §3.4   Key derivation (`NTOWFv2`, `LMOWFv2`)
//! * §3.4.4 Message Integrity Code (MIC)
//! * §4.2.4 Known-answer test vectors
//!
//! This module implements the **server side only**. We parse incoming
//! `NEGOTIATE_MESSAGE` (Type 1) and `AUTHENTICATE_MESSAGE` (Type 3) blobs,
//! produce the `CHALLENGE_MESSAGE` (Type 2) reply, and validate the client's
//! NT response to derive a session key.

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use rc4::Rc4;
use rc4::cipher::{KeyInit, StreamCipher};

use crate::proto::error::{ProtoError, ProtoResult};

type HmacMd5 = Hmac<Md5>;

// --- NTLMSSP signature & message types --------------------------------------

/// 8-byte signature `"NTLMSSP\0"` prefixing every NTLMSSP message.
pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub const MSG_NEGOTIATE: u32 = 0x0000_0001;
pub const MSG_CHALLENGE: u32 = 0x0000_0002;
pub const MSG_AUTHENTICATE: u32 = 0x0000_0003;

// --- NTLMSSP negotiate flags (MS-NLMP §2.2.2.5) -----------------------------

pub mod flags {
    pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
    pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
    pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
    #[cfg(test)]
    pub const NTLMSSP_NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
    pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const NTLMSSP_TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;
    pub const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
    pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    pub const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;
}

// --- AV_PAIR types (MS-NLMP §2.2.2.1) ---------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AvId {
    Eol = 0x0000,
    NbComputerName = 0x0001,
    NbDomainName = 0x0002,
    DnsComputerName = 0x0003,
    DnsDomainName = 0x0004,
    DnsTreeName = 0x0005,
    Flags = 0x0006,
    Timestamp = 0x0007,
    SingleHost = 0x0008,
    TargetName = 0x0009,
    ChannelBindings = 0x000A,
}

/// One AV_PAIR (attribute-value pair) from a target-info / authenticate-target-info list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvPair {
    pub id: u16,
    pub value: Vec<u8>,
}

impl AvPair {
    pub fn new(id: AvId, value: Vec<u8>) -> Self {
        Self {
            id: id as u16,
            value,
        }
    }
}

/// Encode a list of AV_PAIRs in wire format (each: 2-byte LE id, 2-byte LE
/// length, value bytes), terminated by an `MsvAvEOL` (id=0, len=0) entry.
pub fn encode_av_pairs(pairs: &[AvPair]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in pairs {
        out.extend_from_slice(&p.id.to_le_bytes());
        out.extend_from_slice(&(p.value.len() as u16).to_le_bytes());
        out.extend_from_slice(&p.value);
    }
    // Terminator
    out.extend_from_slice(&(AvId::Eol as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Decode AV_PAIRs from a byte slice; stops at (and consumes) the EOL entry.
pub fn decode_av_pairs(buf: &[u8]) -> ProtoResult<Vec<AvPair>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        if buf.len() < i + 4 {
            return Err(ProtoError::Auth("av_pair list truncated"));
        }
        let id = u16::from_le_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_le_bytes([buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if id == AvId::Eol as u16 {
            // EOL must have len=0; tolerate stray bytes.
            break;
        }
        if buf.len() < i + len {
            return Err(ProtoError::Auth("av_pair value truncated"));
        }
        out.push(AvPair {
            id,
            value: buf[i..i + len].to_vec(),
        });
        i += len;
    }
    Ok(out)
}

// --- Helpers ---------------------------------------------------------------

/// UTF-8 -> UTF-16LE bytes (no BOM).
pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Decode UTF-16LE bytes into a `String` (lossy on bad surrogates).
fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// MD4 of UTF-16LE password - the "NT hash".
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(utf16le(password));
    let out = h.finalize();
    let mut o = [0u8; 16];
    o.copy_from_slice(&out);
    o
}

/// `NTOWFv2(password, user, domain) = HMAC_MD5(NT_hash(password), UTF-16LE(UPPER(user) || domain))`.
///
/// The user name is uppercased; the domain is **not** (per MS-NLMP §3.4 NTOWFv2).
pub fn ntowf_v2(nt_hash_bytes: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(nt_hash_bytes).expect("HMAC accepts any key length");
    mac.update(&utf16le(&user.to_uppercase()));
    mac.update(&utf16le(domain));
    let res = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&res);
    out
}

/// Constant-time 16-byte comparison.
fn ct_eq_16(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- Read helpers for NTLMSSP fields -----------------------------------------

/// A `(len, max_len, offset)` field descriptor as used throughout NTLMSSP messages.
/// The parser keeps the fields used to slice payloads; `max_len` is ignored.
#[derive(Debug, Clone, Copy)]
struct Field {
    len: u16,
    offset: u32,
}

fn read_field(buf: &[u8], at: usize) -> ProtoResult<Field> {
    let d = at
        .checked_add(8)
        .and_then(|end| buf.get(at..end))
        .ok_or(ProtoError::Auth("field descriptor truncated"))?;
    Ok(Field {
        len: u16::from_le_bytes([d[0], d[1]]),
        offset: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
    })
}

fn slice_field(buf: &[u8], f: Field) -> ProtoResult<&[u8]> {
    let start = f.offset as usize;
    let end = start.saturating_add(f.len as usize);
    if end > buf.len() {
        return Err(ProtoError::Auth("field slice out of range"));
    }
    Ok(&buf[start..end])
}

fn check_signature(buf: &[u8], expected_msg: u32) -> ProtoResult<()> {
    if buf.len() < 12 {
        return Err(ProtoError::Auth("ntlmssp message too short"));
    }
    if &buf[..8] != NTLMSSP_SIGNATURE {
        return Err(ProtoError::Auth("ntlmssp signature mismatch"));
    }
    let msg = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if msg != expected_msg {
        return Err(ProtoError::Auth("unexpected ntlmssp message type"));
    }
    Ok(())
}

// --- NEGOTIATE_MESSAGE (Type 1) ---------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct NtlmNegotiate {
    pub flags: u32,
    /// Raw bytes of the original message - needed for MIC computation later.
    pub raw: Vec<u8>,
}

impl NtlmNegotiate {
    /// Parse a Type 1 NEGOTIATE_MESSAGE.
    ///
    /// Layout (MS-NLMP §2.2.1.1):
    /// ```text
    /// 0  : "NTLMSSP\0"
    /// 8  : MessageType = 0x01 (u32 LE)
    /// 12 : NegotiateFlags (u32 LE)
    /// 16 : DomainNameFields (8 bytes: len, maxlen, offset)
    /// 24 : WorkstationFields (8 bytes)
    /// 32 : Version (8 bytes, optional - only if NTLMSSP_NEGOTIATE_VERSION set)
    /// ```
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        check_signature(buf, MSG_NEGOTIATE)?;
        if buf.len() < 32 {
            return Err(ProtoError::Auth("NEGOTIATE_MESSAGE too short"));
        }
        let flags = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let domain_field = read_field(buf, 16)?;
        let ws_field = read_field(buf, 24)?;

        // Fields may be empty (offset/len = 0) when supplied flags don't set
        // them. Non-empty ones must lie inside the message.
        for field in [domain_field, ws_field] {
            if field.len != 0 {
                slice_field(buf, field)?;
            }
        }

        Ok(Self {
            flags,
            raw: buf.to_vec(),
        })
    }
}

// --- CHALLENGE_MESSAGE (Type 2) ---------------------------------------------

/// Server-side construction parameters for the CHALLENGE_MESSAGE.
#[derive(Debug, Clone)]
pub struct ChallengeParams<'a> {
    pub server_challenge: [u8; 8],
    pub target_name: &'a str,
    pub nb_domain_name: &'a str,
    pub nb_computer_name: &'a str,
    pub dns_domain_name: &'a str,
    pub dns_computer_name: &'a str,
    /// Windows FILETIME (100-ns intervals since 1601-01-01), supplied by the
    /// caller.
    pub timestamp: u64,
    /// Negotiated flags (already AND-ed with server policy).
    pub flags: u32,
}

/// Build a Type 2 CHALLENGE_MESSAGE.
///
/// Layout (MS-NLMP §2.2.1.2):
/// ```text
/// 0  : "NTLMSSP\0"
/// 8  : MessageType = 0x02
/// 12 : TargetNameFields (8 bytes)
/// 20 : NegotiateFlags (4 bytes)
/// 24 : ServerChallenge (8 bytes)
/// 32 : Reserved (8 bytes, zeroed)
/// 40 : TargetInfoFields (8 bytes)
/// 48 : Version (8 bytes)
/// 56 : Payload...
/// ```
pub fn build_challenge(p: &ChallengeParams<'_>) -> Vec<u8> {
    let target_name_utf16 = utf16le(p.target_name);
    let av_pairs = vec![
        AvPair::new(AvId::NbDomainName, utf16le(p.nb_domain_name)),
        AvPair::new(AvId::NbComputerName, utf16le(p.nb_computer_name)),
        AvPair::new(AvId::DnsDomainName, utf16le(p.dns_domain_name)),
        AvPair::new(AvId::DnsComputerName, utf16le(p.dns_computer_name)),
        AvPair::new(AvId::Timestamp, p.timestamp.to_le_bytes().to_vec()),
    ];
    let target_info = encode_av_pairs(&av_pairs);

    let header_len: u32 = 56;
    let target_name_offset = header_len;
    let target_info_offset = target_name_offset + target_name_utf16.len() as u32;

    let mut out =
        Vec::with_capacity(header_len as usize + target_name_utf16.len() + target_info.len());
    // 0..8: signature
    out.extend_from_slice(NTLMSSP_SIGNATURE);
    // 8..12: message type
    out.extend_from_slice(&MSG_CHALLENGE.to_le_bytes());
    // 12..20: TargetNameFields
    let tn_len = target_name_utf16.len() as u16;
    out.extend_from_slice(&tn_len.to_le_bytes());
    out.extend_from_slice(&tn_len.to_le_bytes());
    out.extend_from_slice(&target_name_offset.to_le_bytes());
    // 20..24: NegotiateFlags
    out.extend_from_slice(&p.flags.to_le_bytes());
    // 24..32: ServerChallenge
    out.extend_from_slice(&p.server_challenge);
    // 32..40: Reserved
    out.extend_from_slice(&[0u8; 8]);
    // 40..48: TargetInfoFields
    let ti_len = target_info.len() as u16;
    out.extend_from_slice(&ti_len.to_le_bytes());
    out.extend_from_slice(&ti_len.to_le_bytes());
    out.extend_from_slice(&target_info_offset.to_le_bytes());
    // 48..56: Version 6.1 build 7424, NTLMSSP revision 15. MS-NLMP only reads
    // it when NTLMSSP_NEGOTIATE_VERSION is set.
    out.extend_from_slice(&[6, 1, 0, 0x1D, 0, 0, 0, 0x0F]);
    // payload
    out.extend_from_slice(&target_name_utf16);
    out.extend_from_slice(&target_info);
    out
}

// --- AUTHENTICATE_MESSAGE (Type 3) ------------------------------------------

#[derive(Debug, Clone)]
pub struct NtlmAuthenticate {
    pub flags: u32,
    #[allow(dead_code)]
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
    pub domain: String,
    pub user: String,
    #[allow(dead_code)]
    pub workstation: String,
    pub encrypted_random_session_key: Vec<u8>,
    /// Optional MIC (16 bytes, zeroed in source bytes during the MIC HMAC).
    pub mic: Option<[u8; 16]>,
    /// Offset of the MIC field within `raw`, if present (for re-zero during validation).
    pub mic_offset: Option<usize>,
    /// Raw bytes of the original message - needed for MIC computation.
    pub raw: Vec<u8>,
}

impl NtlmAuthenticate {
    /// Parse a Type 3 AUTHENTICATE_MESSAGE.
    ///
    /// Layout (MS-NLMP §2.2.1.3):
    /// ```text
    /// 0  : "NTLMSSP\0"
    /// 8  : MessageType = 0x03
    /// 12 : LmChallengeResponseFields
    /// 20 : NtChallengeResponseFields
    /// 28 : DomainNameFields
    /// 36 : UserNameFields
    /// 44 : WorkstationFields
    /// 52 : EncryptedRandomSessionKeyFields
    /// 60 : NegotiateFlags (4 bytes)
    /// 64 : Version (8 bytes)
    /// 72 : MIC (16 bytes - present only in some versions)
    /// 88 : Payload...
    /// ```
    /// The MIC is present when the AV_PAIR list of the NTLMv2 response has
    /// an `MsvAvFlags` entry with bit 0x2 set (MS-NLMP 3.2.5.1.2); bytes
    /// 72..88 are then read as the MIC.
    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        check_signature(buf, MSG_AUTHENTICATE)?;
        if buf.len() < 64 {
            return Err(ProtoError::Auth("AUTHENTICATE_MESSAGE too short"));
        }
        let lm_field = read_field(buf, 12)?;
        let nt_field = read_field(buf, 20)?;
        let domain_field = read_field(buf, 28)?;
        let user_field = read_field(buf, 36)?;
        let ws_field = read_field(buf, 44)?;
        let key_field = read_field(buf, 52)?;
        let flags = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]);

        let lm_response = if lm_field.len == 0 {
            Vec::new()
        } else {
            slice_field(buf, lm_field)?.to_vec()
        };
        let nt_response = if nt_field.len == 0 {
            Vec::new()
        } else {
            slice_field(buf, nt_field)?.to_vec()
        };
        let domain_bytes = if domain_field.len == 0 {
            Vec::new()
        } else {
            slice_field(buf, domain_field)?.to_vec()
        };
        let user_bytes = if user_field.len == 0 {
            Vec::new()
        } else {
            slice_field(buf, user_field)?.to_vec()
        };
        let (mic, mic_offset) = if ntlmv2_av_flags(&nt_response) & MSV_AV_FLAG_MIC != 0 {
            let field = buf
                .get(MIC_OFFSET..MIC_OFFSET + 16)
                .ok_or(ProtoError::Auth("MIC field missing"))?;
            let mut mic = [0u8; 16];
            mic.copy_from_slice(field);
            (Some(mic), Some(MIC_OFFSET))
        } else {
            (None, None)
        };
        let ws_bytes = if ws_field.len == 0 {
            Vec::new()
        } else {
            slice_field(buf, ws_field)?.to_vec()
        };
        let encrypted_random_session_key = if key_field.len == 0 {
            Vec::new()
        } else {
            slice_field(buf, key_field)?.to_vec()
        };

        // The server advertises only NTLMSSP_NEGOTIATE_UNICODE, so names are UTF-16LE.
        let domain = utf16le_to_string(&domain_bytes);
        let user = utf16le_to_string(&user_bytes);
        let workstation = utf16le_to_string(&ws_bytes);

        Ok(Self {
            flags,
            lm_response,
            nt_response,
            domain,
            user,
            workstation,
            encrypted_random_session_key,
            mic,
            mic_offset,
            raw: buf.to_vec(),
        })
    }
}

/// Offset of the MIC field in an AUTHENTICATE_MESSAGE.
const MIC_OFFSET: usize = 72;

/// `MsvAvFlags` bit 0x2: the AUTHENTICATE_MESSAGE carries a MIC.
const MSV_AV_FLAG_MIC: u32 = 0x0000_0002;

/// Offset of the AV_PAIR list in an NTLMv2 response: NTProofStr (16) and
/// the NTLMv2_CLIENT_CHALLENGE header up to AvPairs (28).
const NTLMV2_AV_PAIRS_OFFSET: usize = 44;

/// `MsvAvFlags` from the AV_PAIR list of an NTLMv2 response, or 0 when the
/// response has no such entry or no parseable list.
fn ntlmv2_av_flags(nt_response: &[u8]) -> u32 {
    let Some(list) = nt_response.get(NTLMV2_AV_PAIRS_OFFSET..) else {
        return 0;
    };
    let Ok(pairs) = decode_av_pairs(list) else {
        return 0;
    };
    pairs
        .iter()
        .find(|p| p.id == AvId::Flags as u16)
        .and_then(|p| p.value.get(..4))
        .map_or(0, |v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

/// RC4K(key, data) from MS-NLMP 6.
fn rc4k(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let mut out = *data;
    Rc4::new_from_slice(key)
        .expect("RC4 accepts a 16-byte key")
        .apply_keystream(&mut out);
    out
}

fn md5_concat(key: &[u8], constant: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(key);
    h.update(constant);
    h.finalize().into()
}

/// Which side's keys an [`NtlmMac`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// NTLM message integrity for one direction, with extended session security
/// (MS-NLMP 3.4.4.2). Keys come from SIGNKEY and SEALKEY (3.4.5.2, 3.4.5.3).
pub struct NtlmMac {
    signing_key: [u8; 16],
    /// RC4 state over the sealing key. The checksum is encrypted with it
    /// when NTLMSSP_NEGOTIATE_KEY_EXCH is negotiated.
    handle: Option<Rc4>,
    seq: u32,
}

impl NtlmMac {
    /// Integrity state for `direction`, or `None` when the flags do not
    /// negotiate both extended session security and signing or sealing.
    pub fn new(flags: u32, exported_session_key: &[u8; 16], direction: Direction) -> Option<Self> {
        if flags & flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY == 0
            || flags & (flags::NTLMSSP_NEGOTIATE_SIGN | flags::NTLMSSP_NEGOTIATE_SEAL) == 0
        {
            return None;
        }
        let (sign_magic, seal_magic): (&[u8], &[u8]) = match direction {
            Direction::ClientToServer => (
                b"session key to client-to-server signing key magic constant\0",
                b"session key to client-to-server sealing key magic constant\0",
            ),
            Direction::ServerToClient => (
                b"session key to server-to-client signing key magic constant\0",
                b"session key to server-to-client sealing key magic constant\0",
            ),
        };
        let seal_len = if flags & flags::NTLMSSP_NEGOTIATE_128 != 0 {
            16
        } else if flags & flags::NTLMSSP_NEGOTIATE_56 != 0 {
            7
        } else {
            5
        };
        let sealing_key = md5_concat(&exported_session_key[..seal_len], seal_magic);
        let handle = (flags & flags::NTLMSSP_NEGOTIATE_KEY_EXCH != 0)
            .then(|| Rc4::new_from_slice(&sealing_key).expect("RC4 accepts a 16-byte key"));
        Some(Self {
            signing_key: md5_concat(exported_session_key, sign_magic),
            handle,
            seq: 0,
        })
    }

    /// NTLMSSP_MESSAGE_SIGNATURE of `message` at the next sequence number.
    pub fn mac(&mut self, message: &[u8]) -> [u8; 16] {
        let mut hmac = HmacMd5::new_from_slice(&self.signing_key).expect("hmac key");
        hmac.update(&self.seq.to_le_bytes());
        hmac.update(message);
        let digest = hmac.finalize().into_bytes();
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&digest[..8]);
        if let Some(handle) = self.handle.as_mut() {
            handle.apply_keystream(&mut checksum);
        }
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&1u32.to_le_bytes());
        out[4..12].copy_from_slice(&checksum);
        out[12..].copy_from_slice(&self.seq.to_le_bytes());
        self.seq = self.seq.wrapping_add(1);
        out
    }

    /// Checks `signature` against the MAC of `message`, in constant time.
    pub fn verify(&mut self, message: &[u8], signature: &[u8]) -> bool {
        ct_eq_16(&self.mac(message), signature)
    }
}

// --- Public state machine ---------------------------------------------------

/// Identity recovered from a successful (or anonymous) authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Anonymous,
    User { user: String, domain: String },
}

/// Successful authentication outcome: identity + 16-byte session key.
#[derive(Clone)]
pub struct AuthOutcome {
    pub identity: Identity,
    /// ExportedSessionKey (MS-NLMP 3.2.5.1.2).
    pub session_key: [u8; 16],
    /// NegotiateFlags of the AUTHENTICATE_MESSAGE.
    pub flags: u32,
    /// The AUTHENTICATE_MESSAGE carried a MIC that matched.
    pub mic_present: bool,
}

impl std::fmt::Debug for AuthOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthOutcome")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// User record holding only the NT hash.
#[derive(Clone)]
pub struct UserCreds {
    pub nt_hash: [u8; 16],
}

impl std::fmt::Debug for UserCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserCreds").finish_non_exhaustive()
    }
}

impl UserCreds {
    /// Derive the NT hash from a plaintext password (UTF-16LE then MD4).
    pub fn from_password(password: &str) -> Self {
        Self {
            nt_hash: nt_hash(password),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NtlmTargetInfo {
    pub target_name: String,
    pub nb_domain: String,
    pub nb_computer: String,
    pub dns_domain: String,
    pub dns_computer: String,
}

impl NtlmTargetInfo {
    pub fn new(
        target_name: impl Into<String>,
        nb_domain: impl Into<String>,
        nb_computer: impl Into<String>,
        dns_domain: impl Into<String>,
        dns_computer: impl Into<String>,
    ) -> Self {
        Self {
            target_name: target_name.into(),
            nb_domain: nb_domain.into(),
            nb_computer: nb_computer.into(),
            dns_domain: dns_domain.into(),
            dns_computer: dns_computer.into(),
        }
    }
}

/// Server-side state machine driving SESSION_SETUP for a single connection.
///
/// Lifecycle:
/// 1. `NtlmServer::new(...)`
/// 2. `step1_negotiate(blob)` - record the client's NEGOTIATE bytes (for MIC).
/// 3. `challenge()` - produce CHALLENGE_MESSAGE bytes; record them too.
/// 4. `authenticate(blob, lookup)` - validate AUTHENTICATE; return outcome.
pub struct NtlmServer {
    server_challenge: [u8; 8],
    target_name: String,
    nb_domain: String,
    nb_computer: String,
    dns_domain: String,
    dns_computer: String,
    timestamp: u64,
    /// Flags we will advertise in the CHALLENGE.
    server_flags: u32,
    /// Negotiated flags after considering the client's NEGOTIATE.
    negotiated_flags: u32,

    /// Bytes of the client NEGOTIATE_MESSAGE (for MIC HMAC over N||C||A).
    negotiate_bytes: Vec<u8>,
    /// Bytes of the server CHALLENGE_MESSAGE (for MIC HMAC).
    challenge_bytes: Vec<u8>,

    /// DER MechTypeList of the client's SPNEGO NegTokenInit, which the
    /// mechListMIC covers. `None` when the client sent raw NTLMSSP.
    pub mech_list: Option<Vec<u8>>,
    /// NTLM was not the client's preferred mechanism, so both sides must
    /// send a mechListMIC (RFC 4178 section 5).
    pub mech_list_mic_required: bool,
}

impl NtlmServer {
    /// Create a new server-side acceptor.
    pub fn new(server_challenge: [u8; 8], target: NtlmTargetInfo, timestamp: u64) -> Self {
        // Flags the server offers.
        let server_flags = flags::NTLMSSP_NEGOTIATE_UNICODE
            | flags::NTLMSSP_REQUEST_TARGET
            | flags::NTLMSSP_NEGOTIATE_NTLM
            | flags::NTLMSSP_NEGOTIATE_SIGN
            | flags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | flags::NTLMSSP_TARGET_TYPE_SERVER
            | flags::NTLMSSP_NEGOTIATE_TARGET_INFO
            | flags::NTLMSSP_NEGOTIATE_VERSION
            | flags::NTLMSSP_NEGOTIATE_128
            | flags::NTLMSSP_NEGOTIATE_KEY_EXCH
            | flags::NTLMSSP_NEGOTIATE_56;

        Self {
            server_challenge,
            target_name: target.target_name,
            nb_domain: target.nb_domain,
            nb_computer: target.nb_computer,
            dns_domain: target.dns_domain,
            dns_computer: target.dns_computer,
            timestamp,
            server_flags,
            negotiated_flags: server_flags,
            negotiate_bytes: Vec::new(),
            challenge_bytes: Vec::new(),
            mech_list: None,
            mech_list_mic_required: false,
        }
    }

    /// True once the client's NEGOTIATE_MESSAGE has been processed.
    pub fn has_negotiate(&self) -> bool {
        !self.negotiate_bytes.is_empty()
    }

    /// Record the client's NEGOTIATE_MESSAGE bytes and intersect flags.
    /// This must be called before `challenge()` if a MIC will be validated.
    pub fn step1_negotiate(&mut self, blob: &[u8]) -> ProtoResult<NtlmNegotiate> {
        let n = NtlmNegotiate::parse(blob)?;
        // Negotiate down: only keep flags both sides set, then keep our must-have ones.
        self.negotiated_flags = (self.server_flags & n.flags)
            | flags::NTLMSSP_NEGOTIATE_TARGET_INFO
            | flags::NTLMSSP_TARGET_TYPE_SERVER
            | flags::NTLMSSP_NEGOTIATE_UNICODE;
        self.negotiate_bytes = n.raw.clone();
        Ok(n)
    }

    /// Build the CHALLENGE_MESSAGE blob. Stores the bytes for later MIC use.
    pub fn challenge(&mut self) -> Vec<u8> {
        let blob = build_challenge(&ChallengeParams {
            server_challenge: self.server_challenge,
            target_name: &self.target_name,
            nb_domain_name: &self.nb_domain,
            nb_computer_name: &self.nb_computer,
            dns_domain_name: &self.dns_domain,
            dns_computer_name: &self.dns_computer,
            timestamp: self.timestamp,
            flags: self.negotiated_flags,
        });
        self.challenge_bytes = blob.clone();
        blob
    }

    /// Validate the AUTHENTICATE_MESSAGE.
    ///
    /// `lookup` is the application's user-database hook: given the user/domain
    /// from the wire, return `Some(UserCreds)` if known, `None` otherwise. An
    /// unknown user goes through the same computation as a wrong password.
    ///
    /// Returns `AuthOutcome::session_key` to be plugged into SMB2 KDF.
    /// Anonymous logon (empty user, empty NT response, and an empty or
    /// single zero byte LM response) returns a zeroed key and
    /// `Identity::Anonymous`.
    pub fn authenticate<F>(&self, blob: &[u8], lookup: F) -> ProtoResult<AuthOutcome>
    where
        F: Fn(&str, &str) -> Option<UserCreds>,
    {
        let auth = NtlmAuthenticate::parse(blob)?;

        // ---- Anonymous (MS-NLMP 3.2.5.1.2 NullSession).
        if auth.user.is_empty()
            && auth.nt_response.is_empty()
            && (auth.lm_response.is_empty() || auth.lm_response == [0])
        {
            return Ok(AuthOutcome {
                identity: Identity::Anonymous,
                session_key: [0u8; 16],
                flags: auth.flags,
                mic_present: false,
            });
        }

        // ---- Locate creds. An unknown user is checked against a fixed hash
        // so that it takes as long as a wrong password.
        let creds = lookup(&auth.user, &auth.domain);
        let known_user = creds.is_some();
        let nt_hash = creds.map_or([0u8; 16], |c| c.nt_hash);

        // ---- NTOWFv2 = HMAC_MD5(NT_hash, UTF-16LE(UPPER(user) || domain))
        let response_key_nt = ntowf_v2(&nt_hash, &auth.user, &auth.domain);

        // ---- NTLMv2 response layout (MS-NLMP §2.2.2.8):
        //   16 bytes NTProofStr || NTLMv2_CLIENT_CHALLENGE blob
        if auth.nt_response.len() < 16 {
            return Err(ProtoError::Auth("NT response too short"));
        }
        let (nt_proof_supplied, client_challenge) = auth.nt_response.split_at(16);

        // ---- NTProofStr = HMAC_MD5(response_key_nt, ServerChallenge || ClientChallenge)
        let mut mac = HmacMd5::new_from_slice(&response_key_nt).expect("hmac key");
        mac.update(&self.server_challenge);
        mac.update(client_challenge);
        let nt_proof_computed = mac.finalize().into_bytes();

        let proof_ok = ct_eq_16(nt_proof_supplied, &nt_proof_computed);
        if !(proof_ok && known_user) {
            return Err(ProtoError::Auth("NT proof mismatch"));
        }

        // ---- SessionBaseKey = HMAC_MD5(response_key_nt, NTProofStr)
        // (MS-NLMP §3.4 - for NTLMv2, KeyExchangeKey = SessionBaseKey.)
        let mut mac = HmacMd5::new_from_slice(&response_key_nt).expect("hmac key");
        mac.update(&nt_proof_computed);
        let session_base_key_bytes = mac.finalize().into_bytes();
        let mut key_exchange_key = [0u8; 16];
        key_exchange_key.copy_from_slice(&session_base_key_bytes);

        // ---- ExportedSessionKey. KEY_EXCH requires a 16-byte
        // EncryptedRandomSessionKey; it is RC4-unwrapped only when signing
        // or sealing is negotiated too.
        let session_key = if auth.flags & flags::NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
            let encrypted: [u8; 16] = auth
                .encrypted_random_session_key
                .as_slice()
                .try_into()
                .map_err(|_| ProtoError::Auth("encrypted session key not 16 bytes"))?;
            if auth.flags & (flags::NTLMSSP_NEGOTIATE_SIGN | flags::NTLMSSP_NEGOTIATE_SEAL) != 0 {
                rc4k(&key_exchange_key, &encrypted)
            } else {
                key_exchange_key
            }
        } else {
            key_exchange_key
        };

        // ---- MIC: HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE ||
        // AUTHENTICATE with the MIC zeroed), required when MsvAvFlags says
        // the message carries one.
        if let (Some(mic_off), Some(supplied)) = (auth.mic_offset, auth.mic) {
            let mut auth_zeroed = auth.raw.clone();
            auth_zeroed[mic_off..mic_off + 16].fill(0);
            let mut mac = HmacMd5::new_from_slice(&session_key).expect("hmac key");
            mac.update(&self.negotiate_bytes);
            mac.update(&self.challenge_bytes);
            mac.update(&auth_zeroed);
            let computed = mac.finalize().into_bytes();
            if !ct_eq_16(&supplied, &computed) {
                return Err(ProtoError::Auth("MIC mismatch"));
            }
        }

        Ok(AuthOutcome {
            identity: Identity::User {
                user: auth.user.clone(),
                domain: auth.domain.clone(),
            },
            session_key,
            flags: auth.flags,
            mic_present: auth.mic.is_some(),
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn av_pair_round_trip() {
        let pairs = vec![
            AvPair::new(AvId::NbDomainName, utf16le("DOMAIN")),
            AvPair::new(AvId::NbComputerName, utf16le("SERVER")),
            AvPair::new(
                AvId::Timestamp,
                0x1234_5678_9abc_def0u64.to_le_bytes().to_vec(),
            ),
        ];
        let bytes = encode_av_pairs(&pairs);
        let decoded = decode_av_pairs(&bytes).unwrap();
        assert_eq!(decoded, pairs);
    }

    #[test]
    fn negotiate_round_trip() {
        // Build a minimal Type 1 by hand and parse it.
        let mut buf = Vec::new();
        buf.extend_from_slice(NTLMSSP_SIGNATURE);
        buf.extend_from_slice(&MSG_NEGOTIATE.to_le_bytes());
        let flags = flags::NTLMSSP_NEGOTIATE_UNICODE
            | flags::NTLMSSP_NEGOTIATE_NTLM
            | flags::NTLMSSP_NEGOTIATE_TARGET_INFO;
        buf.extend_from_slice(&flags.to_le_bytes());
        // Domain + workstation fields: empty.
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&[0u8; 8]);
        // Version (8 bytes).
        buf.extend_from_slice(&[0u8; 8]);

        let n = NtlmNegotiate::parse(&buf).unwrap();
        assert_eq!(n.flags, flags);
    }

    #[test]
    fn challenge_round_trip_structure() {
        let blob = build_challenge(&ChallengeParams {
            server_challenge: [1, 2, 3, 4, 5, 6, 7, 8],
            target_name: "SERVER",
            nb_domain_name: "DOMAIN",
            nb_computer_name: "SERVER",
            dns_domain_name: "domain.local",
            dns_computer_name: "server.domain.local",
            timestamp: 0,
            flags: flags::NTLMSSP_NEGOTIATE_UNICODE
                | flags::NTLMSSP_NEGOTIATE_NTLM
                | flags::NTLMSSP_NEGOTIATE_TARGET_INFO,
        });
        // Signature + message type.
        assert_eq!(&blob[..8], NTLMSSP_SIGNATURE);
        assert_eq!(
            u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]),
            MSG_CHALLENGE
        );
        // Server challenge at offset 24.
        assert_eq!(&blob[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // Decode AV_PAIRs from the target-info section.
        let ti_off = u32::from_le_bytes([blob[44], blob[45], blob[46], blob[47]]) as usize;
        let ti_len = u16::from_le_bytes([blob[40], blob[41]]) as usize;
        let av = decode_av_pairs(&blob[ti_off..ti_off + ti_len]).unwrap();
        assert!(av.iter().any(|p| p.id == AvId::NbDomainName as u16));
        assert!(av.iter().any(|p| p.id == AvId::Timestamp as u16));
    }

    /// MS-NLMP §4.2.4 known-answer test for NTLMv2:
    ///     User="User", Domain="Domain", Password="Password"
    ///     ServerChallenge = 01 23 45 67 89 ab cd ef
    ///     ClientChallenge AV-pair blob = 01 01 00 00 00 00 00 00
    ///                                    00 00 00 00 00 00 00 00
    ///                                    aa aa aa aa aa aa aa aa
    ///                                    00 00 00 00 02 00 0c 00
    ///                                    44 00 6f 00 6d 00 61 00
    ///                                    69 00 6e 00 01 00 0c 00
    ///                                    53 00 65 00 72 00 76 00
    ///                                    65 00 72 00 00 00 00 00
    ///                                    00 00 00 00
    /// Expected NTProofStr = 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c
    #[test]
    fn ntlmv2_known_answer() {
        let nt = nt_hash("Password");
        // NT hash of "Password" - MS-NLMP §4.2.2.1.4: a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52
        assert_eq!(
            nt,
            [
                0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f,
                0xd8, 0x52
            ]
        );

        // NTOWFv2("Password","User","Domain")
        // MS-NLMP §4.2.4.1.1: 0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f
        let key_nt = ntowf_v2(&nt, "User", "Domain");
        assert_eq!(
            key_nt,
            [
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
                0x2e, 0x3f
            ]
        );

        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        // NTLMv2_CLIENT_CHALLENGE blob from §4.2.4.1.3
        let client_challenge_blob: &[u8] = &[
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RespType, HiRespType, Reserved
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TimeStamp
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // ChallengeFromClient
            0x00, 0x00, 0x00, 0x00, // Reserved
            // AV pairs
            0x02, 0x00, 0x0c, 0x00, // MsvAvNbDomainName, len=12
            0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e,
            0x00, // "Domain"
            0x01, 0x00, 0x0c, 0x00, // MsvAvNbComputerName, len=12
            0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72,
            0x00, // "Server"
            0x00, 0x00, 0x00, 0x00, // EOL
            0x00, 0x00, 0x00, 0x00, // trailing 4 zero bytes (padding seen in spec)
        ];

        let mut mac = HmacMd5::new_from_slice(&key_nt).unwrap();
        mac.update(&server_challenge);
        mac.update(client_challenge_blob);
        let nt_proof = mac.finalize().into_bytes();

        // MS-NLMP §4.2.4.2.2:
        //   NTProofStr = 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c
        assert_eq!(
            nt_proof.as_slice(),
            [
                0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef,
                0x6a, 0x1c
            ]
        );
    }

    #[test]
    fn server_round_trip_authenticates_user() {
        // End-to-end: build a fake AUTHENTICATE_MESSAGE with a known proof and
        // make sure NtlmServer accepts it.
        let mut srv = NtlmServer::new(
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            NtlmTargetInfo::new(
                "SERVER",
                "DOMAIN",
                "SERVER",
                "domain.local",
                "server.domain.local",
            ),
            0,
        );
        // Skip step1_negotiate - MIC will be absent.
        let _challenge = srv.challenge();

        // Compute NTProofStr the same way the client would.
        let nt = nt_hash("Password");
        let key_nt = ntowf_v2(&nt, "User", "Domain");
        let client_challenge_blob: Vec<u8> = vec![
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
            // Empty AV pair list (EOL only)
            0x00, 0x00, 0x00, 0x00,
        ];
        let mut mac = HmacMd5::new_from_slice(&key_nt).unwrap();
        mac.update(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        mac.update(&client_challenge_blob);
        let nt_proof = mac.finalize().into_bytes();

        let mut nt_response = Vec::new();
        nt_response.extend_from_slice(&nt_proof);
        nt_response.extend_from_slice(&client_challenge_blob);

        // Build AUTHENTICATE_MESSAGE.
        let user_u16 = utf16le("User");
        let dom_u16 = utf16le("Domain");
        let ws_u16 = utf16le("CLIENT");
        let lm_response: Vec<u8> = vec![0u8; 24];

        // Layout: header is 72 bytes when no MIC is present
        // (signature 8 + msgtype 4 + 6x8-byte fields + flags 4 + version 8 = 72).
        // With MIC, it would be 88.
        let header_len: u32 = 72;
        let mut payload = Vec::new();
        let lm_off = header_len;
        payload.extend_from_slice(&lm_response);
        let nt_off = header_len + payload.len() as u32;
        payload.extend_from_slice(&nt_response);
        let dom_off = header_len + payload.len() as u32;
        payload.extend_from_slice(&dom_u16);
        let user_off = header_len + payload.len() as u32;
        payload.extend_from_slice(&user_u16);
        let ws_off = header_len + payload.len() as u32;
        payload.extend_from_slice(&ws_u16);
        let key_off = header_len + payload.len() as u32;
        // No encrypted session key.

        let mut buf = Vec::new();
        buf.extend_from_slice(NTLMSSP_SIGNATURE);
        buf.extend_from_slice(&MSG_AUTHENTICATE.to_le_bytes());
        // Lm
        buf.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&lm_off.to_le_bytes());
        // Nt
        buf.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&nt_off.to_le_bytes());
        // Domain
        buf.extend_from_slice(&(dom_u16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(dom_u16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&dom_off.to_le_bytes());
        // User
        buf.extend_from_slice(&(user_u16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(user_u16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&user_off.to_le_bytes());
        // Workstation
        buf.extend_from_slice(&(ws_u16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(ws_u16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&ws_off.to_le_bytes());
        // EncryptedRandomSessionKey
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&key_off.to_le_bytes());
        // Flags
        buf.extend_from_slice(&flags::NTLMSSP_NEGOTIATE_UNICODE.to_le_bytes());
        // Version (8 bytes)
        buf.extend_from_slice(&[0u8; 8]);
        // No MIC: header is 72 bytes.
        assert_eq!(buf.len() as u32, header_len);
        buf.extend_from_slice(&payload);

        let creds = UserCreds::from_password("Password");
        let outcome = srv
            .authenticate(&buf, |u, d| {
                if u == "User" && d == "Domain" {
                    Some(creds.clone())
                } else {
                    None
                }
            })
            .expect("auth should succeed");

        assert_eq!(
            outcome.identity,
            Identity::User {
                user: "User".to_string(),
                domain: "Domain".to_string()
            }
        );

        // Wrong password fails.
        let bad = UserCreds::from_password("WrongPassword");
        let err = srv
            .authenticate(&buf, |_u, _d| Some(bad.clone()))
            .unwrap_err();
        assert!(matches!(err, ProtoError::Auth(_)));
    }

    #[test]
    fn debug_output_hides_keys() {
        let creds = UserCreds {
            nt_hash: [0xAB; 16],
        };
        assert_eq!(format!("{creds:?}"), "UserCreds { .. }");
        let outcome = AuthOutcome {
            identity: Identity::Anonymous,
            session_key: [0xCD; 16],
            flags: 0,
            mic_present: false,
        };
        let shown = format!("{outcome:?}");
        assert_eq!(shown, "AuthOutcome { identity: Anonymous, .. }");
    }

    #[test]
    fn anonymous_logon() {
        let mut srv = NtlmServer::new(
            [0u8; 8],
            NtlmTargetInfo::new("SERVER", "DOMAIN", "SERVER", "d.local", "s.d.local"),
            0,
        );
        let _ = srv.challenge();

        // Build an AUTHENTICATE_MESSAGE with empty user + empty NT response.
        let header_len: u32 = 72;
        let mut buf = Vec::new();
        buf.extend_from_slice(NTLMSSP_SIGNATURE);
        buf.extend_from_slice(&MSG_AUTHENTICATE.to_le_bytes());
        for _ in 0..6 {
            // 6 empty fields (Lm, Nt, Domain, User, Workstation, Key)
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&header_len.to_le_bytes());
        }
        buf.extend_from_slice(&flags::NTLMSSP_NEGOTIATE_ANONYMOUS.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]); // version

        let outcome = srv
            .authenticate(&buf, |_u, _d| None)
            .expect("anonymous should succeed");
        assert_eq!(outcome.identity, Identity::Anonymous);
        assert_eq!(outcome.session_key, [0u8; 16]);
    }

    fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
        let mut mac = HmacMd5::new_from_slice(key).unwrap();
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    /// Fields of a hand-built AUTHENTICATE_MESSAGE.
    struct AuthMsg<'a> {
        user: &'a str,
        password: &'a str,
        flags: u32,
        /// `MsvAvFlags` value to put in the NTLMv2 response.
        av_flags: Option<u32>,
        /// Leave room for a MIC at offset 72.
        mic_field: bool,
        lm: &'a [u8],
        nt: Option<&'a [u8]>,
        encrypted_key: &'a [u8],
    }

    impl Default for AuthMsg<'_> {
        fn default() -> Self {
            Self {
                user: "User",
                password: "Password",
                flags: flags::NTLMSSP_NEGOTIATE_UNICODE,
                av_flags: None,
                mic_field: false,
                lm: &[],
                nt: None,
                encrypted_key: &[],
            }
        }
    }

    const CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    fn server() -> NtlmServer {
        let mut srv = NtlmServer::new(
            CHALLENGE,
            NtlmTargetInfo::new("SERVER", "DOMAIN", "SERVER", "d.local", "s.d.local"),
            0,
        );
        let mut negotiate = NTLMSSP_SIGNATURE.to_vec();
        negotiate.extend_from_slice(&MSG_NEGOTIATE.to_le_bytes());
        negotiate.extend_from_slice(&0xE288_8235u32.to_le_bytes());
        negotiate.extend_from_slice(&[0u8; 16]);
        srv.step1_negotiate(&negotiate).unwrap();
        srv.challenge();
        srv
    }

    /// The message and the KeyExchangeKey the server derives from it.
    fn build_auth(m: &AuthMsg<'_>) -> (Vec<u8>, [u8; 16]) {
        let key_nt = ntowf_v2(&nt_hash(m.password), m.user, "");
        let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&[0; 8]);
        blob.extend_from_slice(&[0xAA; 8]);
        blob.extend_from_slice(&[0; 4]);
        if let Some(av) = m.av_flags {
            blob.extend_from_slice(&encode_av_pairs(&[AvPair::new(
                AvId::Flags,
                av.to_le_bytes().to_vec(),
            )]));
        } else {
            blob.extend_from_slice(&encode_av_pairs(&[]));
        }
        let proof = hmac_md5(&key_nt, &[&CHALLENGE, &blob]);
        let key_exchange_key = hmac_md5(&key_nt, &[&proof]);
        let nt =
            m.nt.map_or_else(|| [&proof[..], &blob].concat(), <[u8]>::to_vec);

        let user = utf16le(m.user);
        let fields: [&[u8]; 6] = [m.lm, &nt, &[], &user, &[], m.encrypted_key];
        let header_len = if m.mic_field { 88u32 } else { 72 };
        let mut msg = NTLMSSP_SIGNATURE.to_vec();
        msg.extend_from_slice(&MSG_AUTHENTICATE.to_le_bytes());
        let mut payload = Vec::new();
        for field in fields {
            let offset = header_len + payload.len() as u32;
            msg.extend_from_slice(&(field.len() as u16).to_le_bytes());
            msg.extend_from_slice(&(field.len() as u16).to_le_bytes());
            msg.extend_from_slice(&offset.to_le_bytes());
            payload.extend_from_slice(field);
        }
        msg.extend_from_slice(&m.flags.to_le_bytes());
        msg.extend_from_slice(&[0u8; 8]);
        if m.mic_field {
            msg.extend_from_slice(&[0u8; 16]);
        }
        msg.extend_from_slice(&payload);
        (msg, key_exchange_key)
    }

    fn sign_mic(srv: &NtlmServer, msg: &mut [u8], key: &[u8; 16]) {
        let mic = hmac_md5(key, &[&srv.negotiate_bytes, &srv.challenge_bytes, msg]);
        msg[72..88].copy_from_slice(&mic);
    }

    fn user_creds(u: &str, _d: &str) -> Option<UserCreds> {
        (u == "User").then(|| UserCreds::from_password("Password"))
    }

    #[test]
    fn mic_is_checked_when_msv_av_flags_announces_it() {
        let srv = server();
        let m = AuthMsg {
            av_flags: Some(MSV_AV_FLAG_MIC),
            mic_field: true,
            ..AuthMsg::default()
        };
        let (mut msg, key) = build_auth(&m);
        sign_mic(&srv, &mut msg, &key);
        let outcome = srv.authenticate(&msg, user_creds).expect("valid MIC");
        assert!(outcome.mic_present);

        msg[80] ^= 1;
        assert!(srv.authenticate(&msg, user_creds).is_err(), "bad MIC");

        // MsvAvFlags announces a MIC, but the header has no room for one.
        let m = AuthMsg {
            av_flags: Some(MSV_AV_FLAG_MIC),
            ..AuthMsg::default()
        };
        let (msg, _) = build_auth(&m);
        assert!(srv.authenticate(&msg, user_creds).is_err(), "stripped MIC");
    }

    #[test]
    fn padding_without_msv_av_flags_is_not_a_mic() {
        let srv = server();
        let m = AuthMsg {
            mic_field: true,
            ..AuthMsg::default()
        };
        let (msg, _) = build_auth(&m);
        let outcome = srv.authenticate(&msg, user_creds).expect("no MIC");
        assert!(!outcome.mic_present);
    }

    #[test]
    fn key_exch_needs_a_16_byte_session_key() {
        let srv = server();
        let flags = flags::NTLMSSP_NEGOTIATE_UNICODE
            | flags::NTLMSSP_NEGOTIATE_KEY_EXCH
            | flags::NTLMSSP_NEGOTIATE_SIGN;
        let m = AuthMsg {
            flags,
            ..AuthMsg::default()
        };
        let (msg, _) = build_auth(&m);
        assert!(srv.authenticate(&msg, user_creds).is_err(), "empty key");

        let random = [0x55u8; 16];
        let (_, kxkey) = build_auth(&m);
        let encrypted = rc4k(&kxkey, &random);
        let m = AuthMsg {
            flags,
            encrypted_key: &encrypted,
            ..AuthMsg::default()
        };
        let (msg, _) = build_auth(&m);
        let outcome = srv.authenticate(&msg, user_creds).expect("16-byte key");
        assert_eq!(outcome.session_key, random);

        // Without SIGN or SEAL the key is checked but not unwrapped.
        let m = AuthMsg {
            flags: flags::NTLMSSP_NEGOTIATE_UNICODE | flags::NTLMSSP_NEGOTIATE_KEY_EXCH,
            encrypted_key: &encrypted,
            ..AuthMsg::default()
        };
        let (msg, kxkey) = build_auth(&m);
        let outcome = srv.authenticate(&msg, user_creds).expect("no signing");
        assert_eq!(outcome.session_key, kxkey);
    }

    #[test]
    fn anonymous_needs_an_empty_or_zero_lm_response() {
        let srv = server();
        for lm in [&[][..], &[0u8][..]] {
            let m = AuthMsg {
                user: "",
                nt: Some(&[]),
                lm,
                ..AuthMsg::default()
            };
            let (msg, _) = build_auth(&m);
            let outcome = srv.authenticate(&msg, |_, _| None).expect("anonymous");
            assert_eq!(outcome.identity, Identity::Anonymous);
        }
        let m = AuthMsg {
            user: "",
            nt: Some(&[]),
            lm: &[0x11; 24],
            ..AuthMsg::default()
        };
        let (msg, _) = build_auth(&m);
        assert!(srv.authenticate(&msg, |_, _| None).is_err());
    }

    #[test]
    fn unknown_user_fails() {
        let srv = server();
        let m = AuthMsg {
            user: "Nobody",
            ..AuthMsg::default()
        };
        let (msg, _) = build_auth(&m);
        assert!(srv.authenticate(&msg, user_creds).is_err());
        // Even when the response was computed against the fixed hash.
        let m = AuthMsg {
            user: "Nobody",
            password: "",
            ..AuthMsg::default()
        };
        let (mut msg, _) = build_auth(&m);
        let key_nt = ntowf_v2(&[0u8; 16], "Nobody", "");
        let nt_off = u32::from_le_bytes(msg[24..28].try_into().unwrap()) as usize;
        let nt_len = u16::from_le_bytes(msg[20..22].try_into().unwrap()) as usize;
        let client_blob = msg[nt_off + 16..nt_off + nt_len].to_vec();
        let proof = hmac_md5(&key_nt, &[&CHALLENGE, &client_blob]);
        msg[nt_off..nt_off + 16].copy_from_slice(&proof);
        assert!(srv.authenticate(&msg, user_creds).is_err());
    }

    /// MS-NLMP 4.2.4.2.3: RC4(SessionBaseKey, RandomSessionKey).
    #[test]
    fn encrypted_session_key_known_answer() {
        let session_base_key = [
            0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9,
            0x5c, 0xa3,
        ];
        let encrypted = [
            0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90, 0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9,
            0xd0, 0x3e,
        ];
        assert_eq!(rc4k(&session_base_key, &encrypted), [0x55; 16]);
    }

    /// MS-NLMP 4.2.4.4: client sealing and signing keys, and the signature
    /// of "Plaintext" sealed and signed at sequence number 0.
    #[test]
    fn gss_wrap_ex_known_answer() {
        let flags = 0xE28A_8233;
        let mut mac = NtlmMac::new(flags, &[0x55; 16], Direction::ClientToServer).unwrap();
        assert_eq!(
            mac.signing_key,
            [
                0x47, 0x88, 0xdc, 0x86, 0x1b, 0x47, 0x82, 0xf3, 0x5d, 0x43, 0xfd, 0x98, 0xfe, 0x1a,
                0x2d, 0x39
            ]
        );
        let plaintext = utf16le("Plaintext");
        let mut sealed = plaintext.clone();
        mac.handle.as_mut().unwrap().apply_keystream(&mut sealed);
        assert_eq!(
            sealed,
            [
                0x54, 0xe5, 0x01, 0x65, 0xbf, 0x19, 0x36, 0xdc, 0x99, 0x60, 0x20, 0xc1, 0x81, 0x1b,
                0x0f, 0x06, 0xfb, 0x5f
            ]
        );
        assert_eq!(
            mac.mac(&plaintext),
            [
                0x01, 0x00, 0x00, 0x00, 0x7f, 0xb3, 0x8e, 0xc5, 0xc5, 0x5d, 0x49, 0x76, 0x00, 0x00,
                0x00, 0x00
            ]
        );
        assert_eq!(mac.seq, 1);
    }

    #[test]
    fn mac_needs_extended_session_security_and_signing() {
        let key = [0x55; 16];
        let ess = flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        let sign = flags::NTLMSSP_NEGOTIATE_SIGN;
        assert!(NtlmMac::new(sign, &key, Direction::ServerToClient).is_none());
        assert!(NtlmMac::new(ess, &key, Direction::ServerToClient).is_none());
        let mut mac = NtlmMac::new(ess | sign, &key, Direction::ServerToClient).unwrap();
        assert!(mac.handle.is_none());
        let sig = mac.mac(b"message");
        let expected = hmac_md5(
            &md5_concat(
                &key,
                b"session key to server-to-client signing key magic constant\0",
            ),
            &[&0u32.to_le_bytes(), b"message"],
        );
        assert_eq!(sig[4..12], expected[..8]);
    }
}
