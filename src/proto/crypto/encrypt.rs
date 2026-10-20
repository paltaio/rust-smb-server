//! SMB 3.x message encryption (MS-SMB2 2.2.41, 3.1.4.3).
//!
//! An encrypted message is an SMB2 TRANSFORM_HEADER followed by the
//! ciphertext of one SMB2 message or compound chain:
//!
//! ```text
//!  0  ProtocolId           0xFD 'S' 'M' 'B'
//!  4  Signature            16-byte AEAD tag
//! 20  Nonce                11 bytes (CCM) or 12 bytes (GCM), zero padded
//! 36  OriginalMessageSize  u32
//! 40  Reserved             u16
//! 42  Flags                u16, 0x0001 (encrypted)
//! 44  SessionId            u64
//! ```
//!
//! Bytes 20..52 are the additional authenticated data.

use std::sync::atomic::{AtomicU64, Ordering};

use aes::{Aes128, Aes256};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use ccm::Ccm;
use ccm::consts::{U11, U16};

use crate::proto::crypto::kdf::smb2_kdf_into;
use crate::proto::error::{ProtoError, ProtoResult};

type Aes128Ccm = Ccm<Aes128, U16, U11>;
type Aes256Ccm = Ccm<Aes256, U16, U11>;

/// Length of the SMB2 TRANSFORM_HEADER.
pub const TRANSFORM_HEADER_LEN: usize = 52;

/// ProtocolId of a TRANSFORM_HEADER.
pub const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xFD, b'S', b'M', b'B'];

const SIGNATURE: std::ops::Range<usize> = 4..20;
const NONCE: std::ops::Range<usize> = 20..36;
const AAD_START: usize = 20;
const FLAG_ENCRYPTED: u16 = 0x0001;

/// The ciphers of SMB2_ENCRYPTION_CAPABILITIES (MS-SMB2 2.2.3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Ccm,
    Aes128Gcm,
    Aes256Ccm,
    Aes256Gcm,
}

impl Cipher {
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(Self::Aes128Ccm),
            0x0002 => Some(Self::Aes128Gcm),
            0x0003 => Some(Self::Aes256Ccm),
            0x0004 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    pub fn id(self) -> u16 {
        match self {
            Self::Aes128Ccm => 0x0001,
            Self::Aes128Gcm => 0x0002,
            Self::Aes256Ccm => 0x0003,
            Self::Aes256Gcm => 0x0004,
        }
    }

    /// Key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes128Gcm => 16,
            Self::Aes256Ccm | Self::Aes256Gcm => 32,
        }
    }

    fn nonce_len(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes256Ccm => 11,
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
        }
    }
}

/// An AEAD keyed for one direction of a session.
enum Aead {
    Aes128Ccm(Box<Aes128Ccm>),
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Ccm(Box<Aes256Ccm>),
    Aes256Gcm(Box<Aes256Gcm>),
}

impl Aead {
    /// Panics unless `key` is `cipher.key_len()` bytes.
    fn new(cipher: Cipher, key: &[u8]) -> Self {
        const KEY_LEN: &str = "key length matches the cipher";
        match cipher {
            Cipher::Aes128Ccm => {
                Self::Aes128Ccm(Box::new(Aes128Ccm::new_from_slice(key).expect(KEY_LEN)))
            }
            Cipher::Aes128Gcm => {
                Self::Aes128Gcm(Box::new(Aes128Gcm::new_from_slice(key).expect(KEY_LEN)))
            }
            Cipher::Aes256Ccm => {
                Self::Aes256Ccm(Box::new(Aes256Ccm::new_from_slice(key).expect(KEY_LEN)))
            }
            Cipher::Aes256Gcm => {
                Self::Aes256Gcm(Box::new(Aes256Gcm::new_from_slice(key).expect(KEY_LEN)))
            }
        }
    }

    /// Encrypts `buf` in place and returns the tag. `nonce` is the
    /// cipher's nonce length.
    fn seal(&self, nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> Option<[u8; 16]> {
        let tag = match self {
            Self::Aes128Ccm(a) => a.encrypt_in_place_detached(nonce.into(), aad, buf),
            Self::Aes128Gcm(a) => a.encrypt_in_place_detached(nonce.into(), aad, buf),
            Self::Aes256Ccm(a) => a.encrypt_in_place_detached(nonce.into(), aad, buf),
            Self::Aes256Gcm(a) => a.encrypt_in_place_detached(nonce.into(), aad, buf),
        };
        tag.ok().map(Into::into)
    }

    /// Decrypts `buf` in place if `tag` matches.
    fn open(&self, nonce: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> bool {
        let tag = GenericArray::from_slice(tag);
        match self {
            Self::Aes128Ccm(a) => a.decrypt_in_place_detached(nonce.into(), aad, buf, tag),
            Self::Aes128Gcm(a) => a.decrypt_in_place_detached(nonce.into(), aad, buf, tag),
            Self::Aes256Ccm(a) => a.decrypt_in_place_detached(nonce.into(), aad, buf, tag),
            Self::Aes256Gcm(a) => a.decrypt_in_place_detached(nonce.into(), aad, buf, tag),
        }
        .is_ok()
    }
}

/// Whether `frame` starts with a TRANSFORM_HEADER ProtocolId.
pub fn is_transform(frame: &[u8]) -> bool {
    frame.starts_with(&TRANSFORM_PROTOCOL_ID)
}

/// SessionId of an encrypted message, or `None` when `frame` is too short
/// to hold a TRANSFORM_HEADER.
pub fn transform_session_id(frame: &[u8]) -> Option<u64> {
    let id = frame.get(44..TRANSFORM_HEADER_LEN)?;
    Some(u64::from_le_bytes(id.try_into().expect("8 bytes")))
}

/// A session's encryption and decryption keys (Session.EncryptionKey and
/// Session.DecryptionKey) and the counter its nonces come from.
pub struct SessionCipher {
    cipher: Cipher,
    encrypt: Aead,
    decrypt: Aead,
    next_nonce: AtomicU64,
}

impl SessionCipher {
    /// Panics unless both keys are `cipher.key_len()` bytes.
    pub fn new(cipher: Cipher, encryption_key: &[u8], decryption_key: &[u8]) -> Self {
        Self {
            cipher,
            encrypt: Aead::new(cipher, encryption_key),
            decrypt: Aead::new(cipher, decryption_key),
            next_nonce: AtomicU64::new(0),
        }
    }

    /// Derives the server's keys from `session_key` (MS-SMB2 3.3.5.5.3):
    /// with SMB 3.1.1's `preauth_hash`, or the SMB 3.0 labels without it.
    /// 256-bit ciphers take 32-byte keys.
    pub fn derive(cipher: Cipher, session_key: &[u8], preauth_hash: Option<&[u8; 64]>) -> Self {
        let len = cipher.key_len();
        let mut encryption_key = [0u8; 32];
        let mut decryption_key = [0u8; 32];
        let (out, into) = (&mut encryption_key[..len], &mut decryption_key[..len]);
        match preauth_hash {
            Some(hash) => {
                smb2_kdf_into(session_key, b"SMBS2CCipherKey\x00", hash, out);
                smb2_kdf_into(session_key, b"SMBC2SCipherKey\x00", hash, into);
            }
            None => {
                smb2_kdf_into(session_key, b"SMB2AESCCM\x00", b"ServerOut\x00", out);
                smb2_kdf_into(session_key, b"SMB2AESCCM\x00", b"ServerIn \x00", into);
            }
        }
        Self::new(cipher, &encryption_key[..len], &decryption_key[..len])
    }

    /// Encrypts `message` for `session_id` and returns the TRANSFORM_HEADER
    /// and ciphertext. Each call takes the next nonce of the session, so no
    /// nonce repeats under one key.
    pub fn encrypt(&self, session_id: u64, message: &[u8]) -> ProtoResult<Vec<u8>> {
        let size = u32::try_from(message.len())
            .map_err(|_| ProtoError::Crypto("message too large to encrypt"))?;
        let counter = self.next_nonce.fetch_add(1, Ordering::Relaxed);

        let mut out = Vec::with_capacity(TRANSFORM_HEADER_LEN + message.len());
        out.extend_from_slice(&TRANSFORM_PROTOCOL_ID);
        out.extend_from_slice(&[0; 16]);
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&FLAG_ENCRYPTED.to_le_bytes());
        out.extend_from_slice(&session_id.to_le_bytes());
        out.extend_from_slice(message);

        let (header, body) = out.split_at_mut(TRANSFORM_HEADER_LEN);
        let nonce = &header[NONCE][..self.cipher.nonce_len()];
        let tag = self
            .encrypt
            .seal(nonce, &header[AAD_START..], body)
            .ok_or(ProtoError::Crypto("encryption failed"))?;
        out[SIGNATURE].copy_from_slice(&tag);
        Ok(out)
    }

    /// Checks and decrypts an encrypted message, returning the SMB2
    /// message inside. The caller matches the SessionId to this session.
    pub fn decrypt(&self, frame: &[u8]) -> ProtoResult<Vec<u8>> {
        if frame.len() <= TRANSFORM_HEADER_LEN || !is_transform(frame) {
            return Err(ProtoError::Crypto("not an encrypted message"));
        }
        let (header, body) = frame.split_at(TRANSFORM_HEADER_LEN);
        let size = u32::from_le_bytes(header[36..40].try_into().expect("4 bytes"));
        if size as usize != body.len() {
            return Err(ProtoError::Crypto("OriginalMessageSize does not match"));
        }
        if u16::from_le_bytes([header[42], header[43]]) != FLAG_ENCRYPTED {
            return Err(ProtoError::Crypto("transform flags are not 0x0001"));
        }
        let mut message = body.to_vec();
        let nonce = &header[NONCE][..self.cipher.nonce_len()];
        if !self.decrypt.open(
            nonce,
            &header[AAD_START..],
            &mut message,
            &header[SIGNATURE],
        ) {
            return Err(ProtoError::Crypto("decryption failed"));
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CIPHERS: [Cipher; 4] = [
        Cipher::Aes128Ccm,
        Cipher::Aes128Gcm,
        Cipher::Aes256Ccm,
        Cipher::Aes256Gcm,
    ];

    /// Cipher pair for the two ends of a session: what one encrypts the
    /// other decrypts.
    fn pair(cipher: Cipher) -> (SessionCipher, SessionCipher) {
        let a = vec![0x11; cipher.key_len()];
        let b = vec![0x22; cipher.key_len()];
        (
            SessionCipher::new(cipher, &a, &b),
            SessionCipher::new(cipher, &b, &a),
        )
    }

    #[test]
    fn nonce_padding_is_zero() {
        for cipher in CIPHERS {
            let (server, _) = pair(cipher);
            for _ in 0..3 {
                let frame = server.encrypt(1, b"x").unwrap();
                assert!(frame[NONCE][cipher.nonce_len()..].iter().all(|&b| b == 0));
            }
        }
    }

    #[test]
    fn rejects_tampering() {
        for cipher in CIPHERS {
            let (server, client) = pair(cipher);
            let frame = server.encrypt(7, b"payload bytes").unwrap();
            // Tag, nonce, size, flags, session id and ciphertext.
            for at in [4, 20, 36, 42, 44, TRANSFORM_HEADER_LEN] {
                let mut bad = frame.clone();
                bad[at] ^= 0x01;
                assert!(client.decrypt(&bad).is_err(), "{cipher:?} byte {at}");
            }
            let mut short = frame.clone();
            short.pop();
            assert!(client.decrypt(&short).is_err());
            assert!(client.decrypt(&frame[..TRANSFORM_HEADER_LEN]).is_err());
        }
    }

    /// The server derives `server_out` to encrypt and `server_in` to
    /// decrypt from an all-zero session key: what it encrypts, a client
    /// holding those keys decrypts, and the other way round.
    fn derives(cipher: Cipher, preauth_hash: Option<&[u8; 64]>, server_out: &str, server_in: &str) {
        let server = SessionCipher::derive(cipher, &[0; 16], preauth_hash);
        let server_out = hex::decode(server_out).unwrap();
        let server_in = hex::decode(server_in).unwrap();
        let client = SessionCipher::new(cipher, &server_in, &server_out);
        let message = b"FE534D42 message";
        let sealed = server.encrypt(1, message).unwrap();
        assert_eq!(client.decrypt(&sealed).unwrap(), message, "{cipher:?} out");
        let sealed = client.encrypt(1, message).unwrap();
        assert_eq!(server.decrypt(&sealed).unwrap(), message, "{cipher:?} in");
    }

    /// Reference keys from Python:
    /// ```text
    /// def kdf(key, label, ctx, l):
    ///     data = b"\x00\x00\x00\x01" + label + b"\x00" + ctx + l.to_bytes(4, "big")
    ///     return hmac.new(key, data, hashlib.sha256).digest()[:l // 8]
    /// kdf(bytes(16), b"SMB2AESCCM\x00", b"ServerOut\x00", 128)
    /// kdf(bytes(16), b"SMB2AESCCM\x00", b"ServerIn \x00", 128)
    /// kdf(bytes(16), b"SMBS2CCipherKey\x00", bytes(64), 128 or 256)
    /// kdf(bytes(16), b"SMBC2SCipherKey\x00", bytes(64), 128 or 256)
    /// ```
    #[test]
    fn derives_keys_per_dialect_and_key_length() {
        derives(
            Cipher::Aes128Ccm,
            None,
            "acd80e01eb950afd89ad3582c400dfff",
            "5260e9b083ea02014afaab4f8581f7ea",
        );
        for cipher in [Cipher::Aes128Ccm, Cipher::Aes128Gcm] {
            derives(
                cipher,
                Some(&[0; 64]),
                "62ad6368e1497589774350d80e8828d8",
                "61d3d00d21fe5dce0f7ed579239e3abc",
            );
        }
        for cipher in [Cipher::Aes256Ccm, Cipher::Aes256Gcm] {
            derives(
                cipher,
                Some(&[0; 64]),
                "4a819180c217bc329679e6f0a4ae821342bbf8fcf5856753fd501adc11300f97",
                "f310c7fc6c090518f251919d601c5ed8bd0be96ff2c3e5becbda964ba3a1dd95",
            );
        }
    }
}
