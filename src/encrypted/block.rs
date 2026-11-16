//! Sealing and opening of file blocks.
//!
//! A stored block is the nonce, the ciphertext and the tag. The additional
//! data is the file header followed by the block index as a big-endian
//! `u64`, so a block opens only at its own position in its own file.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit};

use super::format::{HEADER_LEN, NONCE_LEN, OVERHEAD, TAG_LEN, is_zero};
use super::header::Header;
use super::keys::KeySchedule;

const AAD_LEN: usize = HEADER_LEN + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockError {
    /// A length that no block of the share can have.
    Length,
    /// The nonce is all zero while the block is not.
    ZeroNonce,
    /// The tag does not verify.
    Authentication,
}

/// AES-256-GCM with a 96-bit nonce and a 128-bit tag, for any additional
/// data.
struct Gcm(Aes256Gcm);

impl Gcm {
    fn new(key: &[u8; 32]) -> Self {
        Self(Aes256Gcm::new(key.into()))
    }

    /// Encrypts `buf` in place and returns the tag. Panics when `buf` is
    /// longer than GCM allows, which no block is.
    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
        self.0
            .encrypt_in_place_detached(nonce.into(), aad, buf)
            .map(Into::into)
            .expect("block is far below the GCM length limit")
    }

    /// Decrypts `buf` in place. After an error `buf` is all zero.
    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), BlockError> {
        let opened = self
            .0
            .decrypt_in_place_detached(nonce.into(), aad, buf, tag.into());
        if opened.is_err() {
            buf.fill(0);
            return Err(BlockError::Authentication);
        }
        Ok(())
    }
}

/// The cipher of one file: its key and its header.
pub(crate) struct FileCipher {
    gcm: Gcm,
    header: Header,
}

impl FileCipher {
    /// The cipher of the file with `header`, under the key `keys` derives
    /// for that file.
    pub(crate) fn new(keys: &KeySchedule, header: Header) -> Self {
        let key = keys.file_key(header.suite(), &header.file_id());
        Self {
            gcm: Gcm::new(key.as_bytes()),
            header,
        }
    }

    fn aad(&self, index: u64) -> [u8; AAD_LEN] {
        let mut aad = [0u8; AAD_LEN];
        aad[..HEADER_LEN].copy_from_slice(self.header.as_bytes());
        aad[HEADER_LEN..].copy_from_slice(&index.to_be_bytes());
        aad
    }

    /// Seals `plain`, the bytes of block `index`, into `out` as nonce,
    /// ciphertext and tag. `plain` is 1 byte up to one full block long and
    /// `out` is `OVERHEAD` bytes longer. `nonce` is fresh and not all zero.
    pub(crate) fn seal_block(
        &self,
        index: u64,
        nonce: &[u8; NONCE_LEN],
        plain: &[u8],
        out: &mut [u8],
    ) -> Result<(), BlockError> {
        if plain.is_empty()
            || plain.len() > self.header.block_shift().block_len()
            || out.len() != plain.len() + OVERHEAD
        {
            return Err(BlockError::Length);
        }
        if is_zero(nonce) {
            return Err(BlockError::ZeroNonce);
        }
        let (nonce_out, rest) = out.split_at_mut(NONCE_LEN);
        let (data, tag_out) = rest.split_at_mut(plain.len());
        nonce_out.copy_from_slice(nonce);
        data.copy_from_slice(plain);
        tag_out.copy_from_slice(&self.gcm.seal(nonce, &self.aad(index), data));
        Ok(())
    }

    /// Opens `stored`, the stored bytes of block `index`, into `out`, which
    /// is `OVERHEAD` bytes shorter. A block of zero bytes is a hole and
    /// opens to zeros. `out` holds plaintext only after `Ok`: a tag that
    /// does not verify leaves it all zero, and an error before decryption
    /// leaves it as it was.
    pub(crate) fn open_block(
        &self,
        index: u64,
        stored: &[u8],
        out: &mut [u8],
    ) -> Result<(), BlockError> {
        if stored.len() <= OVERHEAD
            || stored.len() > self.header.block_shift().block_len() + OVERHEAD
            || out.len() != stored.len() - OVERHEAD
        {
            return Err(BlockError::Length);
        }
        if is_zero(stored) {
            out.fill(0);
            return Ok(());
        }
        let data_end = stored.len() - TAG_LEN;
        let nonce: [u8; NONCE_LEN] = std::array::from_fn(|i| stored[i]);
        let tag: [u8; TAG_LEN] = std::array::from_fn(|i| stored[data_end + i]);
        if is_zero(&nonce) {
            return Err(BlockError::ZeroNonce);
        }
        out.copy_from_slice(&stored[NONCE_LEN..data_end]);
        self.gcm.open(&nonce, &self.aad(index), out, &tag)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::super::format::BlockShift;
    use super::super::random::random_nonces;
    use super::super::testing::{file_id, key_schedule, other_key_schedule, unhex};
    use super::super::wycheproof_gcm::CASES;
    use super::*;

    const BLOCK_0_SHA256: &str = "ed61ac25758509c50135a35c711bf124eec1dcaee83781547c6f909b5e8aaa49";
    const BLOCK_1_SHA256: &str = "97d4b605e9bb61215f0996cecbfae6c169fd91c30457e0e10a151d16268cd305";

    fn shift(bits: u8) -> BlockShift {
        BlockShift::new(bits).unwrap()
    }

    fn header(bits: u8) -> Header {
        Header::new(shift(bits), file_id()).unwrap()
    }

    fn cipher(bits: u8) -> FileCipher {
        FileCipher::new(&key_schedule(), header(bits))
    }

    fn seal(cipher: &FileCipher, index: u64, nonce: u8, plain: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; plain.len() + OVERHEAD];
        cipher
            .seal_block(index, &[nonce; NONCE_LEN], plain, &mut out)
            .unwrap();
        out
    }

    fn open(cipher: &FileCipher, index: u64, stored: &[u8]) -> Result<Vec<u8>, BlockError> {
        let mut out = vec![0xee; stored.len().saturating_sub(OVERHEAD)];
        cipher.open_block(index, stored, &mut out)?;
        Ok(out)
    }

    /// Opening `stored` fails with `expected` and hands out no plaintext.
    fn assert_refused(cipher: &FileCipher, index: u64, stored: &[u8], expected: BlockError) {
        let mut out = vec![0xee; stored.len().saturating_sub(OVERHEAD)];
        assert_eq!(cipher.open_block(index, stored, &mut out), Err(expected));
        let left = if expected == BlockError::Authentication {
            0
        } else {
            0xee
        };
        assert!(out.iter().all(|&b| b == left), "{expected:?}");
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    struct Case {
        id: u32,
        valid: bool,
        key: [u8; 32],
        iv: [u8; NONCE_LEN],
        aad: Vec<u8>,
        msg: Vec<u8>,
        ct: Vec<u8>,
        tag: [u8; TAG_LEN],
    }

    fn wycheproof_cases() -> Vec<Case> {
        let hex = |s: &str| if s == "-" { Vec::new() } else { unhex(s) };
        CASES
            .lines()
            .map(|line| {
                let f: Vec<&str> = line.split(' ').collect();
                assert_eq!(f.len(), 8, "{line}");
                Case {
                    id: f[0].parse().unwrap(),
                    valid: match f[1] {
                        "valid" => true,
                        "invalid" => false,
                        other => panic!("result {other}"),
                    },
                    key: hex(f[2]).try_into().unwrap(),
                    iv: hex(f[3]).try_into().unwrap(),
                    aad: hex(f[4]),
                    msg: hex(f[5]),
                    ct: hex(f[6]),
                    tag: hex(f[7]).try_into().unwrap(),
                }
            })
            .collect()
    }

    #[test]
    fn wycheproof_aes_256_gcm() {
        let cases = wycheproof_cases();
        assert_eq!(cases.len(), 66);
        assert_eq!(cases.iter().filter(|c| c.valid).count(), 39);
        for case in &cases {
            let gcm = Gcm::new(&case.key);
            let id = case.id;
            if case.valid {
                let mut buf = case.msg.clone();
                let tag = gcm.seal(&case.iv, &case.aad, &mut buf);
                assert_eq!(buf, case.ct, "tcId {id}: ciphertext");
                assert_eq!(tag, case.tag, "tcId {id}: tag");

                let mut buf = case.ct.clone();
                gcm.open(&case.iv, &case.aad, &mut buf, &case.tag)
                    .unwrap_or_else(|_| panic!("tcId {id}: valid case rejected"));
                assert_eq!(buf, case.msg, "tcId {id}: plaintext");
            } else {
                let mut buf = case.ct.clone();
                let got = gcm.open(&case.iv, &case.aad, &mut buf, &case.tag);
                assert_eq!(got, Err(BlockError::Authentication), "tcId {id}");
                assert!(buf.iter().all(|&b| b == 0), "tcId {id}: bytes kept");
            }
        }
    }

    #[test]
    fn block_vectors() {
        let cipher = cipher(16);
        let plain = pattern(70_000);
        let blocks = [
            (0, &plain[..65_536], [1; NONCE_LEN], BLOCK_0_SHA256),
            (1, &plain[65_536..], [2; NONCE_LEN], BLOCK_1_SHA256),
        ];
        for (index, data, nonce, digest) in blocks {
            let mut stored = vec![0u8; data.len() + OVERHEAD];
            cipher.seal_block(index, &nonce, data, &mut stored).unwrap();
            assert_eq!(stored[..NONCE_LEN], nonce, "block {index}");
            assert_eq!(
                hex::encode(Sha256::digest(&stored)),
                digest,
                "block {index}"
            );
            assert_eq!(open(&cipher, index, &stored).unwrap(), data);
        }
    }

    #[test]
    fn round_trips_full_and_partial_blocks() {
        let cipher = cipher(13);
        let full = shift(13).block_len();
        for len in [1, full] {
            let plain = pattern(len);
            let mut nonce = [[0u8; NONCE_LEN]];
            random_nonces(&mut nonce).unwrap();
            let mut stored = vec![0u8; len + OVERHEAD];
            cipher
                .seal_block(7, &nonce[0], &plain, &mut stored)
                .unwrap();
            assert_eq!(open(&cipher, 7, &stored).unwrap(), plain, "len {len}");
        }
    }

    #[test]
    fn zero_blocks_are_holes() {
        let cipher = cipher(13);
        let full = shift(13).block_len() + OVERHEAD;
        for len in [OVERHEAD + 1, 100, full] {
            let stored = vec![0u8; len];
            assert_eq!(
                open(&cipher, 3, &stored).unwrap(),
                vec![0u8; len - OVERHEAD],
                "stored len {len}"
            );
        }
    }

    #[test]
    fn zero_nonce_is_refused_even_when_the_tag_would_verify() {
        let cipher = cipher(13);
        let zero = [0u8; NONCE_LEN];
        let mut data = pattern(50);
        let tag = cipher.gcm.seal(&zero, &cipher.aad(2), &mut data);
        let stored = [&zero[..], &data, &tag].concat();
        assert_refused(&cipher, 2, &stored, BlockError::ZeroNonce);

        let mut out = vec![0u8; 50 + OVERHEAD];
        assert_eq!(
            cipher.seal_block(2, &zero, &pattern(50), &mut out),
            Err(BlockError::ZeroNonce)
        );
    }

    #[test]
    fn any_changed_byte_fails_authentication() {
        let cipher = cipher(13);
        let stored = seal(&cipher, 4, 0x11, &pattern(20));
        for at in 0..stored.len() {
            for bit in [0x01, 0x80] {
                let mut bad = stored.clone();
                bad[at] ^= bit;
                assert_refused(&cipher, 4, &bad, BlockError::Authentication);
            }
        }
        assert!(open(&cipher, 4, &stored).is_ok());
    }

    #[test]
    fn block_opens_only_at_its_index_header_and_key() {
        let cipher = cipher(16);
        let stored = seal(&cipher, 9, 3, &pattern(1000));
        assert!(open(&cipher, 9, &stored).is_ok());
        for index in [0, 8, 10, u64::MAX, 9 << 32] {
            assert_refused(&cipher, index, &stored, BlockError::Authentication);
        }

        let mut other_id = file_id();
        other_id[0] ^= 1;
        let other_header = Header::new(shift(16), other_id).unwrap();
        let other_file = FileCipher::new(&key_schedule(), other_header);
        assert_refused(&other_file, 9, &stored, BlockError::Authentication);

        let other_shift = FileCipher::new(&key_schedule(), header(13));
        assert_refused(&other_shift, 9, &stored, BlockError::Authentication);

        let other_key = FileCipher::new(&other_key_schedule(), header(16));
        assert_refused(&other_key, 9, &stored, BlockError::Authentication);
    }

    #[test]
    fn lengths_that_hold_no_block_are_refused() {
        let cipher = cipher(13);
        let full = shift(13).block_len() + OVERHEAD;
        for len in [0, 1, 12, 27, 28, full + 1, full + 28, 4 * full] {
            assert_refused(&cipher, 0, &vec![7u8; len], BlockError::Length);
            assert_refused(&cipher, 0, &vec![0u8; len], BlockError::Length);
        }
        let stored = seal(&cipher, 0, 1, &pattern(10));
        for out_len in [0, 9, 11, 38] {
            let mut out = vec![0u8; out_len];
            assert_eq!(
                cipher.open_block(0, &stored, &mut out),
                Err(BlockError::Length)
            );
        }
    }

    #[test]
    fn seal_refuses_what_no_block_holds() {
        let cipher = cipher(13);
        let nonce = [1u8; NONCE_LEN];
        let mut out = vec![0u8; OVERHEAD];
        assert_eq!(
            cipher.seal_block(0, &nonce, &[], &mut out),
            Err(BlockError::Length)
        );
        let mut out = vec![0u8; 40];
        assert_eq!(
            cipher.seal_block(0, &nonce, &[1; 10], &mut out),
            Err(BlockError::Length),
            "out is not plain plus overhead"
        );
        let big = vec![1u8; 8193];
        let mut big_out = vec![0u8; 8193 + OVERHEAD];
        assert_eq!(
            cipher.seal_block(0, &nonce, &big, &mut big_out),
            Err(BlockError::Length)
        );
        let full = vec![1u8; 8192];
        let mut full_out = vec![0u8; 8192 + OVERHEAD];
        assert_eq!(cipher.seal_block(0, &nonce, &full, &mut full_out), Ok(()));
    }
}
