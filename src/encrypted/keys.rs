//! Key schedule: HKDF-SHA-256 (RFC 5869) over the caller's 32-byte key.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const HASH_LEN: usize = 32;
/// Longest HKDF-Expand output: 255 hash blocks.
const MAX_OKM_LEN: usize = 255 * HASH_LEN;

const MARKER_INFO: &[u8] = b"smb-server/encryption/v1/marker";
const NAMES_INFO: &[u8] = b"smb-server/encryption/v1/names";
const CONTENT_INFO: &[u8] = b"smb-server/encryption/v1/content";

/// Keys derived from the caller's key.
pub(crate) struct KeySchedule {
    prk: Zeroizing<[u8; HASH_LEN]>,
    name_key: Zeroizing<[u8; 64]>,
}

/// A derived 32-byte key.
pub(crate) struct DerivedKey(Zeroizing<[u8; 32]>);

impl DerivedKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl KeySchedule {
    /// Derives the PRK and the name key. `key` is dropped once the PRK exists.
    pub(crate) fn new(key: Zeroizing<[u8; 32]>) -> Self {
        let prk = extract(&[0u8; HASH_LEN], &key[..]);
        drop(key);
        let name_key = expand(&prk, &[NAMES_INFO]);
        Self { prk, name_key }
    }

    /// Key of the HMAC that authenticates the share's marker object.
    pub(crate) fn marker_key(&self) -> DerivedKey {
        DerivedKey(expand(&self.prk, &[MARKER_INFO]))
    }

    /// The AES-SIV key: the first 32 bytes are the S2V (CMAC) key, the last 32
    /// the CTR key (RFC 5297 section 2.6).
    pub(crate) fn name_key(&self) -> &[u8; 64] {
        &self.name_key
    }

    /// AES-256-GCM key of the file with `file_id`, written with `suite`.
    pub(crate) fn file_key(&self, suite: u8, file_id: &[u8; 16]) -> DerivedKey {
        DerivedKey(expand(&self.prk, &[CONTENT_INFO, &[suite], file_id]))
    }
}

/// Writes the MAC to `out` and wipes the temporary copy.
fn finalize_into(mac: HmacSha256, out: &mut [u8; HASH_LEN]) {
    let mut tag = mac.finalize().into_bytes();
    out.copy_from_slice(&tag);
    tag.as_mut_slice().zeroize();
}

/// HKDF-Extract (RFC 5869 section 2.2).
fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC-SHA-256 accepts keys of any length");
    mac.update(ikm);
    let mut prk = Zeroizing::new([0u8; HASH_LEN]);
    finalize_into(mac, &mut prk);
    prk
}

/// HKDF-Expand (RFC 5869 section 2.3) to `N` bytes. `info` is the
/// concatenation of its parts.
fn expand<const N: usize>(prk: &[u8; HASH_LEN], info: &[&[u8]]) -> Zeroizing<[u8; N]> {
    const { assert!(N <= MAX_OKM_LEN) };
    let mut okm = Zeroizing::new([0u8; N]);
    let mut block = Zeroizing::new([0u8; HASH_LEN]);
    for (counter, out) in (1..=u8::MAX).zip(okm.chunks_mut(HASH_LEN)) {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .expect("HMAC-SHA-256 accepts keys of any length");
        if counter > 1 {
            mac.update(&block[..]);
        }
        for part in info {
            mac.update(part);
        }
        mac.update(&[counter]);
        finalize_into(mac, &mut block);
        out.copy_from_slice(&block[..out.len()]);
    }
    okm
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::super::testing::{file_id, key_schedule, unhex};
    use super::*;

    const SUITE: u8 = 1;

    const PRK: &str = "46bd320605c5a6b6163ab70bc6345b92a5f908e79fe58979c23ebb47d1a5e307";
    const MARKER_KEY: &str = "1e150142cb962cd4f3fb790e1e81671e34e8eb71950c01b3c8408235e8e860bd";
    const NAME_KEY: &str = concat!(
        "e3b13b0123dda065bc68506beead8e502a6a2f9a6b860b3b212cb6b82185aaf3",
        "2d2b0ccdc1793cbf450ed123fee70ee73ac7ea997dd047160f429d6bd30687c6",
    );
    const FILE_KEY: &str = "2f66b269cfb6b9910b856a29c32e9b2e07289928c74454bb42fb28bf216fef90";
    const OKM_DIGEST: &str = "e3963f0e8b66c425fb6879cf9bdaf9aac0ffdbac3093b9857871bb35b0056dce";

    fn check_rfc5869<const L: usize>(ikm: &[u8], salt: &[u8], info: &[u8], prk: &str, okm: &str) {
        let got_prk = extract(salt, ikm);
        assert_eq!(got_prk.as_slice(), unhex(prk));
        let got_okm = expand::<L>(&got_prk, &[info]);
        assert_eq!(got_okm.as_slice(), unhex(okm));
    }

    #[test]
    fn rfc5869_case_1() {
        check_rfc5869::<42>(
            &[0x0b; 22],
            &(0x00..=0x0c).collect::<Vec<u8>>(),
            &(0xf0..=0xf9).collect::<Vec<u8>>(),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            concat!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865",
            ),
        );
    }

    #[test]
    fn rfc5869_case_2() {
        check_rfc5869::<82>(
            &(0x00..=0x4f).collect::<Vec<u8>>(),
            &(0x60..=0xaf).collect::<Vec<u8>>(),
            &(0xb0..=0xff).collect::<Vec<u8>>(),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            concat!(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
                "cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
        );
    }

    #[test]
    fn rfc5869_case_3() {
        check_rfc5869::<42>(
            &[0x0b; 22],
            &[],
            &[],
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            concat!(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8",
            ),
        );
    }

    #[test]
    fn prk_vector() {
        assert_eq!(key_schedule().prk.as_slice(), unhex(PRK));
    }

    #[test]
    fn marker_key_vector() {
        assert_eq!(
            key_schedule().marker_key().as_bytes().as_slice(),
            unhex(MARKER_KEY)
        );
    }

    #[test]
    fn name_key_vector() {
        assert_eq!(key_schedule().name_key().as_slice(), unhex(NAME_KEY));
    }

    #[test]
    fn file_key_vector() {
        let key = key_schedule().file_key(SUITE, &file_id());
        assert_eq!(key.as_bytes().as_slice(), unhex(FILE_KEY));
    }

    #[test]
    fn expand_runs_to_the_last_counter() {
        let prk = extract(b"salt", b"ikm");
        let okm = expand::<MAX_OKM_LEN>(&prk, &[b"info"]);
        assert_eq!(Sha256::digest(okm.as_slice()).as_slice(), unhex(OKM_DIGEST));
    }
}
