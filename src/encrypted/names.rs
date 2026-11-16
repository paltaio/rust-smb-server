//! Encrypted names: AES-SIV over the UTF-8 bytes of the name, spelled in
//! base32.
//!
//! A name whose spelling fits the long-name threshold is stored as that
//! spelling. A longer name is stored as the entry `<hash>.l` next to the side
//! object `<hash>.n`, which holds the AES-SIV output as raw bytes. The hash is
//! base32 of the first 20 bytes of the SHA-256 of that output.

use aes_siv::siv::Aes256Siv;
use aes_siv::{Key, KeyInit, Tag};
use sha2::{Digest, Sha256};

use super::base32::{self, Base32Error};
use super::format::MARKER_NAME;
use super::keys::KeySchedule;
use crate::path::is_valid_component;

/// Length of the SIV that starts an AES-SIV output.
pub(super) const SIV_LEN: usize = 16;
/// Longest name in UTF-8: 255 UTF-16 units of at most three bytes each.
const MAX_NAME_BYTES: usize = 3 * 255;
/// Longest AES-SIV output of a name.
pub(super) const MAX_SEALED_LEN: usize = SIV_LEN + MAX_NAME_BYTES;
/// Longest stored name, in characters.
pub(super) const MAX_STORED_NAME_LEN: usize = 255;
/// Longest side object. A caller takes the size of an object first and reads
/// none of one that is longer; `decode_long` refuses it too.
pub(crate) const MAX_SIDE_OBJECT_LEN: usize = 1024;
/// Bytes of the SHA-256 digest that name a long entry.
const HASH_BYTES: usize = 20;
const HASH_CHARS: usize = base32::encoded_len(HASH_BYTES);
pub(super) const LONG_SUFFIX: &str = ".l";
const SIDE_SUFFIX: &str = ".n";
/// The associated data of every name: one component, empty. Zero components
/// give a different output.
const NAME_AD: &[u8] = b"";

/// A name as the inner backend stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredName {
    /// The name of the entry: the spelling of a short name, or `<hash>.l`.
    pub(crate) entry: String,
    /// The side object of a long name.
    pub(crate) side_object: Option<SideObject>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SideObject {
    /// `<hash>.n`, in the directory of the entry.
    pub(crate) name: String,
    /// The AES-SIV output, 17 to 781 bytes.
    pub(crate) content: Vec<u8>,
}

/// Why a stored name does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameError {
    /// A character outside the base32 alphabet.
    Alphabet,
    /// Not the one spelling of a byte string, or over 255 characters.
    Spelling,
    /// Not 17 to 781 bytes, the sizes of a sealed name.
    Length,
    /// The SIV does not authenticate under the key.
    Authentication,
    /// The plaintext is not UTF-8 or not a valid path component.
    Plaintext,
    /// A long entry name that is not 32 base32 characters and `.l`.
    Entry,
    /// A side object longer than `MAX_SIDE_OBJECT_LEN`.
    SideObjectSize,
    /// The side object does not hash to the entry name.
    SideObjectHash,
}

impl From<Base32Error> for NameError {
    fn from(error: Base32Error) -> Self {
        match error {
            Base32Error::Character => Self::Alphabet,
            Base32Error::Length | Base32Error::TrailingBits => Self::Spelling,
        }
    }
}

/// What a stored name is, judged from its spelling alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoredKind {
    /// The marker object, in the root.
    Marker,
    /// `<32 base32 characters>.n`.
    SideObject,
    /// `<32 base32 characters>.l`.
    LongEntry,
    /// Only alphabet characters: `decode_short` decides.
    ShortCandidate,
    /// Anything else.
    Foreign,
}

fn new_siv(key: &[u8; 64]) -> Aes256Siv {
    Aes256Siv::new(Key::<Aes256Siv>::from_slice(key))
}

/// AES-SIV of `plaintext` with `ad` as the one associated-data component: the
/// 16-byte SIV followed by the ciphertext.
fn seal_siv(key: &[u8; 64], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; SIV_LEN + plaintext.len()];
    let (siv_out, body) = out.split_at_mut(SIV_LEN);
    body.copy_from_slice(plaintext);
    let siv = new_siv(key)
        .encrypt_in_place_detached([ad], body)
        .expect("one associated-data component is below the limit");
    siv_out.copy_from_slice(&siv);
    out
}

/// The plaintext of an output of `seal_siv`, or `None` when the output is
/// shorter than a SIV or does not authenticate.
fn open_siv(key: &[u8; 64], ad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let (siv, body) = sealed.split_at_checked(SIV_LEN)?;
    let mut plaintext = body.to_vec();
    new_siv(key)
        .decrypt_in_place_detached([ad], &mut plaintext, Tag::from_slice(siv))
        .ok()?;
    Some(plaintext)
}

/// Base32 of the first 20 bytes of the SHA-256 of `content`.
pub(super) fn long_hash(content: &[u8]) -> String {
    base32::encode(&Sha256::digest(content)[..HASH_BYTES])
}

/// The hash in `name` when it is `<32 base32 characters><suffix>`.
fn hash_part<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let hash = name.strip_suffix(suffix)?;
    (hash.len() == HASH_CHARS && hash.bytes().all(base32::is_alphabet)).then_some(hash)
}

/// The stored form of `name` for a share whose long-name threshold is
/// `threshold` (62 to 255): the spelling of its AES-SIV output when that has
/// at most `threshold` characters, else a long entry and its side object.
/// `None` when `name` is not a valid path component.
pub(crate) fn encode_name(keys: &KeySchedule, name: &str, threshold: u8) -> Option<StoredName> {
    if !is_valid_component(name) {
        return None;
    }
    let sealed = seal_siv(keys.name_key(), NAME_AD, name.as_bytes());
    if base32::encoded_len(sealed.len()) <= usize::from(threshold) {
        return Some(StoredName {
            entry: base32::encode(&sealed),
            side_object: None,
        });
    }
    let hash = long_hash(&sealed);
    Some(StoredName {
        entry: format!("{hash}{LONG_SUFFIX}"),
        side_object: Some(SideObject {
            name: format!("{hash}{SIDE_SUFFIX}"),
            content: sealed,
        }),
    })
}

/// The AES-SIV output of `plaintext` as `encode_name` makes it, without the
/// check that the plaintext is a valid path component or UTF-8.
#[cfg(any(test, fuzzing))]
pub(super) fn seal_unchecked(keys: &KeySchedule, plaintext: &[u8]) -> Vec<u8> {
    seal_siv(keys.name_key(), NAME_AD, plaintext)
}

/// The short stored form of `plaintext` as `encode_name` makes it, without the
/// check that the plaintext is a valid path component.
#[cfg(test)]
pub(super) fn encode_unchecked(keys: &KeySchedule, plaintext: &str) -> String {
    base32::encode(&seal_unchecked(keys, plaintext.as_bytes()))
}

/// The name in an AES-SIV output: 17 to 781 bytes, a SIV that authenticates,
/// and a plaintext that is UTF-8 and a valid path component. The plaintext is
/// used only after the SIV authenticated.
fn open_name(keys: &KeySchedule, sealed: &[u8]) -> Result<String, NameError> {
    if !(SIV_LEN + 1..=MAX_SEALED_LEN).contains(&sealed.len()) {
        return Err(NameError::Length);
    }
    let plaintext = open_siv(keys.name_key(), NAME_AD, sealed).ok_or(NameError::Authentication)?;
    let name = String::from_utf8(plaintext).map_err(|_| NameError::Plaintext)?;
    if !is_valid_component(&name) {
        return Err(NameError::Plaintext);
    }
    Ok(name)
}

/// The name behind a short stored name. Each check must pass: at most 255
/// characters; only alphabet characters; the one spelling of a byte string;
/// at least 17 bytes; a SIV that authenticates; a UTF-8 plaintext that is a
/// valid path component. A name decodes whatever the threshold.
pub(crate) fn decode_short(keys: &KeySchedule, stored: &str) -> Result<String, NameError> {
    if stored.len() > MAX_STORED_NAME_LEN {
        return Err(NameError::Spelling);
    }
    let sealed = base32::decode(stored)?;
    open_name(keys, &sealed)
}

/// The name behind the long entry `entry` (`<hash>.l`), given the content of
/// its side object. The content has at most `MAX_SIDE_OBJECT_LEN` bytes and
/// hashes to the entry name; then it must be a sealed name, as for
/// `decode_short`.
pub(crate) fn decode_long(
    keys: &KeySchedule,
    entry: &str,
    side_object: &[u8],
) -> Result<String, NameError> {
    let hash = hash_part(entry, LONG_SUFFIX).ok_or(NameError::Entry)?;
    if side_object.len() > MAX_SIDE_OBJECT_LEN {
        return Err(NameError::SideObjectSize);
    }
    if long_hash(side_object) != hash {
        return Err(NameError::SideObjectHash);
    }
    open_name(keys, side_object)
}

/// Classifies a stored name. `in_root` is true for the root directory of the
/// inner backend, the only place the marker lives.
pub(crate) fn classify(stored: &str, in_root: bool) -> StoredKind {
    if in_root && stored == MARKER_NAME {
        StoredKind::Marker
    } else if hash_part(stored, SIDE_SUFFIX).is_some() {
        StoredKind::SideObject
    } else if hash_part(stored, LONG_SUFFIX).is_some() {
        StoredKind::LongEntry
    } else if !stored.is_empty() && stored.bytes().all(base32::is_alphabet) {
        StoredKind::ShortCandidate
    } else {
        StoredKind::Foreign
    }
}

/// The side object name `<hash>.n` of the long entry `entry` (`<hash>.l`).
/// `None` when `entry` is not a long entry name.
pub(crate) fn side_object_name(entry: &str) -> Option<String> {
    hash_part(entry, LONG_SUFFIX).map(|hash| format!("{hash}{SIDE_SUFFIX}"))
}

#[cfg(test)]
mod tests {
    use aes_siv::siv::Aes128Siv;

    use super::super::testing::{key_schedule, other_key_schedule, unhex};
    use super::super::wycheproof_siv::CASES;
    use super::*;
    use crate::tests::data::xorshift;

    const A_STORED: &str = "grpvuf7g2h5sd5gwg5iwdpyz4fyq";

    const A_SEALED: &str = "345f5a17e6d1fb21f4d6375161bf19e171";

    const N22_STORED: &str = "wqusrymksvlcqx5vtmccaf3sl6jmg2gatxmgzff2ctzbldg7dfojwq3rm3jb2";

    const N23_STORED: &str = "uevf4zqmsptcnqfjktlgqnlyruamarcfbiph4akbarblnbbrjz7zo2zehlcv4cy";

    const N23_HASH: &str = "jcucprs3tpqbviuvyqoeh44uezreayce";

    const N23_SEALED: &str = concat!(
        "a12a5e660c93e626c0a954d66835788d00c044450a1e7e01410442b684314e7f",
        "976b243ac55e0b",
    );

    const N143_STORED: &str = concat!(
        "rwmpthfffldk4cm6mtfs5y2v55geyefmx7y2plxhgagomdmlwfps3ql5pg5evort",
        "vzyjfzduxabzcsugkst4chq76hfvs2zbbhmhxiqyaluyaslt7wyc6dvzvarsk7h6",
        "vkctgtygu4k66bhpdwufgi2t3nevojylktydphnni4gzp5fs3vjvz5t2j4lxzve6",
        "62wuymsu7dck6ewiyutwsdpcal7ys3oii6vn37lt7mhka2senip54nmg2dhyduq",
    );

    const N144_HASH: &str = "32aasvsxaak5qcqvz7bcb3xe64ik7ixz";

    const N144_SEALED: &str = concat!(
        "eb6ddfdf1f08bab4a6aa215ece40a78ea429e8c2ad16183f0cd347e515db048a",
        "2e8a5c7347776c4cc51746df811b2bc7363a21154b4682d2bf68c91508277a4c",
        "7f80fbb7411c3955271a0452ec33dd2a6277685aa3aacbb334b72e86a292a102",
        "42b4de632d2ed4b6fb9fe2f0468bad2ff493f111dc1cc9feacd92cd12978594f",
        "27fde8e9c24e2ec5c67fffe2d452cf102edb45fd2fff355ef8b611e3af5b7f2e",
    );

    const CJK_HASH: &str = "d4dgwea72yk7o7d7h4mymmbgecvuanxr";

    const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";

    fn encoded(name: &str, threshold: u8) -> StoredName {
        encode_name(&key_schedule(), name, threshold).unwrap()
    }

    /// The AES-SIV output of `plaintext` under the test key.
    fn sealed(plaintext: &[u8]) -> Vec<u8> {
        seal_siv(key_schedule().name_key(), NAME_AD, plaintext)
    }

    /// Decodes `stored` the way its shape asks for.
    fn decode_stored(keys: &KeySchedule, stored: &StoredName) -> Result<String, NameError> {
        match &stored.side_object {
            None => decode_short(keys, &stored.entry),
            Some(side) => decode_long(keys, &stored.entry, &side.content),
        }
    }

    /// `text` with the character at `index` replaced by `with`.
    fn with_char(text: &str, index: usize, with: char) -> String {
        let mut chars: Vec<char> = text.chars().collect();
        chars[index] = with;
        chars.into_iter().collect()
    }

    /// The long entry name that an attacker who knows `content` can make.
    fn long_entry_of(content: &[u8]) -> String {
        format!("{}{LONG_SUFFIX}", long_hash(content))
    }

    /// Entry and side object content of a long name.
    fn long_vector(name: &str) -> (String, Vec<u8>) {
        let stored = encoded(name, 62);
        (stored.entry, stored.side_object.unwrap().content)
    }

    // AES-SIV

    #[test]
    fn rfc_5297_a1_deterministic_example() {
        let key = unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ad = unhex("101112131415161718191a1b1c1d1e1f2021222324252627");
        let plain = unhex("112233445566778899aabbccddee");
        let new = || Aes128Siv::new(Key::<Aes128Siv>::from_slice(&key));

        let mut buf = plain.clone();
        let tag = new()
            .encrypt_in_place_detached([ad.as_slice()], &mut buf)
            .unwrap();
        assert_eq!(tag.as_slice(), unhex("85632d07c6e8f37f950acd320a2ecc93"));
        assert_eq!(buf, unhex("40c02b9690c4dc04daef7f6afe5c"));

        new()
            .decrypt_in_place_detached([ad.as_slice()], &mut buf, &tag)
            .unwrap();
        assert_eq!(buf, plain);

        let mut bad = tag;
        bad[0] ^= 1;
        let mut buf = unhex("40c02b9690c4dc04daef7f6afe5c");
        let result = new().decrypt_in_place_detached([ad.as_slice()], &mut buf, &bad);
        assert!(result.is_err());
    }

    struct Case {
        id: u32,
        valid: bool,
        key: [u8; 64],
        aad: Vec<u8>,
        msg: Vec<u8>,
        ct: Vec<u8>,
    }

    fn wycheproof_cases() -> Vec<Case> {
        let hex = |s: &str| if s == "-" { Vec::new() } else { unhex(s) };
        CASES
            .lines()
            .map(|line| {
                let f: Vec<&str> = line.split(' ').collect();
                assert_eq!(f.len(), 6, "{line}");
                Case {
                    id: f[0].parse().unwrap(),
                    valid: match f[1] {
                        "valid" => true,
                        "invalid" => false,
                        other => panic!("result {other}"),
                    },
                    key: hex(f[2]).try_into().unwrap(),
                    aad: hex(f[3]),
                    msg: hex(f[4]),
                    ct: hex(f[5]),
                }
            })
            .collect()
    }

    #[test]
    fn wycheproof_aes_256_siv() {
        let cases = wycheproof_cases();
        assert_eq!(cases.len(), 147);
        assert_eq!(cases.iter().filter(|c| c.valid).count(), 39);
        for case in &cases {
            let id = case.id;
            let (key, aad, ct) = (&case.key, &case.aad, &case.ct);
            if case.valid {
                assert_eq!(seal_siv(key, aad, &case.msg), *ct, "tcId {id}: output");
                let opened = open_siv(key, aad, ct);
                assert_eq!(opened.as_ref(), Some(&case.msg), "tcId {id}: plaintext");
            } else {
                assert_eq!(open_siv(key, aad, ct), None, "tcId {id}: accepted");
            }
        }
    }

    #[test]
    fn names_use_one_empty_associated_data_component() {
        let keys = key_schedule();
        let output = |headers: &[&[u8]]| {
            let mut body = b"a".to_vec();
            let siv = new_siv(keys.name_key())
                .encrypt_in_place_detached(headers, &mut body)
                .unwrap();
            [siv.as_slice(), &body].concat()
        };
        let one_empty = output(&[b""]);
        assert_ne!(output(&[]), one_empty);
        assert_ne!(output(&[b"", b""]), one_empty);
        assert_ne!(output(&[b"x"]), one_empty);
    }

    // Stored name vectors, key 0x00..=0x1f

    #[test]
    fn vector_one_byte_name() {
        let stored = encoded("a", 255);
        assert_eq!(stored.entry, A_STORED);
        assert_eq!(stored.entry.len(), 28);
        assert_eq!(stored.side_object, None);
        assert_eq!(hex::encode(sealed(b"a")), A_SEALED);
        assert_eq!(decode_short(&key_schedule(), A_STORED).unwrap(), "a");
    }

    #[test]
    fn vector_longest_short_name() {
        let name = "a".repeat(143);
        let stored = encoded(&name, 255);
        assert_eq!(stored.entry, N143_STORED);
        assert_eq!(stored.entry.len(), 255);
        assert_eq!(stored.side_object, None);
        assert_eq!(decode_short(&key_schedule(), N143_STORED).unwrap(), name);
    }

    #[test]
    fn vector_shortest_long_name() {
        let name = "a".repeat(144);
        let stored = encoded(&name, 255);
        assert_eq!(stored.entry, format!("{N144_HASH}.l"));
        let side = stored.side_object.as_ref().unwrap();
        assert_eq!(side.name, format!("{N144_HASH}.n"));
        assert_eq!(side.content.len(), 160);
        assert_eq!(hex::encode(&side.content), N144_SEALED);
        assert_eq!(base32::encoded_len(side.content.len()), 256);
        assert_eq!(decode_stored(&key_schedule(), &stored).unwrap(), name);
    }

    #[test]
    fn vector_longest_name() {
        let name = "\u{6587}".repeat(255);
        assert_eq!(name.len(), 765);
        assert_eq!(name.encode_utf16().count(), 255);
        let stored = encoded(&name, 255);
        assert_eq!(stored.entry, format!("{CJK_HASH}.l"));
        let side = stored.side_object.as_ref().unwrap();
        assert_eq!(side.name, format!("{CJK_HASH}.n"));
        assert_eq!(side.content.len(), 781);
        assert_eq!(decode_stored(&key_schedule(), &stored).unwrap(), name);
    }

    #[test]
    fn vector_canonical_form_follows_the_threshold() {
        let keys = key_schedule();

        let name = "a".repeat(22);
        let stored = encoded(&name, 62);
        assert_eq!(stored.entry, N22_STORED);
        assert_eq!(stored.entry.len(), 61);
        assert_eq!(stored.side_object, None);

        let name = "a".repeat(23);
        let short = encoded(&name, 255);
        assert_eq!(short.entry, N23_STORED);
        assert_eq!(short.entry.len(), 63);
        assert_eq!(short.side_object, None);

        let long = encoded(&name, 62);
        assert_eq!(long.entry, format!("{N23_HASH}.l"));
        let side = long.side_object.as_ref().unwrap();
        assert_eq!(side.name, format!("{N23_HASH}.n"));
        assert_eq!(hex::encode(&side.content), N23_SEALED);

        assert_eq!(decode_stored(&keys, &short).unwrap(), name);
        assert_eq!(decode_stored(&keys, &long).unwrap(), name);
    }

    // Encoding

    #[test]
    fn canonical_form_switches_at_the_threshold() {
        let keys = key_schedule();
        for len in 1..=150usize {
            let name = "b".repeat(len);
            let spelling = base32::encoded_len(len + SIV_LEN);
            // The ends of the range and each side of the switch.
            let near = [spelling - 1, spelling, spelling + 1].map(|t| t.clamp(62, 255) as u8);
            for threshold in [62u8, 255].into_iter().chain(near) {
                let label = format!("threshold {threshold} len {len}");
                let stored = encode_name(&keys, &name, threshold).unwrap();
                match &stored.side_object {
                    None => {
                        assert!(spelling <= usize::from(threshold), "{label}");
                        assert_eq!(stored.entry.len(), spelling, "{label}");
                    }
                    Some(side) => {
                        assert!(spelling > usize::from(threshold), "{label}");
                        assert_eq!(stored.entry.len(), 34, "{label}");
                        assert_eq!(side.name.len(), 34, "{label}");
                        assert_eq!(side.content.len(), len + SIV_LEN, "{label}");
                    }
                }
                assert_eq!(decode_stored(&keys, &stored).unwrap(), name, "{label}");
            }
        }
    }

    #[test]
    fn stored_names_fit_for_every_name_length() {
        let keys = key_schedule();
        for len in 1..=255usize {
            let name = "\u{6587}".repeat(len);
            let stored = encode_name(&keys, &name, 255).unwrap();
            assert!(stored.entry.len() <= MAX_STORED_NAME_LEN, "len {len}");
            if let Some(side) = &stored.side_object {
                assert!(side.content.len() <= 781, "len {len}");
                assert_eq!(stored.entry.len(), 34, "len {len}");
                assert_eq!(side.name.len(), 34, "len {len}");
            }
            assert_eq!(decode_stored(&keys, &stored).unwrap(), name, "len {len}");
        }
    }

    #[test]
    fn astral_names_round_trip_up_to_255_units() {
        let keys = key_schedule();
        let name = "\u{1f600}".repeat(127);
        assert_eq!(name.encode_utf16().count(), 254);
        let stored = encode_name(&keys, &name, 255).unwrap();
        assert_eq!(decode_stored(&keys, &stored).unwrap(), name);
        assert!(encode_name(&keys, &"\u{1f600}".repeat(128), 255).is_none());
    }

    #[test]
    fn only_valid_components_encode() {
        let keys = key_schedule();
        assert!(encode_name(&keys, "a/b", 255).is_none());
        assert!(encode_name(&keys, &"a".repeat(256), 255).is_none());
        assert!(encode_name(&keys, "a b", 255).is_some());
        assert!(encode_name(&keys, &"a".repeat(255), 255).is_some());
    }

    #[test]
    fn names_are_not_normalized() {
        let keys = key_schedule();
        let names = ["caf\u{e9}", "cafe\u{301}"];
        let entries = names.map(|name| encoded(name, 255).entry);
        assert_ne!(entries[0], entries[1]);
        for (name, entry) in names.iter().zip(&entries) {
            assert_eq!(decode_short(&keys, entry).unwrap(), *name);
        }
    }

    // Short names

    #[test]
    fn short_name_with_foreign_characters_is_refused() {
        let keys = key_schedule();
        let upper = with_char(A_STORED, 3, 'P');
        assert_eq!(decode_short(&keys, &upper), Err(NameError::Alphabet));
        let padded = format!("{A_STORED}===");
        assert_eq!(decode_short(&keys, &padded), Err(NameError::Alphabet));
        // Three characters are no spelling either; the alphabet check comes
        // first.
        assert_eq!(decode_short(&keys, "a0a"), Err(NameError::Alphabet));
    }

    #[test]
    fn short_name_with_another_spelling_is_refused() {
        let keys = key_schedule();
        // 25 characters are the spelling of no byte string.
        let result = decode_short(&keys, &A_STORED[..25]);
        assert_eq!(result, Err(NameError::Spelling));
        // 28 characters leave four unused bits in the last one; 'b' sets one.
        let trailing = with_char(A_STORED, 27, 'b');
        assert_eq!(decode_short(&keys, &trailing), Err(NameError::Spelling));
    }

    #[test]
    fn short_name_over_255_characters_is_refused() {
        let keys = key_schedule();
        let longest = base32::encode(&[0u8; 159]);
        assert_eq!(longest.len(), 255);
        assert_eq!(
            decode_short(&keys, &longest),
            Err(NameError::Authentication)
        );
        let too_long = base32::encode(&[0u8; 160]);
        assert_eq!(too_long.len(), 256);
        assert_eq!(decode_short(&keys, &too_long), Err(NameError::Spelling));
    }

    #[test]
    fn short_name_under_17_bytes_is_refused() {
        let keys = key_schedule();
        assert_eq!(decode_short(&keys, ""), Err(NameError::Length));
        let text = base32::encode(&[0x5a; 16]);
        assert_eq!(decode_short(&keys, &text), Err(NameError::Length));
        let text = base32::encode(&[0x5a; 17]);
        assert_eq!(decode_short(&keys, &text), Err(NameError::Authentication));
    }

    #[test]
    fn short_name_that_does_not_authenticate_is_refused() {
        let keys = key_schedule();
        let text = with_char(A_STORED, 10, 'a');
        assert_eq!(decode_short(&keys, &text), Err(NameError::Authentication));
        let reversed: String = A_STORED.chars().rev().collect();
        assert!(decode_short(&keys, &reversed).is_err());
        assert_eq!(
            decode_short(&other_key_schedule(), A_STORED),
            Err(NameError::Authentication)
        );
    }

    #[test]
    fn short_name_with_an_invalid_plaintext_is_refused() {
        let keys = key_schedule();
        let invalid: [&[u8]; 2] = [b"\xff\xfe\xfd", b"a/b"];
        for plain in invalid {
            let text = base32::encode(&sealed(plain));
            assert_eq!(
                decode_short(&keys, &text),
                Err(NameError::Plaintext),
                "{plain:?}"
            );
        }
        let valid = base32::encode(&sealed(b"a.txt"));
        assert_eq!(decode_short(&keys, &valid).unwrap(), "a.txt");
    }

    // Long entries

    #[test]
    fn long_entry_names_must_have_the_shape() {
        let keys = key_schedule();
        let (entry, content) = long_vector(&"f".repeat(100));
        let hash = entry.strip_suffix(".l").unwrap();
        let bad = [
            A_STORED.to_string(),
            format!("{hash}.n"),
            format!("{}.l", &hash[1..]),
            format!("{hash}a.l"),
            format!("{}.l", with_char(hash, 4, '0')),
        ];
        for entry in bad {
            let result = decode_long(&keys, &entry, &content);
            assert_eq!(result, Err(NameError::Entry), "{entry:?}");
        }
    }

    #[test]
    fn side_object_over_1024_bytes_is_refused() {
        let keys = key_schedule();
        let content = vec![0u8; 1025];
        let entry = long_entry_of(&content);
        assert_eq!(
            decode_long(&keys, &entry, &content),
            Err(NameError::SideObjectSize)
        );
        // At 1024 bytes the size check passes; the object is still too long
        // for any name.
        let content = vec![0u8; 1024];
        let entry = long_entry_of(&content);
        assert_eq!(decode_long(&keys, &entry, &content), Err(NameError::Length));
    }

    #[test]
    fn side_object_longer_than_any_name_is_refused() {
        let keys = key_schedule();
        let mut next = xorshift(0x9e37_79b9_7f4a_7c15);
        let content: Vec<u8> = (0..782).map(|_| next() as u8).collect();
        let entry = long_entry_of(&content);
        assert_eq!(decode_long(&keys, &entry, &content), Err(NameError::Length));
        // A sealed name of 781 bytes is the longest that decodes.
        let content = sealed("\u{6587}".repeat(255).as_bytes());
        assert_eq!(content.len(), 781);
        let entry = long_entry_of(&content);
        assert!(decode_long(&keys, &entry, &content).is_ok());
    }

    #[test]
    fn missing_or_wrong_side_object_is_refused() {
        let keys = key_schedule();
        let (entry, _) = long_vector(&"g".repeat(150));
        let (_, other) = long_vector(&"h".repeat(150));
        let wrong: [&[u8]; 2] = [&[], &other];
        for wrong in wrong {
            assert_eq!(
                decode_long(&keys, &entry, wrong),
                Err(NameError::SideObjectHash),
                "len {}",
                wrong.len()
            );
        }
        // An entry that names empty content decodes no further.
        let empty = long_entry_of(&[]);
        assert_eq!(decode_long(&keys, &empty, &[]), Err(NameError::Length));
    }

    #[test]
    fn tampered_side_object_is_refused() {
        let keys = key_schedule();
        let (entry, mut bytes) = long_vector(&"i".repeat(144));
        bytes[40] ^= 0x01;
        // The entry still names the original content.
        assert_eq!(
            decode_long(&keys, &entry, &bytes),
            Err(NameError::SideObjectHash)
        );
        // Renaming the entry to match leaves the SIV to catch it.
        assert_eq!(
            decode_long(&keys, &long_entry_of(&bytes), &bytes),
            Err(NameError::Authentication)
        );
    }

    #[test]
    fn long_entry_with_an_invalid_plaintext_is_refused() {
        let keys = key_schedule();
        let decode = |plain: &[u8]| {
            let content = sealed(plain);
            decode_long(&keys, &long_entry_of(&content), &content)
        };
        // 256 units: refused as a name, though the SIV authenticates.
        assert_eq!(decode(&[b'a'; 256]), Err(NameError::Plaintext));
        assert_eq!(decode(&[b'a'; 255]).unwrap(), "a".repeat(255));
        assert_eq!(decode(b"\xff\xfe"), Err(NameError::Plaintext));
    }

    // Classification

    #[test]
    fn marker_is_a_marker_in_the_root_only() {
        assert_eq!(classify(MARKER_NAME, true), StoredKind::Marker);
        assert_eq!(classify(MARKER_NAME, false), StoredKind::Foreign);
        for name in [".SMB-ENCRYPTION", ".smb-encryption.l"] {
            assert_eq!(classify(name, true), StoredKind::Foreign, "{name:?}");
        }
    }

    #[test]
    fn near_misses_of_the_long_shapes_are_foreign() {
        let hash = N144_HASH;
        for name in [
            format!("{}.l", &hash[1..]),
            format!("{hash}a.n"),
            format!("{}.l", with_char(hash, 7, '8')),
            format!("{hash}.x"),
            format!("{hash}.ln"),
        ] {
            assert_eq!(classify(&name, false), StoredKind::Foreign, "{name:?}");
        }
    }

    #[test]
    fn alphabet_only_names_are_short_candidates() {
        assert_eq!(classify(A_STORED, false), StoredKind::ShortCandidate);
        assert_eq!(classify(N143_STORED, true), StoredKind::ShortCandidate);
        // Classification does not decode.
        for len in [1usize, 2, 3, 31, 32, 33, 34, 100, 255] {
            let name = "a".repeat(len);
            assert_eq!(
                classify(&name, false),
                StoredKind::ShortCandidate,
                "len {len}"
            );
        }
        for name in ["", "aB", "a0"] {
            assert_eq!(classify(name, false), StoredKind::Foreign, "{name:?}");
        }
    }

    #[test]
    fn every_encoded_entry_is_classified_by_its_shape() {
        let keys = key_schedule();
        for len in 1..=200usize {
            let stored = encode_name(&keys, &"m".repeat(len), 255).unwrap();
            match &stored.side_object {
                None => assert_eq!(classify(&stored.entry, true), StoredKind::ShortCandidate),
                Some(side) => {
                    assert_eq!(classify(&stored.entry, true), StoredKind::LongEntry);
                    assert_eq!(classify(&side.name, true), StoredKind::SideObject);
                }
            }
        }
    }

    #[test]
    fn side_object_name_follows_the_long_entry() {
        let stored = encoded(&"a".repeat(144), 255);
        let side = stored.side_object.unwrap();
        assert_eq!(side_object_name(&stored.entry), Some(side.name));
        let not_long = [
            format!("{N144_HASH}.n"),
            format!("{}.l", &N144_HASH[1..]),
            A_STORED.to_string(),
        ];
        for name in not_long {
            assert_eq!(side_object_name(&name), None, "{name:?}");
        }
    }

    // Untrusted input

    #[test]
    fn arbitrary_stored_names_are_refused_without_panicking() {
        let keys = key_schedule();
        let mut next = xorshift(0x2545_f491_4f6c_dd1d);
        for len in 0..=300usize {
            for _ in 0..40 {
                let text: String = (0..len)
                    .map(|_| char::from(ALPHABET.as_bytes()[(next() & 31) as usize]))
                    .collect();
                assert!(decode_short(&keys, &text).is_err());
            }
            let junk: String = (0..len)
                .filter_map(|_| char::from_u32((next() % 0x250) as u32 + 0x20))
                .collect();
            assert!(decode_short(&keys, &junk).is_err());
        }
    }
}
