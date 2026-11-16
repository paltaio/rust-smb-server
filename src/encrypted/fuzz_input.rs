//! Runs bytes that stored data may hold through the parsers of the encrypted
//! backend, for the `encrypted_input` fuzz target and for the tests.
//!
//! The first byte of the input picks a parser and the rest is its payload.

use std::sync::OnceLock;

use zeroize::Zeroizing;

use super::base32::{self, is_alphabet};
use super::block::{BlockError, FileCipher};
use super::format::{
    BlockShift, FILE_ID_LEN, FORMAT_VERSION, HEADER_LEN, MARKER_LEN, MARKER_NAME, MAX_STORED_SIZE,
    MIN_LONG_NAME_THRESHOLD, NONCE_LEN, OVERHEAD, SHARE_ID_LEN, is_zero,
};
use super::header::{Header, HeaderError};
use super::keys::KeySchedule;
use super::marker::{BODY_LEN, MarkerError, MarkerSettings, build_marker, parse_marker, sign};
use super::names::{
    LONG_SUFFIX, MAX_SEALED_LEN, MAX_SIDE_OBJECT_LEN, MAX_STORED_NAME_LEN, NameError, SIV_LEN,
    StoredKind, classify, decode_long, decode_short, encode_name, long_hash, seal_unchecked,
    side_object_name,
};
use super::size::{
    BlockRange, LogicalSize, StoredKind as StoredSizeKind, block_range, expected_stored_size,
    logical_size, stored_size,
};
use crate::path::is_valid_component;

/// The key every parser runs under.
const KEY: [u8; 32] = [0x6b; 32];

const MARKER_MAGIC: &[u8] = b"smbencmk";

/// Bytes past the stored size of a block that a run hands over with buffers of
/// the matching length, so that only the length checks refuse them.
const PAST: usize = 4;

/// The parser of each pick, taken modulo the length of the table.
const PARSERS: [fn(&[u8]) -> bool; 6] = [marker, header, short_name, long_name, sizes, block];

fn keys() -> &'static KeySchedule {
    static KEYS: OnceLock<KeySchedule> = OnceLock::new();
    KEYS.get_or_init(|| KeySchedule::new(Zeroizing::new(KEY)))
}

/// The index in `PARSERS` of the parser that `pick` stands for.
fn parser_of(pick: u8) -> usize {
    usize::from(pick) % PARSERS.len()
}

/// What `fuzzing::encrypted_input` runs. Returns whether the parser took the
/// payload as valid.
pub(crate) fn run(data: &[u8]) -> bool {
    match data.split_first() {
        Some((&pick, payload)) => PARSERS[parser_of(pick)](payload),
        None => false,
    }
}

/// The long entry name that `side` hashes to.
fn hashed_entry(side: &[u8]) -> String {
    format!("{}{LONG_SUFFIX}", long_hash(side))
}

/// Whether `len` bytes can be the AES-SIV output of a name.
fn is_sealed_len(len: usize) -> bool {
    (SIV_LEN + 1..=MAX_SEALED_LEN).contains(&len)
}

/// `bytes` cut or padded with zeros to `N` bytes.
fn padded<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let len = bytes.len().min(N);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// The block shift `pick` stands for, 13 to 20.
fn shift_of(pick: u8) -> BlockShift {
    BlockShift::new(BlockShift::MIN + pick % (BlockShift::MAX - BlockShift::MIN + 1))
        .expect("the shift is in range")
}

/// The longest prefix of `bytes` that is UTF-8.
fn utf8_prefix(bytes: &[u8]) -> &str {
    str::from_utf8(bytes).unwrap_or_else(|error| {
        str::from_utf8(&bytes[..error.valid_up_to()]).expect("the prefix is UTF-8")
    })
}

/// A marker, parsed as it is and as the first 28 bytes of it with a MAC of
/// the key.
fn marker(payload: &[u8]) -> bool {
    let keys = keys();
    let parsed = parse_marker(payload, keys);
    if payload.len() != MARKER_LEN {
        assert_eq!(parsed, Err(MarkerError::Invalid));
    }
    match parsed {
        Ok(settings) => {
            let share_id: [u8; SHARE_ID_LEN] = padded(&payload[BODY_LEN - SHARE_ID_LEN..]);
            let rebuilt = build_marker(&settings, &share_id, keys).expect("the settings fit");
            assert_eq!(rebuilt.as_slice(), payload);
        }
        Err(MarkerError::Unsupported(version)) => {
            assert!(payload.starts_with(MARKER_MAGIC));
            assert!(version == payload[8] && version != FORMAT_VERSION);
        }
        Err(MarkerError::KeyMismatch) => {
            assert!(payload.starts_with(MARKER_MAGIC) && payload[8] == FORMAT_VERSION);
        }
        Err(MarkerError::Invalid) => {}
    }

    let body: [u8; BODY_LEN] = padded(payload);
    assert_eq!(
        parse_marker(&sign(keys, &body), keys),
        expected_marker(&body)
    );
    parsed.is_ok()
}

/// What a marker body with a MAC of the key parses to.
fn expected_marker(body: &[u8; BODY_LEN]) -> Result<MarkerSettings, MarkerError> {
    if !body.starts_with(MARKER_MAGIC) {
        return Err(MarkerError::Invalid);
    }
    if body[8] != FORMAT_VERSION {
        return Err(MarkerError::Unsupported(body[8]));
    }
    let (flags, shift, threshold) = (body[9], body[10], body[11]);
    let threshold_fits = if flags == 1 {
        threshold >= MIN_LONG_NAME_THRESHOLD
    } else {
        threshold == 0
    };
    match BlockShift::new(shift) {
        Some(block_shift) if flags <= 1 && threshold_fits => Ok(MarkerSettings {
            encrypt_names: flags == 1,
            block_shift,
            long_name_threshold: threshold,
        }),
        _ => Err(MarkerError::Invalid),
    }
}

/// A shift byte and a header, parsed as they are, and a header made of the
/// first 16 bytes after the shift as its file id.
fn header(payload: &[u8]) -> bool {
    let Some((&pick, bytes)) = payload.split_first() else {
        return false;
    };
    let shift = shift_of(pick);
    let parsed = Header::parse(bytes, shift);
    match &parsed {
        Ok(header) => {
            assert_eq!(header.as_bytes()[..], *bytes);
            assert_eq!(header.block_shift(), shift);
            assert_eq!(Header::new(shift, header.file_id()).as_ref(), Some(header));
        }
        Err(error) if bytes.len() != HEADER_LEN => assert_eq!(*error, HeaderError::Invalid),
        Err(_) => {}
    }

    let file_id: [u8; FILE_ID_LEN] = padded(bytes);
    match Header::new(shift, file_id) {
        None => assert!(is_zero(&file_id)),
        Some(made) => {
            assert_eq!(made.file_id(), file_id);
            assert_eq!(Header::parse(made.as_bytes(), shift), Ok(made));
            let other = shift_of(pick.wrapping_add(1));
            assert_eq!(
                Header::parse(made.as_bytes(), other),
                Err(HeaderError::Invalid)
            );
        }
    }
    parsed.is_ok()
}

/// A flags byte, a threshold byte and a text. Bit 0 of the flags says the
/// text is in the root and the other bits pick the byte of a side object to
/// alter; the threshold byte picks a long-name threshold from 62 to 255. The
/// text is decoded as a short stored name and encoded as a plaintext name. The
/// bytes, as a plaintext that need not be a name, are sealed and decoded too.
fn short_name(payload: &[u8]) -> bool {
    let keys = keys();
    let Some(([flags, threshold], rest)) = payload.split_first_chunk() else {
        return false;
    };
    let text = utf8_prefix(rest);
    let in_root = flags & 1 == 1;

    let kind = classify(text, in_root);
    let alphabet = text.bytes().all(is_alphabet);
    assert_eq!(
        kind == StoredKind::ShortCandidate,
        alphabet && !text.is_empty()
    );
    assert_eq!(kind == StoredKind::Marker, in_root && text == MARKER_NAME);

    let decoded = decode_short(keys, text);
    if text.len() > MAX_STORED_NAME_LEN {
        assert_eq!(decoded, Err(NameError::Spelling));
    } else if !alphabet {
        assert_eq!(decoded, Err(NameError::Alphabet));
    }
    if let Ok(name) = &decoded {
        assert!(is_valid_component(name));
        let encoded = encode_name(keys, name, u8::MAX).expect("a decoded name is a component");
        assert_eq!(encoded.entry, text);
    }

    if is_sealed_len(SIV_LEN + rest.len()) {
        let sealed = seal_unchecked(keys, rest);
        let expected = match str::from_utf8(rest) {
            Ok(plain) if is_valid_component(plain) => Ok(plain.to_owned()),
            _ => Err(NameError::Plaintext),
        };
        assert_eq!(decode_long(keys, &hashed_entry(&sealed), &sealed), expected);
        if base32::encoded_len(sealed.len()) <= MAX_STORED_NAME_LEN {
            assert_eq!(decode_short(keys, &base32::encode(&sealed)), expected);
        }
    }

    let threshold = MIN_LONG_NAME_THRESHOLD + threshold % (u8::MAX - MIN_LONG_NAME_THRESHOLD + 1);
    match encode_name(keys, text, threshold) {
        None => assert!(!is_valid_component(text)),
        Some(stored) => {
            assert!(is_valid_component(text));
            match &stored.side_object {
                None => {
                    assert!(stored.entry.len() <= usize::from(threshold));
                    assert_eq!(classify(&stored.entry, false), StoredKind::ShortCandidate);
                    assert_eq!(decode_short(keys, &stored.entry).as_deref(), Ok(text));
                }
                Some(side) => {
                    assert!(is_sealed_len(side.content.len()));
                    assert_eq!(classify(&stored.entry, false), StoredKind::LongEntry);
                    assert_eq!(classify(&side.name, false), StoredKind::SideObject);
                    assert_eq!(side_object_name(&stored.entry).as_ref(), Some(&side.name));
                    assert_eq!(decode_short(keys, &stored.entry), Err(NameError::Alphabet));
                    assert_eq!(
                        decode_long(keys, &stored.entry, &side.content).as_deref(),
                        Ok(text)
                    );
                    let mut altered = side.content.clone();
                    let at = usize::from(*flags >> 1) % altered.len();
                    altered[at] ^= 1;
                    assert_eq!(
                        decode_long(keys, &stored.entry, &altered),
                        Err(NameError::SideObjectHash)
                    );
                }
            }
        }
    }
    decoded.is_ok()
}

/// A length byte, that many bytes of long entry name, and the rest as the
/// side object. The side object is also decoded under the entry name that
/// its own hash gives.
fn long_name(payload: &[u8]) -> bool {
    let keys = keys();
    let Some((&len, rest)) = payload.split_first() else {
        return false;
    };
    let (entry, side) = rest.split_at(usize::from(len).min(rest.len()));
    let entry = utf8_prefix(entry);

    let is_entry = classify(entry, false) == StoredKind::LongEntry;
    assert_eq!(side_object_name(entry).is_some(), is_entry);
    let decoded = decode_long(keys, entry, side);
    if !is_entry {
        assert_eq!(decoded, Err(NameError::Entry));
    } else if side.len() > MAX_SIDE_OBJECT_LEN {
        assert_eq!(decoded, Err(NameError::SideObjectSize));
    }
    if let Ok(name) = &decoded {
        assert!(is_valid_component(name));
        assert!(is_sealed_len(side.len()));
    }

    let hashed = decode_long(keys, &hashed_entry(side), side);
    if side.len() > MAX_SIDE_OBJECT_LEN {
        assert_eq!(hashed, Err(NameError::SideObjectSize));
    } else if !is_sealed_len(side.len()) {
        assert_eq!(hashed, Err(NameError::Length));
    } else if let Ok(name) = &hashed {
        assert!(is_valid_component(name));
    } else {
        assert!(matches!(
            hashed,
            Err(NameError::Authentication | NameError::Plaintext)
        ));
    }
    decoded.is_ok()
}

/// The range of blocks `first..=last` of a file of `logical` bytes, in 128
/// bits.
fn expected_range(shift: BlockShift, logical: u64, first: u64, last: u64) -> Option<BlockRange> {
    let (block, overhead) = (u128::from(shift.block_size()), OVERHEAD as u128);
    let (logical, first, last) = (u128::from(logical), u128::from(first), u128::from(last));
    if first > last || last * block >= logical {
        return None;
    }
    let count = last - first + 1;
    let plain_len = (count - 1) * block + (logical - last * block).min(block);
    Some(BlockRange {
        offset: u64::try_from(HEADER_LEN as u128 + first * (block + overhead)).ok()?,
        stored_len: u64::try_from(plain_len + count * overhead).ok()?,
        plain_len: u64::try_from(plain_len).ok()?,
    })
}

/// A shift byte and four big-endian `u64` words, padded with zeros: a stored
/// size, a logical size, and the first and last block of a range. Valid when
/// the stored size is one that a file has.
fn sizes(payload: &[u8]) -> bool {
    let shift = shift_of(payload.first().copied().unwrap_or_default());
    let word =
        |index: usize| u64::from_be_bytes(padded(payload.get(1 + 8 * index..).unwrap_or_default()));
    let (stored, logical, first, last) = (word(0), word(1), word(2), word(3));

    let info = logical_size(shift, stored);
    assert!(info.size <= stored);
    let normal = info.kind == StoredSizeKind::Normal;
    match stored_size(shift, info.size) {
        Some(back) => assert_eq!(back == stored, normal),
        None => assert!(stored > MAX_STORED_SIZE),
    }

    let mapped = stored_size(shift, logical);
    assert_eq!(mapped, expected_stored_size(shift, logical));
    if let Some(mapped) = mapped {
        let back = LogicalSize {
            size: logical,
            kind: StoredSizeKind::Normal,
        };
        assert_eq!(logical_size(shift, mapped), back);
    }
    assert_eq!(
        block_range(shift, logical, first, last),
        expected_range(shift, logical, first, last)
    );
    normal
}

/// A shift byte, a file id, a block index as a big-endian `u64` and stored
/// bytes. The stored bytes are opened as the block. Their first 12 bytes also
/// serve as a nonce and the bytes after them, up to one block and `PAST` bytes
/// more, as a plaintext to seal and open again.
fn block(payload: &[u8]) -> bool {
    const HEAD: usize = 1 + FILE_ID_LEN + 8;
    let Some((head, stored)) = payload.split_at_checked(HEAD) else {
        return false;
    };
    let shift = shift_of(head[0]);
    let file_id: [u8; FILE_ID_LEN] = padded(&head[1..]);
    let index = u64::from_be_bytes(padded(&head[1 + FILE_ID_LEN..]));
    let Some(header) = Header::new(shift, file_id) else {
        return false;
    };
    let cipher = FileCipher::new(keys(), header);
    let opened = open_checked(&cipher, shift, index, stored);
    seal_checked(&cipher, shift, file_id, index, stored, head[0]);
    opened
}

/// Opens `stored` as block `index` and checks the outcome. Returns whether it
/// opened.
fn open_checked(cipher: &FileCipher, shift: BlockShift, index: u64, stored: &[u8]) -> bool {
    let largest = shift.block_len() + OVERHEAD;
    let fits = (OVERHEAD + 1..=largest).contains(&stored.len());
    let out_len = if (OVERHEAD + 1..=largest + PAST).contains(&stored.len()) {
        stored.len() - OVERHEAD
    } else {
        0
    };
    let mut out = vec![0xee; out_len];
    let opened = cipher.open_block(index, stored, &mut out);
    if !fits {
        assert_eq!(opened, Err(BlockError::Length));
        assert!(out.iter().all(|&byte| byte == 0xee));
    } else if is_zero(stored) {
        assert_eq!(opened, Ok(()));
        assert!(is_zero(&out));
    } else if is_zero(&stored[..NONCE_LEN]) {
        assert_eq!(opened, Err(BlockError::ZeroNonce));
        assert!(out.iter().all(|&byte| byte == 0xee));
    } else if opened.is_ok() {
        let mut again = vec![0u8; stored.len()];
        cipher
            .seal_block(index, &padded(stored), &out, &mut again)
            .expect("an opened block seals again");
        assert_eq!(again, stored);
    } else {
        assert_eq!(opened, Err(BlockError::Authentication));
        assert!(is_zero(&out));
    }
    opened.is_ok()
}

/// Seals the bytes of `stored` after its nonce under that nonce, opens the
/// result, and opens it with a bit altered, at another index and under another
/// file id. `salt` picks the bit. The plaintext runs up to one block and
/// `PAST` bytes more; one that passes the block is refused.
fn seal_checked(
    cipher: &FileCipher,
    shift: BlockShift,
    file_id: [u8; FILE_ID_LEN],
    index: u64,
    stored: &[u8],
    salt: u8,
) {
    let nonce: [u8; NONCE_LEN] = padded(stored);
    let plain = stored.get(NONCE_LEN..).unwrap_or_default();
    let plain = &plain[..plain.len().min(shift.block_len() + PAST)];
    let mut sealed = vec![0u8; plain.len() + OVERHEAD];
    if let Err(error) = cipher.seal_block(index, &nonce, plain, &mut sealed) {
        if plain.is_empty() || plain.len() > shift.block_len() {
            assert_eq!(error, BlockError::Length);
        } else {
            assert_eq!(error, BlockError::ZeroNonce);
            assert!(is_zero(&nonce));
        }
        return;
    }
    assert_eq!(sealed[..NONCE_LEN], nonce);
    let mut back = vec![0u8; plain.len()];
    assert_eq!(cipher.open_block(index, &sealed, &mut back), Ok(()));
    assert_eq!(back, plain);

    let at = (index % sealed.len() as u64) as usize;
    let mut altered = sealed.clone();
    altered[at] ^= 1 << (salt % 8);
    assert!(matches!(
        cipher.open_block(index, &altered, &mut back),
        Err(BlockError::Authentication | BlockError::ZeroNonce)
    ));
    assert_eq!(
        cipher.open_block(index.wrapping_add(1), &sealed, &mut back),
        Err(BlockError::Authentication)
    );
    let mut other_id = file_id;
    other_id[FILE_ID_LEN - 1] ^= 0x80;
    if let Some(other) = Header::new(shift, other_id) {
        let other = FileCipher::new(keys(), other);
        assert_eq!(
            other.open_block(index, &sealed, &mut back),
            Err(BlockError::Authentication)
        );
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::panic;

    use super::super::testing::{file_id, other_file_id};
    use super::*;
    use crate::tests::data::{nonzero_pattern, xorshift};

    thread_local! {
        /// The largest allocation of this thread since the last reset.
        static LARGEST: Cell<usize> = const { Cell::new(0) };
    }

    struct Largest;

    fn note(size: usize) {
        LARGEST.with(|largest| largest.set(largest.get().max(size)));
    }

    unsafe impl GlobalAlloc for Largest {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note(layout.size());
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            note(layout.size());
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            note(new_size);
            unsafe { System.realloc(ptr, layout, new_size) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Largest = Largest;

    const MARKER: u8 = 0;
    const HEADER: u8 = 1;
    const SHORT_NAME: u8 = 2;
    const LONG_NAME: u8 = 3;
    const SIZES: u8 = 4;
    const BLOCK: u8 = 5;

    const SHARE_ID: [u8; SHARE_ID_LEN] = [0x10; SHARE_ID_LEN];

    /// An input and whether its parser takes it as valid.
    struct Seed {
        name: String,
        input: Vec<u8>,
        accepted: bool,
    }

    fn ok(name: impl Into<String>, input: Vec<u8>) -> Seed {
        Seed {
            name: name.into(),
            input,
            accepted: true,
        }
    }

    fn bad(name: impl Into<String>, input: Vec<u8>) -> Seed {
        Seed {
            name: name.into(),
            input,
            accepted: false,
        }
    }

    fn input(pick: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![pick];
        bytes.extend(parts.concat());
        bytes
    }

    /// Runs `input`, and checks that no allocation of the run passes the
    /// stored size of a block of the shift it names, with the bytes past it
    /// that a run allows, or 1024 bytes for the other parsers.
    fn run_bounded(input: &[u8]) -> bool {
        LARGEST.set(0);
        let outcome = panic::catch_unwind(|| run(input));
        let largest = LARGEST.get();
        let accepted = outcome.unwrap_or_else(|panic| {
            eprintln!("input {}", hex::encode(input));
            panic::resume_unwind(panic)
        });
        let limit = match input {
            [pick, shift, ..] if parser_of(*pick) == usize::from(BLOCK) => {
                shift_of(*shift).block_len() + OVERHEAD + PAST
            }
            _ => MAX_SIDE_OBJECT_LEN,
        };
        assert!(largest <= limit, "allocated {largest} bytes, limit {limit}");
        accepted
    }

    fn marker_seeds() -> Vec<Seed> {
        let make = |encrypt_names, shift, threshold| {
            let settings = MarkerSettings {
                encrypt_names,
                block_shift: BlockShift::new(shift).unwrap(),
                long_name_threshold: threshold,
            };
            build_marker(&settings, &SHARE_ID, keys()).unwrap()
        };
        let edited = |edit: fn(&mut [u8; BODY_LEN])| {
            let mut body: [u8; BODY_LEN] = padded(&make(true, 16, 255));
            edit(&mut body);
            sign(keys(), &body)
        };
        let wrap = |bytes: &[u8]| input(MARKER, &[bytes]);
        let good = make(true, 16, 255);
        let mut bad_mac = good;
        bad_mac[MARKER_LEN - 1] ^= 1;
        let mut future_bad_mac = edited(|b| b[8] = 2);
        future_bad_mac[MARKER_LEN - 1] ^= 1;
        vec![
            ok("marker with names", wrap(&good)),
            ok("marker without names", wrap(&make(false, 13, 0))),
            ok("marker with threshold 62", wrap(&make(true, 20, 62))),
            ok("marker with pick 252", input(252, &[&good])),
            bad("marker with a bad MAC", wrap(&bad_mac)),
            bad("marker of 59 bytes", wrap(&good[..59])),
            bad(
                "marker of 61 bytes",
                wrap(&[&good[..], &[0u8][..]].concat()),
            ),
            bad("marker without bytes", vec![MARKER]),
            bad("marker with another magic", wrap(&edited(|b| b[0] ^= 1))),
            bad("marker of version 2", wrap(&edited(|b| b[8] = 2))),
            bad("marker of version 2, bad MAC", wrap(&future_bad_mac)),
            bad("marker with flag 3", wrap(&edited(|b| b[9] = 3))),
            bad("marker with shift 12", wrap(&edited(|b| b[10] = 12))),
            bad("marker with shift 21", wrap(&edited(|b| b[10] = 21))),
            bad("marker with threshold 61", wrap(&edited(|b| b[11] = 61))),
            bad("marker with threshold 0", wrap(&edited(|b| b[11] = 0))),
            bad("marker, no names, threshold", wrap(&edited(|b| b[9] = 0))),
        ]
    }

    fn header_seeds() -> Vec<Seed> {
        let header_of = |pick: u8| *Header::new(shift_of(pick), file_id()).unwrap().as_bytes();
        let with = |pick: u8, bytes: &[u8]| input(HEADER, &[&[pick], bytes]);
        let good = header_of(3);
        let edited = |at: usize, value: u8| {
            let mut bytes = good;
            bytes[at] = value;
            with(3, &bytes)
        };
        let mut zero_id = good;
        zero_id[8..].fill(0);
        let mut seeds: Vec<Seed> = (0..8)
            .map(|pick| {
                let shift = shift_of(pick).get();
                ok(
                    format!("header of shift {shift}"),
                    with(pick, &header_of(pick)),
                )
            })
            .collect();
        seeds.extend([
            bad("header of another shift", with(4, &good)),
            bad("header with another magic", edited(0, b'x')),
            bad("header of version 2", edited(4, 2)),
            bad("header of suite 2", edited(5, 2)),
            bad("header with a reserved byte", edited(7, 1)),
            bad("header with a zero file id", with(3, &zero_id)),
            bad("header of 23 bytes", with(3, &good[..23])),
            bad(
                "header of 25 bytes",
                with(3, &[&good[..], &[0u8][..]].concat()),
            ),
            bad("header without bytes", with(3, &[])),
            bad("header without a shift", vec![HEADER]),
        ]);
        seeds
    }

    fn short_input(flags: u8, threshold: u8, text: &[u8]) -> Vec<u8> {
        input(SHORT_NAME, &[&[flags, threshold], text])
    }

    fn short_name_seeds() -> Vec<Seed> {
        let entry = |name: &str| encode_name(keys(), name, u8::MAX).unwrap().entry;
        let (a, longest) = (entry("a"), entry(&"n".repeat(143)));
        let stored = |text: &str| short_input(0, 0, text.as_bytes());
        let plain = |text: &str| short_input(0, 193, text.as_bytes());
        let long_entry = format!("{}{LONG_SUFFIX}", "a".repeat(32));
        let side_name = side_object_name(&long_entry).unwrap();
        let alphabet = "abcdefghijklmnopqrstuvwxyz234567".repeat(63);
        vec![
            ok("short name of 1 byte", stored(&a)),
            ok("short name of 143 bytes", stored(&longest)),
            bad("short name in capitals", stored(&a.to_uppercase())),
            bad("short name with a 1", stored(&format!("1{}", &a[1..]))),
            bad(
                "short name, other last bits",
                stored(&format!("{}r", &a[..27])),
            ),
            bad("short name of 9 characters", stored("aaaaaaaaa")),
            bad("short name of 255 characters", stored(&"a".repeat(255))),
            bad("short name of 256 characters", stored(&"a".repeat(256))),
            bad("short name of 2000 x", stored(&"x".repeat(2000))),
            bad("short name of 2000 hyphens", stored(&"-".repeat(2000))),
            bad(
                "short name of 2000 alphabet characters",
                stored(&alphabet[..2000]),
            ),
            bad("short name without bytes", stored("")),
            bad(
                "marker name in the root",
                short_input(1, 0, MARKER_NAME.as_bytes()),
            ),
            bad("side object name", stored(&side_name)),
            bad("long entry name", stored(&long_entry)),
            bad("plain name", stored("report.docx")),
            bad("plain name, long at 62", stored(&"q".repeat(40))),
            bad("plain name of 143 bytes", plain(&"n".repeat(143))),
            bad("plain name of 144 bytes", plain(&"n".repeat(144))),
            bad("plain name of 255 units", plain(&"\u{4e2d}".repeat(255))),
            bad("plain name of 256 units", plain(&"x".repeat(256))),
            bad("plain name with a control", stored("a\u{1}b")),
            bad("plain name with a slash", stored("a/b")),
            bad("plain dot", stored(".")),
            bad("plain dot dot", stored("..")),
            bad(
                "plain name that is not UTF-8",
                short_input(0, 0, &[0xff, 0xfe, b'a']),
            ),
            bad("plain byte that is not UTF-8", short_input(0, 0, &[0xff])),
        ]
    }

    fn long_input(entry: &[u8], side: &[u8]) -> Vec<u8> {
        input(
            LONG_NAME,
            &[&[u8::try_from(entry.len()).unwrap()], entry, side],
        )
    }

    fn long_name_seeds() -> Vec<Seed> {
        let pair = |name: &str| {
            let stored = encode_name(keys(), name, MIN_LONG_NAME_THRESHOLD).unwrap();
            (stored.entry, stored.side_object.unwrap().content)
        };
        let (entry, side) = pair(&"n".repeat(144));
        let (wide_entry, wide_side) = pair(&"\u{4e2d}".repeat(255));
        let (small_entry, small_side) = pair(&"x".repeat(40));
        let a = base32::decode(&encode_name(keys(), "a", u8::MAX).unwrap().entry).unwrap();
        let a_entry = hashed_entry(&a);
        let (mut longer, mut altered) = (side.clone(), side.clone());
        longer.push(0);
        altered[0] ^= 1;
        let side_name = side_object_name(&entry).unwrap();
        vec![
            ok(
                "long name of 144 bytes",
                long_input(entry.as_bytes(), &side),
            ),
            ok(
                "long name of 255 units",
                long_input(wide_entry.as_bytes(), &wide_side),
            ),
            ok(
                "long name of 40 bytes",
                long_input(small_entry.as_bytes(), &small_side),
            ),
            ok(
                "short name in long form",
                long_input(a_entry.as_bytes(), &a),
            ),
            bad(
                "side object and a byte",
                long_input(entry.as_bytes(), &longer),
            ),
            bad(
                "side object altered",
                long_input(entry.as_bytes(), &altered),
            ),
            bad(
                "side object of 1025 bytes",
                long_input(entry.as_bytes(), &[1; 1025]),
            ),
            bad(
                "side object of 1024 bytes",
                long_input(entry.as_bytes(), &[1; 1024]),
            ),
            bad(
                "side object of 800 bytes",
                long_input(entry.as_bytes(), &[1; 800]),
            ),
            bad(
                "side object without bytes",
                long_input(entry.as_bytes(), &[]),
            ),
            bad(
                "side object of 16 bytes",
                long_input(hashed_entry(&[1; 16]).as_bytes(), &[1; 16]),
            ),
            bad(
                "side object of 782 bytes",
                long_input(hashed_entry(&[1; 782]).as_bytes(), &[1; 782]),
            ),
            bad(
                "side object of 1025 bytes, own hash",
                long_input(hashed_entry(&[1; 1025]).as_bytes(), &[1; 1025]),
            ),
            bad(
                "side object name as entry",
                long_input(side_name.as_bytes(), &side),
            ),
            bad(
                "entry of 33 characters",
                long_input(&entry.as_bytes()[1..], &side),
            ),
            bad("entry that is not UTF-8", long_input(&[0xff; 34], &side)),
            bad(
                "length past the payload",
                input(LONG_NAME, &[&[255], entry.as_bytes()]),
            ),
            bad("long name without bytes", vec![LONG_NAME]),
        ]
    }

    fn sizes_seeds() -> Vec<Seed> {
        const H: u64 = HEADER_LEN as u64;
        const O: u64 = OVERHEAD as u64;
        const LAST_OF_SHIFT_13: u64 = (1 << 51) - 1;
        let mut seeds = Vec::new();
        for pick in [0u8, 3, 7] {
            let block = shift_of(pick).block_size();
            let full = block + O;
            // Stored size and whether it is one a file has, logical size,
            // and the first and last block of a range.
            let mut cases = vec![
                (0, true, 0, 0, 0),
                (1, false, 1, 0, 0),
                (H - 1, false, block - 1, 0, 0),
                (H, false, block, 0, 0),
                (H + 1, false, block + 1, 0, 1),
                (H + O, false, 2 * block, 1, 1),
                (H + O + 1, true, 2 * block + 1, 1, 2),
                (H + full, true, 3 * block + 5, 0, 2),
                (H + full + O, false, 4 * block, 3, 3),
                (H + full + O + 1, true, 1 << 40, 0, 1 << 27),
                (H + 2 * full, true, MAX_STORED_SIZE, 1 << 27, 1 << 27),
                (MAX_STORED_SIZE, true, MAX_STORED_SIZE + 1, 0, u64::MAX),
                (MAX_STORED_SIZE + 1, true, u64::MAX - 1, u64::MAX, u64::MAX),
                (u64::MAX, true, u64::MAX, 1, 0),
                (
                    0,
                    true,
                    1 << 40,
                    0,
                    1 << (u64::BITS - u32::from(shift_of(pick).get())),
                ),
            ];
            if pick == 0 {
                // The stored size of the logical size, the stored length of the
                // range and its offset each overflow 64 bits.
                cases.extend([
                    (0, true, u64::MAX, 0, LAST_OF_SHIFT_13),
                    (0, true, u64::MAX, LAST_OF_SHIFT_13, LAST_OF_SHIFT_13),
                    (0, true, 18_383_908_449_127_579_647, 0, 1),
                ]);
            }
            for (stored, accepted, logical, first, last) in cases {
                let mut bytes = vec![SIZES, pick];
                for word in [stored, logical, first, last] {
                    bytes.extend_from_slice(&word.to_be_bytes());
                }
                let name = format!(
                    "sizes at shift {}: stored {stored}, logical {logical}, blocks {first} to {last}",
                    shift_of(pick).get()
                );
                seeds.push(Seed {
                    name,
                    input: bytes,
                    accepted,
                });
            }
        }
        seeds
    }

    /// The stored block of `plain` at `index` under `file_id()`, with the
    /// nonce 7 in every byte.
    fn sealed(pick: u8, index: u64, plain: &[u8]) -> Vec<u8> {
        let header = Header::new(shift_of(pick), file_id()).unwrap();
        let mut out = vec![0u8; plain.len() + OVERHEAD];
        FileCipher::new(keys(), header)
            .seal_block(index, &[7; NONCE_LEN], plain, &mut out)
            .unwrap();
        out
    }

    fn block_input(pick: u8, id: &[u8], index: u64, stored: &[u8]) -> Vec<u8> {
        input(BLOCK, &[&[pick], id, &index.to_be_bytes(), stored])
    }

    fn block_seeds() -> Vec<Seed> {
        const FULL: usize = 8192;
        let plain = nonzero_pattern(FULL);
        let largest: Vec<u8> = (0..1u32 << BlockShift::MAX)
            .map(|i| (i % 251) as u8)
            .collect();
        let at = |pick: u8, index: u64, stored: &[u8]| block_input(pick, &file_id(), index, stored);
        let (mut tag, mut data, mut nonce) = (
            sealed(0, 0, &plain[..100]),
            sealed(0, 0, &plain[..100]),
            sealed(0, 0, &plain[..100]),
        );
        *tag.last_mut().unwrap() ^= 1;
        data[20] ^= 1;
        nonce[0] ^= 1;
        let zero_nonce = [&[0u8; NONCE_LEN][..], &[1u8; 20][..]].concat();
        let largest_len = (1usize << BlockShift::MAX) + OVERHEAD;
        let nonce_and = |len: usize| [&[7u8; NONCE_LEN][..], &nonzero_pattern(len)].concat();
        let (full_plain, one_over) = (nonce_and(FULL), nonce_and(FULL + 1));
        vec![
            ok("block of 1 byte", at(0, 0, &sealed(0, 0, &plain[..1]))),
            ok("block of 100 bytes", at(0, 5, &sealed(0, 5, &plain[..100]))),
            ok("full block", at(0, 1 << 40, &sealed(0, 1 << 40, &plain))),
            ok("block of shift 16", at(3, 2, &sealed(3, 2, &plain[..300]))),
            ok("largest block", at(7, 3, &sealed(7, 3, &largest))),
            ok("hole of a full block", at(0, 0, &[0; FULL + OVERHEAD])),
            ok("hole of 1 byte", at(0, 0, &[0; OVERHEAD + 1])),
            ok("hole of the largest block", at(7, 0, &vec![0; largest_len])),
            bad("block of 28 bytes", at(0, 0, &[1; OVERHEAD])),
            bad("block without bytes", at(0, 0, &[])),
            bad(
                "hole of 1 byte over a block",
                at(0, 0, &[0; FULL + OVERHEAD + 1]),
            ),
            bad(
                "block of 1 byte over",
                at(0, 0, &vec![1; FULL + OVERHEAD + 1]),
            ),
            bad(
                "block of 4 bytes over",
                at(0, 0, &vec![1; FULL + OVERHEAD + PAST]),
            ),
            bad(
                "block of 5 bytes over",
                at(0, 0, &vec![1; FULL + OVERHEAD + PAST + 1]),
            ),
            bad(
                "block of 1000 bytes over",
                at(0, 0, &vec![1; FULL + OVERHEAD + 1000]),
            ),
            bad(
                "hole of 1 byte over the largest block",
                at(7, 0, &vec![0; largest_len + 1]),
            ),
            bad("block with a plaintext of a block", at(0, 0, &full_plain)),
            bad("block with a plaintext of 1 byte over", at(0, 0, &one_over)),
            bad("block with a zero nonce", at(0, 0, &zero_nonce)),
            bad("block with a flipped tag", at(0, 0, &tag)),
            bad("block with a flipped byte", at(0, 0, &data)),
            bad("block with a flipped nonce", at(0, 0, &nonce)),
            bad(
                "block at another index",
                at(0, 2, &sealed(0, 1, &plain[..100])),
            ),
            bad(
                "block of another file",
                block_input(0, &other_file_id(), 0, &sealed(0, 0, &plain[..100])),
            ),
            bad(
                "block of another shift",
                at(1, 0, &sealed(0, 0, &plain[..100])),
            ),
            bad(
                "block with a zero file id",
                block_input(0, &[0; FILE_ID_LEN], 0, &[1; 40]),
            ),
            bad("block cut inside the head", vec![BLOCK, 0, 1, 2, 3]),
        ]
    }

    fn seeds() -> Vec<Seed> {
        [
            marker_seeds(),
            header_seeds(),
            short_name_seeds(),
            long_name_seeds(),
            sizes_seeds(),
            block_seeds(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// A random input: bytes, or a seed with up to three edits.
    fn generate(next: &mut impl FnMut() -> u64, pools: &[Vec<Vec<u8>>]) -> Vec<u8> {
        if next().is_multiple_of(4) {
            let len = if next().is_multiple_of(16) {
                next() % 3000
            } else {
                next() % 130
            };
            return (0..len).map(|_| next() as u8).collect();
        }
        let pool = &pools[(next() % pools.len() as u64) as usize];
        let mut bytes = pool[(next() % pool.len() as u64) as usize].clone();
        for _ in 0..next() % 4 {
            let len = bytes.len() as u64;
            match next() % 5 {
                0 if len > 0 => bytes[(next() % len) as usize] ^= 1 << (next() % 8),
                1 if len > 0 => bytes[(next() % len) as usize] = next() as u8,
                2 => bytes.truncate((next() % (len + 1)) as usize),
                3 => {
                    let extra = next() % 40;
                    bytes.extend((0..extra).map(|_| next() as u8));
                }
                _ if len > 0 => bytes[0] = next() as u8,
                _ => {}
            }
        }
        bytes
    }

    #[test]
    fn seeds_are_accepted_or_refused_as_labelled() {
        let seeds = seeds();
        let mut names = HashSet::new();
        for seed in &seeds {
            assert!(names.insert(&seed.name), "two seeds named {}", seed.name);
            let accepted = run_bounded(&seed.input);
            assert_eq!(accepted, seed.accepted, "seed {}", seed.name);
        }
        for parser in 0..PARSERS.len() {
            let of = |accepted| {
                seeds
                    .iter()
                    .any(|seed| parser_of(seed.input[0]) == parser && seed.accepted == accepted)
            };
            assert!(of(true) && of(false), "parser {parser}");
        }
        assert!(!run(&[]));
    }

    #[test]
    fn generated_inputs_pass_every_parser_check() {
        let mut pools = vec![Vec::new(); PARSERS.len()];
        for seed in seeds() {
            if seed.input.len() <= 2048 {
                pools[parser_of(seed.input[0])].push(seed.input);
            }
        }
        let mut next = xorshift(0x9e37_79b9_7f4a_7c15);
        let mut accepted = [0u32; PARSERS.len()];
        for _ in 0..100_000 {
            let input = generate(&mut next, &pools);
            if run_bounded(&input) {
                accepted[parser_of(input[0])] += 1;
            }
        }
        assert!(accepted.iter().all(|&count| count > 0), "{accepted:?}");
    }
}
