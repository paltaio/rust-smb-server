//! Fixtures shared by the unit tests.

use zeroize::Zeroizing;

use super::keys::KeySchedule;

pub(super) fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// Schedule of the key 0x00..=0x1f.
pub(super) fn key_schedule() -> KeySchedule {
    KeySchedule::new(Zeroizing::new(std::array::from_fn(|i| i as u8)))
}

/// Schedule of a key other than the one of `key_schedule`.
pub(super) fn other_key_schedule() -> KeySchedule {
    KeySchedule::new(Zeroizing::new([7u8; 32]))
}

/// File id 0xa0..=0xaf.
pub(super) fn file_id() -> [u8; 16] {
    std::array::from_fn(|i| 0xa0 + i as u8)
}

/// A xorshift64 generator; `seed` must not be zero.
pub(super) fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}
