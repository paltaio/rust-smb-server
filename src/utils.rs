//! Small helpers shared across modules.

use std::time::{SystemTime, UNIX_EPOCH};

/// Number of 100-nanosecond intervals between 1601-01-01 (Windows FILETIME
/// epoch) and 1970-01-01 (UNIX epoch). 369 years.
pub(crate) const FILETIME_OFFSET: u64 = 116_444_736_000_000_000;

/// Convert a `SystemTime` to a Windows FILETIME (100ns ticks since 1601).
pub fn system_time_to_filetime(t: SystemTime) -> u64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => FILETIME_OFFSET + (d.as_secs() * 10_000_000) + (d.subsec_nanos() as u64 / 100),
        // Pre-1970: clamp to the FILETIME epoch.
        Err(_) => 0,
    }
}

/// Convert "now" to FILETIME.
pub fn now_filetime() -> u64 {
    system_time_to_filetime(SystemTime::now())
}

/// Encode a `&str` to little-endian UTF-16 bytes.
pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Decode a UTF-16LE byte slice into a `Vec<u16>`, returning `None` on a
/// non-aligned buffer.
pub fn utf16le_to_units(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(
        bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect(),
    )
}

/// Fill `out` from the OS RNG.
pub fn fill_random(out: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(out)
}
