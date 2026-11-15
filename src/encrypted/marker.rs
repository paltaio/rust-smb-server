//! The marker object in the root of a share: format version, settings and a
//! MAC that rejects a wrong key or an altered marker.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::format::{
    BlockShift, FORMAT_VERSION, MARKER_LEN, MIN_LONG_NAME_THRESHOLD, SHARE_ID_LEN,
};
use super::keys::KeySchedule;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"smbencmk";
const NAMES_ENCRYPTED: u8 = 1;
/// Bytes the MAC covers.
pub(super) const BODY_LEN: usize = MARKER_LEN - 32;

/// Settings a share keeps for its whole life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MarkerSettings {
    pub(crate) encrypt_names: bool,
    pub(crate) block_shift: BlockShift,
    /// Longest stored name, 62 to 255; 0 when names are not encrypted.
    pub(crate) long_name_threshold: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MarkerError {
    /// Wrong size, magic or field values; or settings a marker cannot hold.
    Invalid,
    /// A format version this build does not read.
    Unsupported(u8),
    /// The MAC does not verify under the key.
    KeyMismatch,
}

impl MarkerSettings {
    fn threshold_fits_names(&self) -> bool {
        if self.encrypt_names {
            self.long_name_threshold >= MIN_LONG_NAME_THRESHOLD
        } else {
            self.long_name_threshold == 0
        }
    }
}

fn marker_mac(keys: &KeySchedule) -> HmacSha256 {
    let key = keys.marker_key();
    HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC-SHA-256 accepts keys of any length")
}

/// The marker made of `body` and the MAC over it.
pub(super) fn sign(keys: &KeySchedule, body: &[u8; BODY_LEN]) -> [u8; MARKER_LEN] {
    let mut mac = marker_mac(keys);
    mac.update(body);
    let mut out = [0u8; MARKER_LEN];
    out[..BODY_LEN].copy_from_slice(body);
    out[BODY_LEN..].copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// The marker of a share with `settings` and a random `share_id`.
///
/// Fails with `Invalid` when the threshold does not fit the names setting.
pub(crate) fn build_marker(
    settings: &MarkerSettings,
    share_id: &[u8; SHARE_ID_LEN],
    keys: &KeySchedule,
) -> Result<[u8; MARKER_LEN], MarkerError> {
    if !settings.threshold_fits_names() {
        return Err(MarkerError::Invalid);
    }
    let mut body = [0u8; BODY_LEN];
    body[..8].copy_from_slice(MAGIC);
    body[8] = FORMAT_VERSION;
    body[9] = if settings.encrypt_names {
        NAMES_ENCRYPTED
    } else {
        0
    };
    body[10] = settings.block_shift.get();
    body[11] = settings.long_name_threshold;
    body[12..].copy_from_slice(share_id);
    Ok(sign(keys, &body))
}

/// Settings of the marker `bytes`, checked in this order: length, magic,
/// version, MAC, field values.
pub(crate) fn parse_marker(
    bytes: &[u8],
    keys: &KeySchedule,
) -> Result<MarkerSettings, MarkerError> {
    let bytes: &[u8; MARKER_LEN] = bytes.try_into().map_err(|_| MarkerError::Invalid)?;
    let (body, tag) = bytes.split_at(BODY_LEN);
    if body[..8] != MAGIC[..] {
        return Err(MarkerError::Invalid);
    }
    if body[8] != FORMAT_VERSION {
        return Err(MarkerError::Unsupported(body[8]));
    }
    let mut mac = marker_mac(keys);
    mac.update(body);
    mac.verify_slice(tag)
        .map_err(|_| MarkerError::KeyMismatch)?;

    let flags = body[9];
    if flags & !NAMES_ENCRYPTED != 0 {
        return Err(MarkerError::Invalid);
    }
    let settings = MarkerSettings {
        encrypt_names: flags & NAMES_ENCRYPTED != 0,
        block_shift: BlockShift::new(body[10]).ok_or(MarkerError::Invalid)?,
        long_name_threshold: body[11],
    };
    if !settings.threshold_fits_names() {
        return Err(MarkerError::Invalid);
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{key_schedule, other_key_schedule, unhex};
    use super::*;

    const MARKER: &str = concat!(
        "736d62656e636d6b010110ff101112131415161718191a1b1c1d1e1f",
        "8d64acbdea318b4e8780ba228f3f347cf93d05c0fc9e0e1e47c8d3e7d9f95a7b",
    );

    /// Share id 0x10..=0x1f.
    fn share_id() -> [u8; SHARE_ID_LEN] {
        std::array::from_fn(|i| 0x10 + i as u8)
    }

    fn defaults() -> MarkerSettings {
        MarkerSettings {
            encrypt_names: true,
            block_shift: BlockShift::DEFAULT,
            long_name_threshold: 255,
        }
    }

    fn marker(settings: &MarkerSettings) -> [u8; MARKER_LEN] {
        build_marker(settings, &share_id(), &key_schedule()).unwrap()
    }

    /// The default marker with `edit` applied to the MAC-covered bytes and
    /// the MAC computed again.
    fn edited(edit: impl FnOnce(&mut [u8; BODY_LEN])) -> [u8; MARKER_LEN] {
        let mut body = [0u8; BODY_LEN];
        body.copy_from_slice(&marker(&defaults())[..BODY_LEN]);
        edit(&mut body);
        sign(&key_schedule(), &body)
    }

    fn parse(bytes: &[u8]) -> Result<MarkerSettings, MarkerError> {
        parse_marker(bytes, &key_schedule())
    }

    #[test]
    fn marker_vector() {
        assert_eq!(marker(&defaults()).as_slice(), unhex(MARKER));
        assert_eq!(parse(&unhex(MARKER)), Ok(defaults()));
    }

    #[test]
    fn round_trips_settings() {
        for (encrypt_names, threshold) in [(true, 62), (true, 100), (true, 255), (false, 0)] {
            let settings = MarkerSettings {
                encrypt_names,
                block_shift: BlockShift::new(BlockShift::MIN).unwrap(),
                long_name_threshold: threshold,
            };
            assert_eq!(parse(&marker(&settings)), Ok(settings));
        }
    }

    #[test]
    fn build_rejects_a_threshold_that_does_not_fit_the_names_setting() {
        for (encrypt_names, threshold) in [(true, 0), (true, 61), (false, 1), (false, 255)] {
            let settings = MarkerSettings {
                long_name_threshold: threshold,
                encrypt_names,
                ..defaults()
            };
            assert_eq!(
                build_marker(&settings, &share_id(), &key_schedule()),
                Err(MarkerError::Invalid),
                "names {encrypt_names}, threshold {threshold}"
            );
        }
    }

    #[test]
    fn wrong_length_is_invalid() {
        let good = marker(&defaults());
        assert_eq!(parse(&good[..59]), Err(MarkerError::Invalid), "short");
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(parse(&long), Err(MarkerError::Invalid), "long");
    }

    #[test]
    fn bad_magic_is_invalid_before_anything_else() {
        let mut bytes = marker(&defaults());
        bytes[0] ^= 0x01;
        assert_eq!(parse(&bytes), Err(MarkerError::Invalid));
        bytes[8] = 9;
        assert_eq!(parse(&bytes), Err(MarkerError::Invalid));
    }

    #[test]
    fn unknown_version_is_unsupported_before_the_mac() {
        let mut bytes = marker(&defaults());
        bytes[8] = 2;
        assert_eq!(parse(&bytes), Err(MarkerError::Unsupported(2)));
    }

    #[test]
    fn mac_mismatch_is_a_key_mismatch() {
        assert_eq!(
            parse_marker(&marker(&defaults()), &other_key_schedule()),
            Err(MarkerError::KeyMismatch)
        );
        for at in 9..MARKER_LEN {
            let mut bytes = marker(&defaults());
            bytes[at] ^= 0x01;
            assert_eq!(parse(&bytes), Err(MarkerError::KeyMismatch), "byte {at}");
        }
    }

    #[test]
    fn mac_is_checked_before_field_values() {
        let mut bytes = marker(&defaults());
        bytes[9] = 0x02;
        bytes[10] = 99;
        assert_eq!(parse(&bytes), Err(MarkerError::KeyMismatch));
    }

    #[test]
    fn bad_field_values_are_invalid() {
        for bit in 1..8 {
            let flags = NAMES_ENCRYPTED | (1 << bit);
            assert_eq!(
                parse(&edited(|body| body[9] = flags)),
                Err(MarkerError::Invalid),
                "flags {flags:#x}"
            );
        }
        assert_eq!(
            parse(&edited(|body| body[10] = 12)),
            Err(MarkerError::Invalid),
            "shift 12"
        );
        for threshold in [0, 1, 61] {
            assert_eq!(
                parse(&edited(|body| body[11] = threshold)),
                Err(MarkerError::Invalid),
                "names on, threshold {threshold}"
            );
        }
        for threshold in [1, 62, 255] {
            assert_eq!(
                parse(&edited(|body| {
                    body[9] = 0;
                    body[11] = threshold;
                })),
                Err(MarkerError::Invalid),
                "names off, threshold {threshold}"
            );
        }
    }
}
