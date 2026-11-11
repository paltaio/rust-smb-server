//! The times and attributes stored with an object, and the `FileInfo` they
//! make.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::backend::{FILE_ATTRIBUTE_READONLY, FileInfo, VALID_SET_ATTRIBUTES};
use crate::utils::{FILETIME_OFFSET, system_time_to_filetime};

use super::keys::FileStamp;
use super::object::{Metadata, ObjectHead};

const MTIME: &str = "mtime";
const BTIME: &str = "btime";
const ATIME: &str = "atime";
const CTIME: &str = "ctime";
const ATTRIBUTES: &str = "smb-attributes";
const SOURCE_MILLIS: &str = "src_last_modified_millis";

/// Allocation sizes are multiples of this.
const ALLOCATION_UNIT: u64 = 4096;

const TICKS_PER_SECOND: u128 = 10_000_000;

/// The four times of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Times {
    created: SystemTime,
    accessed: SystemTime,
    written: SystemTime,
    changed: SystemTime,
}

impl Times {
    /// All four times at `time`.
    fn all(time: SystemTime) -> Self {
        Times {
            created: time,
            accessed: time,
            written: time,
            changed: time,
        }
    }
}

/// The times an object has: those stored in its user metadata, with the write
/// time falling back to `src_last_modified_millis` (Unix milliseconds) and then
/// to `Last-Modified`, and the other times to the write time.
fn times(head: &ObjectHead) -> Times {
    let user = &head.metadata.user;
    let stored = |key: &str| user.get(key).and_then(|text| parse_seconds(text));
    let written = stored(MTIME)
        .or_else(|| user.get(SOURCE_MILLIS).and_then(|text| parse_millis(text)))
        .unwrap_or(head.last_modified);
    Times {
        created: stored(BTIME).unwrap_or(written),
        accessed: stored(ATIME).unwrap_or(written),
        written,
        changed: stored(CTIME).unwrap_or(written),
    }
}

/// The attributes stored with an object: READONLY and the flags a client can
/// set. DIRECTORY is never stored.
pub(super) fn attributes(head: &ObjectHead) -> u32 {
    head.metadata
        .user
        .get(ATTRIBUTES)
        .and_then(|text| parse_attributes(text))
        .unwrap_or(0)
        & VALID_SET_ATTRIBUTES
}

/// The four times of the object `head` describes as FILETIME ticks: creation,
/// access, write and change.
pub(super) fn head_times(head: &ObjectHead) -> [u64; 4] {
    let times = times(head);
    [times.created, times.accessed, times.written, times.changed].map(system_time_to_filetime)
}

/// All four times at `time`, as FILETIME ticks.
pub(super) fn same_times(time: SystemTime) -> [u64; 4] {
    [system_time_to_filetime(time); 4]
}

/// A FILETIME count of 100 ns ticks since 1601 as Unix seconds with nine
/// fraction digits, as `parse_seconds` reads them.
fn format_filetime(ticks: u64) -> String {
    let since_epoch = i128::from(ticks) - i128::from(FILETIME_OFFSET);
    let ticks = since_epoch.unsigned_abs();
    format!(
        "{}{}.{:09}",
        if since_epoch < 0 { "-" } else { "" },
        ticks / TICKS_PER_SECOND,
        ticks % TICKS_PER_SECOND * 100
    )
}

/// The user metadata that stores `times` (FILETIME ticks) and `attributes`.
pub(super) fn stored_metadata(times: [u64; 4], attributes: u32) -> BTreeMap<String, String> {
    let [created, accessed, written, changed] = times;
    [
        (BTIME, format_filetime(created)),
        (ATIME, format_filetime(accessed)),
        (MTIME, format_filetime(written)),
        (CTIME, format_filetime(changed)),
        (ATTRIBUTES, format!("{attributes:x}")),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}

/// The content type of the marker object of a directory.
pub(super) const MARKER_TYPE: &str = "application/x-directory";

/// The metadata of the marker object of a directory with these times and
/// attributes.
pub(super) fn marker_metadata(times: [u64; 4], attributes: u32) -> Metadata {
    Metadata {
        user: stored_metadata(times, attributes),
        content_type: Some(MARKER_TYPE.to_owned()),
        ..Metadata::default()
    }
}

/// Unix seconds with an optional fraction, as in `1700000000.123456789`.
/// Digits of the fraction past the ninth are dropped.
fn parse_seconds(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (whole, fraction) = match unsigned.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (unsigned, ""),
    };
    let digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(fraction) {
        return None;
    }
    if unsigned.contains('.') && fraction.is_empty() {
        return None;
    }
    let secs: u64 = whole.parse().ok()?;
    let mut nanos = 0u32;
    for (place, digit) in fraction.bytes().take(9).enumerate() {
        nanos += u32::from(digit - b'0') * 10u32.pow(8 - place as u32);
    }
    let offset = Duration::new(secs, nanos);
    if negative {
        UNIX_EPOCH.checked_sub(offset)
    } else {
        UNIX_EPOCH.checked_add(offset)
    }
}

/// Unix milliseconds, the form of `src_last_modified_millis`.
fn parse_millis(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let millis: u64 = text.parse().ok()?;
    UNIX_EPOCH.checked_add(Duration::from_millis(millis))
}

fn parse_attributes(text: &str) -> Option<u32> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

fn info(name: &str, is_directory: bool, size: u64, times: Times, attributes: u32) -> FileInfo {
    let ticks = [times.created, times.accessed, times.written, times.changed];
    entry_info(
        name,
        is_directory,
        size,
        ticks.map(system_time_to_filetime),
        attributes,
    )
}

/// The `FileInfo` of a file or directory with these times as FILETIME ticks
/// (creation, access, write, change) and these attributes.
pub(super) fn entry_info(
    name: &str,
    is_directory: bool,
    size: u64,
    times: [u64; 4],
    attributes: u32,
) -> FileInfo {
    let mut info = FileInfo::new(name);
    if !is_directory {
        info.end_of_file = size;
        info.allocation_size = size
            .checked_next_multiple_of(ALLOCATION_UNIT)
            .unwrap_or(size);
    }
    [
        info.creation_time,
        info.last_access_time,
        info.last_write_time,
        info.change_time,
    ] = times;
    info.is_directory = is_directory;
    info.read_only = attributes & FILE_ATTRIBUTE_READONLY != 0;
    info.file_attributes = attributes & VALID_SET_ATTRIBUTES;
    info
}

/// The `FileInfo` of the object `head` describes.
pub(super) fn file_info(name: &str, head: &ObjectHead) -> FileInfo {
    info(name, false, head.size, times(head), attributes(head))
}

/// The `FileInfo` of a directory with the marker object `marker`. A directory
/// without one has no stored times, so all four are `fallback`.
pub(super) fn dir_info(name: &str, marker: Option<&ObjectHead>, fallback: SystemTime) -> FileInfo {
    match marker {
        Some(head) => info(name, true, 0, times(head), attributes(head)),
        None => info(name, true, 0, Times::all(fallback), 0),
    }
}

/// The `FileInfo` of an object a listing names but whose metadata was not
/// read: every time is `Last-Modified`.
pub(super) fn stamp_info(name: &str, stamp: &FileStamp) -> FileInfo {
    info(name, false, stamp.size, Times::all(stamp.last_modified), 0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::backend::{FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN};
    use crate::s3::object::Metadata;
    use crate::utils::FILETIME_OFFSET;

    const TICKS: u64 = 10_000_000;

    fn at(secs: u64, nanos: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, nanos)
    }

    fn head(user: &[(&str, &str)]) -> ObjectHead {
        ObjectHead {
            size: 10,
            etag: "\"e\"".into(),
            last_modified: at(1_000, 0),
            metadata: Metadata {
                user: user
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect::<BTreeMap<_, _>>(),
                ..Metadata::default()
            },
        }
    }

    #[test]
    fn seconds_with_up_to_nine_fraction_digits_parse() {
        assert_eq!(parse_seconds("1700000000"), Some(at(1_700_000_000, 0)));
        assert_eq!(
            parse_seconds("1700000000.5"),
            Some(at(1_700_000_000, 500_000_000))
        );
        assert_eq!(
            parse_seconds("1700000000.123456789"),
            Some(at(1_700_000_000, 123_456_789))
        );
        assert_eq!(parse_seconds("0.000000001"), Some(at(0, 1)));
        assert_eq!(parse_seconds("0"), Some(UNIX_EPOCH));
        assert_eq!(parse_seconds(" 12.25 "), Some(at(12, 250_000_000)));
        assert_eq!(parse_seconds("007.5"), Some(at(7, 500_000_000)));
    }

    #[test]
    fn extra_fraction_digits_are_dropped() {
        assert_eq!(parse_seconds("5.1234567899999"), Some(at(5, 123_456_789)));
    }

    #[test]
    fn seconds_before_1970_parse() {
        assert_eq!(
            parse_seconds("-1.5"),
            Some(UNIX_EPOCH - Duration::new(1, 500_000_000))
        );
        assert_eq!(parse_seconds("-0"), Some(UNIX_EPOCH));
    }

    #[test]
    fn text_that_is_not_seconds_does_not_parse() {
        for bad in [
            "",
            " ",
            ".",
            ".5",
            "5.",
            "1e9",
            "1.5e9",
            "+5",
            "--5",
            "5.-1",
            "0x10",
            "1,5",
            "abc",
            "1 2",
            "99999999999999999999",
            "1.2.3",
            "\u{661}",
        ] {
            assert_eq!(parse_seconds(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn milliseconds_parse() {
        assert_eq!(
            parse_millis("1700000000123"),
            Some(at(1_700_000_000, 123_000_000))
        );
        assert_eq!(parse_millis("0"), Some(UNIX_EPOCH));
        for bad in ["", "-1", "1.5", "x", "18446744073709551616"] {
            assert_eq!(parse_millis(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn attributes_parse_as_hex() {
        assert_eq!(parse_attributes("21"), Some(0x21));
        assert_eq!(parse_attributes("A1"), Some(0xa1));
        assert_eq!(parse_attributes("ffffffff"), Some(u32::MAX));
        for bad in ["", "0x21", "g", "-1", "100000000", "2 1"] {
            assert_eq!(parse_attributes(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn stored_times_win_over_last_modified() {
        let t = times(&head(&[
            ("mtime", "1700000000.123456789"),
            ("btime", "1600000000.5"),
            ("atime", "1800000000"),
            ("ctime", "1650000000.000000001"),
        ]));
        assert_eq!(t.written, at(1_700_000_000, 123_456_789));
        assert_eq!(t.created, at(1_600_000_000, 500_000_000));
        assert_eq!(t.accessed, at(1_800_000_000, 0));
        assert_eq!(t.changed, at(1_650_000_000, 1));
    }

    #[test]
    fn the_write_time_falls_back_to_the_source_time_and_then_last_modified() {
        let t = times(&head(&[("src_last_modified_millis", "1700000000250")]));
        assert_eq!(t, Times::all(at(1_700_000_000, 250_000_000)));
        let t = times(&head(&[
            ("mtime", "5"),
            ("src_last_modified_millis", "9000"),
        ]));
        assert_eq!(t.written, at(5, 0));
        let t = times(&head(&[]));
        assert_eq!(t, Times::all(at(1_000, 0)));
        let t = times(&head(&[
            ("mtime", "junk"),
            ("src_last_modified_millis", "junk"),
        ]));
        assert_eq!(t, Times::all(at(1_000, 0)));
        let t = times(&head(&[
            ("mtime", "junk"),
            ("src_last_modified_millis", "7000"),
        ]));
        assert_eq!(t, Times::all(at(7, 0)));
    }

    #[test]
    fn the_other_times_fall_back_to_the_resolved_write_time() {
        let t = times(&head(&[
            ("btime", "10"),
            ("src_last_modified_millis", "5000"),
        ]));
        assert_eq!(t.written, at(5, 0));
        assert_eq!(t.created, at(10, 0));
        assert_eq!(t.accessed, at(5, 0));
        assert_eq!(t.changed, at(5, 0));
        let t = times(&head(&[("mtime", "20"), ("atime", "junk")]));
        assert_eq!(t, Times::all(at(20, 0)));
    }

    #[test]
    fn a_file_describes_its_size_times_and_attributes() {
        let mut object = head(&[("mtime", "1700000000.123456789"), ("smb-attributes", "21")]);
        object.size = 5000;
        let info = file_info("a.txt", &object);
        let secs = 1_700_000_000 + FILETIME_OFFSET / TICKS;
        assert_eq!(info.name, "a.txt");
        assert_eq!(info.end_of_file, 5000);
        assert_eq!(info.allocation_size, 8192);
        assert_eq!(info.last_write_time, secs * TICKS + 1_234_567);
        assert_eq!(info.creation_time, info.last_write_time);
        assert!(!info.is_directory);
        assert!(info.read_only);
        assert_eq!(info.file_index, 0);
        assert_eq!(info.unix_mode, None);
        assert_eq!(info.ea_size, 0);
        assert_eq!(info.attributes(), 0x21);
    }

    #[test]
    fn ticks_become_unix_seconds_with_nine_digits() {
        let at = |secs: u64, ticks: u64| FILETIME_OFFSET + secs * TICKS + ticks;
        assert_eq!(
            format_filetime(at(1_700_000_000, 1_234_567)),
            "1700000000.123456700"
        );
        assert_eq!(format_filetime(FILETIME_OFFSET), "0.000000000");
        assert_eq!(format_filetime(FILETIME_OFFSET - 5), "-0.000000500");
        assert_eq!(
            format_filetime(FILETIME_OFFSET - 30 * TICKS - 1),
            "-30.000000100"
        );
        assert_eq!(format_filetime(0), "-11644473600.000000000");
    }

    #[test]
    fn the_largest_ticks_format_without_overflow() {
        assert_eq!(format_filetime(u64::MAX), "1833029933770.955161500");
        let stored = stored_metadata([u64::MAX, 0, i64::MAX as u64, 1], 0);
        assert_eq!(stored["btime"], "1833029933770.955161500");
        assert_eq!(stored["atime"], "-11644473600.000000000");
        assert_eq!(stored["mtime"], "910692730085.477580700");
    }

    #[test]
    fn allocation_rounds_up_to_the_unit() {
        let allocated = |size| {
            let mut object = head(&[]);
            object.size = size;
            file_info("f", &object).allocation_size
        };
        assert_eq!(allocated(0), 0);
        assert_eq!(allocated(1), 4096);
        assert_eq!(allocated(4096), 4096);
        assert_eq!(allocated(4097), 8192);
        assert_eq!(allocated(u64::MAX), u64::MAX);
    }

    #[test]
    fn only_attributes_a_client_can_set_are_kept() {
        let flags = |text| attributes(&head(&[("smb-attributes", text)]));
        assert_eq!(flags("23"), 0x23);
        assert_eq!(
            flags("ffffffff"),
            VALID_SET_ATTRIBUTES,
            "DIRECTORY and NORMAL are not stored"
        );
        assert_eq!(flags("10") & FILE_ATTRIBUTE_DIRECTORY, 0);
        assert_eq!(flags("junk"), 0);
        assert_eq!(attributes(&head(&[])), 0);
        let info = file_info("f", &head(&[("smb-attributes", "22")]));
        assert!(!info.read_only);
        assert_eq!(
            info.attributes(),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE
        );
    }

    #[test]
    fn a_directory_without_a_marker_has_the_fallback_time() {
        let built = at(2_000, 500);
        let info = dir_info("d", None, built);
        let ticks = system_time_to_filetime(built);
        assert!(info.is_directory);
        assert_eq!((info.end_of_file, info.allocation_size), (0, 0));
        assert_eq!(
            [
                info.creation_time,
                info.last_access_time,
                info.last_write_time,
                info.change_time
            ],
            [ticks; 4]
        );
        assert!(!info.read_only);
        assert_eq!(info.attributes(), FILE_ATTRIBUTE_DIRECTORY);
    }

    #[test]
    fn a_directory_with_a_marker_has_its_stored_times_and_attributes() {
        let marker = head(&[("mtime", "30"), ("btime", "20"), ("smb-attributes", "3")]);
        let info = dir_info("d", Some(&marker), at(9_999, 0));
        assert_eq!(info.last_write_time, system_time_to_filetime(at(30, 0)));
        assert_eq!(info.creation_time, system_time_to_filetime(at(20, 0)));
        assert!(info.is_directory && info.read_only);
        assert_eq!(
            info.attributes(),
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
        );
    }

    #[test]
    fn a_listed_object_without_metadata_has_last_modified_for_every_time() {
        let stamp = FileStamp {
            size: 7,
            etag: "\"e\"".into(),
            last_modified: at(500, 0),
        };
        let info = stamp_info("f", &stamp);
        let ticks = system_time_to_filetime(at(500, 0));
        assert_eq!(info.end_of_file, 7);
        assert_eq!(
            [
                info.creation_time,
                info.last_access_time,
                info.last_write_time,
                info.change_time
            ],
            [ticks; 4]
        );
        assert_eq!(info.attributes(), 0x80);
    }
}
