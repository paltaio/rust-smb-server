//! Dates in the forms S3 uses: the `x-amz-date` timestamp, RFC 3339 in XML
//! bodies and RFC 1123 in headers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SECS_PER_DAY: i64 = 86_400;

/// `YYYYMMDDTHHMMSSZ` for the whole seconds of `time` in UTC. The first eight
/// characters are the date stamp that scopes a signature.
pub(crate) fn amz_date(time: SystemTime) -> String {
    let secs = unix_seconds(time);
    let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
    let time_of_day = secs.rem_euclid(SECS_PER_DAY);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        time_of_day / 3600,
        time_of_day % 3600 / 60,
        time_of_day % 60
    )
}

/// An RFC 3339 timestamp such as `2013-05-24T00:00:00.000Z` or
/// `2013-05-24T05:30:00+05:30`. `None` when `text` is not one or names a
/// day that does not exist.
pub(crate) fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let b = text.as_bytes();
    let year = number(b, 0, 4)?;
    let month = number(b, 5, 2)?;
    let day = number(b, 8, 2)?;
    let hour = number(b, 11, 2)?;
    let minute = number(b, 14, 2)?;
    let second = number(b, 17, 2)?;
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || !matches!(b.get(10), Some(b'T' | b't'))
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let mut at = 19;
    let mut nanos = 0;
    if b.get(at) == Some(&b'.') {
        let start = at + 1;
        at = start;
        let mut scale = 100_000_000;
        while let Some(digit) = b.get(at).filter(|c| c.is_ascii_digit()) {
            nanos += u32::from(digit - b'0') * scale;
            scale /= 10;
            at += 1;
        }
        if at == start {
            return None;
        }
    }
    let offset = match b.get(at)? {
        b'Z' | b'z' => {
            at += 1;
            0
        }
        sign @ (b'+' | b'-') => {
            let hours = number(b, at + 1, 2)?;
            let minutes = number(b, at + 4, 2)?;
            if b.get(at + 3) != Some(&b':') || hours > 23 || minutes > 59 {
                return None;
            }
            at += 6;
            let seconds = i64::from(hours * 3600 + minutes * 60);
            if *sign == b'-' { -seconds } else { seconds }
        }
        _ => return None,
    };
    if at != b.len() {
        return None;
    }
    from_civil(year, month, day, hour, minute, second, nanos, offset)
}

/// An RFC 1123 date as HTTP headers carry it: `Fri, 24 May 2013 00:00:00 GMT`.
pub(crate) fn parse_http_date(text: &str) -> Option<SystemTime> {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let b = text.as_bytes();
    if b.len() != 29
        || !DAYS.contains(&text.get(0..3)?)
        || &b[3..5] != b", "
        || b[7] != b' '
        || b[11] != b' '
        || b[16] != b' '
        || b[19] != b':'
        || b[22] != b':'
        || &b[25..] != b" GMT"
    {
        return None;
    }
    let name = text.get(8..11)?;
    let month = MONTHS.iter().position(|m| *m == name)? + 1;
    from_civil(
        number(b, 12, 4)?,
        u32::try_from(month).ok()?,
        number(b, 5, 2)?,
        number(b, 17, 2)?,
        number(b, 20, 2)?,
        number(b, 23, 2)?,
        0,
        0,
    )
}

/// The value of the `len` ASCII digits of `b` at `at`.
fn number(b: &[u8], at: usize, len: usize) -> Option<u32> {
    let digits = b.get(at..at.checked_add(len)?)?;
    digits.iter().try_fold(0u32, |n, c| {
        c.is_ascii_digit().then(|| n * 10 + u32::from(c - b'0'))
    })
}

#[expect(clippy::too_many_arguments, reason = "the fields of a timestamp")]
fn from_civil(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
    offset: i64,
) -> Option<SystemTime> {
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    let secs = days * SECS_PER_DAY + i64::from(hour * 3600 + minute * 60 + second) - offset;
    let nanos = Duration::from_nanos(nanos.into());
    match u64::try_from(secs) {
        Ok(after) => UNIX_EPOCH.checked_add(Duration::from_secs(after) + nanos),
        Err(_) => UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))?
            .checked_add(nanos),
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Whole seconds since the epoch, rounded toward the past.
fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(before) => {
            let before = before.duration();
            let whole = i64::try_from(before.as_secs()).unwrap_or(i64::MAX - 1);
            -whole - i64::from(before.subsec_nanos() > 0)
        }
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The year, month and day of a count of days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_from_march + 2) / 5 + 1) as u32;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month as u32, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn formats_the_timestamp_of_a_request() {
        assert_eq!(amz_date(UNIX_EPOCH), "19700101T000000Z");
        assert_eq!(amz_date(at(1_369_353_600)), "20130524T000000Z");
        assert_eq!(amz_date(at(1_709_251_199)), "20240229T235959Z");
        assert_eq!(amz_date(at(1_709_251_200)), "20240301T000000Z");
        assert_eq!(amz_date(at(4_102_444_800)), "21000101T000000Z");
        assert_eq!(amz_date(at(253_402_300_799)), "99991231T235959Z");
    }

    #[test]
    fn formatting_drops_fractions_and_floors_dates_before_1970() {
        let late = UNIX_EPOCH + Duration::new(1_369_353_600, 999_999_999);
        assert_eq!(amz_date(late), "20130524T000000Z");
        assert_eq!(
            amz_date(UNIX_EPOCH - Duration::from_millis(1)),
            "19691231T235959Z"
        );
        assert_eq!(
            amz_date(UNIX_EPOCH - Duration::from_secs(86_400)),
            "19691231T000000Z"
        );
    }

    #[test]
    fn civil_dates_round_trip_through_day_counts() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2013, 5, 24), 15_849);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        let mut expected = days_from_civil(1600, 1, 1);
        for year in 1600..=2500 {
            for month in 1..=12 {
                for day in 1..=days_in_month(year as u32, month) {
                    assert_eq!(days_from_civil(year, month, day), expected);
                    assert_eq!(civil_from_days(expected), (year, month, day));
                    expected += 1;
                }
            }
        }
    }

    #[test]
    fn parses_rfc3339_timestamps() {
        assert_eq!(
            parse_rfc3339("2013-05-24T00:00:00.000Z"),
            Some(at(1_369_353_600))
        );
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
        assert_eq!(
            parse_rfc3339("2024-02-29T23:59:59z"),
            Some(at(1_709_251_199))
        );
        assert_eq!(
            parse_rfc3339("2013-05-24t00:00:00Z"),
            Some(at(1_369_353_600))
        );
        assert_eq!(
            parse_rfc3339("1969-12-31T23:59:59Z"),
            Some(UNIX_EPOCH - Duration::from_secs(1))
        );
    }

    #[test]
    fn rfc3339_fractions_keep_up_to_nine_digits() {
        let parsed = |text| parse_rfc3339(text).unwrap();
        let base = at(1_369_353_600);
        assert_eq!(
            parsed("2013-05-24T00:00:00.5Z"),
            base + Duration::from_millis(500)
        );
        assert_eq!(
            parsed("2013-05-24T00:00:00.123456789Z"),
            base + Duration::from_nanos(123_456_789)
        );
        assert_eq!(
            parsed("2013-05-24T00:00:00.1234567891999Z"),
            base + Duration::from_nanos(123_456_789)
        );
        assert_eq!(
            parse_rfc3339("1969-12-31T23:59:59.5Z"),
            Some(UNIX_EPOCH - Duration::from_millis(500))
        );
    }

    #[test]
    fn rfc3339_offsets_move_the_instant() {
        let utc = at(1_369_353_600);
        assert_eq!(parse_rfc3339("2013-05-24T05:30:00+05:30"), Some(utc));
        assert_eq!(parse_rfc3339("2013-05-23T19:00:00-05:00"), Some(utc));
        assert_eq!(parse_rfc3339("2013-05-24T00:00:00+00:00"), Some(utc));
    }

    #[test]
    fn a_leap_second_lands_on_the_next_minute() {
        assert_eq!(
            parse_rfc3339("2016-12-31T23:59:60Z"),
            parse_rfc3339("2017-01-01T00:00:00Z")
        );
    }

    #[test]
    fn rejects_malformed_rfc3339_timestamps() {
        for text in [
            "",
            "2013-05-24",
            "2013-05-24T00:00:00",
            "2013-05-24 00:00:00Z",
            "2013-05-24T00:00:00.Z",
            "2013-05-24T00:00:00Zjunk",
            "2013-05-24T00:00:00+0530",
            "2013-05-24T00:00:00+24:00",
            "2013-05-24T00:00:00+05:60",
            "2013-13-24T00:00:00Z",
            "2013-00-24T00:00:00Z",
            "2013-05-00T00:00:00Z",
            "2013-05-32T00:00:00Z",
            "2013-04-31T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2013-05-24T24:00:00Z",
            "2013-05-24T00:60:00Z",
            "2013-05-24T00:00:61Z",
            "2013/05/24T00:00:00Z",
            "2013-05-24T00-00-00Z",
            "+013-05-24T00:00:00Z",
            "2013-05-24T00:00:00.1.2Z",
            "20130524T000000Z",
        ] {
            assert_eq!(parse_rfc3339(text), None, "{text:?}");
        }
    }

    #[test]
    fn parses_http_dates() {
        assert_eq!(
            parse_http_date("Fri, 24 May 2013 00:00:00 GMT"),
            Some(at(1_369_353_600))
        );
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(at(784_111_777))
        );
        assert_eq!(
            parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(UNIX_EPOCH)
        );
        assert_eq!(
            parse_http_date("Thu, 29 Feb 2024 12:00:00 GMT"),
            Some(at(1_709_208_000))
        );
    }

    #[test]
    fn rejects_malformed_http_dates() {
        for text in [
            "",
            "Fri, 24 May 2013 00:00:00",
            "Fri, 24 May 2013 00:00:00 UTC",
            "Fri, 24 May 2013 00:00:00 GMT ",
            "Fri 24 May 2013 00:00:00 GMT",
            "Fry, 24 May 2013 00:00:00 GMT",
            "Fri, 24 Mai 2013 00:00:00 GMT",
            "Fri,  4 May 2013 00:00:00 GMT",
            "Fri, 31 Apr 2013 00:00:00 GMT",
            "Fri, 24 May 2013 24:00:00 GMT",
            "Fri, 24 May 2013 00-00-00 GMT",
            "Friday, 24-May-13 00:00:00 GMT",
            "Fri May 24 00:00:00 2013",
            "Fri, 24 May 20x3 00:00:00 GMT",
            "Fri, 24 Ma\u{e9} 2013 00:00:00 GMT",
        ] {
            assert_eq!(parse_http_date(text), None, "{text:?}");
        }
    }
}
