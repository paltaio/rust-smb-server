//! What the S3 calls read and write about an object besides its bytes.

use std::collections::BTreeMap;
use std::time::SystemTime;

use http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_TYPE, ETAG,
    EXPIRES, LAST_MODIFIED,
};
use http::{HeaderMap, HeaderName, HeaderValue};

use super::date::parse_http_date;
use super::error::S3Error;

const USER_PREFIX: &str = "x-amz-meta-";
pub(crate) const STORAGE_CLASS: HeaderName = HeaderName::from_static("x-amz-storage-class");
const DEFAULT_STORAGE_CLASS: &str = "STANDARD";

/// The metadata of an object that a write has to send again, or the object
/// loses it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Metadata {
    /// The `x-amz-meta-<name>` headers, by lowercase name without the prefix.
    pub(crate) user: BTreeMap<String, String>,
    pub(crate) content_type: Option<String>,
    pub(crate) cache_control: Option<String>,
    pub(crate) content_disposition: Option<String>,
    pub(crate) content_encoding: Option<String>,
    pub(crate) content_language: Option<String>,
    /// The `Expires` header as the store sent it.
    pub(crate) expires: Option<String>,
    /// `None` for the default class. A `STANDARD` header reads as `None`.
    pub(crate) storage_class: Option<String>,
}

impl Metadata {
    /// The metadata in the headers of a HEAD or GET answer. Values that are
    /// not UTF-8 are left out.
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        let text = |name: &HeaderName| {
            headers
                .get(name)
                .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
                .map(str::to_owned)
        };
        let user = headers
            .iter()
            .filter_map(|(name, value)| {
                let key = name.as_str().strip_prefix(USER_PREFIX)?;
                let value = std::str::from_utf8(value.as_bytes()).ok()?;
                Some((key.to_owned(), value.to_owned()))
            })
            .collect();
        Metadata {
            user,
            content_type: text(&CONTENT_TYPE),
            cache_control: text(&CACHE_CONTROL),
            content_disposition: text(&CONTENT_DISPOSITION),
            content_encoding: text(&CONTENT_ENCODING),
            content_language: text(&CONTENT_LANGUAGE),
            expires: text(&EXPIRES),
            storage_class: text(&STORAGE_CLASS).filter(|class| class != DEFAULT_STORAGE_CLASS),
        }
    }

    /// Adds the metadata to the headers of a request that stores an object.
    pub(crate) fn write_headers(&self, headers: &mut HeaderMap) -> Result<(), S3Error> {
        for (key, value) in &self.user {
            let name = HeaderName::from_bytes(format!("{USER_PREFIX}{key}").as_bytes())
                .map_err(|_| S3Error::InvalidArgument("a metadata name is not a header name"))?;
            headers.insert(name, header_value(value)?);
        }
        for (name, value) in [
            (CONTENT_TYPE, &self.content_type),
            (CACHE_CONTROL, &self.cache_control),
            (CONTENT_DISPOSITION, &self.content_disposition),
            (CONTENT_ENCODING, &self.content_encoding),
            (CONTENT_LANGUAGE, &self.content_language),
            (EXPIRES, &self.expires),
            (STORAGE_CLASS, &self.storage_class),
        ] {
            if let Some(value) = value {
                headers.insert(name, header_value(value)?);
            }
        }
        Ok(())
    }
}

pub(crate) fn header_value(text: &str) -> Result<HeaderValue, S3Error> {
    HeaderValue::from_bytes(text.as_bytes())
        .map_err(|_| S3Error::InvalidArgument("a value is not a valid header value"))
}

/// What a HEAD or GET tells about an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectHead {
    pub(crate) size: u64,
    /// In quoted form, as in the `ETag` header.
    pub(crate) etag: String,
    pub(crate) last_modified: SystemTime,
    pub(crate) metadata: Metadata,
}

impl ObjectHead {
    /// Reads the headers of an answer about an object of `size` bytes.
    pub(crate) fn from_headers(headers: &HeaderMap, size: u64) -> Result<Self, S3Error> {
        let last_modified = headers
            .get(LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_http_date)
            .ok_or(S3Error::InvalidResponse(
                "the object has no valid modification time",
            ))?;
        Ok(ObjectHead {
            size,
            etag: headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(normalize_etag)
                .unwrap_or_default(),
            last_modified,
            metadata: Metadata::from_headers(headers),
        })
    }
}

/// An ETag in the quoted form of the `ETag` header, with no weak marker.
/// Stores differ in whether XML documents carry the quotes.
pub(crate) fn normalize_etag(etag: &str) -> String {
    let etag = etag.trim();
    let etag = etag.strip_prefix("W/").unwrap_or(etag);
    if etag.is_empty() || (etag.len() >= 2 && etag.starts_with('"') && etag.ends_with('"')) {
        etag.to_owned()
    } else {
        format!("\"{etag}\"")
    }
}

/// A non-empty range of bytes of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ByteRange {
    start: u64,
    len: u64,
}

impl ByteRange {
    pub(crate) fn new(start: u64, len: u64) -> Result<Self, S3Error> {
        if len == 0 || start.checked_add(len).is_none() {
            return Err(S3Error::InvalidArgument(
                "a byte range is empty or ends past u64::MAX",
            ));
        }
        Ok(ByteRange { start, len })
    }

    pub(crate) fn start(&self) -> u64 {
        self.start
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// The offset of the last byte.
    pub(crate) fn last(&self) -> u64 {
        self.start + self.len - 1
    }

    /// The value of a `Range` or `x-amz-copy-source-range` header.
    pub(crate) fn header_value(&self) -> String {
        format!("bytes={}-{}", self.start, self.last())
    }
}

/// The first byte, last byte and object size of a `Content-Range` value.
pub(crate) fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let (range, size) = value.trim().strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let number = |text: &str| {
        (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    };
    let (first, last, size) = (number(first)?, number(last)?, number(size)?);
    (first <= last && last < size).then_some((first, last, size))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn reads_user_and_system_metadata_from_headers() {
        let map = headers(&[
            ("x-amz-meta-mtime", "1700000000.123456789"),
            ("X-Amz-Meta-Smb-Attributes", "20"),
            ("content-type", "text/plain"),
            ("cache-control", "max-age=60"),
            ("content-disposition", "attachment; filename=\"a.txt\""),
            ("content-encoding", "gzip"),
            ("content-language", "en"),
            ("expires", "Fri, 24 May 2013 00:00:00 GMT"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ("content-length", "10"),
            ("etag", "\"abc\""),
        ]);
        let metadata = Metadata::from_headers(&map);
        assert_eq!(
            metadata.user,
            BTreeMap::from([
                ("mtime".to_owned(), "1700000000.123456789".to_owned()),
                ("smb-attributes".to_owned(), "20".to_owned()),
            ])
        );
        assert_eq!(metadata.content_type.as_deref(), Some("text/plain"));
        assert_eq!(metadata.cache_control.as_deref(), Some("max-age=60"));
        assert_eq!(
            metadata.content_disposition.as_deref(),
            Some("attachment; filename=\"a.txt\"")
        );
        assert_eq!(metadata.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(metadata.content_language.as_deref(), Some("en"));
        assert_eq!(
            metadata.expires.as_deref(),
            Some("Fri, 24 May 2013 00:00:00 GMT")
        );
        assert_eq!(
            metadata.storage_class.as_deref(),
            Some("REDUCED_REDUNDANCY")
        );
    }

    #[test]
    fn the_default_storage_class_reads_as_none() {
        let read = |class| {
            Metadata::from_headers(&headers(&[("x-amz-storage-class", class)])).storage_class
        };
        assert_eq!(read("STANDARD"), None);
        assert_eq!(read("STANDARD_IA").as_deref(), Some("STANDARD_IA"));
        assert_eq!(read("standard").as_deref(), Some("standard"));
    }

    #[test]
    fn absent_metadata_stays_absent() {
        assert_eq!(
            Metadata::from_headers(&HeaderMap::new()),
            Metadata::default()
        );
    }

    #[test]
    fn metadata_survives_a_write_and_a_read() {
        let metadata = Metadata {
            user: BTreeMap::from([
                ("mtime".to_owned(), "1.5".to_owned()),
                ("btime".to_owned(), "2".to_owned()),
                ("tag".to_owned(), "caf\u{e9}".to_owned()),
            ]),
            content_type: Some("application/octet-stream".into()),
            cache_control: Some("no-cache".into()),
            content_disposition: Some("inline".into()),
            content_encoding: Some("br".into()),
            content_language: Some("es-CL".into()),
            expires: Some("Fri, 24 May 2013 00:00:00 GMT".into()),
            storage_class: Some("STANDARD_IA".into()),
        };
        let mut map = HeaderMap::new();
        metadata.write_headers(&mut map).unwrap();
        assert_eq!(map["x-amz-meta-mtime"], "1.5");
        assert_eq!(map["x-amz-storage-class"], "STANDARD_IA");
        assert_eq!(Metadata::from_headers(&map), metadata);
    }

    #[test]
    fn unset_metadata_writes_no_headers() {
        let mut map = HeaderMap::new();
        Metadata::default().write_headers(&mut map).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn metadata_that_cannot_be_a_header_is_refused() {
        for metadata in [
            Metadata {
                user: BTreeMap::from([("bad name".to_owned(), "v".to_owned())]),
                ..Metadata::default()
            },
            Metadata {
                user: BTreeMap::from([("k".to_owned(), "line\nbreak".to_owned())]),
                ..Metadata::default()
            },
            Metadata {
                content_type: Some("a\r\nb".into()),
                ..Metadata::default()
            },
        ] {
            let mut map = HeaderMap::new();
            assert!(
                matches!(
                    metadata.write_headers(&mut map),
                    Err(S3Error::InvalidArgument(_))
                ),
                "{metadata:?}"
            );
        }
    }

    #[test]
    fn reads_an_object_head() {
        let map = headers(&[
            ("last-modified", "Fri, 24 May 2013 00:00:00 GMT"),
            ("etag", "\"abc\""),
            ("x-amz-meta-mtime", "5"),
        ]);
        let head = ObjectHead::from_headers(&map, 42).unwrap();
        assert_eq!(head.size, 42);
        assert_eq!(head.etag, "\"abc\"");
        assert_eq!(
            head.last_modified,
            UNIX_EPOCH + Duration::from_secs(1_369_353_600)
        );
        assert_eq!(head.metadata.user["mtime"], "5");
    }

    #[test]
    fn an_object_head_needs_a_modification_time() {
        for map in [
            headers(&[("etag", "\"abc\"")]),
            headers(&[("etag", "\"abc\""), ("last-modified", "yesterday")]),
        ] {
            assert!(matches!(
                ObjectHead::from_headers(&map, 1),
                Err(S3Error::InvalidResponse(_))
            ));
        }
    }

    #[test]
    fn an_object_head_without_an_etag_has_an_empty_one() {
        let map = headers(&[("last-modified", "Fri, 24 May 2013 00:00:00 GMT")]);
        assert_eq!(ObjectHead::from_headers(&map, 0).unwrap().etag, "");
    }

    #[test]
    fn etags_take_the_quoted_form() {
        assert_eq!(normalize_etag("\"abc\""), "\"abc\"");
        assert_eq!(normalize_etag("abc"), "\"abc\"");
        assert_eq!(normalize_etag(" \"abc\" "), "\"abc\"");
        assert_eq!(normalize_etag("W/\"abc\""), "\"abc\"");
        assert_eq!(normalize_etag("\"abc-12\""), "\"abc-12\"");
        assert_eq!(normalize_etag(""), "");
        assert_eq!(normalize_etag("\"\""), "\"\"");
    }

    #[test]
    fn a_byte_range_names_its_first_and_last_byte() {
        let range = ByteRange::new(10, 5).unwrap();
        assert_eq!((range.start(), range.len(), range.last()), (10, 5, 14));
        assert_eq!(range.header_value(), "bytes=10-14");
        assert_eq!(ByteRange::new(0, 1).unwrap().header_value(), "bytes=0-0");
        let end = ByteRange::new(u64::MAX - 1, 1).unwrap();
        assert_eq!(end.last(), u64::MAX - 1);
    }

    #[test]
    fn an_empty_or_overflowing_byte_range_is_refused() {
        assert!(ByteRange::new(5, 0).is_err());
        assert!(ByteRange::new(u64::MAX, 1).is_err());
        assert!(ByteRange::new(1, u64::MAX).is_err());
    }

    #[test]
    fn parses_content_range_values() {
        assert_eq!(parse_content_range("bytes 0-9/100"), Some((0, 9, 100)));
        assert_eq!(parse_content_range("bytes 5-5/6"), Some((5, 5, 6)));
        assert_eq!(parse_content_range(" bytes 10-19/20 "), Some((10, 19, 20)));
        for bad in [
            "",
            "bytes 0-9/*",
            "bytes */100",
            "bytes 9-0/100",
            "bytes 0-100/100",
            "bytes 0-9",
            "0-9/100",
            "bytes 0-9/1x",
            "bytes -9/100",
            "bytes +0-9/100",
            "bytes 0--9/100",
            "items 0-9/100",
        ] {
            assert_eq!(parse_content_range(bad), None, "{bad:?}");
        }
    }
}
