//! The records in the cache directory: one small text file for each entry
//! or tombstone, in the form [`Record::encode`] writes.
//!
//! A record starts with a version line, then has one `name value` line per
//! field, and ends with a line `end`. Paths, keys and metadata are
//! percent-encoded. A field that is not set has no line.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::ops::Range;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::path::is_valid_component;

use super::encode::uri_encode;
use super::keys::MAX_KEY_LEN;
use super::object::{Metadata, ObjectHead};
use super::ranges::RangeSet;

const HEADER: &str = "smb-s3-record 1";

/// Longest record the cache directory reads, in bytes.
pub(crate) const MAX_RECORD_LEN: u64 = 64 << 20;

/// Why a record was refused: the name of the field that is missing, repeated,
/// unknown or not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed(pub(crate) &'static str);

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the record has a bad {}", self.0)
    }
}

impl std::error::Error for Malformed {}

/// What a record says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Record {
    Entry(Box<EntryRecord>),
    Tombstone(TombstoneRecord),
}

/// The id of a record: 32 lowercase hexadecimal digits. It names the record
/// file and the data file of the same entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RecordId(String);

impl RecordId {
    /// The id `text` spells, if it is one.
    pub(crate) fn parse(text: &str) -> Option<RecordId> {
        (text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .then(|| RecordId(text.to_owned()))
    }

    /// An id made of the 16 bytes `bytes`.
    pub(crate) fn from_bytes(bytes: &[u8; 16]) -> RecordId {
        RecordId(super::encode::hex(bytes))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Keys that must be deleted from the bucket, none of them held by an entry
/// the backend has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TombstoneRecord {
    pub(crate) id: RecordId,
    /// At least one key.
    pub(crate) keys: Vec<String>,
}

/// The remote version an entry starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseRecord {
    pub(crate) key: String,
    pub(crate) head: ObjectHead,
}

/// The local data of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalRecord {
    pub(crate) len: u64,
    pub(crate) present: RangeSet,
}

/// A file or directory the backend holds changes for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryRecord {
    pub(crate) id: RecordId,
    pub(crate) is_dir: bool,
    /// The path below the share root, with `/` between the names.
    pub(crate) path: String,
    pub(crate) key: String,
    /// Keys to delete from the bucket once the entry's content is stored.
    pub(crate) gone: Vec<String>,
    pub(crate) base: Option<BaseRecord>,
    /// Whether `key` may exist in the bucket.
    pub(crate) remote: bool,
    pub(crate) local: Option<LocalRecord>,
    /// Creation, access, write and change time as FILETIME ticks.
    pub(crate) times: [u64; 4],
    pub(crate) attributes: u32,
    pub(crate) generation: u64,
    /// The multipart upload that is running for the entry.
    pub(crate) upload_id: Option<String>,
    /// Whether the entry's upload failed for good.
    pub(crate) failed: bool,
    /// Whether the times or attributes are not in the bucket yet.
    pub(crate) meta_pending: bool,
    /// Whether the marker object of the directory is not in the bucket yet.
    pub(crate) marker_pending: bool,
}

const SYSTEM_FIELDS: [&str; 7] = [
    "content-type",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "expires",
    "storage-class",
];

fn system_value<'m>(metadata: &'m Metadata, name: &str) -> &'m Option<String> {
    match name {
        "content-type" => &metadata.content_type,
        "cache-control" => &metadata.cache_control,
        "content-disposition" => &metadata.content_disposition,
        "content-encoding" => &metadata.content_encoding,
        "content-language" => &metadata.content_language,
        "expires" => &metadata.expires,
        _ => &metadata.storage_class,
    }
}

fn system_slot<'m>(metadata: &'m mut Metadata, name: &str) -> Option<&'m mut Option<String>> {
    Some(match name {
        "content-type" => &mut metadata.content_type,
        "cache-control" => &mut metadata.cache_control,
        "content-disposition" => &mut metadata.content_disposition,
        "content-encoding" => &mut metadata.content_encoding,
        "content-language" => &mut metadata.content_language,
        "expires" => &mut metadata.expires,
        "storage-class" => &mut metadata.storage_class,
        _ => return None,
    })
}

/// `text` with every byte outside `A-Za-z0-9-._~` as `%XX`.
pub(crate) fn escape(text: &str) -> String {
    uri_encode(text, false)
}

/// [`escape`] that leaves `/` as it is, for paths and keys.
fn escape_path(text: &str) -> String {
    uri_encode(text, true)
}

/// The text `escape` or `escape_path` made `text` from. `None` for anything
/// they do not write, or when the bytes are not UTF-8.
pub(crate) fn unescape(text: &str) -> Option<String> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                out.push((high * 16 + low) as u8);
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b);
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

impl Record {
    pub(crate) fn id(&self) -> &RecordId {
        match self {
            Record::Entry(entry) => &entry.id,
            Record::Tombstone(tombstone) => &tombstone.id,
        }
    }

    /// The text of the record.
    #[cfg_attr(not(test), expect(dead_code, reason = "called by tests only"))]
    pub(crate) fn encode(&self) -> String {
        match self {
            Record::Entry(entry) => entry.encode(),
            Record::Tombstone(tombstone) => tombstone.encode(),
        }
    }

    /// Reads a record. Never panics, whatever `bytes` hold.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Record, Malformed> {
        let text = std::str::from_utf8(bytes).map_err(|_| Malformed("encoding"))?;
        let body = text.strip_suffix("end\n").ok_or(Malformed("end"))?;
        let mut lines = body.split_terminator('\n');
        if lines.next() != Some(HEADER) {
            return Err(Malformed("version"));
        }
        let mut fields = Fields(Vec::new());
        for text in lines {
            let (name, value) = text.split_once(' ').unwrap_or((text, ""));
            fields.0.push((name, value));
        }
        let record = match fields.one("kind")? {
            "entry" => Record::Entry(Box::new(EntryRecord::decode(&mut fields)?)),
            "tombstone" => Record::Tombstone(TombstoneRecord::decode(&mut fields)?),
            _ => return Err(Malformed("kind")),
        };
        fields.finish()?;
        Ok(record)
    }
}

fn line(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push(' ');
    out.push_str(value);
    out.push('\n');
}

impl EntryRecord {
    /// The text of the record.
    pub(crate) fn encode(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(HEADER);
        out.push('\n');
        self.encode_into(&mut out);
        out.push_str("end\n");
        out
    }

    fn encode_into(&self, out: &mut String) {
        line(out, "kind", "entry");
        line(out, "id", self.id.as_str());
        line(out, "type", if self.is_dir { "dir" } else { "file" });
        line(out, "path", &escape_path(&self.path));
        line(out, "key", &escape_path(&self.key));
        for key in &self.gone {
            line(out, "gone", &escape_path(key));
        }
        line(out, "remote", flag(self.remote));
        if let Some(local) = &self.local {
            line(out, "local", &local.len.to_string());
            let ranges: Vec<String> = local
                .present
                .iter()
                .map(|r| format!("{}-{}", r.start, r.end))
                .collect();
            line(out, "present", &ranges.join(","));
        }
        let [created, accessed, written, changed] = self.times;
        line(
            out,
            "times",
            &format!("{created} {accessed} {written} {changed}"),
        );
        line(out, "attributes", &format!("{:x}", self.attributes));
        line(out, "generation", &self.generation.to_string());
        if let Some(upload) = &self.upload_id {
            line(out, "upload", &escape(upload));
        }
        line(out, "failed", flag(self.failed));
        line(out, "pending-meta", flag(self.meta_pending));
        line(out, "pending-marker", flag(self.marker_pending));
        if let Some(base) = &self.base {
            line(out, "base-key", &escape_path(&base.key));
            line(out, "base-etag", &escape(&base.head.etag));
            line(out, "base-size", &base.head.size.to_string());
            line(
                out,
                "base-modified",
                &nanos_since_epoch(base.head.last_modified).to_string(),
            );
            for (name, value) in &base.head.metadata.user {
                line(
                    out,
                    "base-user",
                    &format!("{} {}", escape(name), escape(value)),
                );
            }
            for name in SYSTEM_FIELDS {
                if let Some(value) = system_value(&base.head.metadata, name) {
                    line(out, "base-system", &format!("{name} {}", escape(value)));
                }
            }
        }
    }

    fn decode(fields: &mut Fields<'_>) -> Result<EntryRecord, Malformed> {
        let id = fields.id()?;
        let is_dir = match fields.one("type")? {
            "file" => false,
            "dir" => true,
            _ => return Err(Malformed("type")),
        };
        let path = fields.text("path")?;
        let key = fields.text("key")?;
        if path.is_empty() || !path.split('/').all(is_valid_component) {
            return Err(Malformed("path"));
        }
        if !valid_key(&key) {
            return Err(Malformed("key"));
        }
        let gone = keys(fields, "gone")?;
        let remote = fields.flag("remote")?;

        let local = match fields.take("local")? {
            None => {
                if fields.take("present")?.is_some() {
                    return Err(Malformed("present"));
                }
                None
            }
            Some(len) => {
                let len = number(len).ok_or(Malformed("local"))?;
                let present = ranges(fields.one("present")?).ok_or(Malformed("present"))?;
                if present.end() > len || is_dir {
                    return Err(Malformed("present"));
                }
                Some(LocalRecord { len, present })
            }
        };
        let times = times(fields.one("times")?).ok_or(Malformed("times"))?;
        let attributes = hex_u32(fields.one("attributes")?).ok_or(Malformed("attributes"))?;
        let generation = number(fields.one("generation")?).ok_or(Malformed("generation"))?;
        let upload_id = match fields.take("upload")? {
            None => None,
            Some(text) => Some(
                unescape(text)
                    .filter(|id| !id.is_empty())
                    .ok_or(Malformed("upload"))?,
            ),
        };
        if is_dir && upload_id.is_some() {
            return Err(Malformed("upload"));
        }
        let failed = fields.flag("failed")?;
        let meta_pending = fields.flag("pending-meta")?;
        let marker_pending = fields.flag("pending-marker")?;
        if marker_pending && !is_dir {
            return Err(Malformed("pending-marker"));
        }
        let base = match fields.take("base-key")? {
            None => None,
            Some(text) => Some(BaseRecord {
                key: unescape(text)
                    .filter(|key| valid_key(key))
                    .ok_or(Malformed("base-key"))?,
                head: decode_head(fields)?,
            }),
        };
        Ok(EntryRecord {
            id,
            is_dir,
            path,
            key,
            gone,
            base,
            remote,
            local,
            times,
            attributes,
            generation,
            upload_id,
            failed,
            meta_pending,
            marker_pending,
        })
    }
}

fn decode_head(fields: &mut Fields<'_>) -> Result<ObjectHead, Malformed> {
    let etag = fields.text("base-etag")?;
    let size = number(fields.one("base-size")?).ok_or(Malformed("base-size"))?;
    let nanos: i128 = fields
        .one("base-modified")?
        .parse()
        .map_err(|_| Malformed("base-modified"))?;
    let last_modified = time_from_nanos(nanos).ok_or(Malformed("base-modified"))?;
    let mut metadata = Metadata::default();
    let mut user = BTreeMap::new();
    for text in fields.all("base-user") {
        let (name, value) = text.split_once(' ').ok_or(Malformed("base-user"))?;
        let (name, value) = (
            unescape(name).filter(|name| !name.is_empty()),
            unescape(value),
        );
        let (Some(name), Some(value)) = (name, value) else {
            return Err(Malformed("base-user"));
        };
        if user.insert(name, value).is_some() {
            return Err(Malformed("base-user"));
        }
    }
    metadata.user = user;
    for text in fields.all("base-system") {
        let (name, value) = text.split_once(' ').ok_or(Malformed("base-system"))?;
        let slot = system_slot(&mut metadata, name).ok_or(Malformed("base-system"))?;
        if slot.is_some() {
            return Err(Malformed("base-system"));
        }
        *slot = Some(unescape(value).ok_or(Malformed("base-system"))?);
    }
    Ok(ObjectHead {
        size,
        etag,
        last_modified,
        metadata,
    })
}

impl TombstoneRecord {
    /// The text of the record.
    pub(crate) fn encode(&self) -> String {
        let mut out = String::from(HEADER);
        out.push('\n');
        line(&mut out, "kind", "tombstone");
        line(&mut out, "id", self.id.as_str());
        for key in &self.keys {
            line(&mut out, "key", &escape_path(key));
        }
        out.push_str("end\n");
        out
    }

    fn decode(fields: &mut Fields<'_>) -> Result<TombstoneRecord, Malformed> {
        let id = fields.id()?;
        let keys = keys(fields, "key")?;
        if keys.is_empty() {
            return Err(Malformed("key"));
        }
        Ok(TombstoneRecord { id, keys })
    }
}

/// The keys of every line `name`, each once.
fn keys(fields: &mut Fields<'_>, name: &'static str) -> Result<Vec<String>, Malformed> {
    let mut seen = HashSet::new();
    let mut keys = Vec::new();
    for text in fields.all(name) {
        let key = unescape(text)
            .filter(|key| valid_key(key))
            .ok_or(Malformed(name))?;
        if !seen.insert(key.clone()) {
            return Err(Malformed(name));
        }
        keys.push(key);
    }
    Ok(keys)
}

/// The lines of a record not read yet.
struct Fields<'a>(Vec<(&'a str, &'a str)>);

impl<'a> Fields<'a> {
    /// The value of the line `name`, if there is one. Fails if there are two.
    fn take(&mut self, name: &'static str) -> Result<Option<&'a str>, Malformed> {
        let mut found = None;
        let mut repeated = false;
        self.0.retain(|&(line_name, value)| {
            if line_name != name {
                return true;
            }
            repeated |= found.replace(value).is_some();
            false
        });
        if repeated {
            return Err(Malformed(name));
        }
        Ok(found)
    }

    fn one(&mut self, name: &'static str) -> Result<&'a str, Malformed> {
        self.take(name)?.ok_or(Malformed(name))
    }

    /// The values of every line `name`.
    fn all(&mut self, name: &str) -> Vec<&'a str> {
        let mut found = Vec::new();
        self.0.retain(|&(line_name, value)| {
            if line_name == name {
                found.push(value);
            }
            line_name != name
        });
        found
    }

    fn id(&mut self) -> Result<RecordId, Malformed> {
        RecordId::parse(self.one("id")?).ok_or(Malformed("id"))
    }

    fn text(&mut self, name: &'static str) -> Result<String, Malformed> {
        unescape(self.one(name)?).ok_or(Malformed(name))
    }

    fn flag(&mut self, name: &'static str) -> Result<bool, Malformed> {
        match self.one(name)? {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(Malformed(name)),
        }
    }

    /// Fails if a line was not read.
    fn finish(self) -> Result<(), Malformed> {
        match self.0.first() {
            None => Ok(()),
            Some(_) => Err(Malformed("field")),
        }
    }
}

fn flag(set: bool) -> &'static str {
    if set { "1" } else { "0" }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY_LEN
}

fn number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn hex_u32(text: &str) -> Option<u32> {
    if text.is_empty()
        || text.len() > 8
        || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

/// Four FILETIME values, separated by single spaces. A value is at most
/// `i64::MAX`, as FILETIME is signed.
fn times(text: &str) -> Option<[u64; 4]> {
    let mut parts = text
        .split(' ')
        .map(|part| number(part).filter(|&ticks| i64::try_from(ticks).is_ok()));
    let all = [
        parts.next()??,
        parts.next()??,
        parts.next()??,
        parts.next()??,
    ];
    parts.next().is_none().then_some(all)
}

/// `start-end` pairs in order, apart from each other, separated by commas.
fn ranges(text: &str) -> Option<RangeSet> {
    let mut set = RangeSet::new();
    if text.is_empty() {
        return Some(set);
    }
    let mut floor = 0;
    for part in text.split(',') {
        let (start, end) = part.split_once('-')?;
        let range: Range<u64> = number(start)?..number(end)?;
        if range.start >= range.end || (range.start <= floor && !set.is_empty()) {
            return None;
        }
        floor = range.end;
        set.insert(range);
    }
    Some(set)
}

fn nanos_since_epoch(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    }
}

fn time_from_nanos(nanos: i128) -> Option<SystemTime> {
    let magnitude = nanos.unsigned_abs();
    let secs = u64::try_from(magnitude / 1_000_000_000).ok()?;
    let offset = Duration::new(secs, (magnitude % 1_000_000_000) as u32);
    if nanos < 0 {
        UNIX_EPOCH.checked_sub(offset)
    } else {
        UNIX_EPOCH.checked_add(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210";

    fn id(text: &str) -> RecordId {
        RecordId::parse(text).unwrap()
    }

    fn head() -> ObjectHead {
        let mut metadata = Metadata::default();
        metadata.user.insert("mtime".into(), "1700000000.5".into());
        metadata
            .user
            .insert("note".into(), "a b+c%d\u{e9}\n".into());
        metadata.content_type = Some("text/plain; charset=utf-8".into());
        metadata.expires = Some("Wed, 21 Oct 2037 07:28:00 GMT".into());
        metadata.storage_class = Some("STANDARD_IA".into());
        ObjectHead {
            size: 1234,
            etag: "\"abc-1\"".into(),
            last_modified: UNIX_EPOCH + Duration::new(1_600_000_000, 250),
            metadata,
        }
    }

    fn entry() -> EntryRecord {
        EntryRecord {
            id: id(ID),
            is_dir: false,
            path: "dir one/f+ile%1.txt".into(),
            key: "pre/dir one/f+ile%1.txt".into(),
            gone: vec!["pre/old name.txt".into(), "pre/other/x%y".into()],
            base: Some(BaseRecord {
                key: "pre/old name.txt".into(),
                head: head(),
            }),
            remote: true,
            local: Some(LocalRecord {
                len: 100,
                present: [0..10, 20..30, 90..100].into_iter().collect(),
            }),
            times: [1, 2, 3, 4],
            attributes: 0x21,
            generation: 7,
            upload_id: Some("upload id/1".into()),
            failed: true,
            meta_pending: true,
            marker_pending: false,
        }
    }

    fn encoded(record: &EntryRecord) -> String {
        record.encode()
    }

    #[test]
    fn an_entry_record_reads_back_as_written() {
        let record = entry();
        let text = encoded(&record);
        assert_eq!(
            Record::decode(text.as_bytes()).unwrap(),
            Record::Entry(Box::new(record))
        );
    }

    #[test]
    fn an_entry_without_optional_fields_reads_back_as_written() {
        let record = EntryRecord {
            id: id(OTHER),
            is_dir: true,
            path: "d".into(),
            key: "d".into(),
            gone: Vec::new(),
            base: None,
            remote: false,
            local: None,
            times: [0; 4],
            attributes: 0,
            generation: 0,
            upload_id: None,
            failed: false,
            meta_pending: false,
            marker_pending: true,
        };
        let text = encoded(&record);
        for optional in ["local", "present", "upload", "base-key", "gone"] {
            assert!(
                !text.lines().any(|l| l.starts_with(&format!("{optional} "))),
                "{optional}"
            );
        }
        assert_eq!(
            Record::decode(text.as_bytes()).unwrap(),
            Record::Entry(Box::new(record))
        );
    }

    #[test]
    fn a_tombstone_record_reads_back_as_written() {
        for keys in [
            vec!["a b/c d/".to_owned()],
            vec!["x".to_owned(), "a b/c d/".to_owned(), "y%".to_owned()],
        ] {
            let record = Record::Tombstone(TombstoneRecord { id: id(ID), keys });
            let text = record.encode();
            assert_eq!(Record::decode(text.as_bytes()).unwrap(), record);
        }
    }

    #[test]
    fn a_tombstone_record_looks_like_this() {
        let record = Record::Tombstone(TombstoneRecord {
            id: id(ID),
            keys: vec!["docs/a b.txt".into(), "old".into()],
        });
        assert_eq!(
            record.encode(),
            "smb-s3-record 1\n\
             kind tombstone\n\
             id 0123456789abcdef0123456789abcdef\n\
             key docs/a%20b.txt\n\
             key old\n\
             end\n"
        );
    }

    #[test]
    fn the_keys_an_entry_deletes_are_gone_lines() {
        let mut record = entry();
        record.gone = vec!["pre/a b.txt".into(), "pre/c.txt".into()];
        let text = encoded(&record);
        assert!(
            text.contains("\ngone pre/a%20b.txt\ngone pre/c.txt\n"),
            "{text}"
        );
        assert_eq!(
            Record::decode(text.as_bytes()).unwrap(),
            Record::Entry(Box::new(record))
        );
    }

    #[test]
    fn a_tombstone_without_keys_or_with_a_key_twice_is_refused() {
        let text = Record::Tombstone(TombstoneRecord {
            id: id(ID),
            keys: vec!["a".into()],
        })
        .encode();
        assert_eq!(fails_on(&text.replace("key a\n", "")), "key");
        assert_eq!(fails_on(&text.replace("key a\n", "key a\nkey a\n")), "key");
        assert_eq!(fails_on(&text.replace("key a\n", "key a b\n")), "key");
        assert_eq!(fails_on(&text.replace("key a\n", "key \n")), "key");
    }

    #[test]
    fn a_bad_or_repeated_gone_key_is_refused() {
        let text = encoded(&entry());
        for bad in [
            "gone ",
            "gone a b",
            "gone %FF",
            &format!("gone {}", "k".repeat(1025)),
        ] {
            let swapped = text.replace("gone pre/other/x%25y\n", &format!("{bad}\n"));
            assert_eq!(fails_on(&swapped), "gone", "{bad:?}");
        }
        let twice = text.replace("gone pre/other/x%25y\n", "gone pre/old%20name.txt\n");
        assert_eq!(fails_on(&twice), "gone");
    }

    #[test]
    fn an_entry_record_looks_like_this() {
        let record = EntryRecord {
            id: id(ID),
            is_dir: false,
            path: "docs/a b.txt".into(),
            key: "docs/a b.txt".into(),
            gone: Vec::new(),
            base: None,
            remote: false,
            local: Some(LocalRecord {
                len: 12,
                present: std::iter::once(0..12).collect(),
            }),
            times: [1, 2, 3, 4],
            attributes: 0x20,
            generation: 3,
            upload_id: None,
            failed: false,
            meta_pending: false,
            marker_pending: false,
        };
        assert_eq!(
            encoded(&record),
            "smb-s3-record 1\n\
             kind entry\n\
             id 0123456789abcdef0123456789abcdef\n\
             type file\n\
             path docs/a%20b.txt\n\
             key docs/a%20b.txt\n\
             remote 0\n\
             local 12\n\
             present 0-12\n\
             times 1 2 3 4\n\
             attributes 20\n\
             generation 3\n\
             failed 0\n\
             pending-meta 0\n\
             pending-marker 0\n\
             end\n"
        );
    }

    #[test]
    fn paths_and_keys_survive_percent_encoding() {
        for text in [
            "plain",
            "a b",
            "a+b",
            "100%",
            "~tilde",
            "a/b/c",
            "caf\u{e9}",
            "\u{65e5}\u{672c}\u{8a9e}",
            "new\nline",
            "tab\t",
            "%41",
            "",
        ] {
            let escaped = escape(text);
            assert!(
                escaped
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)),
                "{escaped}"
            );
            assert_eq!(unescape(&escaped).as_deref(), Some(text), "{text:?}");
            assert_eq!(unescape(&escape_path(text)).as_deref(), Some(text));
        }
        assert_eq!(escape("a b/c"), "a%20b%2Fc");
        assert_eq!(escape_path("a b/c"), "a%20b/c");
    }

    #[test]
    fn text_that_escape_would_not_write_does_not_unescape() {
        for bad in ["a b", "a+b", "%", "%4", "%zz", "%FF", "%C3", "\n", "\u{e9}"] {
            assert_eq!(unescape(bad), None, "{bad:?}");
        }
        assert_eq!(unescape("%c3%a9").as_deref(), Some("\u{e9}"));
    }

    /// The sample record with the value of line `name` replaced.
    fn with_value(name: &str, value: &str) -> String {
        encoded(&entry())
            .lines()
            .map(|l| match l.split_once(' ') {
                Some((n, _)) if n == name => format!("{name} {value}"),
                _ => l.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn without_line(name: &str) -> String {
        encoded(&entry())
            .lines()
            .filter(|l| l.split(' ').next() != Some(name))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn fails_on(text: &str) -> &'static str {
        match Record::decode(text.as_bytes()) {
            Err(Malformed(field)) => field,
            Ok(record) => panic!("read {record:?} from {text:?}"),
        }
    }

    #[test]
    fn a_bad_value_in_any_field_is_refused_by_name() {
        let cases: &[(&str, &[&str])] = &[
            ("kind", &["", "dir", "Entry", "entry x"]),
            (
                "id",
                &[
                    "",
                    "0123",
                    &ID.to_uppercase(),
                    "g123456789abcdef0123456789abcdef",
                ],
            ),
            ("type", &["", "File", "link"]),
            (
                "path",
                &[
                    "", "a b", "%2F", "a%2F%2Fb", "%2Fa", "a%2F", "..", "a%2F..", "%FF", "a%3Ab",
                ],
            ),
            ("key", &["", "a b", "%FF", &"k".repeat(1025)]),
            ("remote", &["", "2", "true", "01"]),
            (
                "local",
                &["", "-1", "x", "1.5", "99999999999999999999", " 1"],
            ),
            (
                "present",
                &[
                    "x",
                    "5",
                    "5-",
                    "-5",
                    "5-5",
                    "6-5",
                    "0-10,5-20",
                    "0-10,10-20",
                    "20-30,0-10",
                    "0-101",
                    "0-10,",
                    ",0-10",
                    "0-10 20-30",
                    "0-+5",
                ],
            ),
            (
                "times",
                &[
                    "",
                    "1 2 3",
                    "1 2 3 4 5",
                    "1 2 3 x",
                    "1  2 3 4",
                    "-1 2 3 4",
                    "1 2 3 4 ",
                    "9223372036854775808 2 3 4",
                    "1 2 3 18446744073709551615",
                ],
            ),
            ("attributes", &["", "x", "123456789", "2G", "20 ", "+20"]),
            (
                "generation",
                &["", "-1", "x", "1e3", "99999999999999999999"],
            ),
            ("upload", &["", "a b", "%FF"]),
            ("failed", &["", "yes", "2"]),
            ("pending-meta", &["", "yes", "2"]),
            ("pending-marker", &["", "yes", "2"]),
            ("base-key", &["", "a b", &"k".repeat(1025)]),
            ("base-etag", &["a b", "%FF"]),
            ("base-size", &["", "-1", "x", "99999999999999999999"]),
            (
                "base-modified",
                &[
                    "",
                    "x",
                    "1.5",
                    "99999999999999999999999999999999999999",
                    "170141183460469231731687303715884105727",
                ],
            ),
        ];
        for (field, values) in cases {
            for value in *values {
                assert_eq!(
                    fails_on(&with_value(field, value)),
                    *field,
                    "{field} {value:?}"
                );
            }
        }
    }

    #[test]
    fn a_bad_metadata_line_is_refused() {
        let text = encoded(&entry());
        for (line, bad) in [
            ("base-user mtime 1700000000.5", "base-user mtime"),
            ("base-user mtime 1700000000.5", "base-user  1"),
            ("base-user mtime 1700000000.5", "base-user a b c"),
            ("base-user mtime 1700000000.5", "base-user a%FF b"),
            ("base-user mtime 1700000000.5", "base-user mtime 1+2"),
            ("base-system content-type", "base-system color blue"),
            ("base-system content-type", "base-system content-type"),
        ] {
            let target = line.split(' ').take(2).collect::<Vec<_>>().join(" ");
            let swapped: String = text
                .lines()
                .map(|l| {
                    if l.starts_with(&target) {
                        format!("{bad}\n")
                    } else {
                        format!("{l}\n")
                    }
                })
                .collect();
            let field = fails_on(&swapped);
            assert!(field.starts_with("base-"), "{bad}: {field}");
        }
        let doubled = text.replace(
            "base-user mtime 1700000000.5\n",
            "base-user mtime 1\nbase-user mtime 2\n",
        );
        assert_eq!(fails_on(&doubled), "base-user");
        let doubled = text.replace(
            "base-system content-type text%2Fplain%3B%20charset%3Dutf-8\n",
            "base-system content-type a\nbase-system content-type b\n",
        );
        assert_eq!(fails_on(&doubled), "base-system");
    }

    #[test]
    fn a_missing_or_repeated_field_is_refused_by_name() {
        for field in [
            "kind",
            "id",
            "type",
            "path",
            "key",
            "remote",
            "times",
            "attributes",
            "generation",
            "failed",
            "pending-meta",
            "pending-marker",
            "present",
            "base-etag",
            "base-size",
            "base-modified",
        ] {
            assert_eq!(fails_on(&without_line(field)), field, "missing {field}");
        }
        for field in [
            "kind",
            "id",
            "type",
            "path",
            "key",
            "remote",
            "local",
            "times",
            "attributes",
            "generation",
            "upload",
            "failed",
            "pending-meta",
            "pending-marker",
            "base-key",
            "base-etag",
            "base-size",
            "base-modified",
        ] {
            let text = encoded(&entry());
            let at = text.find(&format!("\n{field} ")).unwrap() + 1;
            let end = at + text[at..].find('\n').unwrap() + 1;
            let twice = format!("{}{}{}", &text[..end], &text[at..end], &text[end..]);
            assert_eq!(fails_on(&twice), field, "repeated {field}");
        }
    }

    #[test]
    fn a_line_that_belongs_to_nothing_is_refused() {
        let text = encoded(&entry()).replace("end\n", "surprise 1\nend\n");
        assert_eq!(fails_on(&text), "field");
        let mut no_base = entry();
        no_base.base = None;
        let text = encoded(&no_base).replace("end\n", "base-size 5\nend\n");
        assert_eq!(fails_on(&text), "field");
        let text = encoded(&no_base).replace("end\n", "base-user a b\nend\n");
        assert_eq!(fails_on(&text), "field");
    }

    #[test]
    fn fields_that_contradict_each_other_are_refused() {
        let mut dir = entry();
        dir.is_dir = true;
        assert_eq!(fails_on(&encoded(&dir)), "present");
        let mut file = entry();
        file.marker_pending = true;
        assert_eq!(fails_on(&encoded(&file)), "pending-marker");
        let text = encoded(&entry()).replace("local 100\n", "");
        assert_eq!(fails_on(&text), "present");
        let mut with_upload = dir_record();
        with_upload.upload_id = Some("u".into());
        assert_eq!(fails_on(&encoded(&with_upload)), "upload");
        let with_entry_field = Record::Tombstone(TombstoneRecord {
            id: id(ID),
            keys: vec!["k".into()],
        })
        .encode()
        .replace("end\n", "remote 1\nend\n");
        assert_eq!(fails_on(&with_entry_field), "field");
    }

    fn dir_record() -> EntryRecord {
        EntryRecord {
            is_dir: true,
            local: None,
            upload_id: None,
            ..entry()
        }
    }

    #[test]
    fn the_largest_time_is_i64_max() {
        let mut record = entry();
        record.times = [i64::MAX as u64, 0, 1, i64::MAX as u64];
        assert_eq!(
            Record::decode(encoded(&record).as_bytes()).unwrap(),
            Record::Entry(Box::new(record))
        );
    }

    #[test]
    fn a_wrong_version_or_ending_is_refused() {
        let text = encoded(&entry());
        assert_eq!(fails_on(&text.replace("record 1", "record 2")), "version");
        assert_eq!(fails_on(&text.replace("smb-s3-record", "x")), "version");
        assert_eq!(fails_on(text.strip_suffix("end\n").unwrap()), "end");
        assert_eq!(fails_on(&text.replace("end\n", "end")), "end");
        assert_eq!(fails_on(&format!("{text}end\n")), "field");
        assert_eq!(fails_on(""), "end");
        assert_eq!(fails_on("end\n"), "version");
        assert_eq!(fails_on(&format!("\n{text}")), "version");
    }

    #[test]
    fn text_that_is_not_utf8_is_refused() {
        let mut bytes = encoded(&entry()).into_bytes();
        bytes[20] = 0xff;
        assert_eq!(Record::decode(&bytes), Err(Malformed("encoding")));
        assert_eq!(
            Record::decode(&[0xff, 0xfe, 0x00]),
            Err(Malformed("encoding"))
        );
    }

    #[test]
    fn every_cut_of_a_record_is_refused() {
        let text = encoded(&entry());
        for cut in 0..text.len() {
            let Some(head) = text.get(..cut) else {
                continue;
            };
            assert!(Record::decode(head.as_bytes()).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn scrambled_records_never_panic() {
        let text = encoded(&entry()).into_bytes();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..4000 {
            let mut bytes = text.clone();
            for _ in 0..=(next() % 4) {
                let at = (next() % bytes.len() as u64) as usize;
                match next() % 3 {
                    0 => bytes[at] = next() as u8,
                    1 => {
                        bytes.remove(at);
                    }
                    _ => bytes.insert(at, b"\n %-0aZ"[(next() % 7) as usize]),
                }
            }
            let _ = Record::decode(&bytes);
        }
        let junk: Vec<u8> = (0..4096).map(|_| next() as u8).collect();
        assert!(Record::decode(&junk).is_err());
    }

    #[test]
    fn times_before_1970_and_exact_nanoseconds_survive() {
        for time in [
            UNIX_EPOCH - Duration::new(5, 999_999_999),
            UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789),
            UNIX_EPOCH,
        ] {
            assert_eq!(time_from_nanos(nanos_since_epoch(time)), Some(time));
        }
        let mut old = entry();
        old.base.as_mut().unwrap().head.last_modified = UNIX_EPOCH - Duration::new(86_400, 7);
        let text = encoded(&old);
        assert_eq!(
            Record::decode(text.as_bytes()).unwrap(),
            Record::Entry(Box::new(old))
        );
    }

    #[test]
    fn ids_are_32_lowercase_hex_digits() {
        assert_eq!(RecordId::parse(ID).as_ref().map(RecordId::as_str), Some(ID));
        for bad in ["", "abc", &ID.to_uppercase(), &format!("{ID}0"), &ID[1..]] {
            assert_eq!(RecordId::parse(bad), None, "{bad:?}");
        }
    }
}
