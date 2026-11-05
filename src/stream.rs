//! Named streams: the suffixes of CREATE names (`file:name`,
//! `file:name:$DATA`, `file::$DATA`, MS-FSCC 2.1.5), the stream list a
//! backend reports, and the handle of a stream open.

use std::str::FromStr;

use async_trait::async_trait;

use crate::backend::{DirEntry, DirWatch, FileInfo, FileTimes, Handle};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// Name of a named data stream: the `name` in `file.txt:name:$DATA`.
///
/// 1 to 255 UTF-16 code units, none of them `\`, `/`, `:` or NUL
/// (MS-FSCC 2.1.5.3). Control characters and `" * < > ? |` are allowed.
/// `==` compares the names as spelled; [`StreamName::matches`] tells
/// whether two names select the same stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamName(String);

impl StreamName {
    /// The name as the client sent it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if `self` and `other` name the same stream: stream names
    /// compare without regard to case.
    pub fn matches(&self, other: &StreamName) -> bool {
        self.0 == other.0 || self.0.to_lowercase() == other.0.to_lowercase()
    }
}

/// True if `a` and `b` name the same stream of a file, `None` being the
/// default stream.
pub(crate) fn same_stream(a: Option<&StreamName>, b: Option<&StreamName>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.matches(b),
        _ => false,
    }
}

/// A named stream of a file, as [`Handle::streams`] lists it. Built with
/// [`StreamInfo::new`]; every field is public.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StreamInfo {
    /// Name of the stream.
    pub name: StreamName,
    /// Size of the stream in bytes.
    pub size: u64,
    /// Space the stream takes, which may be `size`.
    pub allocation_size: u64,
}

impl StreamInfo {
    /// The stream `name` with `size` bytes in `allocation_size` bytes.
    pub fn new(name: StreamName, size: u64, allocation_size: u64) -> Self {
        Self {
            name,
            size,
            allocation_size,
        }
    }
}

impl FromStr for StreamName {
    type Err = SmbError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let units = s.encode_utf16().count();
        if !(1..=MAX_STREAM_NAME_UNITS).contains(&units) || s.contains(['\\', '/', ':', '\0']) {
            return Err(SmbError::NameInvalid);
        }
        Ok(Self(s.to_string()))
    }
}

/// Longest stream name, in UTF-16 code units (MS-FSCC 2.1.5.3).
const MAX_STREAM_NAME_UNITS: usize = 255;

/// The stream a CREATE name selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StreamPart {
    /// No suffix.
    None,
    /// `::$DATA`: the unnamed data stream, which a directory does not have.
    Data,
    /// `::$INDEX_ALLOCATION` or `:$I30:$INDEX_ALLOCATION`: the directory
    /// itself.
    Directory,
    /// `:name` or `:name:$DATA`.
    Named(StreamName),
    /// `:name:$INDEX_ALLOCATION` with any other name.
    NamedDirectory(StreamName),
}

/// Splits a CREATE name into the path of the file and the stream it
/// selects (MS-FSA 2.1.5.1, phases 5 and 6). Only the last component may
/// carry a suffix; a name that ends in `:` is invalid, and the stream type
/// is `$DATA` or `$INDEX_ALLOCATION`, compared case-insensitively. The file
/// part follows every [`SmbPath`] rule.
pub(crate) fn parse_create_name(units: &[u16]) -> SmbResult<(SmbPath, StreamPart)> {
    let name = String::from_utf16(units).map_err(|_| SmbError::NameInvalid)?;
    let Some((file, suffix)) = name.split_once(':') else {
        return Ok((name.parse()?, StreamPart::None));
    };
    if name.ends_with(':') {
        return Err(SmbError::NameInvalid);
    }
    // A separator or a third `:` after the first `:` lands in the stream
    // name or the type, and both refuse it.
    let (stream, kind) = suffix.split_once(':').unwrap_or((suffix, "$DATA"));
    let directory = if kind.eq_ignore_ascii_case("$DATA") {
        false
    } else if kind.eq_ignore_ascii_case("$INDEX_ALLOCATION") {
        true
    } else {
        return Err(SmbError::NameInvalid);
    };
    let path = file.parse()?;
    // `$I30` is the name of a directory's index (MS-FSA 2.1.5.1 phase 7).
    let part = match (stream, directory) {
        ("", false) => StreamPart::Data,
        ("", true) => StreamPart::Directory,
        (index, true) if index.eq_ignore_ascii_case("$I30") => StreamPart::Directory,
        (stream, false) => StreamPart::Named(stream.parse()?),
        (stream, true) => StreamPart::NamedDirectory(stream.parse()?),
    };
    Ok((path, part))
}

/// What a FileRenameInformation name that starts with `:` renames the
/// open's stream to: `:name`, `:name:type` or `::type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamTarget {
    /// The new name; `None` for the default stream.
    pub stream: Option<StreamName>,
    /// The stream type the name gives, if it gives one.
    pub kind: Option<StreamType>,
}

/// A stream type in a stream rename target, compared case-insensitively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamType {
    /// `$DATA`.
    Data,
    /// `$INDEX_ALLOCATION`.
    Directory,
    /// Any other type.
    Other,
}

/// Parses a stream rename target, a name that starts with `:` (MS-FSA
/// 2.1.5.15.12.1). One that ends in `:`, has a third `:`, or has a name or
/// type MS-FSCC 2.1.5.3 and 2.1.5.4 refuse fails with
/// STATUS_INVALID_PARAMETER.
pub(crate) fn parse_stream_target(units: &[u16]) -> Result<StreamTarget, u32> {
    let invalid = crate::ntstatus::STATUS_INVALID_PARAMETER;
    let name = String::from_utf16(units).map_err(|_| invalid)?;
    let rest = name.strip_prefix(':').ok_or(invalid)?;
    if name.ends_with(':') {
        return Err(invalid);
    }
    let (stream, kind) = match rest.split_once(':') {
        Some((stream, kind)) => (stream, Some(kind)),
        None => (rest, None),
    };
    if kind.is_some_and(|k| k.contains(['\\', '/', ':', '\0'])) {
        return Err(invalid);
    }
    let stream = match stream {
        "" => None,
        stream => Some(stream.parse().map_err(|_| invalid)?),
    };
    let kind = kind.map(|kind| {
        if kind.eq_ignore_ascii_case("$DATA") {
            StreamType::Data
        } else if kind.eq_ignore_ascii_case("$INDEX_ALLOCATION") {
            StreamType::Directory
        } else {
            StreamType::Other
        }
    });
    Ok(StreamTarget { stream, kind })
}

/// The characters macOS clients send as U+F020 to U+F027 in names, in that
/// order. U+F001 to U+F01F stand for 0x01 to 0x1F, and U+F028 and U+F029
/// for a space and a `.` that end a name.
#[cfg(any(all(feature = "localfs", target_os = "macos"), test))]
const SFM_CHARS: [char; 8] = ['"', '*', ':', '<', '>', '?', '\\', '|'];

/// The name macOS means by the stream name `name`. macOS clients send the
/// characters NTFS names cannot hold as private-use characters, in the
/// mapping of Services for Macintosh: `:` as U+F022, for example, and a
/// trailing space as U+F028. Each becomes the character it stands for
/// again; U+F028 and U+F029 only at the end of the name.
#[cfg(any(all(feature = "localfs", target_os = "macos"), test))]
pub(crate) fn from_sfm(name: &str) -> String {
    let last = name.chars().count().saturating_sub(1);
    name.chars()
        .enumerate()
        .map(|(i, c)| match u32::from(c) {
            n @ 0xF001..=0xF01F => char::from_u32(n - 0xF000).unwrap_or(c),
            n @ 0xF020..=0xF027 => SFM_CHARS[(n - 0xF020) as usize],
            0xF028 if i == last => ' ',
            0xF029 if i == last => '.',
            _ => c,
        })
        .collect()
}

/// The stream name for the name `name`, the inverse of [`from_sfm`]: the
/// characters it maps back are sent as macOS clients send them. A name
/// that already holds one of the private-use characters `from_sfm` maps,
/// where it maps it, has no stream name, and comes back changed.
#[cfg(any(all(feature = "localfs", target_os = "macos"), test))]
pub(crate) fn to_sfm(name: &str) -> String {
    let last = name.chars().count().saturating_sub(1);
    name.chars()
        .enumerate()
        .map(|(i, c)| match c {
            '\u{1}'..='\u{1F}' => char::from_u32(0xF000 + u32::from(c)).unwrap_or(c),
            ' ' if i == last => '\u{F028}',
            '.' if i == last => '\u{F029}',
            c => SFM_CHARS
                .iter()
                .position(|&m| m == c)
                .and_then(|at| char::from_u32(0xF020 + at as u32))
                .unwrap_or(c),
        })
        .collect()
}

/// What an open of a named stream reports of its file, `info` as the
/// backend gave it: a named stream is a data stream, also on a directory,
/// so its attributes leave out FILE_ATTRIBUTE_DIRECTORY, and
/// FileStandardInformation says it is no directory.
pub(crate) fn data_stream_info(info: FileInfo) -> FileInfo {
    FileInfo {
        is_directory: false,
        ..info
    }
}

/// The error a stream request on a share that stores named streams answers
/// for `e`. macOS keeps an extended attribute in a `._` file instead when a
/// stream request fails with STATUS_NOT_SUPPORTED, and would then look for
/// it in the stream and not find it; such a backend error becomes
/// STATUS_ACCESS_DENIED.
pub(crate) fn stream_error(e: SmbError) -> SmbError {
    match e {
        SmbError::NotSupported => SmbError::AccessDenied,
        e => e,
    }
}

/// The status for a request the server does not serve:
/// STATUS_NOT_SUPPORTED, or STATUS_INVALID_PARAMETER on a named stream
/// (`on_stream`), for the reason [`stream_error`] gives.
pub(crate) fn unsupported(on_stream: bool) -> u32 {
    if on_stream {
        crate::ntstatus::STATUS_INVALID_PARAMETER
    } else {
        crate::ntstatus::STATUS_NOT_SUPPORTED
    }
}

/// The handle of a named stream open, which answers every backend error as
/// [`stream_error`] does.
pub(crate) struct StreamHandle(pub(crate) Box<dyn Handle>);

#[async_trait]
impl Handle for StreamHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<bytes::Bytes> {
        self.0.read(offset, len).await.map_err(stream_error)
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.0.write(offset, data).await.map_err(stream_error)
    }

    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        self.0.write_owned(offset, data).await.map_err(stream_error)
    }

    async fn flush(&self) -> SmbResult<()> {
        self.0.flush().await.map_err(stream_error)
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        self.0.stat().await.map_err(stream_error)
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.0.set_times(times).await.map_err(stream_error)
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.0
            .set_attributes(attributes)
            .await
            .map_err(stream_error)
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.0.truncate(len).await.map_err(stream_error)
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        self.0.list_dir(pattern).await.map_err(stream_error)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        self.0.close().await.map_err(stream_error)
    }

    async fn link_count(&self) -> SmbResult<u32> {
        self.0.link_count().await.map_err(stream_error)
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        self.0.dir_is_empty().await.map_err(stream_error)
    }

    async fn watch(&self) -> SmbResult<Option<Box<dyn DirWatch>>> {
        self.0.watch().await.map_err(stream_error)
    }

    async fn streams(&self) -> SmbResult<Vec<StreamInfo>> {
        self.0.streams().await.map_err(stream_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> SmbResult<(SmbPath, StreamPart)> {
        parse_create_name(&s.encode_utf16().collect::<Vec<_>>())
    }

    fn named(s: &str) -> StreamPart {
        StreamPart::Named(s.parse().unwrap())
    }

    fn path(s: &str) -> SmbPath {
        s.parse().unwrap()
    }

    #[test]
    fn names_without_a_suffix_are_paths() {
        assert_eq!(
            parse("dir\\f.txt").unwrap(),
            (path("dir\\f.txt"), StreamPart::None)
        );
        assert_eq!(parse("").unwrap(), (SmbPath::root(), StreamPart::None));
    }

    #[test]
    fn suffixes_select_a_stream() {
        let cases = [
            ("f:s", named("s")),
            ("f:s:$DATA", named("s")),
            ("f:s:$DaTa", named("s")),
            ("f:$DATA", named("$DATA")),
            ("f:$DATA:$DATA", named("$DATA")),
            ("f::$DATA", StreamPart::Data),
            ("f::$data", StreamPart::Data),
            ("f::$INDEX_ALLOCATION", StreamPart::Directory),
            ("f::$Index_Allocation", StreamPart::Directory),
            ("f:$I30:$INDEX_ALLOCATION", StreamPart::Directory),
            ("f:$i30:$index_allocation", StreamPart::Directory),
            ("f:$I30", named("$I30")),
            ("f:$I30:$DATA", named("$I30")),
            (
                "f:s:$INDEX_ALLOCATION",
                StreamPart::NamedDirectory("s".parse().unwrap()),
            ),
        ];
        for (name, part) in cases {
            assert_eq!(parse(name).unwrap(), (path("f"), part), "{name}");
        }
        assert_eq!(
            parse("\\dir\\f.txt:s").unwrap(),
            (path("dir\\f.txt"), named("s"))
        );
        assert_eq!(parse(":s").unwrap(), (SmbPath::root(), named("s")));
        for root in ["::$DATA", ".::$DATA", "\\::$DATA"] {
            assert_eq!(
                parse(root).unwrap(),
                (SmbPath::root(), StreamPart::Data),
                "{root}"
            );
        }
        assert_eq!(
            parse("::$INDEX_ALLOCATION").unwrap(),
            (SmbPath::root(), StreamPart::Directory)
        );
    }

    #[test]
    fn stream_names_take_characters_file_names_refuse() {
        for stream in ["\u{5}?*", "a\"b<c>|", " lead and trail. ", "\n"] {
            assert_eq!(
                parse(&format!("f:{stream}")).unwrap(),
                (path("f"), named(stream)),
                "{stream:?}"
            );
        }
        let tags = "com.apple.metadata\u{F022}_kMDItemUserTags";
        assert_eq!(parse(&format!("f:{tags}")).unwrap().1, named(tags));
    }

    #[test]
    fn malformed_suffixes_are_refused() {
        for name in [
            "f:",
            "f::",
            "f:s:",
            "f::$DATA:",
            "f:a:b:c",
            "f:s:$DATA:$DATA",
            "f:s:$FOO",
            "f::$BITMAP",
            "f:s:DATA",
            "a:s\\b",
            "a:s/b",
            "a::$DATA\\b",
            "dir:s\\f.txt",
            "dir\\:s",
            "f:\0",
            "*:s",
            "a\\..\\b:s",
        ] {
            assert!(parse(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn stream_names_count_utf16_units() {
        let longest = "x".repeat(255);
        assert_eq!(parse(&format!("f:{longest}")).unwrap().1, named(&longest));
        assert!(parse(&format!("f:{longest}x")).is_err());
        // U+1F600 takes two units.
        let pairs = format!("{}x", "\u{1F600}".repeat(127));
        assert_eq!(parse(&format!("f:{pairs}")).unwrap().1, named(&pairs));
        assert!(parse(&format!("f:{}", "\u{1F600}".repeat(128))).is_err());
    }

    #[test]
    fn unpaired_surrogates_are_refused() {
        let mut units: Vec<u16> = "f:s".encode_utf16().collect();
        units.push(0xD800);
        assert!(parse_create_name(&units).is_err());
    }

    fn target(s: &str) -> Result<StreamTarget, u32> {
        parse_stream_target(&s.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn rename_targets_name_a_stream_and_maybe_its_type() {
        let cases = [
            (":t", Some("t"), None),
            (":t:$DATA", Some("t"), Some(StreamType::Data)),
            (":t:$data", Some("t"), Some(StreamType::Data)),
            (
                ":t:$INDEX_ALLOCATION",
                Some("t"),
                Some(StreamType::Directory),
            ),
            (":t:$FOO", Some("t"), Some(StreamType::Other)),
            ("::$DATA", None, Some(StreamType::Data)),
            ("::$INDEX_ALLOCATION", None, Some(StreamType::Directory)),
            (":a\"b*?", Some("a\"b*?"), None),
        ];
        for (name, stream, kind) in cases {
            let expected = StreamTarget {
                stream: stream.map(|s| s.parse().unwrap()),
                kind,
            };
            assert_eq!(target(name), Ok(expected), "{name}");
        }
        let longest = format!(":{}", "x".repeat(255));
        assert!(target(&longest).is_ok());
    }

    #[test]
    fn malformed_rename_targets_are_invalid_parameters() {
        let long = format!(":{}", "x".repeat(256));
        for name in [
            ":",
            "::",
            ":t:",
            "::$DATA:",
            ":a:b:c",
            ":t:$DATA:$DATA",
            ":a\\b",
            ":a/b",
            ":t:$DA\\TA",
            ":a\0",
            "t",
            long.as_str(),
        ] {
            assert_eq!(
                target(name),
                Err(crate::ntstatus::STATUS_INVALID_PARAMETER),
                "{name:?}"
            );
        }
    }

    #[test]
    fn stream_names_match_without_case() {
        let name = |s: &str| s.parse::<StreamName>().unwrap();
        assert!(name("Zone.Identifier").matches(&name("zone.IDENTIFIER")));
        assert!(name("\u{C9}t\u{E9}").matches(&name("\u{E9}T\u{C9}")));
        assert!(!name("a").matches(&name("b")));
        assert_ne!(name("A"), name("a"));
    }

    #[test]
    fn stream_errors_never_say_not_supported() {
        assert!(matches!(
            stream_error(SmbError::NotSupported),
            SmbError::AccessDenied
        ));
        assert!(matches!(
            stream_error(SmbError::DiskFull),
            SmbError::DiskFull
        ));
    }

    #[test]
    fn private_use_characters_from_macos_map_back() {
        assert_eq!(
            from_sfm("com.apple.metadata\u{F022}_kMDItemUserTags"),
            "com.apple.metadata:_kMDItemUserTags"
        );
        let sent: String = (0xF001..=0xF027)
            .map(|n| char::from_u32(n).unwrap())
            .collect();
        let meant: String = (1..=0x1F)
            .map(|n| char::from_u32(n).unwrap())
            .chain("\"*:<>?\\|".chars())
            .collect();
        assert_eq!(from_sfm(&sent), meant);
        assert_eq!(from_sfm("tag\u{F028}"), "tag ");
        assert_eq!(from_sfm("tag\u{F029}"), "tag.");
        for kept in [
            "\u{F000}",
            "\u{F02A}",
            "a\u{F028}b",
            "a\u{F029}b",
            "a*b",
            "\u{1F600}",
        ] {
            assert_eq!(from_sfm(kept), kept);
        }
    }

    #[test]
    fn names_map_to_stream_names_and_back() {
        let name = to_sfm("com.apple.metadata:kMDItemFinderComment");
        assert_eq!(name, "com.apple.metadata\u{F022}kMDItemFinderComment");
        assert!(name.parse::<StreamName>().is_ok());
        assert_eq!(to_sfm("a*?\\b"), "a\u{F021}\u{F025}\u{F026}b");
        assert_eq!(to_sfm("a. b "), "a. b\u{F028}");
        assert_eq!(to_sfm("x\u{1}."), "x\u{F001}\u{F029}");
        for name in ["a:b\\c", "trailing. ", "a*?<>|\"\u{1}.", "plain", ""] {
            assert_eq!(from_sfm(&to_sfm(name)), name);
            assert!(!to_sfm(name).contains(['*', ':', '\\']));
        }
        // A name holding a private-use character where it would map comes
        // back as another name.
        for name in ["a\u{F021}b", "tag\u{F028}"] {
            assert_ne!(from_sfm(&to_sfm(name)), name);
        }
        // Literal characters do not round-trip.
        for literal in ["a*b", "tag ", "x\u{1}"] {
            assert_ne!(to_sfm(&from_sfm(literal)), literal);
        }
    }

    #[test]
    fn stream_names_validate_on_their_own() {
        assert_eq!("s".parse::<StreamName>().unwrap().as_str(), "s");
        for bad in ["", "a:b", "a\\b", "a/b", "a\0b"] {
            assert!(bad.parse::<StreamName>().is_err(), "{bad:?}");
        }
    }
}
