//! `SmbPath`: validated, normalized SMB path used between dispatcher and
//! backend.
//!
//! Handlers decode wire names to `&[u16]` and build an `SmbPath` with
//! `from_utf16`; backends can use it without further checks.

use std::str::FromStr;

use crate::error::{SmbError, SmbResult};

/// A validated, component-list path. No `..`, no Windows-forbidden chars, no
/// alternate streams. Always relative to the share root; the empty path is
/// the root.
///
/// Each component is a filename as MS-FSCC 2.1.5.2 defines it: 1 to 255
/// UTF-16 code units, with no control characters and none of
/// `" * / : < > ? \ |`. The whole path is at most 32,760 UTF-16 code units.
/// On Windows hosts the reserved device names (`CON`, `PRN`, `AUX`, `NUL`,
/// `COM1`-`COM9` and `LPT1`-`LPT9`, with or without an extension) are
/// rejected too.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmbPath {
    components: Vec<String>,
}

impl SmbPath {
    /// The share root.
    pub fn root() -> Self {
        Self::default()
    }

    /// Construct from a UTF-16 code-unit slice (already decoded from UTF-16LE
    /// wire bytes).
    pub fn from_utf16(units: &[u16]) -> SmbResult<Self> {
        let s = decode_utf16_strict(units)?;
        s.parse()
    }

    fn parse_components(s: &str) -> SmbResult<Self> {
        // Strip a leading separator (clients sometimes prefix `\` or `/`).
        let trimmed = s
            .strip_prefix('\\')
            .or_else(|| s.strip_prefix('/'))
            .unwrap_or(s);
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        if trimmed.encode_utf16().count() > MAX_PATH_UNITS {
            return Err(SmbError::NameInvalid);
        }

        // 2. Reject forbidden characters anywhere in the path. `\` and `/`
        //    are separators here.
        if trimmed.chars().any(|c| is_control(c) || is_forbidden(c)) {
            return Err(SmbError::NameInvalid);
        }

        // 3. Split on `\` or `/`; reject `..` and empty components; skip `.`.
        let mut components = Vec::new();
        for raw in trimmed.split(['\\', '/']) {
            if raw.is_empty() {
                // Doubled separator like `foo\\bar`: reject.
                return Err(SmbError::NameInvalid);
            }
            if raw == "." {
                continue;
            }
            if raw == ".." {
                return Err(SmbError::NameInvalid);
            }
            // 4. Length and, on Windows hosts, reserved device names.
            if raw.encode_utf16().count() > MAX_COMPONENT_UNITS || host_reserved_name(raw) {
                return Err(SmbError::NameInvalid);
            }
            components.push(raw.to_string());
        }
        Ok(Self { components })
    }

    /// Path components in order. Empty for the root.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Is this the share root?
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Return the parent path, or `None` if this is the root.
    pub fn parent(&self) -> Option<SmbPath> {
        if self.is_root() {
            return None;
        }
        let mut parent = self.components.clone();
        parent.pop();
        Some(SmbPath { components: parent })
    }

    /// Return the last component, if any.
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(|s| s.as_str())
    }

    /// Validate `last` and append its components to this path.
    pub fn join(&self, last: &str) -> SmbResult<SmbPath> {
        // Run `last` through the same validator (treating it as a single-
        // component path).
        let extra = last.parse::<SmbPath>()?;
        let mut out = self.clone();
        out.components.extend(extra.components);
        Ok(out)
    }

    /// Render as a backslash-separated string. Empty for root.
    pub fn display_backslash(&self) -> String {
        self.components.join("\\")
    }
}

/// True if `a` and `b` name the same entry, comparing names
/// case-insensitively unless `case_sensitive`.
pub(crate) fn same_path(a: &SmbPath, b: &SmbPath, case_sensitive: bool) -> bool {
    a.components().len() == b.components().len() && starts_with(a, b, case_sensitive)
}

/// `path` with its leading `from` replaced by `to`, if `path` is `from` or
/// lies below it, comparing names case-insensitively unless
/// `case_sensitive`.
pub(crate) fn rebase(
    path: &SmbPath,
    from: &SmbPath,
    to: &SmbPath,
    case_sensitive: bool,
) -> Option<SmbPath> {
    if !starts_with(path, from, case_sensitive) {
        return None;
    }
    let mut components = to.components.clone();
    components.extend_from_slice(&path.components[from.components.len()..]);
    Some(SmbPath { components })
}

fn starts_with(path: &SmbPath, prefix: &SmbPath, case_sensitive: bool) -> bool {
    path.components.len() >= prefix.components.len()
        && path
            .components
            .iter()
            .zip(&prefix.components)
            .all(|(x, y)| {
                if case_sensitive {
                    x == y
                } else {
                    x.to_lowercase() == y.to_lowercase()
                }
            })
}

impl FromStr for SmbPath {
    type Err = SmbError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_components(s)
    }
}

impl std::fmt::Display for SmbPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_root() {
            f.write_str("\\")
        } else {
            f.write_str(&self.display_backslash())
        }
    }
}

/// Longest filename component, in UTF-16 code units (MS-FSCC 2.1.5.2).
const MAX_COMPONENT_UNITS: usize = 255;

/// Longest pathname, in UTF-16 code units (MS-FSCC 2.1.5).
const MAX_PATH_UNITS: usize = 32_760;

/// True if `name` is one filename component that `SmbPath` accepts, so a
/// client that sees it in a listing can open it.
#[cfg_attr(
    not(feature = "localfs"),
    allow(dead_code, reason = "used by LocalFsBackend")
)]
pub(crate) fn is_valid_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.encode_utf16().count() <= MAX_COMPONENT_UNITS
        && !name
            .chars()
            .any(|c| is_control(c) || is_forbidden(c) || matches!(c, '\\' | '/'))
        && !host_reserved_name(name)
}

/// True if `pattern` is a valid QUERY_DIRECTORY search pattern (MS-FSA
/// 2.1.5.6.3): a filename component in which the wildcards `* ? < > "` may
/// appear, or `.` or `..`.
pub(crate) fn is_valid_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && pattern.encode_utf16().count() <= MAX_COMPONENT_UNITS
        && !pattern
            .chars()
            .any(|c| is_control(c) || matches!(c, ':' | '|' | '\\' | '/'))
}

fn is_control(c: char) -> bool {
    ('\u{0000}'..='\u{001F}').contains(&c)
}

fn is_forbidden(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
}

/// True if `name` is a reserved DOS device name on this host. Only Windows
/// resolves these names to devices.
fn host_reserved_name(name: &str) -> bool {
    cfg!(windows) && is_reserved_dos_name(name)
}

fn is_reserved_dos_name(s: &str) -> bool {
    // Strip extension before checking, e.g. "CON.txt" is also reserved.
    let stem = match s.rsplit_once('.') {
        Some((stem, _)) => stem,
        None => s,
    };
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") || matches_com_or_lpt(&upper)
}

fn matches_com_or_lpt(s: &str) -> bool {
    if s.len() != 4 {
        return false;
    }
    let bytes = s.as_bytes();
    let prefix = &bytes[..3];
    let last = bytes[3] as char;
    if !matches!(last, '1'..='9') {
        return false;
    }
    prefix == b"COM" || prefix == b"LPT"
}

fn decode_utf16_strict(units: &[u16]) -> SmbResult<String> {
    // Reject unpaired surrogates explicitly. `String::from_utf16` does this
    // already; we surface its error as NameInvalid.
    String::from_utf16(units).map_err(|_| SmbError::NameInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn p(s: &str) -> SmbPath {
        s.parse().unwrap()
    }

    #[test]
    fn root_paths() {
        assert!("".parse::<SmbPath>().unwrap().is_root());
        assert!("\\".parse::<SmbPath>().unwrap().is_root());
        assert!("/".parse::<SmbPath>().unwrap().is_root());
        assert!(SmbPath::from_utf16(&utf16("")).unwrap().is_root());
    }

    #[test]
    fn simple_paths_split() {
        let p = "dir\\sub\\file.txt".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["dir", "sub", "file.txt"]);
        assert_eq!(p.display_backslash(), "dir\\sub\\file.txt");
        assert!(!p.is_root());
        assert_eq!(p.file_name(), Some("file.txt"));
    }

    #[test]
    fn forward_slash_accepted() {
        let p = "a/b/c".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["a", "b", "c"]);
    }

    #[test]
    fn dot_components_skipped() {
        let p = "a\\.\\b".parse::<SmbPath>().unwrap();
        assert_eq!(p.components(), &["a", "b"]);
    }

    #[test]
    fn parent_returns_one_component_less() {
        let p = "a\\b\\c".parse::<SmbPath>().unwrap();
        let parent = p.parent().unwrap();
        assert_eq!(parent.components(), &["a", "b"]);
        let grand = parent.parent().unwrap();
        assert_eq!(grand.components(), &["a"]);
        let root = grand.parent().unwrap();
        assert!(root.is_root());
        assert!(root.parent().is_none());
    }

    #[test]
    fn join_appends_component() {
        let p = "a".parse::<SmbPath>().unwrap();
        let q = p.join("b").unwrap();
        assert_eq!(q.components(), &["a", "b"]);
    }

    #[test]
    fn rejects_double_dot() {
        assert!("a\\..\\b".parse::<SmbPath>().is_err());
        assert!("..".parse::<SmbPath>().is_err());
    }

    #[test]
    fn rejects_double_separator() {
        assert!("a\\\\b".parse::<SmbPath>().is_err());
    }

    #[test]
    fn rejects_forbidden_chars() {
        for bad in ["a<b", "a>b", "a:b", "a\"b", "a|b", "a?b", "a*b"] {
            assert!(bad.parse::<SmbPath>().is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_control_chars() {
        let s = format!("a{}b", '\u{0001}');
        assert!(s.parse::<SmbPath>().is_err());
        let s = format!("a{}b", '\u{0000}');
        assert!(s.parse::<SmbPath>().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_reserved_dos_names() {
        for bad in [
            "CON", "con", "PRN", "AUX", "NUL", "COM1", "LPT9", "Con.txt", "NUL.dat",
        ] {
            assert!(bad.parse::<SmbPath>().is_err(), "{bad}");
            assert!(!is_valid_component(bad), "{bad}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn accepts_reserved_dos_names_where_the_host_does() {
        for name in ["CON", "aux.c", "dir\\nul", "LPT9.log"] {
            assert!(name.parse::<SmbPath>().is_ok(), "{name}");
        }
        assert!(is_valid_component("aux.c"));
    }

    #[test]
    fn limits_component_and_path_length() {
        let longest = "x".repeat(255);
        assert!(longest.parse::<SmbPath>().is_ok());
        assert!(format!("{longest}y").parse::<SmbPath>().is_err());
        // Length counts UTF-16 code units: U+1F600 takes two.
        assert!("\u{1F600}".repeat(127).parse::<SmbPath>().is_ok());
        assert!("\u{1F600}".repeat(128).parse::<SmbPath>().is_err());

        let component = "x".repeat(254);
        let path = vec![component.as_str(); 129].join("\\");
        assert_eq!(path.len(), 32_894);
        assert!(path.parse::<SmbPath>().is_err());
        let path = vec![component.as_str(); 128].join("\\");
        assert_eq!(path.len(), 32_639);
        assert!(path.parse::<SmbPath>().is_ok());
    }

    #[test]
    fn component_validation_matches_path_parsing() {
        for name in ["a.txt", " lead", "\u{F021}"] {
            assert!(is_valid_component(name), "{name}");
            assert!(name.parse::<SmbPath>().is_ok(), "{name}");
        }
        for name in ["", ".", "..", "a:b", "a*b", "a\\b", "a/b", "a\u{1}b"] {
            assert!(!is_valid_component(name), "{name:?}");
        }
        assert!(!is_valid_component(&"x".repeat(256)));
    }

    #[test]
    fn pattern_validation_allows_wildcards_and_dots() {
        for pattern in ["*", "*.txt", "a?b", "<.\"", ">", ".", ".."] {
            assert!(is_valid_pattern(pattern), "{pattern}");
        }
        for pattern in ["", "a|b", "a:b", "a\\b", "a/b", "a\u{0}"] {
            assert!(!is_valid_pattern(pattern), "{pattern:?}");
        }
        assert!(!is_valid_pattern(&"*".repeat(256)));
    }

    #[test]
    fn allows_lookalike_names() {
        // Not reserved.
        assert!("CON1".parse::<SmbPath>().is_ok());
        assert!("LPT".parse::<SmbPath>().is_ok());
        assert!("LPT0".parse::<SmbPath>().is_ok()); // 0 is not in the 1-9 range
        assert!("NUL_FILE.txt".parse::<SmbPath>().is_ok());
    }

    #[test]
    fn rejects_unpaired_surrogate() {
        let units: [u16; 2] = [0xD800, 0x0061]; // unpaired high surrogate
        assert!(SmbPath::from_utf16(&units).is_err());
    }

    #[test]
    fn rebase_moves_the_path_and_everything_below_it() {
        let (from, to) = (p("Dir"), p("new\\place"));
        assert_eq!(rebase(&p("Dir"), &from, &to, true), Some(to.clone()));
        assert_eq!(
            rebase(&p("Dir\\Sub\\f.txt"), &from, &to, true),
            Some(p("new\\place\\Sub\\f.txt"))
        );
        assert_eq!(rebase(&p("dir\\f.txt"), &from, &to, true), None);
        assert_eq!(
            rebase(&p("dir\\f.txt"), &from, &to, false),
            Some(p("new\\place\\f.txt"))
        );
        assert_eq!(rebase(&p("Dirt"), &from, &to, false), None);
        assert_eq!(rebase(&p("other\\Dir"), &from, &to, false), None);
    }

    #[test]
    fn round_trip_via_utf16() {
        let p = SmbPath::from_utf16(&utf16("a\\b")).unwrap();
        assert_eq!(p.components(), &["a", "b"]);
    }
}
