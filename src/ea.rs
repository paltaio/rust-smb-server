//! Extended attributes: the FILE_FULL_EA_INFORMATION and
//! FILE_GET_EA_INFORMATION lists of MS-FSCC 2.4.16, the names a file's
//! attributes may have, and their sizes and limits.

use std::collections::{HashMap, HashSet};

use crate::ntstatus;

/// One extended attribute of a file or directory (MS-FSCC 2.4.16). Built
/// with [`Ea::new`]; every field is public.
///
/// The protocol layer passes backends only names of 1 to 254 bytes of
/// UTF-8 without control characters or any of `\ / : * ? " < > | , + = [
/// ] ;`. Names compare without regard to ASCII case.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ea {
    pub name: String,
    /// The value. Setting an empty value removes the attribute; a listed
    /// attribute has a value.
    pub value: Vec<u8>,
    /// FILE_NEED_EA: the file cannot be read by applications that do not
    /// understand extended attributes, and a CREATE with
    /// FILE_NO_EA_KNOWLEDGE fails on it.
    pub needed: bool,
}

impl Ea {
    /// The attribute `name` holding `value`, without FILE_NEED_EA.
    pub fn new(name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            needed: false,
        }
    }
}

/// `name` as names compare: in ASCII lowercase.
pub(crate) fn name_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Flags value of an attribute with FILE_NEED_EA.
pub(crate) const FILE_NEED_EA: u8 = 0x80;

/// Longest name: under 255 bytes (MS-FSCC 2.4.16).
pub(crate) const MAX_NAME: usize = 254;

/// Longest value.
pub(crate) const MAX_VALUE: usize = 0xFFFF;

/// Most bytes the attributes of one file take as [`stored_length`] counts
/// them: 64 KiB - 5 (MS-FSA 2.1.5.15.6).
pub(crate) const MAX_STORED_LENGTH: usize = 65531;

/// Bytes of a FILE_FULL_EA_INFORMATION entry before its name.
const FULL_HEADER: usize = 8;

/// Bytes of a FILE_GET_EA_INFORMATION entry before its name.
const GET_HEADER: usize = 5;

/// Fewest bytes a FILE_GET_EA_INFORMATION entry takes in its list: the
/// size of the structure.
const MIN_GET_ENTRY: usize = 8;

/// True if `name` is a name an attribute may have: 1 to 254 bytes, none
/// of them a control character or one of `\ / : * ? " < > | , + = [ ] ;`.
/// [`Ea`] names are also UTF-8.
pub(crate) fn valid_name(name: &[u8]) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name
            .iter()
            .all(|&b| b >= 0x20 && !b"\\/:*?\"<>|,+=[];".contains(&b))
}

/// The name `bytes` spell, if [`valid_name`] takes it and it is UTF-8.
fn name_of(bytes: &[u8]) -> Result<String, u32> {
    if !valid_name(bytes) {
        return Err(ntstatus::STATUS_INVALID_EA_NAME);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| ntstatus::STATUS_INVALID_EA_NAME)
}

/// [`FileInfo::ea_size`](crate::FileInfo::ea_size) of attributes with the
/// name and value lengths `eas`: their FILE_FULL_EA_INFORMATION entries,
/// each padded to 4 bytes. 0 for none.
#[cfg(any(test, all(feature = "localfs", target_os = "linux")))]
pub(crate) fn list_length(eas: impl IntoIterator<Item = (usize, usize)>) -> u32 {
    let total: usize = eas
        .into_iter()
        .map(|(name, value)| (FULL_HEADER + name + 1 + value).next_multiple_of(4))
        .sum();
    u32::try_from(total).unwrap_or(u32::MAX)
}

/// What the attributes `eas` take against [`MAX_STORED_LENGTH`]: 5 bytes,
/// the name and the value of each.
pub(crate) fn stored_length(eas: &[Ea]) -> usize {
    eas.iter().map(stored_size).sum()
}

fn stored_size(ea: &Ea) -> usize {
    5 + ea.name.len() + ea.value.len()
}

/// [`stored_length`] of the attributes a file with `current` has once
/// `changes`, each name once, replace, add or with empty values remove
/// theirs.
pub(crate) fn stored_length_after(current: &[Ea], changes: &[Ea]) -> usize {
    let mut sizes: HashMap<String, usize> = current
        .iter()
        .map(|ea| (name_key(&ea.name), stored_size(ea)))
        .collect();
    for change in changes {
        let key = name_key(&change.name);
        if change.value.is_empty() {
            sizes.remove(&key);
        } else {
            sizes.insert(key, stored_size(change));
        }
    }
    sizes.values().sum()
}

/// An entry of a list as found in its buffer.
struct Raw<'a> {
    flags: u8,
    name: &'a [u8],
    /// The byte after the name, where its NUL goes.
    nul: u8,
    value: &'a [u8],
}

/// The entries of a list whose entries have `header` bytes before their
/// names and need at least `min` bytes left in the buffer; `lengths` gives
/// the lengths of an entry's name and value from its header. `None` when
/// an entry runs past the buffer, or names a next entry that is not 4-byte
/// aligned past its end.
fn entries<'a>(
    buf: &'a [u8],
    header: usize,
    min: usize,
    lengths: impl Fn(&[u8]) -> (usize, usize),
) -> Option<Vec<Raw<'a>>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        let entry = buf.get(at..)?;
        let head = entry.get(..header.max(min))?;
        let next = u32::from_le_bytes(head[0..4].try_into().expect("four bytes")) as usize;
        let (name_len, value_len) = lengths(head);
        let len = header + name_len + 1 + value_len;
        let body = entry.get(..len)?;
        if next != 0 && (!next.is_multiple_of(4) || next < len) {
            return None;
        }
        out.push(Raw {
            flags: if header == FULL_HEADER { head[4] } else { 0 },
            name: &body[header..header + name_len],
            nul: body[header + name_len],
            value: &body[header + name_len + 1..],
        });
        if next == 0 {
            return Some(out);
        }
        at = at.checked_add(next)?;
    }
}

/// Reads a FILE_FULL_EA_INFORMATION list, as SET_INFO and the `ExtA`
/// create context carry it: STATUS_EA_LIST_INCONSISTENT
/// when an entry runs past the buffer, has no NUL after its name or names
/// a next entry that is not 4-byte aligned past its end, then
/// STATUS_INVALID_EA_NAME for a name [`valid_name`] refuses or that is not
/// UTF-8, or flags other than FILE_NEED_EA. Bytes after the last entry and
/// in padding are ignored.
pub(crate) fn parse_full_list(buf: &[u8]) -> Result<Vec<Ea>, u32> {
    full_entries(buf)?
        .into_iter()
        .map(|e| {
            if e.flags & !FILE_NEED_EA != 0 {
                return Err(ntstatus::STATUS_INVALID_EA_NAME);
            }
            Ok(Ea {
                name: name_of(e.name)?,
                value: e.value.to_vec(),
                needed: e.flags & FILE_NEED_EA != 0,
            })
        })
        .collect()
}

/// Checks a FILE_FULL_EA_INFORMATION list as [`parse_full_list`] does,
/// but for its names and flags.
pub(crate) fn check_full_list(buf: &[u8]) -> Result<(), u32> {
    full_entries(buf).map(|_| ())
}

fn full_entries(buf: &[u8]) -> Result<Vec<Raw<'_>>, u32> {
    let lengths = |head: &[u8]| {
        let value = u16::from_le_bytes([head[6], head[7]]);
        (usize::from(head[5]), usize::from(value))
    };
    entries(buf, FULL_HEADER, FULL_HEADER, lengths)
        .filter(|raw| raw.iter().all(|e| e.nul == 0))
        .ok_or(ntstatus::STATUS_EA_LIST_INCONSISTENT)
}

/// Reads a FILE_GET_EA_INFORMATION list, the names a FileFullEaInformation
/// query asks for: STATUS_EA_LIST_INCONSISTENT for an
/// empty name, an entry with fewer than 8 bytes left in the buffer or one
/// that runs past it, or a next entry that is not 4-byte aligned past it,
/// then STATUS_INVALID_EA_NAME for a name [`valid_name`] refuses or that
/// is not UTF-8. The byte after a name is taken for its NUL, whatever it
/// holds. A name listed again is left out.
pub(crate) fn parse_get_list(buf: &[u8]) -> Result<Vec<String>, u32> {
    let raw = entries(buf, GET_HEADER, MIN_GET_ENTRY, |head| {
        (usize::from(head[4]), 0)
    })
    .filter(|raw| raw.iter().all(|e| !e.name.is_empty()))
    .ok_or(ntstatus::STATUS_EA_LIST_INCONSISTENT)?;
    let mut seen = HashSet::with_capacity(raw.len());
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for e in raw {
        let name = name_of(e.name)?;
        if seen.insert(name_key(&name)) {
            out.push(name);
        }
    }
    Ok(out)
}

/// The attributes of `eas` that `names` name, in their order, with an
/// empty value for a name none of them has.
pub(crate) fn select(eas: &[Ea], names: &[String]) -> Vec<Ea> {
    let by_name: HashMap<String, &Ea> = eas.iter().map(|ea| (name_key(&ea.name), ea)).collect();
    names
        .iter()
        .map(|name| match by_name.get(&name_key(name)) {
            Some(&ea) => ea.clone(),
            None => Ea::new(name.as_str(), Vec::new()),
        })
        .collect()
}

/// Keeps the last of the attributes in `eas` that share a name, in the
/// place of the first.
pub(crate) fn dedup(eas: &mut Vec<Ea>) {
    let mut at: HashMap<String, usize> = HashMap::with_capacity(eas.len());
    let mut kept: Vec<Ea> = Vec::with_capacity(eas.len());
    for ea in eas.drain(..) {
        match at.get(&name_key(&ea.name)) {
            Some(&i) => kept[i] = ea,
            None => {
                at.insert(name_key(&ea.name), kept.len());
                kept.push(ea);
            }
        }
    }
    *eas = kept;
}

/// Bytes the FILE_FULL_EA_INFORMATION entry of `ea` takes, unpadded.
pub(crate) fn entry_len(ea: &Ea) -> usize {
    FULL_HEADER + ea.name.len() + 1 + ea.value.len()
}

/// Encodes `eas` as a FILE_FULL_EA_INFORMATION list: each entry but the
/// last padded with zeros to 4 bytes, the last with NextEntryOffset 0.
pub(crate) fn encode_full_list<'a>(eas: impl IntoIterator<Item = &'a Ea>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut last: Option<usize> = None;
    for ea in eas {
        if let Some(prev) = last {
            out.resize(out.len().next_multiple_of(4), 0);
            let next = (out.len() - prev) as u32;
            out[prev..prev + 4].copy_from_slice(&next.to_le_bytes());
        }
        last = Some(out.len());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.push(if ea.needed { FILE_NEED_EA } else { 0 });
        out.push(ea.name.len() as u8);
        out.extend_from_slice(&(ea.value.len() as u16).to_le_bytes());
        out.extend_from_slice(ea.name.as_bytes());
        out.push(0);
        out.extend_from_slice(&ea.value);
    }
    out
}

/// True if `ea` is one FILE_FULL_EA_INFORMATION can carry and a client
/// can name: a valid name and a value of 1 to 65535 bytes.
pub(crate) fn listable(ea: &Ea) -> bool {
    valid_name(ea.name.as_bytes()) && (1..=MAX_VALUE).contains(&ea.value.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(next: u32, flags: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = next.to_le_bytes().to_vec();
        out.push(flags);
        out.push(name.len() as u8);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.push(0);
        out.extend_from_slice(value);
        out
    }

    fn get(next: u32, name: &[u8]) -> Vec<u8> {
        let mut out = next.to_le_bytes().to_vec();
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.push(0);
        out
    }

    #[test]
    fn a_list_reads_back_as_encoded() {
        let mut needed = Ea::new("Big", vec![7; 300]);
        needed.needed = true;
        let eas = vec![
            Ea::new("a", b"x".to_vec()),
            needed,
            Ea::new("c.d", b"yz".to_vec()),
        ];
        let buf = encode_full_list(&eas);
        // "a": 8 + 1 + 1 + 1 = 11, padded to 12; "Big": 8 + 3 + 1 + 300 =
        // 312; "c.d" unpadded.
        assert_eq!(buf.len(), 12 + 312 + 14);
        assert_eq!(buf[0..4], 12u32.to_le_bytes());
        assert_eq!(buf[11], 0, "padding");
        assert_eq!(buf[12..16], 312u32.to_le_bytes());
        assert_eq!(buf[16], FILE_NEED_EA);
        assert_eq!(buf[324..328], 0u32.to_le_bytes(), "the last entry");
        assert_eq!(parse_full_list(&buf).unwrap(), eas);
        // The last entry counts padded.
        let lengths = eas.iter().map(|ea| (ea.name.len(), ea.value.len()));
        assert_eq!(list_length(lengths), 12 + 312 + 16);
        assert_eq!(list_length([]), 0);
        assert_eq!(stored_length(&eas), 7 + 308 + 10);
    }

    #[test]
    fn a_list_that_runs_past_its_buffer_is_inconsistent() {
        let inconsistent = Err(ntstatus::STATUS_EA_LIST_INCONSISTENT);
        let one = entry(0, 0, b"n", b"v");
        assert_eq!(parse_full_list(&one[..one.len() - 1]), inconsistent);
        assert_eq!(parse_full_list(&one[..7]), inconsistent);
        assert_eq!(parse_full_list(&[]), inconsistent);
        // A header alone, with an empty name and no NUL.
        assert_eq!(parse_full_list(&entry(0, 0, b"", b"")[..8]), inconsistent);
        // Next entry past the end, misaligned, or inside this one.
        let mut two = entry(12, 0, b"n", b"v");
        two.push(0xEE);
        two.extend_from_slice(&entry(0, 0, b"m", b"w"));
        assert_eq!(parse_full_list(&two).unwrap().len(), 2, "any padding");
        for next in [24, 14, 8] {
            two[0] = next;
            assert_eq!(parse_full_list(&two), inconsistent, "next {next}");
        }
        // No NUL after the name.
        let mut unterminated = entry(0, 0, b"n", b"v");
        unterminated[9] = b'x';
        assert_eq!(parse_full_list(&unterminated), inconsistent);
        // A malformed entry wins over a bad name before it.
        let mut bad_then_short = entry(12, 0, b"a*", b"");
        bad_then_short.resize(12, 0);
        bad_then_short.extend_from_slice(&entry(0, 0, b"m", b"w")[..9]);
        assert_eq!(parse_full_list(&bad_then_short), inconsistent);
        // Bytes after the last entry are ignored.
        let mut trailing = entry(0, 0, b"n", b"v");
        trailing.extend_from_slice(&[1, 2, 3]);
        assert_eq!(parse_full_list(&trailing).unwrap().len(), 1);
    }

    #[test]
    fn names_and_flags_are_checked() {
        let invalid = Err(ntstatus::STATUS_INVALID_EA_NAME);
        for name in [
            &b""[..],
            b"a*b",
            b"a:b",
            b"a\x01",
            b"caf\xe9",
            b"[x]",
            b"a;b",
        ] {
            assert_eq!(
                parse_full_list(&entry(0, 0, name, b"v")),
                invalid,
                "{name:?}"
            );
        }
        assert_eq!(parse_full_list(&entry(0, 0, &[b'a'; 255], b"v")), invalid);
        assert_eq!(parse_full_list(&entry(0, 0x01, b"n", b"v")), invalid);
        for name in [&[b'a'; 254][..], b"a b.c#$\x7f", "caf\u{e9}".as_bytes()] {
            assert!(
                parse_full_list(&entry(0, 0, name, b"v")).is_ok(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn long_lists_avoid_pairwise_name_checks() {
        let count = 100_000;
        let names: Vec<String> = (0..count).map(|i| format!("n{i:06}")).collect();
        let mut get = Vec::new();
        for (at, name) in names.iter().chain(names.iter()).enumerate() {
            let next: u32 = if at + 1 == 2 * count { 0 } else { 16 };
            let start = get.len();
            get.extend_from_slice(&next.to_le_bytes());
            get.push(name.len() as u8);
            get.extend_from_slice(name.as_bytes());
            get.push(0);
            get.resize(start + 16, 0);
        }
        let eas: Vec<Ea> = names
            .iter()
            .map(|n| Ea::new(n.as_str(), b"v".to_vec()))
            .collect();
        let started = std::time::Instant::now();
        let parsed = parse_get_list(&get).unwrap();
        assert_eq!(parsed.len(), count);
        assert_eq!(select(&eas, &parsed).len(), count);
        let mut twice: Vec<Ea> = eas.iter().chain(eas.iter()).cloned().collect();
        dedup(&mut twice);
        assert_eq!(twice.len(), count);
        assert_eq!(stored_length_after(&eas, &eas), stored_length(&eas));
        // Pairwise name checks would take minutes here.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_name_list_reads_each_name_once() {
        let mut buf = get(8, b"ab");
        buf.extend_from_slice(&get(0, b"CDE"));
        assert_eq!(parse_get_list(&buf).unwrap(), ["ab", "CDE"]);
        let mut twice = get(12, b"beta");
        twice.resize(12, 0);
        twice.extend_from_slice(&get(0, b"BETA"));
        assert_eq!(parse_get_list(&twice).unwrap(), ["beta"]);
        buf[0] = 6;
        assert_eq!(
            parse_get_list(&buf),
            Err(ntstatus::STATUS_EA_LIST_INCONSISTENT)
        );
        assert_eq!(
            parse_get_list(&get(0, b"a?b")),
            Err(ntstatus::STATUS_INVALID_EA_NAME)
        );
        // A one-character name takes 7 bytes, one short of an entry.
        let short = get(0, b"x");
        assert_eq!(
            parse_get_list(&short),
            Err(ntstatus::STATUS_EA_LIST_INCONSISTENT)
        );
        let mut padded = short.clone();
        padded.push(0);
        assert_eq!(parse_get_list(&padded).unwrap(), ["x"]);
        // The byte after the name need not be a NUL.
        let mut unterminated = get(0, b"alpha");
        *unterminated.last_mut().unwrap() = b'X';
        assert_eq!(parse_get_list(&unterminated).unwrap(), ["alpha"]);
        for bad in [&get(0, b"")[..], &[0, 0, 0, 0], &get(0, b"alpha")[..9]] {
            assert_eq!(
                parse_get_list(bad),
                Err(ntstatus::STATUS_EA_LIST_INCONSISTENT),
                "{bad:?}"
            );
        }
    }
}
