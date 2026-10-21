//! NDR 2.0 (C706 chapter 14), little-endian, for the srvsvc calls. Every
//! item is aligned to its size from the start of the stub; padding is
//! written as zeros and not checked on input.

/// Longest string a request may carry, in UTF-16 units.
const MAX_STRING_UNITS: u32 = 1024;

/// The first referent id of a stub. Ids then grow by 4 for every pointer
/// that is not NULL, as Samba's marshaller numbers them.
const FIRST_REFERENT: u32 = 0x0002_0000;

/// Reads a request stub. Every read returns `None` past the end of the
/// stub or on a value the rules here refuse.
pub(crate) struct NdrReader<'a> {
    stub: &'a [u8],
    at: usize,
}

impl<'a> NdrReader<'a> {
    pub(crate) fn new(stub: &'a [u8]) -> Self {
        Self { stub, at: 0 }
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let at = self.at.next_multiple_of(4);
        let bytes = self.stub.get(at..at + 4)?;
        self.at = at + 4;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    /// A unique pointer (C706 14.3.10): whether its referent follows.
    pub(crate) fn pointer(&mut self) -> Option<bool> {
        Some(self.u32()? != 0)
    }

    /// A conformant varying string of UTF-16 units (C706 14.3.4.2), without
    /// its terminating NUL when it has one. The offset must be 0, and the
    /// string must hold 1 to 1024 units, no more than its maximum count.
    pub(crate) fn string(&mut self) -> Option<Vec<u16>> {
        let max_count = self.u32()?;
        let offset = self.u32()?;
        let actual_count = self.u32()?;
        if offset != 0
            || actual_count == 0
            || actual_count > max_count
            || actual_count > MAX_STRING_UNITS
        {
            return None;
        }
        let len = actual_count as usize * 2;
        let bytes = self.stub.get(self.at..self.at + len)?;
        self.at += len;
        let mut units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        if units.last() == Some(&0) {
            units.pop();
        }
        Some(units)
    }
}

/// Writes a response stub.
pub(crate) struct NdrWriter {
    stub: Vec<u8>,
    next_referent: u32,
}

impl NdrWriter {
    pub(crate) fn new() -> Self {
        Self {
            stub: Vec::new(),
            next_referent: FIRST_REFERENT,
        }
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.stub.resize(self.stub.len().next_multiple_of(4), 0);
        self.stub.extend_from_slice(&value.to_le_bytes());
    }

    /// A unique or embedded pointer: a new referent id, or 0 for NULL.
    pub(crate) fn pointer(&mut self, present: bool) {
        if present {
            let id = self.next_referent;
            self.next_referent += 4;
            self.u32(id);
        } else {
            self.u32(0);
        }
    }

    /// A conformant varying string of `text` and its terminating NUL.
    pub(crate) fn string(&mut self, text: &str) {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let count = u32::try_from(units.len()).expect("a short string");
        self.u32(count);
        self.u32(0);
        self.u32(count);
        for unit in units {
            self.stub.extend_from_slice(&unit.to_le_bytes());
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.stub
    }
}

/// Bytes [`NdrWriter::string`] takes for `text`, padding to 4 included.
pub(crate) fn string_len(text: &str) -> usize {
    12 + (2 * (text.encode_utf16().count() + 1)).next_multiple_of(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn strings_take_their_nul_and_pad_to_4() {
        for (text, len) in [
            ("", 16),
            ("a", 16),
            ("ab", 20),
            ("abc", 20),
            ("\u{1F9A4}", 20),
        ] {
            let mut w = NdrWriter::new();
            w.string(text);
            w.u32(7);
            let stub = w.finish();
            assert_eq!(stub.len(), len + 4, "{text:?}");
            assert_eq!(string_len(text), len, "{text:?}");
            let mut r = NdrReader::new(&stub);
            assert_eq!(r.string(), Some(units(text)));
            assert_eq!(r.u32(), Some(7));
        }
        // Max and actual count include the NUL; two units for U+1F9A4.
        let mut w = NdrWriter::new();
        w.string("\u{1F9A4}");
        assert_eq!(&w.finish()[..12], [3, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn referent_ids_count_from_0x20000_and_skip_null() {
        let mut w = NdrWriter::new();
        w.pointer(true);
        w.pointer(false);
        w.pointer(true);
        assert_eq!(w.finish(), [0, 0, 2, 0, 0, 0, 0, 0, 4, 0, 2, 0]);
    }

    #[test]
    fn reads_align_from_the_stub_start() {
        let mut stub = vec![1, 0, 0, 0];
        stub.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, b'x', 0]);
        stub.extend_from_slice(&[0xEE, 0xEE, 9, 0, 0, 0]);
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.pointer(), Some(true));
        assert_eq!(r.string(), Some(units("x")));
        assert_eq!(r.u32(), Some(9));
        assert_eq!(r.u32(), None);
    }

    #[test]
    fn a_missing_nul_is_tolerated() {
        let stub = [2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, b'a', 0, b'b', 0];
        assert_eq!(NdrReader::new(&stub).string(), Some(units("ab")));
    }

    #[test]
    fn strings_outside_the_rules_are_refused() {
        let string = |max: u32, offset: u32, actual: u32, units: usize| {
            let mut stub = Vec::new();
            for v in [max, offset, actual] {
                stub.extend_from_slice(&v.to_le_bytes());
            }
            stub.resize(12 + 2 * units, b'a');
            stub
        };
        let cases = [
            ("actual past max", string(1, 0, 2, 2)),
            ("offset", string(2, 1, 1, 1)),
            ("empty", string(1, 0, 0, 0)),
            ("past 1024 units", string(2000, 0, 1025, 1025)),
            ("past the stub", string(10, 0, 10, 9)),
            ("short header", string(1, 0, 1, 0)[..8].to_vec()),
        ];
        for (what, stub) in cases {
            assert_eq!(NdrReader::new(&stub).string(), None, "{what}");
        }
        assert!(
            NdrReader::new(&string(1024, 0, 1024, 1024))
                .string()
                .is_some()
        );
    }

    #[test]
    fn a_misaligned_tail_is_short() {
        assert_eq!(NdrReader::new(&[0; 3]).u32(), None);
        let mut r = NdrReader::new(&[0; 6]);
        assert_eq!(r.u32(), Some(0));
        assert_eq!(r.u32(), None);
    }
}
