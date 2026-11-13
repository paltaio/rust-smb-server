//! Lowercase base32 without padding (RFC 4648 section 6 alphabet).
//!
//! Every byte string has exactly one spelling, and the decoder accepts only
//! that one.

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Base32Error {
    /// A character outside the alphabet.
    Character,
    /// A length no byte string encodes to: 1, 3 or 6 modulo 8.
    Length,
    /// The unused low bits of the last character are not zero.
    TrailingBits,
}

pub(crate) fn is_alphabet(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'2'..=b'7')
}

/// Five-bit value of `byte`, which must satisfy `is_alphabet`.
fn digit(byte: u8) -> u32 {
    match byte {
        b'a'..=b'z' => u32::from(byte - b'a'),
        _ => u32::from(byte - b'2') + 26,
    }
}

/// Characters that `bytes` bytes encode to.
pub(crate) const fn encoded_len(bytes: usize) -> usize {
    (bytes * 8).div_ceil(5)
}

/// Bytes that `chars` characters decode to, or `None` for a length no byte
/// string encodes to.
pub(crate) const fn decoded_len(chars: usize) -> Option<usize> {
    let bytes = chars * 5 / 8;
    if encoded_len(bytes) == chars {
        Some(bytes)
    } else {
        None
    }
}

pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(data.len()));
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The bytes `text` spells. Checks the characters, then the length, then the
/// unused bits.
pub(crate) fn decode(text: &str) -> Result<Vec<u8>, Base32Error> {
    if !text.bytes().all(is_alphabet) {
        return Err(Base32Error::Character);
    }
    let len = decoded_len(text.len()).ok_or(Base32Error::Length)?;
    let mut out = Vec::with_capacity(len);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        acc = (acc << 5) | digit(byte);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(Base32Error::TrailingBits);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::testing::unhex;
    use super::*;

    const RFC_4648: [(&str, &str); 7] = [
        ("", ""),
        ("f", "my"),
        ("fo", "mzxq"),
        ("foo", "mzxw6"),
        ("foob", "mzxw6yq"),
        ("fooba", "mzxw6ytb"),
        ("foobar", "mzxw6ytboi"),
    ];

    #[test]
    fn rfc_4648_vectors() {
        for (plain, coded) in RFC_4648 {
            assert_eq!(encode(plain.as_bytes()), coded, "{plain:?}");
            assert_eq!(decode(coded).unwrap(), plain.as_bytes(), "{coded:?}");
        }
    }

    #[test]
    fn alphabet_and_digits() {
        for byte in 0..=u8::MAX {
            assert_eq!(is_alphabet(byte), ALPHABET.contains(&byte), "{byte}");
        }
        for (value, &byte) in ALPHABET.iter().enumerate() {
            assert_eq!(digit(byte), value as u32, "{byte}");
        }
    }

    #[test]
    fn round_trip_every_length_up_to_40() {
        for len in 0..=40usize {
            for data in [
                (0..len).map(|i| (i * 37 + 11) as u8).collect::<Vec<u8>>(),
                vec![0x00; len],
                vec![0xff; len],
            ] {
                let coded = encode(&data);
                assert_eq!(coded.len(), encoded_len(len), "len {len}");
                assert_eq!(decoded_len(coded.len()), Some(len), "len {len}");
                assert_eq!(decode(&coded).unwrap(), data, "len {len}");
            }
        }
    }

    #[test]
    fn rejects_the_length_classes_no_byte_string_has() {
        for chars in 0..=64usize {
            let text = "a".repeat(chars);
            if matches!(chars % 8, 1 | 3 | 6) {
                assert_eq!(decoded_len(chars), None, "chars {chars}");
                assert_eq!(decode(&text), Err(Base32Error::Length), "chars {chars}");
            } else {
                let len = decoded_len(chars).unwrap();
                assert_eq!(decode(&text).unwrap(), vec![0u8; len], "chars {chars}");
            }
        }
    }

    #[test]
    fn rejects_nonzero_trailing_bits_in_each_length_class() {
        // (characters, unused low bits of the last character)
        for (chars, unused) in [(2usize, 2u32), (4, 4), (5, 1), (7, 3), (10, 2), (13, 1)] {
            let head = "a".repeat(chars - 1);
            for (value, &last) in ALPHABET.iter().enumerate() {
                let text = format!("{head}{}", char::from(last));
                if value & ((1 << unused) - 1) == 0 {
                    assert!(decode(&text).is_ok(), "{text}");
                } else {
                    assert_eq!(decode(&text), Err(Base32Error::TrailingBits), "{text}");
                }
            }
        }
    }

    #[test]
    fn every_digit_has_its_place() {
        let bytes = unhex("00443214c74254b635cf84653a56d7c675be77df");
        assert_eq!(encode(&bytes), "abcdefghijklmnopqrstuvwxyz234567");
    }

    #[test]
    fn one_spelling_per_byte_string() {
        // Of the 1024 strings of two characters, 256 are accepted: one
        // spelling of each one-byte string.
        let mut accepted = 0;
        for &a in ALPHABET {
            for &b in ALPHABET {
                let text = String::from_utf8(vec![a, b]).unwrap();
                if let Ok(bytes) = decode(&text) {
                    assert_eq!(encode(&bytes), text);
                    accepted += 1;
                }
            }
        }
        assert_eq!(accepted, 256);
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        for text in ["MY", "my======", "m y", "m\u{e9}"] {
            assert_eq!(decode(text), Err(Base32Error::Character), "{text:?}");
        }
    }

    #[test]
    fn character_check_comes_before_the_length_check() {
        assert_eq!(decode("a0a"), Err(Base32Error::Character));
        assert_eq!(decode("a"), Err(Base32Error::Length));
    }
}
