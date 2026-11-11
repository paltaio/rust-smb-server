//! Text encodings of the S3 wire formats.

/// Lowercase hexadecimal digits of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

/// Standard base64 with padding.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let b = |i: usize| u32::from(group.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        let sextet = |shift: u32| char::from(ALPHABET[(n >> shift & 63) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if group.len() > 1 { sextet(6) } else { '=' });
        out.push(if group.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

/// Percent-encodes every byte of `text` outside `A-Za-z0-9-._~`, with
/// uppercase hex digits. `/` stays as it is when `keep_slash` is set, as in
/// the path of an object key.
pub(crate) fn uri_encode(text: &str, keep_slash: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(b));
            }
            b'/' if keep_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push(char::from(DIGITS[usize::from(b >> 4)]));
                out.push(char::from(DIGITS[usize::from(b & 15)]));
            }
        }
    }
    out
}

/// Reverses the URL encoding of a listing: `%XX` escapes and `+` for a
/// space. `None` for a malformed escape or when the result is not UTF-8.
pub(crate) fn uri_decode(text: &str) -> Option<String> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                out.push((high * 16 + low) as u8);
            }
            b'+' => out.push(b' '),
            _ => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

/// Query parameters with names and values encoded and the pairs sorted by
/// encoded name and then value, as signing requires.
#[derive(Debug, Default)]
pub(crate) struct Query(Vec<(String, String)>);

impl Query {
    pub(crate) fn new(params: &[(&str, &str)]) -> Self {
        let mut pairs: Vec<(String, String)> = params
            .iter()
            .map(|(name, value)| (uri_encode(name, false), uri_encode(value, false)))
            .collect();
        pairs.sort();
        Query(pairs)
    }

    /// The form signing uses: every parameter as `name=value`, `name=` for
    /// an empty value.
    pub(crate) fn canonical(&self) -> String {
        self.join(true)
    }

    /// The form sent in the URL: `name` alone for an empty value.
    pub(crate) fn wire(&self) -> String {
        self.join(false)
    }

    fn join(&self, equals_when_empty: bool) -> String {
        let mut out = String::new();
        for (i, (name, value)) in self.0.iter().enumerate() {
            if i > 0 {
                out.push('&');
            }
            out.push_str(name);
            if equals_when_empty || !value.is_empty() {
                out.push('=');
                out.push_str(value);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "{input:?}");
        }
        assert_eq!(base64(&[0xfb, 0xff, 0xfe]), "+//+");
    }

    #[test]
    fn leaves_unreserved_characters_alone() {
        let unreserved = "AZaz09-._~";
        assert_eq!(uri_encode(unreserved, false), unreserved);
        assert_eq!(uri_encode(unreserved, true), unreserved);
    }

    #[test]
    fn encodes_every_other_byte_of_a_key() {
        for (key, expected) in [
            ("a b", "a%20b"),
            ("a+b", "a%2Bb"),
            ("100%", "100%25"),
            ("a~b", "a~b"),
            ("dir/sub dir/file", "dir/sub%20dir/file"),
            ("a/", "a/"),
            ("a//b", "a//b"),
            ("caf\u{e9}", "caf%C3%A9"),
            ("a$b&c=d", "a%24b%26c%3Dd"),
            ("a?b#c", "a%3Fb%23c"),
            ("a*b(c)'d!", "a%2Ab%28c%29%27d%21"),
            ("tab\tnewline\n", "tab%09newline%0A"),
            ("", ""),
        ] {
            assert_eq!(uri_encode(key, true), expected, "{key:?}");
        }
    }

    #[test]
    fn encodes_the_slash_outside_a_key() {
        assert_eq!(uri_encode("a/b c", false), "a%2Fb%20c");
    }

    #[test]
    fn decodes_what_a_listing_encodes() {
        for text in [
            "a b",
            "a+b",
            "100%",
            "a~b/c d",
            "caf\u{e9}/\u{65e5}\u{672c}",
            "\u{1f600} + % /",
            "a&b=c",
        ] {
            let encoded = uri_encode(text, true);
            assert_eq!(uri_decode(&encoded).as_deref(), Some(text), "{encoded}");
        }
    }

    #[test]
    fn a_plus_in_a_listing_is_a_space() {
        assert_eq!(uri_decode("a+b%2Bc%20d").as_deref(), Some("a b+c d"));
    }

    #[test]
    fn rejects_bad_escapes_and_bytes_that_are_not_utf8() {
        assert_eq!(uri_decode("%"), None);
        assert_eq!(uri_decode("a%2"), None);
        assert_eq!(uri_decode("%zz"), None);
        assert_eq!(uri_decode("%+1"), None);
        assert_eq!(uri_decode("%ff"), None);
        assert_eq!(uri_decode("%C3"), None);
    }

    #[test]
    fn sorts_and_encodes_query_parameters() {
        let query = Query::new(&[("prefix", "J"), ("max-keys", "2")]);
        assert_eq!(query.canonical(), "max-keys=2&prefix=J");
        assert_eq!(query.wire(), "max-keys=2&prefix=J");
        let query = Query::new(&[("prefix", "a b/c+d"), ("delimiter", "/")]);
        assert_eq!(query.canonical(), "delimiter=%2F&prefix=a%20b%2Fc%2Bd");
        assert_eq!(query.wire(), query.canonical());
        assert_eq!(Query::new(&[]).canonical(), "");
        assert_eq!(Query::new(&[]).wire(), "");
    }

    #[test]
    fn an_empty_value_has_no_equals_sign_in_the_url_only() {
        let query = Query::new(&[("uploads", "")]);
        assert_eq!(query.canonical(), "uploads=");
        assert_eq!(query.wire(), "uploads");
        let query = Query::new(&[("partNumber", "1"), ("delete", ""), ("uploadId", "x")]);
        assert_eq!(query.canonical(), "delete=&partNumber=1&uploadId=x");
        assert_eq!(query.wire(), "delete&partNumber=1&uploadId=x");
    }

    #[test]
    fn sorts_query_parameters_after_encoding() {
        // "a b" encodes to "a%20b", which sorts before "a-b" since '%' < '-'.
        let query = Query::new(&[("a-b", "1"), ("a b", "2")]);
        assert_eq!(query.canonical(), "a%20b=2&a-b=1");
        let query = Query::new(&[("k", "b"), ("k", "a")]);
        assert_eq!(query.canonical(), "k=a&k=b");
    }
}
