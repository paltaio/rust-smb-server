//! AWS Signature Version 4 request signing for S3, with the signature in the
//! `Authorization` header.

use std::fmt;
use std::time::SystemTime;

use hmac::{Hmac, Mac};
use http::{HeaderMap, HeaderName, Method};
use sha2::{Digest, Sha256};

use super::date::amz_date;
use super::encode::hex;
use super::error::S3Error;
use super::object::header_value;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SERVICE: &str = "s3";
const X_AMZ_DATE: HeaderName = HeaderName::from_static("x-amz-date");
const X_AMZ_CONTENT_SHA256: HeaderName = HeaderName::from_static("x-amz-content-sha256");
const X_AMZ_SECURITY_TOKEN: HeaderName = HeaderName::from_static("x-amz-security-token");

/// Hex SHA-256 of an empty body.
pub(crate) const EMPTY_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// An access key pair and an optional session token. `Debug` shows none of
/// them.
#[derive(Clone)]
pub(crate) struct Credentials {
    pub(crate) access_key: String,
    pub(crate) secret_key: String,
    pub(crate) session_token: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials").finish_non_exhaustive()
    }
}

/// Signs S3 requests for one region.
#[derive(Debug)]
pub(crate) struct Signer {
    credentials: Credentials,
    region: String,
}

impl Signer {
    pub(crate) fn new(credentials: Credentials, region: impl Into<String>) -> Self {
        Signer {
            credentials,
            region: region.into(),
        }
    }

    /// Adds `x-amz-date`, `x-amz-content-sha256`, `x-amz-security-token` when
    /// there is a session token, and `Authorization` to `headers`, and signs
    /// every header in the map, so `Host` must be there already. `path` and
    /// `query` are the encoded forms sent in the URL (`query` as
    /// `Query::canonical` returns it) and `payload_sha256` is the hex SHA-256
    /// of the body.
    pub(crate) fn sign(
        &self,
        method: &Method,
        path: &str,
        query: &str,
        headers: &mut HeaderMap,
        payload_sha256: &str,
        now: SystemTime,
    ) -> Result<(), S3Error> {
        let timestamp = amz_date(now);
        let date = &timestamp[..8];
        headers.insert(X_AMZ_DATE, header_value(&timestamp)?);
        headers.insert(X_AMZ_CONTENT_SHA256, header_value(payload_sha256)?);
        if let Some(token) = &self.credentials.session_token {
            let mut value = header_value(token)?;
            value.set_sensitive(true);
            headers.insert(X_AMZ_SECURITY_TOKEN, value);
        }

        let (canonical, signed_headers) =
            canonical_request(method, path, query, headers, payload_sha256);
        let scope = format!("{date}/{}/{SERVICE}/aws4_request", self.region);
        let to_sign = string_to_sign(&timestamp, &scope, &canonical);
        let signature = signature(&self.credentials.secret_key, date, &self.region, &to_sign);
        let mut authorization = header_value(&format!(
            "{ALGORITHM} Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}",
            self.credentials.access_key
        ))?;
        authorization.set_sensitive(true);
        headers.insert(http::header::AUTHORIZATION, authorization);
        Ok(())
    }
}

/// The canonical request and its `SignedHeaders` list.
fn canonical_request(
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    payload_sha256: &str,
) -> (Vec<u8>, String) {
    let mut fields: Vec<(&str, Vec<u8>)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), canonical_value(value.as_bytes())))
        .collect();
    // The sort is stable, so the values of one header keep their order.
    fields.sort_by_key(|field| field.0);
    let mut merged: Vec<(&str, Vec<u8>)> = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        match merged.last_mut() {
            Some((last, joined)) if *last == name => {
                joined.push(b',');
                joined.extend_from_slice(&value);
            }
            _ => merged.push((name, value)),
        }
    }

    let mut out = Vec::new();
    for part in [method.as_str(), path, query] {
        out.extend_from_slice(part.as_bytes());
        out.push(b'\n');
    }
    for (name, value) in &merged {
        out.extend_from_slice(name.as_bytes());
        out.push(b':');
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    out.push(b'\n');
    let signed_headers = merged
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    out.extend_from_slice(signed_headers.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload_sha256.as_bytes());
    (out, signed_headers)
}

/// A header value without surrounding blanks and with each run of blanks
/// inside it reduced to one space.
fn canonical_value(value: &[u8]) -> Vec<u8> {
    let is_blank = |b: &u8| matches!(b, b' ' | b'\t');
    let start = value
        .iter()
        .position(|b| !is_blank(b))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !is_blank(b))
        .map_or(start, |i| i + 1);
    let mut out = Vec::with_capacity(end - start);
    let mut in_blanks = false;
    for b in &value[start..end] {
        if is_blank(b) {
            if !in_blanks {
                out.push(b' ');
            }
            in_blanks = true;
        } else {
            out.push(*b);
            in_blanks = false;
        }
    }
    out
}

fn string_to_sign(timestamp: &str, scope: &str, canonical_request: &[u8]) -> String {
    format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request))
    )
}

/// Hex signature of `to_sign` with the key derived for `date`, `region`
/// and the S3 service.
fn signature(secret_key: &str, date: &str, region: &str, to_sign: &str) -> String {
    let mut key = hmac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    for part in [region, SERVICE, "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    hex(&hmac(&key, to_sign.as_bytes()))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use http::HeaderValue;

    use super::super::encode::{Query, uri_encode};
    use super::*;

    const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const HOST: &str = "examplebucket.s3.amazonaws.com";

    /// An example request of the AWS signature documentation, with its
    /// canonical request, string to sign, signature and `Authorization` header.
    struct Example {
        method: Method,
        key: &'static str,
        query: &'static [(&'static str, &'static str)],
        headers: &'static [(&'static str, &'static str)],
        body: &'static [u8],
        canonical_request: &'static str,
        string_to_sign: &'static str,
        signature: &'static str,
        authorization: &'static str,
    }

    fn credentials(session_token: Option<&str>) -> Credentials {
        Credentials {
            access_key: ACCESS_KEY.into(),
            secret_key: SECRET_KEY.into(),
            session_token: session_token.map(Into::into),
        }
    }

    fn signer() -> Signer {
        Signer::new(credentials(None), "us-east-1")
    }

    /// The headers of `GET /` for the example host, signed by `signer` at the
    /// time of the examples.
    fn sign_root(signer: &Signer) -> Result<HeaderMap, S3Error> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HOST.parse().unwrap());
        signer.sign(
            &Method::GET,
            "/",
            "",
            &mut headers,
            EMPTY_SHA256,
            example_time(),
        )?;
        Ok(headers)
    }

    fn authorization(headers: &HeaderMap) -> String {
        headers[http::header::AUTHORIZATION]
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn example_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_369_353_600)
    }

    /// Signs `example` and compares each result with the documentation.
    fn check(example: &Example) {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HOST.parse().unwrap());
        for (name, value) in example.headers {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        let path = format!("/{}", uri_encode(example.key, true));
        let query = Query::new(example.query).canonical();
        let payload = hex(&Sha256::digest(example.body));
        signer()
            .sign(
                &example.method,
                &path,
                &query,
                &mut headers,
                &payload,
                example_time(),
            )
            .unwrap();

        assert_eq!(
            headers.remove(http::header::AUTHORIZATION).unwrap(),
            example.authorization
        );
        let (canonical, _) = canonical_request(&example.method, &path, &query, &headers, &payload);
        assert_eq!(
            String::from_utf8(canonical.clone()).unwrap(),
            example.canonical_request
        );
        let to_sign = string_to_sign(
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            &canonical,
        );
        assert_eq!(to_sign, example.string_to_sign);
        assert_eq!(
            signature(SECRET_KEY, "20130524", "us-east-1", &to_sign),
            example.signature
        );
        assert_eq!(headers["x-amz-content-sha256"], payload.as_str());
        assert_eq!(headers["x-amz-date"], "20130524T000000Z");
    }

    #[test]
    fn signs_a_get_object_with_a_range() {
        check(&Example {
            method: Method::GET,
            key: "test.txt",
            query: &[],
            headers: &[("range", "bytes=0-9")],
            body: b"",
            canonical_request: "GET\n\
                /test.txt\n\
                \n\
                host:examplebucket.s3.amazonaws.com\n\
                range:bytes=0-9\n\
                x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                x-amz-date:20130524T000000Z\n\
                \n\
                host;range;x-amz-content-sha256;x-amz-date\n\
                e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n\
                20130524T000000Z\n\
                20130524/us-east-1/s3/aws4_request\n\
                7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
            signature: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        });
    }

    #[test]
    fn signs_a_put_object_with_a_key_that_needs_encoding() {
        check(&Example {
            method: Method::PUT,
            key: "test$file.text",
            query: &[],
            headers: &[
                ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            body: b"Welcome to Amazon S3.",
            canonical_request: "PUT\n\
                /test%24file.text\n\
                \n\
                date:Fri, 24 May 2013 00:00:00 GMT\n\
                host:examplebucket.s3.amazonaws.com\n\
                x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\n\
                x-amz-date:20130524T000000Z\n\
                x-amz-storage-class:REDUCED_REDUNDANCY\n\
                \n\
                date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n\
                44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
            string_to_sign: "AWS4-HMAC-SHA256\n\
                20130524T000000Z\n\
                20130524/us-east-1/s3/aws4_request\n\
                9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d",
            signature: "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
        });
    }

    #[test]
    fn signs_a_get_bucket_lifecycle_subresource() {
        check(&Example {
            method: Method::GET,
            key: "",
            query: &[("lifecycle", "")],
            headers: &[],
            body: b"",
            canonical_request: "GET\n\
                /\n\
                lifecycle=\n\
                host:examplebucket.s3.amazonaws.com\n\
                x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                x-amz-date:20130524T000000Z\n\
                \n\
                host;x-amz-content-sha256;x-amz-date\n\
                e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n\
                20130524T000000Z\n\
                20130524/us-east-1/s3/aws4_request\n\
                9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca",
            signature: "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
        });
    }

    #[test]
    fn signs_a_list_objects_query_in_sorted_order() {
        check(&Example {
            method: Method::GET,
            key: "",
            query: &[("prefix", "J"), ("max-keys", "2")],
            headers: &[],
            body: b"",
            canonical_request: "GET\n\
                /\n\
                max-keys=2&prefix=J\n\
                host:examplebucket.s3.amazonaws.com\n\
                x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                x-amz-date:20130524T000000Z\n\
                \n\
                host;x-amz-content-sha256;x-amz-date\n\
                e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n\
                20130524T000000Z\n\
                20130524/us-east-1/s3/aws4_request\n\
                df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7",
            signature: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        });
    }

    #[test]
    fn a_session_token_is_signed_and_sent() {
        let signer = Signer::new(credentials(Some("token/with+chars==")), "us-east-1");
        let headers = sign_root(&signer).unwrap();
        assert_eq!(headers["x-amz-security-token"], "token/with+chars==");
        let authorization = authorization(&headers);
        assert!(
            authorization.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"
            ),
            "{authorization}"
        );
    }

    #[test]
    fn the_region_scopes_the_signature() {
        let sign = |region: &str| {
            authorization(&sign_root(&Signer::new(credentials(None), region)).unwrap())
        };
        let east = sign("us-east-1");
        let west = sign("eu-west-1");
        assert!(
            west.contains("/20130524/eu-west-1/s3/aws4_request,"),
            "{west}"
        );
        assert_ne!(
            east.rsplit_once("Signature=").unwrap().1,
            west.rsplit_once("Signature=").unwrap().1
        );
    }

    #[test]
    fn header_values_are_trimmed_and_blanks_collapsed() {
        assert_eq!(canonical_value(b"  a   b \t c  "), b"a b c");
        assert_eq!(canonical_value(b"plain"), b"plain");
        assert_eq!(canonical_value(b"   "), b"");
        assert_eq!(canonical_value(b""), b"");
        assert_eq!(canonical_value(b"\"quoted  value\""), b"\"quoted value\"");
    }

    #[test]
    fn repeated_headers_are_joined_with_commas() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HOST.parse().unwrap());
        headers.append("x-amz-meta-a", HeaderValue::from_static("one"));
        headers.append("x-amz-meta-a", HeaderValue::from_static("two"));
        headers.insert("x-amz-meta-b", HeaderValue::from_static(" 3 "));
        let (canonical, signed) = canonical_request(&Method::GET, "/", "", &headers, EMPTY_SHA256);
        assert_eq!(signed, "host;x-amz-meta-a;x-amz-meta-b");
        let text = String::from_utf8(canonical).unwrap();
        assert!(
            text.contains(
                "\nhost:examplebucket.s3.amazonaws.com\nx-amz-meta-a:one,two\nx-amz-meta-b:3\n\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_signed_object_key_is_encoded_once() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HOST.parse().unwrap());
        let path = format!("/{}", uri_encode("dir/a b+c%d~e/\u{e9}", true));
        let (canonical, _) = canonical_request(&Method::GET, &path, "", &headers, EMPTY_SHA256);
        assert!(canonical.starts_with(b"GET\n/dir/a%20b%2Bc%25d~e/%C3%A9\n\n"));
    }

    #[test]
    fn credentials_debug_output_hides_everything() {
        let credentials = Credentials {
            access_key: "access-key-id".into(),
            secret_key: "secret-key-value".into(),
            session_token: Some("token-value".into()),
        };
        let shown = format!("{credentials:?}");
        let signer = format!("{:?}", Signer::new(credentials, "us-east-1"));
        for text in [shown, signer] {
            for secret in ["access-key-id", "secret-key-value", "token-value"] {
                assert!(!text.contains(secret), "{text}");
            }
        }
    }

    #[test]
    fn the_authorization_and_token_headers_are_sensitive() {
        let signer = Signer::new(credentials(Some("token-value")), "us-east-1");
        let headers = sign_root(&signer).unwrap();
        assert!(headers[http::header::AUTHORIZATION].is_sensitive());
        assert!(headers["x-amz-security-token"].is_sensitive());
        let shown = format!("{headers:?}");
        assert!(!shown.contains("token-value"), "{shown}");
        assert!(!shown.contains("Signature="), "{shown}");
    }

    #[test]
    fn a_token_that_is_not_a_header_value_is_refused() {
        let signer = Signer::new(credentials(Some("line\nbreak")), "us-east-1");
        let error = sign_root(&signer).unwrap_err();
        assert!(matches!(error, S3Error::InvalidArgument(_)), "{error:?}");
    }
}
