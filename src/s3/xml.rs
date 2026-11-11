//! The XML documents the S3 calls send and receive.

use std::borrow::Cow;
use std::time::SystemTime;

use quick_xml::escape::escape;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::reader::Reader;
use tracing::debug;

use super::date::parse_rfc3339;
use super::encode::uri_decode;
use super::error::S3Error;
use super::object::normalize_etag;

/// Deepest element nesting accepted.
const MAX_DEPTH: usize = 16;

/// One page of a ListObjectsV2 answer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Listing {
    pub(crate) objects: Vec<ListedObject>,
    /// The common prefixes, each ending in the delimiter.
    pub(crate) prefixes: Vec<String>,
    /// The token that asks for the next page; `None` on the last one.
    pub(crate) next_token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ListedObject {
    pub(crate) key: String,
    pub(crate) size: u64,
    pub(crate) etag: String,
    pub(crate) last_modified: SystemTime,
}

/// The answer to CopyObject and UploadPartCopy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CopyResult {
    pub(crate) etag: String,
    pub(crate) last_modified: Option<SystemTime>,
}

/// A key a DeleteObjects call could not delete.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DeleteFailure {
    pub(crate) key: String,
    pub(crate) code: Option<String>,
}

/// A part of a multipart upload, as CompleteMultipartUpload lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompletedPart {
    pub(crate) number: u32,
    pub(crate) etag: String,
}

/// An element with its text and children. Namespaces and attributes are
/// dropped.
#[derive(Debug)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn new(start: &BytesStart<'_>) -> Self {
        let local = start.local_name();
        let name: &str = local.as_ref();
        Node {
            name: name.to_owned(),
            text: String::new(),
            children: Vec::new(),
        }
    }

    fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|child| child.name == name)
    }

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// The text of a child, without surrounding white space.
    fn trimmed(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.trim())
    }

    /// The text of a child exactly as written, for keys and tokens.
    fn raw(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.as_str())
    }
}

/// Reads a document into a tree. Rejects anything that is not well-formed
/// UTF-8 XML, document type declarations, entities other than the predefined
/// ones, and nesting past [`MAX_DEPTH`].
fn parse(body: &[u8]) -> Result<Node, S3Error> {
    let text = std::str::from_utf8(body)
        .map_err(|_| S3Error::InvalidResponse("the document is not UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = Reader::from_str(text);
    let mut open: Vec<Node> = Vec::new();
    let mut root = None;
    loop {
        match reader
            .read_event()
            .map_err(|_| S3Error::InvalidResponse("the document is not well-formed XML"))?
        {
            Event::Start(start) => {
                if open.len() >= MAX_DEPTH {
                    return Err(S3Error::InvalidResponse("the document is nested too deep"));
                }
                if open.is_empty() && root.is_some() {
                    return Err(S3Error::InvalidResponse(
                        "the document has more than one root element",
                    ));
                }
                open.push(Node::new(&start));
            }
            Event::Empty(start) => close(Node::new(&start), &mut open, &mut root)?,
            Event::End(_) => {
                let node = open
                    .pop()
                    .ok_or(S3Error::InvalidResponse("an end tag has no start tag"))?;
                close(node, &mut open, &mut root)?;
            }
            Event::Text(text) => push_text(&mut open, &text.xml10_content())?,
            Event::CData(data) => push_text(&mut open, &data.xml10_content())?,
            Event::GeneralRef(reference) => {
                let c = resolve_reference(&reference)?;
                push_text(&mut open, c.encode_utf8(&mut [0; 4]))?;
            }
            Event::DocType(_) => {
                return Err(S3Error::InvalidResponse(
                    "the document has a type declaration",
                ));
            }
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if !open.is_empty() {
        return Err(S3Error::InvalidResponse(
            "the document ends inside an element",
        ));
    }
    root.ok_or(S3Error::InvalidResponse("the document is empty"))
}

fn close(node: Node, open: &mut [Node], root: &mut Option<Node>) -> Result<(), S3Error> {
    match open.last_mut() {
        Some(parent) => parent.children.push(node),
        None if root.is_none() => *root = Some(node),
        None => {
            return Err(S3Error::InvalidResponse(
                "the document has more than one root element",
            ));
        }
    }
    Ok(())
}

fn push_text(open: &mut [Node], text: &str) -> Result<(), S3Error> {
    match open.last_mut() {
        Some(node) => node.text.push_str(text),
        None if text.trim().is_empty() => {}
        None => {
            return Err(S3Error::InvalidResponse(
                "the document has text outside its root element",
            ));
        }
    }
    Ok(())
}

/// The character a reference stands for: a character reference to a
/// character XML allows, or one of the five predefined entities.
fn resolve_reference(reference: &BytesRef<'_>) -> Result<char, S3Error> {
    if reference.is_char_ref() {
        return match reference.resolve_char_ref() {
            Ok(Some(c)) if is_xml_char(c) => Ok(c),
            _ => Err(S3Error::InvalidResponse(
                "the document has a bad character reference",
            )),
        };
    }
    match &**reference {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ => Err(S3Error::InvalidResponse(
            "the document has an undeclared entity",
        )),
    }
}

/// Whether XML 1.0 allows `c` in a document.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..)
}

/// The tree of a document whose root element is `expected`.
fn document(body: &[u8], expected: &str) -> Result<Node, S3Error> {
    let root = parse(body)?;
    if root.name == expected {
        Ok(root)
    } else {
        Err(S3Error::InvalidResponse(
            "the document has an unexpected root element",
        ))
    }
}

/// Whether `body` is an `Error` document, which a store may send under
/// status 200 once the answer has begun.
pub(crate) fn is_error_document(body: &[u8]) -> bool {
    let mut rest = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    rest = rest.trim_ascii_start();
    if rest.starts_with(b"<?xml") {
        let Some(end) = rest.windows(2).position(|pair| pair == b"?>") else {
            return false;
        };
        rest = rest[end + 2..].trim_ascii_start();
    }
    rest.strip_prefix(b"<Error").is_some_and(|after| {
        matches!(
            after.first(),
            Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')
        )
    })
}

/// The error a failed answer describes, under `status`. `request_id` from
/// the headers wins over the one in the document. Without a readable `Error`
/// document the error carries the status and the request id alone.
pub(crate) fn error_response(body: &[u8], status: u16, request_id: Option<&str>) -> S3Error {
    match parse(body) {
        Ok(root) if root.name == "Error" => S3Error::status(
            status,
            root.trimmed("Code"),
            request_id.or_else(|| root.trimmed("RequestId")),
        ),
        _ => S3Error::status(status, None, request_id),
    }
}

/// A ListObjectsV2 answer. Keys and prefixes are URL-decoded when the answer
/// says it encoded them; entries that do not decode are left out.
pub(crate) fn parse_listing(body: &[u8]) -> Result<Listing, S3Error> {
    let root = document(body, "ListBucketResult")?;
    let encoded = root.trimmed("EncodingType") == Some("url");
    let decode = |text: &str| {
        if encoded {
            uri_decode(text)
        } else {
            Some(text.to_owned())
        }
    };

    let mut objects = Vec::new();
    for item in root.children_named("Contents") {
        let Some(key) = item.raw("Key").and_then(decode) else {
            debug!("left out a listed key that does not decode");
            continue;
        };
        objects.push(ListedObject {
            key,
            size: item
                .trimmed("Size")
                .and_then(|size| size.parse().ok())
                .ok_or(S3Error::InvalidResponse(
                    "a listed object has no valid size",
                ))?,
            etag: normalize_etag(item.trimmed("ETag").unwrap_or_default()),
            last_modified: item.trimmed("LastModified").and_then(parse_rfc3339).ok_or(
                S3Error::InvalidResponse("a listed object has no valid modification time"),
            )?,
        });
    }
    let mut prefixes = Vec::new();
    for item in root.children_named("CommonPrefixes") {
        match item.raw("Prefix").and_then(decode) {
            Some(prefix) => prefixes.push(prefix),
            None => debug!("left out a listed prefix that does not decode"),
        }
    }

    let truncated = root.trimmed("IsTruncated") == Some("true");
    let next_token = root
        .raw("NextContinuationToken")
        .filter(|token| !token.is_empty())
        .map(str::to_owned);
    if truncated && next_token.is_none() {
        return Err(S3Error::InvalidResponse(
            "a truncated listing has no continuation token",
        ));
    }
    Ok(Listing {
        objects,
        prefixes,
        next_token: next_token.filter(|_| truncated),
    })
}

/// The upload id of an InitiateMultipartUploadResult.
pub(crate) fn parse_upload_id(body: &[u8]) -> Result<String, S3Error> {
    let root = document(body, "InitiateMultipartUploadResult")?;
    root.trimmed("UploadId")
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or(S3Error::InvalidResponse("the upload has no id"))
}

/// The ETag of a CompleteMultipartUploadResult.
pub(crate) fn parse_completed(body: &[u8]) -> Result<String, S3Error> {
    let root = document(body, "CompleteMultipartUploadResult")?;
    etag_of(&root)
}

/// A CopyObjectResult or CopyPartResult, `name` being the root element.
pub(crate) fn parse_copy(body: &[u8], name: &str) -> Result<CopyResult, S3Error> {
    let root = document(body, name)?;
    Ok(CopyResult {
        etag: etag_of(&root)?,
        last_modified: root.trimmed("LastModified").and_then(parse_rfc3339),
    })
}

fn etag_of(root: &Node) -> Result<String, S3Error> {
    root.trimmed("ETag")
        .filter(|etag| !etag.is_empty())
        .map(normalize_etag)
        .ok_or(S3Error::InvalidResponse("the answer has no ETag"))
}

/// The keys a DeleteResult reports as not deleted.
pub(crate) fn parse_delete_result(body: &[u8]) -> Result<Vec<DeleteFailure>, S3Error> {
    let root = document(body, "DeleteResult")?;
    root.children_named("Error")
        .map(|failure| {
            Ok(DeleteFailure {
                key: failure
                    .raw("Key")
                    .ok_or(S3Error::InvalidResponse("a delete failure names no key"))?
                    .to_owned(),
                code: failure.trimmed("Code").map(str::to_owned),
            })
        })
        .collect()
}

/// `text` as XML character data. A carriage return becomes a character
/// reference, as a literal one would read back as a line feed.
fn escape_text(text: &str) -> Cow<'_, str> {
    let escaped = escape(text);
    if escaped.contains('\r') {
        Cow::Owned(escaped.replace('\r', "&#13;"))
    } else {
        escaped
    }
}

/// The body of CompleteMultipartUpload for `parts`, in the order given.
pub(crate) fn complete_request(parts: &[CompletedPart]) -> String {
    let mut out = String::from("<CompleteMultipartUpload>");
    for part in parts {
        out.push_str("<Part><PartNumber>");
        out.push_str(&part.number.to_string());
        out.push_str("</PartNumber><ETag>");
        out.push_str(&escape_text(&part.etag));
        out.push_str("</ETag></Part>");
    }
    out.push_str("</CompleteMultipartUpload>");
    out
}

/// The body of a quiet DeleteObjects for `keys`. Fails for a key XML cannot
/// carry.
pub(crate) fn delete_request<K: AsRef<str>>(keys: &[K]) -> Result<String, S3Error> {
    let mut out = String::from("<Delete><Quiet>true</Quiet>");
    for key in keys {
        let key = key.as_ref();
        if !key.chars().all(is_xml_char) {
            return Err(S3Error::InvalidArgument(
                "a key has a character XML cannot carry",
            ));
        }
        out.push_str("<Object><Key>");
        out.push_str(&escape_text(key));
        out.push_str("</Key></Object>");
    }
    out.push_str("</Delete>");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn listing(inner: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <ListBucketResult xmlns=\"{NS}\"><Name>bucket</Name>{inner}</ListBucketResult>"
        )
    }

    fn contents(key: &str, size: u64) -> String {
        format!(
            "<Contents><Key>{key}</Key><LastModified>2013-05-24T00:00:00.000Z</LastModified>\
             <ETag>&quot;etag-{size}&quot;</ETag><Size>{size}</Size>\
             <StorageClass>STANDARD</StorageClass></Contents>"
        )
    }

    #[test]
    fn parses_a_listing_page() {
        let body = listing(&format!(
            "<Prefix>photos/</Prefix><KeyCount>3</KeyCount><MaxKeys>1000</MaxKeys>\
             <Delimiter>/</Delimiter><IsTruncated>false</IsTruncated>{}{}\
             <CommonPrefixes><Prefix>photos/2006/</Prefix></CommonPrefixes>\
             <CommonPrefixes><Prefix>photos/2007/</Prefix></CommonPrefixes>",
            contents("photos/a.jpg", 11),
            contents("photos/b.jpg", 0),
        ));
        let parsed = parse_listing(body.as_bytes()).unwrap();
        assert_eq!(
            parsed,
            Listing {
                objects: vec![
                    ListedObject {
                        key: "photos/a.jpg".into(),
                        size: 11,
                        etag: "\"etag-11\"".into(),
                        last_modified: at(1_369_353_600),
                    },
                    ListedObject {
                        key: "photos/b.jpg".into(),
                        size: 0,
                        etag: "\"etag-0\"".into(),
                        last_modified: at(1_369_353_600),
                    },
                ],
                prefixes: vec!["photos/2006/".into(), "photos/2007/".into()],
                next_token: None,
            }
        );
    }

    #[test]
    fn a_truncated_listing_carries_its_continuation_token() {
        let body = listing(&format!(
            "<IsTruncated>true</IsTruncated><NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>{}",
            contents("a", 1)
        ));
        let parsed = parse_listing(body.as_bytes()).unwrap();
        assert_eq!(
            parsed.next_token.as_deref(),
            Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=")
        );
        assert_eq!(parsed.objects.len(), 1);
    }

    #[test]
    fn a_truncated_listing_without_a_token_is_invalid() {
        let body = listing("<IsTruncated>true</IsTruncated>");
        assert!(matches!(
            parse_listing(body.as_bytes()),
            Err(S3Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn a_token_on_the_last_page_is_ignored() {
        let body = listing(
            "<IsTruncated>false</IsTruncated><NextContinuationToken>x</NextContinuationToken>",
        );
        assert_eq!(parse_listing(body.as_bytes()).unwrap().next_token, None);
    }

    #[test]
    fn an_empty_listing_has_no_entries() {
        let body = listing("<KeyCount>0</KeyCount><IsTruncated>false</IsTruncated>");
        let parsed = parse_listing(body.as_bytes()).unwrap();
        assert!(parsed.objects.is_empty() && parsed.prefixes.is_empty());
        let bare = "<ListBucketResult/>";
        assert!(parse_listing(bare.as_bytes()).unwrap().objects.is_empty());
    }

    #[test]
    fn decodes_url_encoded_keys_and_prefixes() {
        let body = listing(&format!(
            "<EncodingType>url</EncodingType>{}{}{}<CommonPrefixes><Prefix>d%C3%A9j%C3%A0+vu/</Prefix></CommonPrefixes>",
            contents("a+b%2Bc%20d/%C3%A9", 1),
            contents("100%25", 2),
            contents("~tilde", 3),
        ));
        let parsed = parse_listing(body.as_bytes()).unwrap();
        let keys: Vec<_> = parsed.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, ["a b+c d/\u{e9}", "100%", "~tilde"]);
        assert_eq!(parsed.prefixes, ["d\u{e9}j\u{e0} vu/"]);
    }

    #[test]
    fn keys_are_left_alone_when_the_answer_is_not_encoded() {
        let body = listing(&contents("100%25+x y", 1));
        let parsed = parse_listing(body.as_bytes()).unwrap();
        assert_eq!(parsed.objects[0].key, "100%25+x y");
    }

    #[test]
    fn keys_keep_their_white_space_and_xml_entities() {
        let body = listing(&contents(" a &amp; b &lt;c&gt; ", 1));
        let parsed = parse_listing(body.as_bytes()).unwrap();
        assert_eq!(parsed.objects[0].key, " a & b <c> ");
        let body = listing(&contents("a&#x20AC;&#233;b", 1));
        assert_eq!(
            parse_listing(body.as_bytes()).unwrap().objects[0].key,
            "a\u{20ac}\u{e9}b"
        );
    }

    #[test]
    fn entries_that_do_not_decode_are_left_out() {
        let body = listing(&format!(
            "<EncodingType>url</EncodingType>{}{}{}<CommonPrefixes><Prefix>%zz/</Prefix></CommonPrefixes>",
            contents("%ff", 1),
            contents("good", 2),
            contents("bad%", 3),
        ));
        let parsed = parse_listing(body.as_bytes()).unwrap();
        assert_eq!(parsed.objects.len(), 1);
        assert_eq!(parsed.objects[0].key, "good");
        assert!(parsed.prefixes.is_empty());
    }

    #[test]
    fn a_listed_object_needs_a_size_and_a_time() {
        for broken in [
            "<Contents><Key>a</Key><LastModified>2013-05-24T00:00:00.000Z</LastModified></Contents>",
            "<Contents><Key>a</Key><Size>x</Size><LastModified>2013-05-24T00:00:00.000Z</LastModified></Contents>",
            "<Contents><Key>a</Key><Size>1</Size></Contents>",
            "<Contents><Key>a</Key><Size>1</Size><LastModified>yesterday</LastModified></Contents>",
        ] {
            assert!(
                matches!(
                    parse_listing(listing(broken).as_bytes()),
                    Err(S3Error::InvalidResponse(_))
                ),
                "{broken}"
            );
        }
    }

    #[test]
    fn an_error_document_under_status_200_is_an_error() {
        let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InternalError</Code>\
                    <Message>We encountered an internal error. Please try again.</Message>\
                    <RequestId>656c76696e6727732072657175657374</RequestId>\
                    <HostId>Uuag1LuByRx9e6j5Onimru9pO4ZVKnJ2Qz7/C1NPcfTWAtRPfTaOFg==</HostId></Error>";
        assert!(is_error_document(body.as_bytes()));
        let error = error_response(body.as_bytes(), 200, None);
        assert!(
            matches!(&error, S3Error::Status { status: 200, .. }),
            "{error:?}"
        );
        assert_eq!(error.code(), Some("InternalError"));
        assert_eq!(error.request_id(), Some("656c76696e6727732072657175657374"));
        assert!(error.is_transient());
        assert!(!error.to_string().contains("We encountered"), "{error}");
    }

    #[test]
    fn an_error_document_is_not_a_result_document() {
        let body = "<Error><Code>InternalError</Code></Error>";
        assert!(parse_completed(body.as_bytes()).is_err());
        assert!(parse_copy(body.as_bytes(), "CopyObjectResult").is_err());
        assert!(parse_copy(body.as_bytes(), "CopyPartResult").is_err());
    }

    #[test]
    fn recognizes_error_documents_by_their_root() {
        for body in [
            "<Error/>",
            "<Error>",
            "  \n<Error><Code>x</Code></Error>",
            "<?xml version=\"1.0\"?><Error/>",
            "<?xml version=\"1.0\"?>\n  <Error xmlns=\"urn:x\"/>",
            "\u{feff}<Error/>",
        ] {
            assert!(is_error_document(body.as_bytes()), "{body:?}");
        }
        for body in [
            "",
            "<ErrorDocument/>",
            "<CopyObjectResult><Error/></CopyObjectResult>",
            "<?xml version=\"1.0\"?",
            "<?xml version=\"1.0\"?>",
            "Error",
            "<Errors/>",
        ] {
            assert!(!is_error_document(body.as_bytes()), "{body:?}");
        }
    }

    #[test]
    fn the_request_id_of_the_answer_wins_over_the_document() {
        let body = "<Error><Code>AccessDenied</Code><RequestId>in-body</RequestId></Error>";
        let error = error_response(body.as_bytes(), 403, Some("in-header"));
        assert_eq!(error.request_id(), Some("in-header"));
        let error = error_response(body.as_bytes(), 403, None);
        assert_eq!(error.request_id(), Some("in-body"));
    }

    #[test]
    fn an_error_answer_without_a_document_keeps_status_and_request_id() {
        for body in [
            &b""[..],
            b"not xml",
            b"<html><body>Bad gateway</body></html>",
            b"<a>",
        ] {
            let error = error_response(body, 502, Some("rid"));
            assert!(matches!(
                &error,
                S3Error::Status {
                    status: 502,
                    code: None,
                    ..
                }
            ));
            assert_eq!(error.request_id(), Some("rid"));
        }
    }

    #[test]
    fn parses_an_error_document_with_a_namespace() {
        let body =
            format!("<Error xmlns=\"{NS}\"><Code>NoSuchUpload</Code><Message>m</Message></Error>");
        let error = error_response(body.as_bytes(), 404, None);
        assert_eq!(error.code(), Some("NoSuchUpload"));
        assert_eq!(error.http_status(), Some(404));
    }

    #[test]
    fn parses_an_initiate_multipart_upload_result() {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<InitiateMultipartUploadResult xmlns=\"{NS}\">\
             <Bucket>example-bucket</Bucket><Key>example-object</Key>\
             <UploadId>VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>\
             </InitiateMultipartUploadResult>"
        );
        assert_eq!(
            parse_upload_id(body.as_bytes()).unwrap(),
            "VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA"
        );
        let missing =
            "<InitiateMultipartUploadResult><Bucket>b</Bucket></InitiateMultipartUploadResult>";
        assert!(parse_upload_id(missing.as_bytes()).is_err());
        let empty =
            "<InitiateMultipartUploadResult><UploadId> </UploadId></InitiateMultipartUploadResult>";
        assert!(parse_upload_id(empty.as_bytes()).is_err());
    }

    #[test]
    fn parses_a_complete_multipart_upload_result() {
        let body = format!(
            "\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUploadResult xmlns=\"{NS}\">\
             <Location>http://Example-Bucket.s3.amazonaws.com/Example-Object</Location>\
             <Bucket>Example-Bucket</Bucket><Key>Example-Object</Key>\
             <ETag>\"3858f62230ac3c915f300c664312c11f-9\"</ETag></CompleteMultipartUploadResult>"
        );
        assert_eq!(
            parse_completed(body.as_bytes()).unwrap(),
            "\"3858f62230ac3c915f300c664312c11f-9\""
        );
        let no_etag = "<CompleteMultipartUploadResult><Key>k</Key></CompleteMultipartUploadResult>";
        assert!(matches!(
            parse_completed(no_etag.as_bytes()),
            Err(S3Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn parses_copy_results() {
        let object = format!(
            "<CopyObjectResult xmlns=\"{NS}\"><LastModified>2009-10-12T17:50:30.000Z</LastModified>\
             <ETag>&quot;9b2cf535f27731c974343645a3985328&quot;</ETag></CopyObjectResult>"
        );
        let parsed = parse_copy(object.as_bytes(), "CopyObjectResult").unwrap();
        assert_eq!(parsed.etag, "\"9b2cf535f27731c974343645a3985328\"");
        assert_eq!(parsed.last_modified, Some(at(1_255_369_830)));

        let part = "<CopyPartResult><ETag>\"abc\"</ETag></CopyPartResult>";
        let parsed = parse_copy(part.as_bytes(), "CopyPartResult").unwrap();
        assert_eq!(parsed.etag, "\"abc\"");
        assert_eq!(parsed.last_modified, None);
    }

    #[test]
    fn a_copy_result_must_be_the_one_asked_for() {
        let part = "<CopyPartResult><ETag>\"abc\"</ETag></CopyPartResult>";
        assert!(matches!(
            parse_copy(part.as_bytes(), "CopyObjectResult"),
            Err(S3Error::InvalidResponse(_))
        ));
        let no_etag = "<CopyObjectResult><LastModified>2009-10-12T17:50:30.000Z</LastModified></CopyObjectResult>";
        assert!(parse_copy(no_etag.as_bytes(), "CopyObjectResult").is_err());
    }

    #[test]
    fn parses_a_delete_result() {
        let body = format!(
            "<DeleteResult xmlns=\"{NS}\">\
             <Error><Key>locked &amp; held</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>\
             <Error><Key>b</Key><Code>InternalError</Code></Error></DeleteResult>"
        );
        assert_eq!(
            parse_delete_result(body.as_bytes()).unwrap(),
            [
                DeleteFailure {
                    key: "locked & held".into(),
                    code: Some("AccessDenied".into())
                },
                DeleteFailure {
                    key: "b".into(),
                    code: Some("InternalError".into())
                },
            ]
        );
        assert!(parse_delete_result(b"<DeleteResult/>").unwrap().is_empty());
        let keyless = "<DeleteResult><Error><Code>x</Code></Error></DeleteResult>";
        assert!(parse_delete_result(keyless.as_bytes()).is_err());
    }

    #[test]
    fn rejects_documents_that_are_not_well_formed() {
        for body in [
            &b""[..],
            b"   ",
            b"plain text",
            b"<ListBucketResult>",
            b"<ListBucketResult></Other>",
            b"<a/><b/>",
            b"<a></a><b></b>",
            b"text<a/>",
            b"<a/>text",
            b"<a>&undefined;</a>",
            b"<a>&#0;</a>",
            b"<a>&#xD800;</a>",
            b"<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>",
            b"<a>\xff</a>",
        ] {
            let result = parse(body);
            assert!(
                matches!(result, Err(S3Error::InvalidResponse(_))),
                "{:?}: {result:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn deep_nesting_is_refused() {
        let deep = format!(
            "{}{}",
            "<a>".repeat(MAX_DEPTH + 1),
            "</a>".repeat(MAX_DEPTH + 1)
        );
        assert!(parse(deep.as_bytes()).is_err());
        let fine = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(parse(fine.as_bytes()).is_ok());
    }

    #[test]
    fn reads_text_in_cdata_and_after_a_byte_order_mark() {
        let body = "\u{feff}<Error><Code><![CDATA[AccessDenied]]></Code></Error>";
        let error = error_response(body.as_bytes(), 403, None);
        assert_eq!(error.code(), Some("AccessDenied"));
    }

    #[test]
    fn writes_the_complete_request() {
        let parts = [
            CompletedPart {
                number: 1,
                etag: "\"a54357aff0632cce46d942af68356b38\"".into(),
            },
            CompletedPart {
                number: 2,
                etag: "\"0c78aef83f66abc1fa1e8477f296d394\"".into(),
            },
        ];
        assert_eq!(
            complete_request(&parts),
            "<CompleteMultipartUpload>\
             <Part><PartNumber>1</PartNumber><ETag>&quot;a54357aff0632cce46d942af68356b38&quot;</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>&quot;0c78aef83f66abc1fa1e8477f296d394&quot;</ETag></Part>\
             </CompleteMultipartUpload>"
        );
        let round_trip = parse(complete_request(&parts).as_bytes()).unwrap();
        let etags: Vec<_> = round_trip
            .children_named("Part")
            .map(|part| part.raw("ETag").unwrap())
            .collect();
        assert_eq!(
            etags,
            [
                "\"a54357aff0632cce46d942af68356b38\"",
                "\"0c78aef83f66abc1fa1e8477f296d394\""
            ]
        );
    }

    #[test]
    fn writes_the_delete_request_with_escaped_keys() {
        let body = delete_request(&["a", "x & <y>", "caf\u{e9}/\u{1f600}"]).unwrap();
        assert_eq!(
            body,
            "<Delete><Quiet>true</Quiet>\
             <Object><Key>a</Key></Object>\
             <Object><Key>x &amp; &lt;y&gt;</Key></Object>\
             <Object><Key>caf\u{e9}/\u{1f600}</Key></Object></Delete>"
        );
        let root = parse(body.as_bytes()).unwrap();
        let keys: Vec<_> = root
            .children_named("Object")
            .map(|object| object.raw("Key").unwrap())
            .collect();
        assert_eq!(keys, ["a", "x & <y>", "caf\u{e9}/\u{1f600}"]);
    }

    #[test]
    fn a_carriage_return_is_written_as_a_character_reference() {
        let keys = ["a\rb", "a\r\nb", "\r", "x & \r<y>"];
        let body = delete_request(&keys).unwrap();
        assert!(!body.contains('\r'), "{body:?}");
        assert!(body.contains("<Key>a&#13;b</Key>"), "{body}");
        assert!(body.contains("<Key>a&#13;\nb</Key>"), "{body}");
        assert!(body.contains("<Key>x &amp; &#13;&lt;y&gt;</Key>"), "{body}");
        let root = parse(body.as_bytes()).unwrap();
        let read: Vec<_> = root
            .children_named("Object")
            .map(|object| object.raw("Key").unwrap())
            .collect();
        assert_eq!(read, keys);
    }

    #[test]
    fn a_carriage_return_in_an_etag_is_written_as_a_character_reference() {
        let parts = [CompletedPart {
            number: 1,
            etag: "\"a\rb\"".into(),
        }];
        let body = complete_request(&parts);
        assert!(!body.contains('\r'), "{body:?}");
        let root = parse(body.as_bytes()).unwrap();
        let part = root.child("Part").unwrap();
        assert_eq!(part.raw("ETag"), Some("\"a\rb\""));
    }

    #[test]
    fn a_key_with_a_character_xml_cannot_carry_is_refused() {
        for key in ["a\u{1}b", "a\u{0}", "a\u{fffe}"] {
            assert!(
                matches!(delete_request(&[key]), Err(S3Error::InvalidArgument(_))),
                "{key:?}"
            );
        }
        assert!(delete_request(&["tab\there"]).is_ok());
    }
}
