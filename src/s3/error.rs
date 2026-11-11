//! The error of a call to an S3 store.

use std::error::Error;
use std::fmt;
use std::io;
use std::iter;
use std::sync::Arc;

use tracing::{error, warn};

use crate::SmbError;

pub(crate) type BoxError = Box<dyn Error + Send + Sync>;

/// Longest error code or request id kept from a response.
const MAX_FIELD_LEN: usize = 128;

/// Why an S3 call failed.
///
/// The text of an error and its `Debug` output carry the HTTP status, the
/// error code and the request id of the store's answer. They never carry
/// credentials, signatures or the body of a response.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum S3Error {
    /// The store answered with an error status, or with an error document
    /// under a success status.
    #[non_exhaustive]
    Status {
        /// The HTTP status of the answer.
        status: u16,
        /// The S3 error code, when the answer has one.
        code: Option<String>,
        /// The request id the store gave the call, when it did.
        request_id: Option<String>,
    },
    /// No answer: the connection, the TLS handshake, the request or the
    /// response body failed.
    Transport(Arc<dyn Error + Send + Sync>),
    /// Nothing was sent or received for 60 seconds.
    TimedOut,
    /// The deadline of the call passed.
    DeadlineExceeded,
    /// The call was stopped. No attempt began after the stop.
    #[doc(hidden)]
    Stopped,
    /// The data to send is not the data its hash covers: the file changed
    /// after it was hashed.
    #[doc(hidden)]
    SourceChanged,
    /// The data to send could not be read from its file.
    SourceRead(Arc<io::Error>),
    /// The answer breaks what the call expects of it.
    InvalidResponse(&'static str),
    /// A setting or argument cannot be used. The text names it.
    InvalidArgument(&'static str),
}

impl S3Error {
    /// A `Status` error. `code` and `request_id` are kept only when they look
    /// like identifiers, so that text from the body of a response never
    /// reaches a message.
    pub(crate) fn status(status: u16, code: Option<&str>, request_id: Option<&str>) -> Self {
        S3Error::Status {
            status,
            code: code.and_then(identifier),
            request_id: request_id.and_then(identifier),
        }
    }

    /// The HTTP status of the store's answer.
    pub(crate) fn http_status(&self) -> Option<u16> {
        match self {
            S3Error::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The S3 error code of the store's answer.
    pub(crate) fn code(&self) -> Option<&str> {
        match self {
            S3Error::Status { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    /// The request id of the store's answer.
    pub(crate) fn request_id(&self) -> Option<&str> {
        match self {
            S3Error::Status { request_id, .. } => request_id.as_deref(),
            _ => None,
        }
    }

    /// Whether the store answered that the key does not exist: status 404
    /// without a code, as a HEAD answer has no body, or with the code
    /// `NoSuchKey`, or an `Error` document with that code under status 200.
    pub(crate) fn is_no_such_key(&self) -> bool {
        matches!(
            (self.http_status(), self.code()),
            (Some(404), None | Some("NoSuchKey")) | (Some(200), Some("NoSuchKey"))
        )
    }

    /// Whether the store answered that a condition of the request does not
    /// hold, such as the `If-Match` of a GET.
    pub(crate) fn is_precondition_failed(&self) -> bool {
        self.http_status() == Some(412)
    }

    /// Whether the data sent was not the data the request was signed for: the
    /// file changed after it was hashed, or the store found the body to differ
    /// from the hash.
    #[cfg_attr(not(test), expect(dead_code, reason = "called by tests only"))]
    pub(crate) fn is_source_changed(&self) -> bool {
        matches!(self, S3Error::SourceChanged)
            || matches!(self.code(), Some("XAmzContentSHA256Mismatch" | "BadDigest"))
    }

    /// Whether the call ended because it was stopped.
    #[cfg_attr(not(test), expect(dead_code, reason = "called by tests only"))]
    pub(crate) fn is_stopped(&self) -> bool {
        matches!(self, S3Error::Stopped)
    }

    /// Whether the store rejected the request for the time on its signature.
    pub(crate) fn is_clock_skew(&self) -> bool {
        self.http_status() == Some(403) && self.code() == Some("RequestTimeTooSkewed")
    }

    /// Whether trying again can help: connection failures, timeouts, status
    /// 408, 429, 500, 502, 503 and 504, status 400 with the code
    /// `RequestTimeout`, and the codes `SlowDown`, `InternalError` and
    /// `ServiceUnavailable`, which a store may send under status 200 once the
    /// answer has begun.
    ///
    /// A clock the store rejects is not included. Waiting can fix it, so a
    /// background call tries again, and a call somebody waits on does not.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            S3Error::Transport(_) | S3Error::TimedOut => true,
            S3Error::Status { status, code, .. } => {
                matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
                    || matches!(
                        code.as_deref(),
                        Some("SlowDown" | "InternalError" | "ServiceUnavailable")
                    )
                    || (*status == 400 && code.as_deref() == Some("RequestTimeout"))
            }
            S3Error::DeadlineExceeded
            | S3Error::Stopped
            | S3Error::SourceChanged
            | S3Error::SourceRead(_)
            | S3Error::InvalidResponse(_)
            | S3Error::InvalidArgument(_) => false,
        }
    }

    pub(crate) fn transport(source: impl Into<BoxError>) -> Self {
        S3Error::Transport(Arc::from(source.into()))
    }

    /// The messages of the errors behind a transport failure, from the
    /// outermost to the innermost, joined by `: `. They carry no credentials,
    /// signatures or bodies.
    pub(crate) fn causes(&self) -> Option<String> {
        let S3Error::Transport(source) = self else {
            return None;
        };
        let first: &(dyn Error + 'static) = source.as_ref();
        let chain: Vec<String> = iter::successors(Some(first), |error| (*error).source())
            .map(ToString::to_string)
            .collect();
        Some(chain.join(": "))
    }

    /// The error a share request fails with, chosen by the code of the store's
    /// answer and by its status when it has no code. Logs a refused access at
    /// warn level, with the code only, and a clock the store rejects at error
    /// level. An answer that matches none of the specific errors becomes `Io`
    /// and is logged at warn level with its status, code, request id and
    /// causes.
    pub(crate) fn into_smb_error(self) -> SmbError {
        let (status, code) = (self.http_status(), self.code());
        match (status, code) {
            (_, Some("RequestTimeTooSkewed")) => {
                error!(
                    code = "RequestTimeTooSkewed",
                    request_id = self.request_id(),
                    "the store rejects the request time; check the system clock"
                );
                SmbError::Io(io::Error::other(self))
            }
            (_, Some("AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch"))
            | (Some(403), _) => {
                warn!(code, "the store denied access");
                SmbError::AccessDenied
            }
            _ if self.is_no_such_key() => SmbError::NotFound,
            (_, Some("ObjectParentIsFile")) => SmbError::PathNotFound,
            (_, Some("ExistingObjectIsDirectory")) => SmbError::Exists,
            (_, Some("KeyTooLongError")) => SmbError::NameInvalid,
            (_, Some("EntityTooLarge")) => SmbError::DiskFull,
            _ => {
                warn!(
                    status,
                    code,
                    request_id = self.request_id(),
                    cause = self.causes(),
                    "the store request failed"
                );
                SmbError::Io(io::Error::other(self))
            }
        }
    }
}

/// `text` when it is a plausible error code or request id.
fn identifier(text: &str) -> Option<String> {
    let text = text.trim();
    let plausible = !text.is_empty()
        && text.len() <= MAX_FIELD_LEN
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/' | b'+' | b'=')
        });
    plausible.then(|| text.to_owned())
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            S3Error::Status {
                status,
                code,
                request_id,
            } => {
                write!(f, "the store answered status {status}")?;
                if let Some(code) = code {
                    write!(f, " with code {code}")?;
                }
                if let Some(id) = request_id {
                    write!(f, " (request id {id})")?;
                }
                Ok(())
            }
            S3Error::Transport(_) => f.write_str("the request failed in transit"),
            S3Error::TimedOut => f.write_str("no data moved for 60 seconds"),
            S3Error::DeadlineExceeded => f.write_str("the deadline passed"),
            S3Error::Stopped => f.write_str("the call was stopped"),
            S3Error::SourceChanged => f.write_str("the data to upload changed after it was hashed"),
            S3Error::SourceRead(_) => f.write_str("the data to upload could not be read"),
            S3Error::InvalidResponse(what) => write!(f, "invalid response: {what}"),
            S3Error::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
        }
    }
}

impl Error for S3Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            S3Error::Transport(source) => Some(source.as_ref()),
            S3Error::SourceRead(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(status: u16, code: &str) -> S3Error {
        S3Error::status(status, Some(code), Some("REQ123"))
    }

    #[test]
    fn displays_status_code_and_request_id() {
        assert_eq!(
            status(503, "SlowDown").to_string(),
            "the store answered status 503 with code SlowDown (request id REQ123)"
        );
        assert_eq!(
            S3Error::status(404, None, None).to_string(),
            "the store answered status 404"
        );
    }

    #[test]
    fn text_from_a_response_body_never_reaches_a_message() {
        let body =
            "<Error>AWSAccessKeyId=AKIA... StringToSign=AWS4-HMAC-SHA256 Signature=abc</Error>";
        let error = S3Error::status(403, Some(body), Some(body));
        assert_eq!(error.code(), None);
        assert_eq!(error.request_id(), None);
        for shown in [error.to_string(), format!("{error:?}")] {
            assert!(!shown.contains("AKIA"), "{shown}");
            assert!(!shown.contains("StringToSign"), "{shown}");
            assert!(!shown.contains("Signature"), "{shown}");
        }
    }

    #[test]
    fn keeps_codes_and_request_ids_that_are_identifiers() {
        let error = S3Error::status(
            500,
            Some(" InternalError "),
            Some("tx00000000000000000001-0065c4b0f9-1234-default"),
        );
        assert_eq!(error.code(), Some("InternalError"));
        assert_eq!(
            error.request_id(),
            Some("tx00000000000000000001-0065c4b0f9-1234-default")
        );
        assert_eq!(S3Error::status(500, Some(""), Some("  ")).code(), None);
        let long = "a".repeat(MAX_FIELD_LEN + 1);
        assert_eq!(S3Error::status(500, Some(&long), None).code(), None);
        assert_eq!(
            S3Error::status(500, Some(&long[1..]), None)
                .code()
                .map(str::len),
            Some(MAX_FIELD_LEN)
        );
    }

    #[test]
    fn the_message_of_a_transport_error_hides_its_source() {
        let error = S3Error::transport("connection refused by 192.0.2.1");
        assert_eq!(error.to_string(), "the request failed in transit");
        assert_eq!(
            error.source().map(ToString::to_string).as_deref(),
            Some("connection refused by 192.0.2.1")
        );
    }

    #[test]
    fn a_status_error_is_read_through_accessors_and_predicates() {
        let error = status(409, "ObjectParentIsFile");
        assert_eq!(error.http_status(), Some(409));
        assert_eq!(error.code(), Some("ObjectParentIsFile"));
        assert_eq!(error.request_id(), Some("REQ123"));
        assert!(!error.is_no_such_key());
        assert!(status(404, "NoSuchKey").is_no_such_key());
        assert!(S3Error::status(404, None, None).is_no_such_key());
        assert!(!status(404, "NoSuchBucket").is_no_such_key());
        assert!(!status(404, "NoSuchUpload").is_no_such_key());
        assert!(!status(403, "NoSuchKey").is_no_such_key());
        assert!(status(412, "PreconditionFailed").is_precondition_failed());
        assert!(S3Error::status(412, None, None).is_precondition_failed());
        assert!(!status(400, "PreconditionFailed").is_precondition_failed());
        assert_eq!(S3Error::TimedOut.http_status(), None);
        assert_eq!(S3Error::InvalidResponse("x").code(), None);
    }

    #[test]
    fn classifies_transient_errors() {
        for transient in [
            S3Error::TimedOut,
            S3Error::transport("reset"),
            S3Error::status(408, None, None),
            S3Error::status(429, None, None),
            S3Error::status(500, None, None),
            S3Error::status(502, None, None),
            S3Error::status(503, None, None),
            S3Error::status(504, None, None),
            status(400, "SlowDown"),
            status(400, "RequestTimeout"),
            status(200, "InternalError"),
            status(200, "SlowDown"),
            status(200, "ServiceUnavailable"),
        ] {
            assert!(transient.is_transient(), "{transient:?}");
        }
        for permanent in [
            S3Error::status(400, None, None),
            S3Error::status(403, None, None),
            S3Error::status(404, None, None),
            S3Error::status(409, None, None),
            S3Error::status(412, None, None),
            S3Error::status(416, None, None),
            S3Error::status(501, None, None),
            status(200, "AccessDenied"),
            status(403, "RequestTimeTooSkewed"),
            status(403, "RequestTimeout"),
            status(400, "XAmzContentSHA256Mismatch"),
            status(400, "BadDigest"),
            S3Error::DeadlineExceeded,
            S3Error::Stopped,
            S3Error::SourceChanged,
            S3Error::SourceRead(Arc::new(io::Error::other("x"))),
            S3Error::InvalidResponse("x"),
            S3Error::InvalidArgument("x"),
        ] {
            assert!(!permanent.is_transient(), "{permanent:?}");
        }
    }

    fn smb(error: S3Error) -> SmbError {
        error.into_smb_error()
    }

    #[test]
    fn maps_store_errors_to_share_errors() {
        assert!(matches!(smb(status(404, "NoSuchKey")), SmbError::NotFound));
        assert!(matches!(
            smb(S3Error::status(404, None, None)),
            SmbError::NotFound
        ));
        for code in [
            "AccessDenied",
            "InvalidAccessKeyId",
            "SignatureDoesNotMatch",
        ] {
            assert!(
                matches!(smb(status(403, code)), SmbError::AccessDenied),
                "{code}"
            );
        }
        assert!(matches!(
            smb(S3Error::status(403, None, None)),
            SmbError::AccessDenied
        ));
        assert!(matches!(
            smb(status(409, "ObjectParentIsFile")),
            SmbError::PathNotFound
        ));
        assert!(matches!(
            smb(status(409, "ExistingObjectIsDirectory")),
            SmbError::Exists
        ));
        assert!(matches!(
            smb(status(400, "KeyTooLongError")),
            SmbError::NameInvalid
        ));
        assert!(matches!(
            smb(status(400, "EntityTooLarge")),
            SmbError::DiskFull
        ));
    }

    #[test]
    fn every_other_failure_is_an_io_error() {
        for error in [
            status(403, "RequestTimeTooSkewed"),
            status(404, "NoSuchBucket"),
            status(409, "OperationAborted"),
            status(503, "SlowDown"),
            S3Error::status(500, None, None),
            S3Error::TimedOut,
            S3Error::transport("reset"),
            S3Error::DeadlineExceeded,
            S3Error::Stopped,
            S3Error::SourceChanged,
            S3Error::SourceRead(Arc::new(io::Error::other("x"))),
            S3Error::InvalidResponse("x"),
            S3Error::InvalidArgument("x"),
        ] {
            let shown = format!("{error:?}");
            assert!(matches!(smb(error), SmbError::Io(_)), "{shown}");
        }
    }

    #[test]
    fn the_io_error_keeps_the_store_error_as_its_source() {
        let SmbError::Io(io) = smb(status(503, "SlowDown")) else {
            panic!("not an io error");
        };
        let source = io.get_ref().unwrap().downcast_ref::<S3Error>().unwrap();
        assert_eq!(source.code(), Some("SlowDown"));
    }

    #[test]
    fn a_rejected_clock_is_told_apart() {
        assert!(status(403, "RequestTimeTooSkewed").is_clock_skew());
        assert!(!status(403, "AccessDenied").is_clock_skew());
        assert!(!status(400, "RequestTimeTooSkewed").is_clock_skew());
        assert!(!S3Error::TimedOut.is_clock_skew());
    }

    #[test]
    fn a_changed_source_is_told_apart() {
        for changed in [
            S3Error::SourceChanged,
            status(400, "XAmzContentSHA256Mismatch"),
            status(400, "BadDigest"),
        ] {
            assert!(changed.is_source_changed(), "{changed:?}");
        }
        for other in [
            S3Error::status(400, None, None),
            status(400, "InvalidRequest"),
            S3Error::TimedOut,
            S3Error::SourceRead(Arc::new(io::Error::other("x"))),
        ] {
            assert!(!other.is_source_changed(), "{other:?}");
        }
    }

    #[test]
    fn an_error_document_under_status_200_maps_by_its_code() {
        for (code, expected) in [
            ("AccessDenied", "AccessDenied"),
            ("InvalidAccessKeyId", "AccessDenied"),
            ("SignatureDoesNotMatch", "AccessDenied"),
            ("NoSuchKey", "NotFound"),
        ] {
            let shown = format!("{:?}", smb(status(200, code)));
            assert!(shown.starts_with(expected), "{code}: {shown}");
        }
        assert!(matches!(
            smb(S3Error::status(200, None, None)),
            SmbError::Io(_)
        ));
        assert!(status(200, "NoSuchKey").is_no_such_key());
    }

    #[test]
    fn the_causes_of_a_transport_error_are_listed_outermost_first() {
        #[derive(Debug)]
        struct Layer(&'static str, Option<Box<Layer>>);
        impl fmt::Display for Layer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
        impl Error for Layer {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                self.1
                    .as_deref()
                    .map(|inner| inner as &(dyn Error + 'static))
            }
        }
        let inner = Layer("connection refused", None);
        let middle = Layer("tcp connect error", Some(Box::new(inner)));
        let error = S3Error::transport(Layer("client error", Some(Box::new(middle))));
        assert_eq!(
            error.causes().as_deref(),
            Some("client error: tcp connect error: connection refused")
        );
        assert_eq!(error.to_string(), "the request failed in transit");
        assert_eq!(status(503, "SlowDown").causes(), None);
        assert_eq!(S3Error::TimedOut.causes(), None);
    }
}
