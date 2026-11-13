//! The body of a request that sends data, and the hash the request is signed
//! with.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use tokio::task::JoinHandle;

use super::data::read_at;
use super::encode::hex;
use super::error::S3Error;
use super::sigv4::EMPTY_SHA256;

/// What a PutObject or UploadPart sends, with the SHA-256 of it that the
/// request is signed with.
#[derive(Clone)]
pub(crate) struct Payload {
    pub(super) source: Source,
    sha256: String,
}

/// Where the bytes of a [`Payload`] are.
#[derive(Clone)]
pub(super) enum Source {
    Memory(Bytes),
    File(FileRange),
}

/// A range of a file. Every attempt of a call reads it again from `offset`.
#[derive(Clone)]
pub(super) struct FileRange {
    pub(super) file: Arc<File>,
    pub(super) offset: u64,
    pub(super) len: u64,
}

impl Payload {
    /// No bytes.
    pub(crate) fn empty() -> Self {
        Payload {
            source: Source::Memory(Bytes::new()),
            sha256: EMPTY_SHA256.to_owned(),
        }
    }

    /// `len` bytes of `file` from `offset`, which hashed to `sha256` (64 hex
    /// digits) when the caller read them. The bytes are read by position,
    /// never through the cursor of `file`. On Windows a read by position moves
    /// the cursor, so its position afterwards is unspecified.
    ///
    /// The request sends the bytes it reads and hashes them on the way. If
    /// they do not hash to `sha256`, the request fails with
    /// [`S3Error::SourceChanged`] before it sends the last piece, and the
    /// store keeps nothing.
    pub(crate) fn file(
        file: Arc<File>,
        offset: u64,
        len: u64,
        sha256: &str,
    ) -> Result<Self, S3Error> {
        if offset.checked_add(len).is_none() {
            return Err(S3Error::InvalidArgument(
                "the file range ends past u64::MAX",
            ));
        }
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(S3Error::InvalidArgument(
                "the SHA-256 is not 64 hexadecimal digits",
            ));
        }
        if len == 0 && !sha256.eq_ignore_ascii_case(EMPTY_SHA256) {
            return Err(S3Error::InvalidArgument(
                "an empty file range does not have the SHA-256 of no bytes",
            ));
        }
        Ok(Payload {
            source: Source::File(FileRange { file, offset, len }),
            sha256: sha256.to_ascii_lowercase(),
        })
    }

    /// The number of bytes.
    pub(crate) fn len(&self) -> u64 {
        match &self.source {
            Source::Memory(data) => data.len() as u64,
            Source::File(range) => range.len,
        }
    }

    /// The hash as 64 lowercase hex digits.
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Hashes `data` at conversion.
impl From<Bytes> for Payload {
    fn from(data: Bytes) -> Self {
        Payload {
            sha256: hex(&Sha256::digest(&data)),
            source: Source::Memory(data),
        }
    }
}

/// Largest piece of a request body handed to the connection at once, and
/// largest read from a file.
pub(crate) const BODY_CHUNK: usize = 64 * 1024;

/// Where a [`FileBody`] leaves the error it fails with. The error that hyper
/// returns for a failed body does not say why, so the sender reads the cause
/// here.
pub(super) type Fault = Arc<OnceLock<S3Error>>;

/// The error a failed body gives hyper. The cause is in the [`Fault`].
#[derive(Debug)]
pub(crate) struct BodyError;

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the request body could not be read")
    }
}

impl Error for BodyError {}

/// The bytes of a [`FileRange`], read in pieces of at most [`BODY_CHUNK`] on
/// the blocking threads of the runtime and hashed as they are read. The last
/// piece is held back until the hash of all of them is the one the payload
/// was given, so a file that changed never gets to the store whole.
pub(super) struct FileBody {
    range: FileRange,
    expected: String,
    /// Bytes handed out.
    sent: u64,
    /// `None` while a read has it, and after a failure.
    hasher: Option<Sha256>,
    reading: Option<JoinHandle<Result<(Bytes, Sha256), S3Error>>>,
    fault: Fault,
}

impl FileBody {
    pub(super) fn new(range: FileRange, sha256: &str, fault: Fault) -> Self {
        FileBody {
            range,
            expected: sha256.to_owned(),
            sent: 0,
            hasher: Some(Sha256::new()),
            reading: None,
            fault,
        }
    }

    /// The bytes not handed out yet.
    pub(super) fn remaining(&self) -> u64 {
        self.range.len - self.sent
    }

    /// Whether a read is running.
    pub(super) fn is_reading(&self) -> bool {
        self.reading.is_some()
    }

    /// The next piece of the file, or `None` after the last.
    pub(super) fn poll_piece(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, BodyError>>> {
        let job = match self.reading.as_mut() {
            Some(job) => job,
            None => {
                let left = self.remaining();
                if left == 0 {
                    return Poll::Ready(None);
                }
                let Some(hasher) = self.hasher.take() else {
                    return Poll::Ready(Some(Err(BodyError)));
                };
                let len = usize::try_from(left).map_or(BODY_CHUNK, |left| left.min(BODY_CHUNK));
                let last = len as u64 == left;
                let file = self.range.file.clone();
                let at = self.range.offset + self.sent;
                let expected = last.then(|| self.expected.clone());
                self.reading.insert(tokio::task::spawn_blocking(move || {
                    read_piece(&file, at, len, hasher, expected.as_deref())
                }))
            }
        };
        let outcome = ready!(Pin::new(job).poll(cx));
        self.reading = None;
        match outcome {
            Ok(Ok((piece, hasher))) => {
                self.sent += piece.len() as u64;
                self.hasher = Some(hasher);
                Poll::Ready(Some(Ok(piece)))
            }
            Ok(Err(error)) => self.fail(error),
            Err(error) => self.fail(S3Error::SourceRead(Arc::new(io::Error::other(error)))),
        }
    }

    fn fail(&mut self, error: S3Error) -> Poll<Option<Result<Bytes, BodyError>>> {
        let _ = self.fault.set(error);
        Poll::Ready(Some(Err(BodyError)))
    }
}

/// Reads `len` bytes of `file` from `at` and adds them to `hasher`. With
/// `expected`, the hash of everything read must equal it. A file that ends
/// early or hashes to something else has changed.
fn read_piece(
    file: &File,
    at: u64,
    len: usize,
    mut hasher: Sha256,
    expected: Option<&str>,
) -> Result<(Bytes, Sha256), S3Error> {
    let mut piece = vec![0; len];
    let read =
        read_full_at(file, &mut piece, at).map_err(|error| S3Error::SourceRead(Arc::new(error)))?;
    if read < len {
        return Err(S3Error::SourceChanged);
    }
    hasher.update(&piece);
    if let Some(expected) = expected
        && hex(&hasher.clone().finalize()) != expected
    {
        return Err(S3Error::SourceChanged);
    }
    Ok((Bytes::from(piece), hasher))
}

/// Reads `buf.len()` bytes of `file` from `offset`. Stops short of that only
/// at the end of the file, and returns the number of bytes read.
fn read_full_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match read_at(file, &mut buf[done..], offset + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::io::{Seek as _, SeekFrom, Write as _};

    use super::*;

    fn file_with(data: &[u8]) -> Arc<File> {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(data).unwrap();
        Arc::new(file)
    }

    /// Writes `data` at `at`.
    fn overwrite(file: &Arc<File>, at: u64, data: &[u8]) {
        let mut file: &File = file;
        file.seek(SeekFrom::Start(at)).unwrap();
        file.write_all(data).unwrap();
    }

    fn sha(data: &[u8]) -> String {
        hex(&Sha256::digest(data))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..=250).cycle().take(len).collect()
    }

    fn open(file: &Arc<File>, offset: u64, len: u64, hash: &str) -> (FileBody, Fault) {
        let fault = Fault::default();
        let range = FileRange {
            file: file.clone(),
            offset,
            len,
        };
        (FileBody::new(range, hash, fault.clone()), fault)
    }

    /// The pieces a body gives up to its end or its first error.
    async fn drain(body: &mut FileBody) -> (Vec<Bytes>, bool) {
        let mut pieces = Vec::new();
        while let Some(piece) = poll_fn(|cx| body.poll_piece(cx)).await {
            match piece {
                Ok(piece) => pieces.push(piece),
                Err(BodyError) => return (pieces, true),
            }
        }
        (pieces, false)
    }

    #[test]
    fn a_memory_payload_carries_its_own_hash() {
        let payload = Payload::from(Bytes::from_static(b"Welcome to Amazon S3."));
        assert_eq!(payload.len(), 21);
        assert_eq!(
            payload.sha256(),
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        assert_eq!(Payload::empty().sha256(), sha(b""));
        assert_eq!(Payload::empty().len(), 0);
        assert_eq!(Payload::from(Bytes::new()).sha256(), EMPTY_SHA256);
    }

    #[test]
    fn a_file_payload_keeps_the_range_and_the_hash_it_is_given() {
        let file = file_with(b"0123456789");
        let hash = sha(b"2345");
        let payload = Payload::file(file, 2, 4, &hash.to_ascii_uppercase()).unwrap();
        assert_eq!(payload.len(), 4);
        assert_eq!(payload.sha256(), hash);
    }

    #[test]
    fn a_file_payload_refuses_what_cannot_be_sent() {
        let file = file_with(b"x");
        for hash in ["", "abc", &"g".repeat(64), &"a".repeat(65)] {
            assert!(
                matches!(
                    Payload::file(file.clone(), 0, 1, hash),
                    Err(S3Error::InvalidArgument(_))
                ),
                "{hash}"
            );
        }
        assert!(matches!(
            Payload::file(file.clone(), u64::MAX, 2, &sha(b"x")),
            Err(S3Error::InvalidArgument(_))
        ));
        assert!(Payload::file(file, 0, 0, &sha(b"")).is_ok());
    }

    #[test]
    fn an_empty_file_range_must_hash_to_nothing() {
        let file = file_with(b"x");
        let nothing = sha(b"");
        let payload = Payload::file(file.clone(), 5, 0, &nothing.to_ascii_uppercase()).unwrap();
        assert_eq!((payload.len(), payload.sha256()), (0, nothing.as_str()));
        assert!(matches!(
            Payload::file(file.clone(), 5, 0, &sha(b"x")),
            Err(S3Error::InvalidArgument(_))
        ));
        assert!(matches!(
            Payload::file(file.clone(), 0, 0, &"0".repeat(64)),
            Err(S3Error::InvalidArgument(_))
        ));
        assert!(Payload::file(file, 0, 1, &sha(b"x")).is_ok());
    }

    #[test]
    fn reads_by_position_and_stops_at_the_end_of_the_file() {
        let file = file_with(b"0123456789");
        let mut buf = [0; 4];
        assert_eq!(read_full_at(&file, &mut buf, 3).unwrap(), 4);
        assert_eq!(&buf, b"3456");
        assert_eq!(read_full_at(&file, &mut buf, 8).unwrap(), 2);
        assert_eq!(&buf[..2], b"89");
        assert_eq!(read_full_at(&file, &mut buf, 10).unwrap(), 0);
        assert_eq!(read_full_at(&file, &mut buf, 1000).unwrap(), 0);
        assert_eq!(read_full_at(&file, &mut [], 0).unwrap(), 0);
        assert_eq!(read_full_at(&file, &mut buf, 0).unwrap(), 4);
        assert_eq!(&buf, b"0123");
    }

    #[tokio::test]
    async fn a_file_body_reads_its_range_in_pieces() {
        let contents = pattern(BODY_CHUNK * 3 + 1000);
        let (offset, len) = (123, BODY_CHUNK * 2 + 77);
        let wanted = &contents[offset..offset + len];
        let file = file_with(&contents);
        let (mut body, fault) = open(&file, offset as u64, len as u64, &sha(wanted));
        assert_eq!(body.remaining(), len as u64);

        let (pieces, failed) = drain(&mut body).await;
        assert!(!failed);
        let sizes: Vec<_> = pieces.iter().map(Bytes::len).collect();
        assert_eq!(sizes, [BODY_CHUNK, BODY_CHUNK, 77]);
        assert_eq!(pieces.concat(), wanted);
        assert_eq!(body.remaining(), 0);
        assert!(fault.get().is_none());
    }

    #[tokio::test]
    async fn the_hash_of_a_single_piece_is_checked_too() {
        let file = file_with(b"0123456789");
        let (mut body, fault) = open(&file, 2, 5, &sha(b"23456"));
        let (pieces, failed) = drain(&mut body).await;
        assert!(!failed);
        assert_eq!(pieces.concat(), b"23456");
        assert!(fault.get().is_none());

        let (mut body, fault) = open(&file, 2, 5, &sha(b"23457"));
        let (pieces, failed) = drain(&mut body).await;
        assert!(pieces.is_empty() && failed);
        assert!(matches!(fault.get(), Some(S3Error::SourceChanged)));
    }

    #[tokio::test]
    async fn a_file_that_changed_fails_the_body_before_its_last_piece() {
        let contents = pattern(BODY_CHUNK * 2 + 10);
        let file = file_with(&contents);
        let (mut body, fault) = open(&file, 0, contents.len() as u64, &sha(&contents));
        // Only the last bytes differ, so the first pieces look right.
        overwrite(&file, contents.len() as u64 - 7, b"changed");
        let (pieces, failed) = drain(&mut body).await;
        assert_eq!(pieces.len(), 2, "the last piece is held back");
        assert!(failed);
        assert!(matches!(fault.get(), Some(S3Error::SourceChanged)));
        let (more, failed) = drain(&mut body).await;
        assert!(more.is_empty() && failed, "a failed body stays failed");
    }

    #[tokio::test]
    async fn a_file_that_became_shorter_fails_the_body() {
        let contents = pattern(BODY_CHUNK + 500);
        let file = file_with(&contents);
        let (mut body, fault) = open(&file, 0, contents.len() as u64, &sha(&contents));
        file.set_len(BODY_CHUNK as u64 + 100).unwrap();
        let (pieces, failed) = drain(&mut body).await;
        assert_eq!(pieces.len(), 1);
        assert!(failed);
        assert!(matches!(fault.get(), Some(S3Error::SourceChanged)));
    }
}
