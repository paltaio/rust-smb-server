//! Reads of file data.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::oneshot;
use tokio::time::timeout_at;
use tracing::debug;

use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::data::{disk_error, read_full_at};
use super::entry::{Base, Entry};
use super::error::S3Error;
use super::object::{ByteRange, ObjectHead};
use super::readahead::{Claim, Outcome, ReadAhead, Version, assemble, extent, span};
use super::retry::Retry;

/// What a read of an entry is made of.
enum Plan {
    /// Nothing: the read is of no bytes or past the end.
    Empty,
    /// The object of the base, which the entry has no local data over.
    Base { key: String, head: Arc<ObjectHead> },
    /// Pieces of local data and of the base, in order.
    Local {
        file: Arc<File>,
        base: Option<(String, Arc<ObjectHead>)>,
        pieces: Vec<(Range<u64>, bool)>,
    },
}

impl Entry {
    fn plan(&self, offset: u64, len: u32) -> Plan {
        let state = self.state();
        let size = state.size();
        if len == 0 || offset >= size {
            return Plan::Empty;
        }
        let base = state
            .base
            .as_ref()
            .map(|base| (base.key.clone(), Arc::clone(&base.head)));
        match state.local() {
            None => match base {
                Some((key, head)) => Plan::Base { key, head },
                None => Plan::Empty,
            },
            Some(local) => {
                let end = offset.saturating_add(u64::from(len)).min(local.len);
                Plan::Local {
                    file: Arc::clone(&local.file),
                    base,
                    pieces: local.present.segments(offset..end),
                }
            }
        }
    }

    /// Reads from `head` from now on, if the entry has no local data.
    fn follow_head(&self, ahead: &Arc<ReadAhead>, head: Arc<ObjectHead>) {
        let mut state = self.state();
        if state.local().is_some() {
            return;
        }
        if let Some(base) = state.base.take() {
            // The new pin is taken before the old one ends, so a version
            // that stays is never unpinned and the chunks other reads have
            // in flight for it are still kept.
            state.base = Some(Base::new(ahead, base.key, head, true));
        }
    }

    /// Reads up to `len` bytes at `offset`. The bytes of local data come from
    /// its file, and the others from the object of the base, all of one
    /// version.
    ///
    /// A read of an entry without local data that finds its object changed or
    /// gone drops the chunks kept of it, asks the store for the object as it
    /// is, and reads again from that, once. With local data, the base
    /// changing fails the read: the bytes of the entry are not those of the
    /// new object.
    pub(super) async fn read(&self, shared: &Shared, offset: u64, len: u32) -> SmbResult<Bytes> {
        let retry = shared.retry();
        let mut refreshed = false;
        loop {
            let (key, head) = match self.plan(offset, len) {
                Plan::Empty => return Ok(Bytes::new()),
                Plan::Local { file, base, pieces } => {
                    return self.read_local(shared, &file, base, &pieces, &retry).await;
                }
                Plan::Base { key, head } => (key, head),
            };
            let error = match shared.fetch_version(&key, &head, offset, len, &retry).await {
                Fetched::Data(data) => return Ok(data),
                Fetched::Failed(e) => return Err(e),
                Fetched::Changed(error) => error,
            };
            if refreshed {
                shared.forget_file(&key);
                return Err(error.into_smb_error());
            }
            debug!("an object changed after it was opened");
            let head = shared
                .refresh(&key, &retry)
                .await
                .map_err(S3Error::into_smb_error)?;
            self.follow_head(&shared.ahead, head);
            refreshed = true;
        }
    }

    async fn read_local(
        &self,
        shared: &Shared,
        file: &Arc<File>,
        base: Option<(String, Arc<ObjectHead>)>,
        pieces: &[(Range<u64>, bool)],
        retry: &Retry,
    ) -> SmbResult<Bytes> {
        let from_file: Vec<Range<u64>> = pieces
            .iter()
            .filter(|(_, present)| *present)
            .map(|(range, _)| range.clone())
            .collect();
        let mut present = if from_file.is_empty() {
            Vec::new()
        } else {
            let file = Arc::clone(file);
            tokio::task::spawn_blocking(move || {
                from_file
                    .into_iter()
                    .map(|range| {
                        let mut bytes = vec![0; (range.end - range.start) as usize];
                        read_full_at(&file, &mut bytes, range.start).map(|()| bytes)
                    })
                    .collect::<io::Result<Vec<Vec<u8>>>>()
            })
            .await
            .map_err(|e| SmbError::Io(io::Error::other(e)))?
            .map_err(disk_error)?
        }
        .into_iter();

        let total: u64 = pieces
            .iter()
            .map(|(range, _)| range.end - range.start)
            .sum();
        let mut out = Vec::with_capacity(usize::try_from(total).unwrap_or_default());
        for (range, is_present) in pieces {
            if *is_present {
                out.extend_from_slice(&present.next().unwrap_or_default());
                continue;
            }
            let Some((key, head)) = &base else {
                // No object lies under the missing bytes.
                out.resize(out.len() + (range.end - range.start) as usize, 0);
                continue;
            };
            let len =
                u32::try_from(range.end - range.start).map_err(|_| SmbError::InvalidParameter)?;
            match shared
                .fetch_version(key, head, range.start, len, retry)
                .await
            {
                Fetched::Data(data) => {
                    out.extend_from_slice(&data);
                    // The object may end before the entry does.
                    out.resize(out.len() + (len as usize).saturating_sub(data.len()), 0);
                }
                Fetched::Failed(e) => return Err(e),
                Fetched::Changed(_) => {
                    debug!("the object under an entry changed after it was opened");
                    shared.forget_file(key);
                    return Err(SmbError::Io(io::Error::other(
                        "the object changed after it was opened",
                    )));
                }
            }
        }
        Ok(Bytes::from(out))
    }
}

/// How a read of one version of an object ended.
enum Fetched {
    Data(Bytes),
    /// The object is not that version any more: it has another ETag or is
    /// gone. The chunks kept of the version are dropped.
    Changed(S3Error),
    Failed(SmbError),
}

/// Whether `error` says the object is not the version that was read: another
/// ETag, or no object.
fn is_changed(error: &S3Error) -> bool {
    error.is_precondition_failed() || error.is_no_such_key()
}

/// The error for an answer that is not about the version asked for.
fn changed() -> S3Error {
    S3Error::status(412, Some("PreconditionFailed"), None)
}

impl Shared {
    /// Up to `len` bytes at `offset` of the version of the object at `key`
    /// that `head` describes. A read of an object without an ETag that finds
    /// it changed ends as `Failed`, not `Changed`.
    async fn fetch_version(
        &self,
        key: &str,
        head: &ObjectHead,
        offset: u64,
        len: u32,
        retry: &Retry,
    ) -> Fetched {
        let Some(version) = Version::of(key, head) else {
            return match self.read_unversioned(key, head, offset, len, retry).await {
                Ok(data) => Fetched::Data(data),
                Err(e) => Fetched::Failed(e),
            };
        };
        match self.read_chunked(&version, offset, len, retry).await {
            Ok(data) => Fetched::Data(data),
            Err(error) if is_changed(&error) => {
                self.ahead.drop_version(&version);
                Fetched::Changed(error)
            }
            Err(error) => Fetched::Failed(error.into_smb_error()),
        }
    }

    /// The bytes `offset..offset + len` of the object at `version`, as far as
    /// it reaches. They come from its chunks. Each chunk not kept is requested
    /// with an `If-Match` for the ETag, and an object with another one fails
    /// the read as a failed precondition.
    async fn read_chunked(
        &self,
        version: &Version,
        offset: u64,
        len: u32,
        retry: &Retry,
    ) -> Result<Bytes, S3Error> {
        let size = version.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(u64::from(len)).min(size);
        let mut parts = Vec::new();
        for index in span(self.read_chunk, offset, end) {
            parts.push(self.chunk(version, index, retry).await?);
        }
        Ok(assemble(self.read_chunk, offset, end, &parts))
    }

    /// The chunk `index` of the object at `version`: kept, brought by another
    /// reader, or requested.
    async fn chunk(&self, version: &Version, index: u64, retry: &Retry) -> Result<Bytes, S3Error> {
        let (start, len) = extent(self.read_chunk, index, version.size);
        loop {
            match self.ahead.claim(version, index) {
                Claim::Held(data) => return Ok(data),
                Claim::Wait(done) => {
                    if let Some(outcome) = wait(done, retry).await? {
                        return outcome;
                    }
                }
                Claim::Fetch(fetch) => {
                    let outcome = self.fetch(version, start, len, retry).await;
                    fetch.finish(outcome.clone());
                    return outcome;
                }
            }
        }
    }

    async fn fetch(&self, version: &Version, start: u64, len: u64, retry: &Retry) -> Outcome {
        let range = ByteRange::new(start, len)?;
        let object = self
            .client
            .get_object(&version.key, range, Some(&version.etag), retry.clone())
            .await?;
        if object.data.len() as u64 != len {
            return Err(changed());
        }
        Ok(object.data)
    }

    /// Up to `len` bytes at `offset` of an object without an ETag, which
    /// `head` describes. Nothing ties a read to a version of such an object,
    /// and no chunk is kept: the bytes are requested as asked for, and a read
    /// fails if the answer has another size or modification time, or an ETag.
    async fn read_unversioned(
        &self,
        key: &str,
        head: &ObjectHead,
        offset: u64,
        len: u32,
        retry: &Retry,
    ) -> SmbResult<Bytes> {
        if len == 0 || offset >= head.size {
            return Ok(Bytes::new());
        }
        let range = ByteRange::new(offset, u64::from(len).min(head.size - offset))
            .map_err(S3Error::into_smb_error)?;
        match self
            .client
            .get_object(key, range, None, retry.clone())
            .await
        {
            Ok(object) if same_version(&object.head, head) => Ok(object.data),
            Ok(_) => {
                debug!("an object without an ETag changed after it was opened");
                self.forget_file(key);
                Err(SmbError::Io(io::Error::other(
                    "the object changed after it was opened",
                )))
            }
            Err(e) => {
                if is_changed(&e) {
                    self.forget_file(key);
                }
                Err(e.into_smb_error())
            }
        }
    }

    /// Asks the store for the object at `key`, which a read found changed,
    /// and drops what is cached of it and of its directory. The next lookup
    /// of the name resolves it again, which also looks for a directory.
    async fn refresh(&self, key: &str, retry: &Retry) -> Result<Arc<ObjectHead>, S3Error> {
        self.forget_file(key);
        self.client
            .head_object(key, retry.clone())
            .await
            .map(Arc::new)
    }
}

/// The outcome of the fetch another reader makes, or `None` if that reader
/// gave up, ran out of time, or failed in a way trying again can fix. Fails
/// when `retry` runs out of time first.
async fn wait(done: oneshot::Receiver<Outcome>, retry: &Retry) -> Result<Option<Outcome>, S3Error> {
    let outcome = match retry.deadline() {
        Some(deadline) => timeout_at(deadline, done)
            .await
            .map_err(|_| S3Error::DeadlineExceeded)?,
        None => done.await,
    };
    Ok(outcome.ok())
}

/// Whether the object a GET returned is the one that was opened, going by its
/// size, modification time and ETag.
fn same_version(got: &ObjectHead, opened: &ObjectHead) -> bool {
    got.size == opened.size && got.last_modified == opened.last_modified && got.etag == opened.etag
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_waiter_stops_at_its_own_deadline() {
        let (_fetcher, done) = oneshot::channel::<Outcome>();
        let retry = Retry::within(Duration::from_secs(5));
        let started = tokio::time::Instant::now();
        let outcome = wait(done, &retry).await;
        assert!(matches!(outcome, Err(S3Error::DeadlineExceeded)));
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiter_gets_the_outcome_or_learns_the_fetcher_gave_up() {
        let retry = Retry::within(Duration::from_secs(5));
        let (fetcher, done) = oneshot::channel::<Outcome>();
        let _ = fetcher.send(Ok(Bytes::from_static(b"abc")));
        assert_eq!(wait(done, &retry).await.unwrap().unwrap().unwrap(), "abc");
        let (fetcher, done) = oneshot::channel::<Outcome>();
        drop(fetcher);
        assert!(wait(done, &retry).await.unwrap().is_none());
    }
}
