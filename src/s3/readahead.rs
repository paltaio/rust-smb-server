//! Chunks of object data kept for the reads that follow, and the requests
//! that fetch them.

use std::collections::{BTreeMap, HashMap};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::{Bytes, BytesMut};
use tokio::sync::oneshot;

use super::error::S3Error;
use super::object::ObjectHead;

/// Most chunks kept of one version of an object.
const VERSION_CHUNKS: usize = 4;

/// Most bytes of chunks kept over all versions. Chunks being fetched and the
/// replies being sent are not counted.
const KEPT_BYTES: usize = 128 << 20;

/// Smallest and largest chunk the backend reads.
pub(super) const MIN_CHUNK: u32 = 64 << 10;
pub(super) const MAX_CHUNK: u32 = 32 << 20;

const _: () = assert!(MAX_CHUNK as usize * VERSION_CHUNKS <= KEPT_BYTES);

/// An object as one ETag and size describe it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct Version {
    pub(super) key: String,
    pub(super) etag: String,
    pub(super) size: u64,
}

impl Version {
    /// The version of the object at `key` that `head` describes, or none if
    /// it has no ETag.
    pub(super) fn of(key: &str, head: &ObjectHead) -> Option<Version> {
        (!head.etag.is_empty()).then(|| Version {
            key: key.to_owned(),
            etag: head.etag.clone(),
            size: head.size,
        })
    }
}

/// How a request for a chunk ended: with its bytes, or with an error.
pub(super) type Outcome = Result<Bytes, S3Error>;

/// What a reader of a chunk does next.
pub(super) enum Claim<'a> {
    /// The chunk is kept.
    Held(Bytes),
    /// Another reader is fetching it and its outcome arrives here. The
    /// channel closes without one when that reader gives up, runs out of
    /// time, or fails in a way trying again can fix.
    Wait(oneshot::Receiver<Outcome>),
    /// Nobody is fetching it: the caller does.
    Fetch(Fetch<'a>),
}

/// The right to fetch a chunk that others wait for. Dropping it without
/// [`finish`](Self::finish) lets the readers that wait claim the chunk again.
pub(super) struct Fetch<'a> {
    ahead: &'a ReadAhead,
    version: &'a Version,
    index: u64,
    open: bool,
}

impl Fetch<'_> {
    /// Keeps the chunk a successful `outcome` brings, and hands `outcome` to
    /// the readers that wait. A fetch that runs out of time, or fails in a way
    /// trying again can fix, hands them nothing: they claim the chunk again
    /// under their own deadlines.
    pub(super) fn finish(mut self, outcome: Outcome) {
        self.open = false;
        self.ahead
            .chunks()
            .finish(self.version, self.index, outcome);
    }
}

impl Drop for Fetch<'_> {
    fn drop(&mut self) {
        if self.open {
            self.ahead.chunks().abandon(self.version, self.index);
        }
    }
}

/// The chunks of object versions that reads fetched, shared by every handle.
/// The chunks of a version are kept while a [`Pin`] on it exists.
pub(super) struct ReadAhead {
    chunks: Mutex<Chunks>,
}

impl ReadAhead {
    pub(super) fn new() -> Self {
        ReadAhead {
            chunks: Mutex::new(Chunks::with_limits(VERSION_CHUNKS, KEPT_BYTES)),
        }
    }

    /// The chunks. Never held across an await.
    fn chunks(&self) -> MutexGuard<'_, Chunks> {
        self.chunks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Pins `version`: its chunks are kept until the last pin on it ends.
    pub(super) fn pin(self: &Arc<Self>, version: Version) -> Pin {
        self.chunks().pin(&version);
        Pin {
            ahead: Arc::clone(self),
            version,
        }
    }

    /// How a reader gets the chunk `index` of `version`.
    pub(super) fn claim<'a>(&'a self, version: &'a Version, index: u64) -> Claim<'a> {
        let mut chunks = self.chunks();
        if let Some(data) = chunks.touch(version, index) {
            return Claim::Held(data);
        }
        let key = (version.clone(), index);
        if let Some(waiting) = chunks.fetching.get_mut(&key) {
            let (send, receive) = oneshot::channel();
            waiting.push(send);
            return Claim::Wait(receive);
        }
        chunks.fetching.insert(key, Vec::new());
        Claim::Fetch(Fetch {
            ahead: self,
            version,
            index,
            open: true,
        })
    }

    /// Drops every chunk of `version`.
    pub(super) fn drop_version(&self, version: &Version) {
        self.chunks().drop_version(version);
    }

    /// Bounds the chunks kept and drops the ones held.
    #[cfg(test)]
    pub(super) fn limit(&self, per_version: usize, cap: usize) {
        self.chunks().limit(per_version, cap);
    }

    /// The bytes of chunks kept.
    #[cfg(test)]
    pub(super) fn held(&self) -> usize {
        self.chunks().held
    }

    /// The readers that wait for a chunk being fetched.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        self.chunks().fetching.values().map(Vec::len).sum()
    }
}

/// The hold of an open file on the version of the object it reads. The last
/// pin on a version to end drops its chunks.
pub(super) struct Pin {
    ahead: Arc<ReadAhead>,
    version: Version,
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.ahead.chunks().unpin(&self.version);
    }
}

struct Slot {
    data: Bytes,
    /// The clock when the chunk was last used.
    tick: u64,
}

/// The chunks kept and the chunks being fetched. Keeping a chunk drops the
/// least recently used ones until a version has at most `per_version` and all
/// versions together at most `cap` bytes.
struct Chunks {
    per_version: usize,
    cap: usize,
    held: usize,
    clock: u64,
    /// The pins on each version.
    pins: HashMap<Version, usize>,
    versions: HashMap<Version, HashMap<u64, Slot>>,
    /// Every chunk kept, by the tick of its last use.
    order: BTreeMap<u64, (Version, u64)>,
    /// The readers that wait for each chunk being fetched.
    fetching: HashMap<(Version, u64), Vec<oneshot::Sender<Outcome>>>,
}

impl Chunks {
    fn with_limits(per_version: usize, cap: usize) -> Self {
        Chunks {
            per_version,
            cap,
            held: 0,
            clock: 0,
            pins: HashMap::new(),
            versions: HashMap::new(),
            order: BTreeMap::new(),
            fetching: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn limit(&mut self, per_version: usize, cap: usize) {
        self.per_version = per_version;
        self.cap = cap;
        self.versions.clear();
        self.order.clear();
        self.held = 0;
    }

    fn pin(&mut self, version: &Version) {
        *self.pins.entry(version.clone()).or_default() += 1;
    }

    /// Ends a pin on `version`, and drops its chunks if it was the last.
    fn unpin(&mut self, version: &Version) {
        let Some(count) = self.pins.get_mut(version) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            self.pins.remove(version);
            self.drop_version(version);
        }
    }

    /// Ends the fetch of a chunk. A successful `outcome` is kept if the
    /// version is pinned. The readers that waited get `outcome`, unless it
    /// says the fetcher ran out of time or failed in a way trying again can
    /// fix: they find their channels closed.
    fn finish(&mut self, version: &Version, index: u64, outcome: Outcome) {
        if let Ok(data) = &outcome {
            self.insert(version, index, data.clone());
        }
        let Some(waiting) = self.fetching.remove(&(version.clone(), index)) else {
            return;
        };
        if let Err(error) = &outcome
            && (matches!(error, S3Error::DeadlineExceeded) || error.is_transient())
        {
            return;
        }
        for reader in waiting {
            // A reader that gave up has dropped its end.
            let _ = reader.send(outcome.clone());
        }
    }

    /// Ends the fetch of a chunk that brought nothing. The readers that
    /// waited find their channels closed.
    fn abandon(&mut self, version: &Version, index: u64) {
        self.fetching.remove(&(version.clone(), index));
    }

    fn drop_version(&mut self, version: &Version) {
        let Some(slots) = self.versions.remove(version) else {
            return;
        };
        for slot in slots.values() {
            self.order.remove(&slot.tick);
            self.held -= slot.data.len();
        }
    }

    /// The chunk, which counts as used.
    fn touch(&mut self, version: &Version, index: u64) -> Option<Bytes> {
        let tick = self.clock;
        let slot = self.versions.get_mut(version)?.get_mut(&index)?;
        let old = std::mem::replace(&mut slot.tick, tick);
        let data = slot.data.clone();
        self.clock += 1;
        if let Some(entry) = self.order.remove(&old) {
            self.order.insert(tick, entry);
        }
        Some(data)
    }

    /// Keeps a chunk of a pinned version after dropping the chunks that leave
    /// no room for it. A chunk larger than the cap is not kept.
    fn insert(&mut self, version: &Version, index: u64, data: Bytes) {
        if data.len() > self.cap || !self.pins.contains_key(version) {
            return;
        }
        while self
            .versions
            .get(version)
            .is_some_and(|slots| slots.len() >= self.per_version)
        {
            let Some(oldest) = self.oldest_of(version) else {
                break;
            };
            self.remove(version, oldest);
        }
        while self.held + data.len() > self.cap {
            let Some((_, (other, index))) = self.order.pop_first() else {
                break;
            };
            self.detach(&other, index);
        }
        let tick = self.clock;
        self.clock += 1;
        self.held += data.len();
        self.order.insert(tick, (version.clone(), index));
        self.versions
            .entry(version.clone())
            .or_default()
            .insert(index, Slot { data, tick });
    }

    fn oldest_of(&self, version: &Version) -> Option<u64> {
        self.versions
            .get(version)?
            .iter()
            .min_by_key(|(_, slot)| slot.tick)
            .map(|(index, _)| *index)
    }

    fn remove(&mut self, version: &Version, index: u64) {
        if let Some(slot) = self.detach(version, index) {
            self.order.remove(&slot.tick);
        }
    }

    /// Takes a chunk out of its version and the bytes it held out of the
    /// count. Its place in the order of use is the caller's to remove.
    fn detach(&mut self, version: &Version, index: u64) -> Option<Slot> {
        let slots = self.versions.get_mut(version)?;
        let slot = slots.remove(&index)?;
        if slots.is_empty() {
            self.versions.remove(version);
        }
        self.held -= slot.data.len();
        Some(slot)
    }
}

/// The indexes of the chunks of `chunk` bytes that hold the bytes
/// `offset..end`, a range that is not empty.
pub(super) fn span(chunk: u64, offset: u64, end: u64) -> RangeInclusive<u64> {
    offset / chunk..=(end - 1) / chunk
}

/// Where the chunk `index` of an object of `size` bytes starts and how long
/// it is. Only the last chunk can be shorter than `chunk`.
pub(super) fn extent(chunk: u64, index: u64, size: u64) -> (u64, u64) {
    let start = index * chunk;
    (start, chunk.min(size - start))
}

/// The bytes `offset..end` out of `parts`: the chunks [`span`] names for the
/// range, in order, each as long as [`extent`] says.
pub(super) fn assemble(chunk: u64, offset: u64, end: u64, parts: &[Bytes]) -> Bytes {
    let mut pieces = parts.iter().zip(offset / chunk..).map(|(data, index)| {
        let start = index * chunk;
        let low = offset.max(start) - start;
        let high = end.min(start.saturating_add(chunk)) - start;
        data.slice(low as usize..high as usize)
    });
    let Some(first) = pieces.next() else {
        return Bytes::new();
    };
    let Some(second) = pieces.next() else {
        // A copy does not keep the whole chunk alive.
        return if first.len() < parts[0].len() {
            Bytes::copy_from_slice(&first)
        } else {
            first
        };
    };
    let mut out = BytesMut::with_capacity((end - offset) as usize);
    out.extend_from_slice(&first);
    out.extend_from_slice(&second);
    for piece in pieces {
        out.extend_from_slice(&piece);
    }
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ahead(per_version: usize, cap: usize) -> Arc<ReadAhead> {
        let ahead = Arc::new(ReadAhead::new());
        ahead.limit(per_version, cap);
        ahead
    }

    fn version_of(key: &str, etag: &str) -> Version {
        Version {
            key: key.to_owned(),
            etag: etag.to_owned(),
            size: 1000,
        }
    }

    /// A version of the object `key` that stays pinned.
    fn version(ahead: &ReadAhead, key: &str) -> Version {
        let version = version_of(key, "\"e\"");
        ahead.chunks().pin(&version);
        version
    }

    fn bytes(len: usize, fill: u8) -> Bytes {
        Bytes::from(vec![fill; len])
    }

    /// Claims the chunk and keeps `data` as its fetch does.
    fn fetched(ahead: &ReadAhead, version: &Version, index: u64, data: Bytes) {
        let Claim::Fetch(fetch) = ahead.claim(version, index) else {
            panic!("chunk {index} of {} is held or being fetched", version.key);
        };
        fetch.finish(Ok(data));
    }

    /// Whether the chunk is kept. A chunk that is not is claimed and given
    /// back, so the next claim fetches it.
    fn is_held(ahead: &ReadAhead, version: &Version, index: u64) -> bool {
        matches!(ahead.claim(version, index), Claim::Held(_))
    }

    fn kept(ahead: &ReadAhead) -> usize {
        ahead.chunks().versions.values().map(HashMap::len).sum()
    }

    #[test]
    fn a_range_is_held_by_the_chunks_it_touches() {
        assert_eq!(span(10, 0, 1), 0..=0);
        assert_eq!(span(10, 0, 10), 0..=0);
        assert_eq!(span(10, 9, 11), 0..=1);
        assert_eq!(span(10, 10, 11), 1..=1);
        assert_eq!(span(10, 5, 35), 0..=3);
        assert_eq!(span(10, 30, 40), 3..=3);
        assert_eq!(span(1, 4, 7), 4..=6);
    }

    #[test]
    fn the_last_chunk_is_as_long_as_the_object_leaves() {
        assert_eq!(extent(10, 0, 25), (0, 10));
        assert_eq!(extent(10, 1, 25), (10, 10));
        assert_eq!(extent(10, 2, 25), (20, 5));
        assert_eq!(extent(10, 2, 21), (20, 1));
        assert_eq!(extent(10, 1, 20), (10, 10));
        assert_eq!(extent(10, 0, 3), (0, 3));
    }

    /// An object of `size` bytes whose byte `n` is `n % 251`.
    fn object(size: u64) -> Vec<u8> {
        (0..size).map(|n| (n % 251) as u8).collect()
    }

    /// The bytes `offset..end` of `data`, assembled from its chunks.
    fn read(chunk: u64, data: &[u8], offset: u64, end: u64) -> Bytes {
        let size = data.len() as u64;
        let parts: Vec<Bytes> = span(chunk, offset, end)
            .map(|index| {
                let (start, len) = extent(chunk, index, size);
                Bytes::copy_from_slice(&data[start as usize..(start + len) as usize])
            })
            .collect();
        assemble(chunk, offset, end, &parts)
    }

    #[test]
    fn a_read_is_assembled_from_the_chunks_it_spans() {
        let data = object(95);
        for chunk in [1, 7, 10, 32, 95, 200] {
            for offset in 0..95 {
                for end in (offset + 1)..=95 {
                    assert_eq!(
                        read(chunk, &data, offset, end),
                        &data[offset as usize..end as usize],
                        "chunk {chunk} offset {offset} end {end}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_read_at_the_end_of_an_object_of_nearly_u64_max_bytes_assembles() {
        let size = u64::MAX - 1;
        for chunk in [10, 16, 64 << 10] {
            for offset in [size - 1, size - 5, size - chunk - 5] {
                let parts: Vec<Bytes> = span(chunk, offset, size)
                    .map(|index| bytes(usize::try_from(extent(chunk, index, size).1).unwrap(), 1))
                    .collect();
                let got = assemble(chunk, offset, size, &parts);
                assert_eq!(got.len() as u64, size - offset, "chunk {chunk} at {offset}");
            }
        }
    }

    #[test]
    fn a_read_inside_one_chunk_is_copied_out_of_it() {
        let chunk = Bytes::from((0..100).collect::<Vec<u8>>());
        let got = assemble(100, 110, 150, std::slice::from_ref(&chunk));
        assert_eq!(got, &chunk[10..50]);
        assert_ne!(
            got.as_ptr(),
            chunk[10..].as_ptr(),
            "the reply has its own bytes"
        );
    }

    #[test]
    fn a_read_of_a_whole_chunk_is_the_chunk() {
        let chunk = Bytes::from((0..100).collect::<Vec<u8>>());
        let got = assemble(100, 100, 200, std::slice::from_ref(&chunk));
        assert_eq!(got.as_ptr(), chunk.as_ptr());
        let last = chunk.slice(..30);
        let got = assemble(100, 200, 230, std::slice::from_ref(&last));
        assert_eq!(got.as_ptr(), last.as_ptr(), "the last chunk, in whole");
    }

    #[test]
    fn a_chunk_is_kept_once_its_fetch_finishes() {
        let ahead = ahead(4, 1000);
        let v = version(&ahead, "a");
        let Claim::Fetch(fetch) = ahead.claim(&v, 0) else {
            panic!("not a fetch");
        };
        assert_eq!(ahead.held(), 0);
        fetch.finish(Ok(bytes(10, 1)));
        assert_eq!(ahead.held(), 10);
        match ahead.claim(&v, 0) {
            Claim::Held(data) => assert_eq!(data, bytes(10, 1)),
            _ => panic!("not held"),
        }
        assert!(!is_held(&ahead, &v, 1));
        assert!(!is_held(&ahead, &version(&ahead, "b"), 0));
        let other_etag = version_of("a", "\"f\"");
        assert!(!is_held(&ahead, &other_etag, 0));
    }

    #[test]
    fn a_version_keeps_its_most_recently_used_chunks() {
        let ahead = ahead(3, 1000);
        let v = version(&ahead, "a");
        for index in 0..3 {
            fetched(&ahead, &v, index, bytes(10, index as u8));
        }
        assert!(is_held(&ahead, &v, 0), "0 is used again");
        fetched(&ahead, &v, 3, bytes(10, 3));
        assert_eq!(ahead.held(), 30);
        assert!(is_held(&ahead, &v, 0));
        assert!(is_held(&ahead, &v, 2));
        assert!(is_held(&ahead, &v, 3));
        assert!(!is_held(&ahead, &v, 1), "1 was the least recently used");
    }

    #[test]
    fn a_version_over_its_chunks_does_not_push_out_another() {
        let ahead = ahead(2, 1000);
        let (a, b) = (version(&ahead, "a"), version(&ahead, "b"));
        fetched(&ahead, &b, 0, bytes(10, 9));
        for index in 0..5 {
            fetched(&ahead, &a, index, bytes(10, 1));
        }
        assert_eq!(ahead.held(), 30);
        assert_eq!(kept(&ahead), 3);
        assert!(is_held(&ahead, &b, 0));
        assert!(is_held(&ahead, &a, 3));
        assert!(is_held(&ahead, &a, 4));
    }

    #[test]
    fn the_least_recently_used_chunk_of_all_goes_when_the_cap_is_reached() {
        let ahead = ahead(4, 50);
        let (a, b, c) = (
            version(&ahead, "a"),
            version(&ahead, "b"),
            version(&ahead, "c"),
        );
        fetched(&ahead, &a, 0, bytes(20, 1));
        fetched(&ahead, &b, 0, bytes(20, 2));
        assert_eq!(ahead.held(), 40);
        assert!(is_held(&ahead, &a, 0), "a is used after b");
        fetched(&ahead, &c, 0, bytes(20, 3));
        assert_eq!(ahead.held(), 40);
        assert!(is_held(&ahead, &a, 0));
        assert!(is_held(&ahead, &c, 0));
        assert!(!is_held(&ahead, &b, 0), "b was the least recently used");
        assert!(!ahead.chunks().versions.contains_key(&b));
    }

    #[test]
    fn the_bytes_kept_never_exceed_the_cap() {
        let cap = 50;
        let ahead = ahead(3, cap);
        for n in 0..300u64 {
            let v = version(&ahead, &format!("k{}", n * 7 % 11));
            let len = 1 + (n * 13 % 23) as usize;
            if let Claim::Fetch(fetch) = ahead.claim(&v, n % 4) {
                fetch.finish(Ok(bytes(len, 0)));
            }
            let chunks = ahead.chunks();
            assert!(chunks.held <= cap, "{}", chunks.held);
            let counted: usize = chunks
                .versions
                .values()
                .flat_map(HashMap::values)
                .map(|slot| slot.data.len())
                .sum();
            assert_eq!(counted, chunks.held);
            assert_eq!(
                chunks.order.len(),
                chunks.versions.values().map(HashMap::len).sum()
            );
            assert!(
                chunks
                    .versions
                    .values()
                    .all(|slots| (1..=3).contains(&slots.len()))
            );
        }
    }

    #[test]
    fn a_chunk_over_the_cap_is_not_kept() {
        let ahead = ahead(4, 50);
        let v = version(&ahead, "a");
        fetched(&ahead, &v, 0, bytes(30, 1));
        fetched(&ahead, &v, 1, bytes(60, 2));
        assert_eq!(ahead.held(), 30);
        assert_eq!(ahead.chunks().order.len(), 1);
        assert!(is_held(&ahead, &v, 0));
        assert!(!is_held(&ahead, &v, 1));
    }

    #[test]
    fn a_dropped_version_leaves_no_chunk_behind() {
        let ahead = ahead(4, 1000);
        let (a, b) = (version(&ahead, "a"), version(&ahead, "b"));
        for index in 0..3 {
            fetched(&ahead, &a, index, bytes(10, 1));
        }
        fetched(&ahead, &b, 0, bytes(5, 2));
        ahead.drop_version(&a);
        assert_eq!(ahead.held(), 5);
        assert_eq!(ahead.chunks().order.len(), 1);
        assert!(!is_held(&ahead, &a, 0));
        assert!(is_held(&ahead, &b, 0));
        ahead.drop_version(&version_of("unknown", "\"e\""));
        assert_eq!(ahead.held(), 5);
    }

    #[test]
    fn the_chunks_of_a_version_are_dropped_with_the_last_pin_on_it() {
        let ahead = ahead(4, 1000);
        let (a, b) = (version_of("a", "\"e\""), version_of("b", "\"e\""));
        let (first, second, other) = (
            ahead.pin(a.clone()),
            ahead.pin(a.clone()),
            ahead.pin(b.clone()),
        );
        fetched(&ahead, &a, 0, bytes(10, 1));
        fetched(&ahead, &a, 1, bytes(10, 1));
        fetched(&ahead, &b, 0, bytes(5, 2));
        assert_eq!(ahead.held(), 25);

        drop(first);
        assert_eq!(ahead.held(), 25, "another pin on the version remains");
        assert!(is_held(&ahead, &a, 1));
        drop(second);
        assert_eq!(ahead.held(), 5);
        assert!(!is_held(&ahead, &a, 0));
        assert!(is_held(&ahead, &b, 0));
        {
            let chunks = ahead.chunks();
            assert!(!chunks.versions.contains_key(&a));
            assert!(!chunks.pins.contains_key(&a));
            assert_eq!(chunks.order.len(), 1);
        }
        drop(other);
        assert_eq!(ahead.held(), 0);
        assert!(ahead.chunks().pins.is_empty());
    }

    #[test]
    fn a_chunk_fetched_for_a_version_no_pin_is_left_on_is_not_kept() {
        let ahead = ahead(4, 1000);
        let v = version_of("a", "\"e\"");
        let pin = ahead.pin(v.clone());
        let Claim::Fetch(fetch) = ahead.claim(&v, 0) else {
            panic!("not a fetch");
        };
        let Claim::Wait(mut waiting) = ahead.claim(&v, 0) else {
            panic!("not waiting");
        };
        drop(pin);
        fetch.finish(Ok(bytes(10, 1)));
        assert_eq!(waiting.try_recv().unwrap().unwrap(), bytes(10, 1));
        assert_eq!(ahead.held(), 0);
        assert_eq!(kept(&ahead), 0);
    }

    #[test]
    fn readers_of_a_chunk_being_fetched_wait_for_its_outcome() {
        let ahead = ahead(4, 1000);
        let v = version(&ahead, "a");
        let Claim::Fetch(fetch) = ahead.claim(&v, 0) else {
            panic!("not a fetch");
        };
        let Claim::Wait(mut first) = ahead.claim(&v, 0) else {
            panic!("not waiting");
        };
        let Claim::Wait(mut second) = ahead.claim(&v, 0) else {
            panic!("not waiting");
        };
        assert_eq!(ahead.waiting(), 2);
        assert!(
            matches!(ahead.claim(&v, 1), Claim::Fetch(_)),
            "another chunk is not being fetched"
        );
        assert!(first.try_recv().is_err());
        fetch.finish(Ok(bytes(10, 4)));
        assert_eq!(first.try_recv().unwrap().unwrap(), bytes(10, 4));
        assert_eq!(second.try_recv().unwrap().unwrap(), bytes(10, 4));
        assert_eq!(ahead.waiting(), 0);
        assert!(is_held(&ahead, &v, 0));
    }

    /// Finishes a fetch with `outcome` while a reader waits for it, and
    /// returns what the reader gets and whether the next claim of the chunk
    /// fetches it.
    fn finished_with(outcome: Outcome) -> (Result<Outcome, oneshot::error::TryRecvError>, bool) {
        let ahead = ahead(4, 1000);
        let v = version(&ahead, "a");
        let Claim::Fetch(fetch) = ahead.claim(&v, 0) else {
            panic!("not a fetch");
        };
        let Claim::Wait(mut waiting) = ahead.claim(&v, 0) else {
            panic!("not waiting");
        };
        fetch.finish(outcome);
        let got = waiting.try_recv();
        assert_eq!(ahead.held(), 0);
        (got, matches!(ahead.claim(&v, 0), Claim::Fetch(_)))
    }

    #[test]
    fn a_fetch_that_fails_for_good_reaches_the_readers_that_waited_and_keeps_nothing() {
        let error = S3Error::status(403, Some("AccessDenied"), None);
        let (got, refetches) = finished_with(Err(error.clone()));
        let Ok(Err(got)) = got else {
            panic!("{error:?} did not reach the reader");
        };
        assert_eq!(got.to_string(), error.to_string());
        assert!(refetches);
    }

    #[test]
    fn a_fetch_that_fails_in_a_way_trying_again_can_fix_lets_the_readers_that_waited_claim_again() {
        let (got, refetches) = finished_with(Err(S3Error::status(503, Some("SlowDown"), None)));
        assert!(matches!(got, Err(oneshot::error::TryRecvError::Closed)));
        assert!(refetches);
    }

    #[test]
    fn a_fetch_that_runs_out_of_time_lets_the_readers_that_waited_claim_again() {
        let (got, refetches) = finished_with(Err(S3Error::DeadlineExceeded));
        assert!(matches!(got, Err(oneshot::error::TryRecvError::Closed)));
        assert!(refetches);
    }

    #[test]
    fn a_fetch_that_is_dropped_lets_the_readers_that_waited_claim_again() {
        let ahead = ahead(4, 1000);
        let v = version(&ahead, "a");
        let Claim::Fetch(fetch) = ahead.claim(&v, 0) else {
            panic!("not a fetch");
        };
        let Claim::Wait(mut waiting) = ahead.claim(&v, 0) else {
            panic!("not waiting");
        };
        drop(fetch);
        assert!(matches!(
            waiting.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(matches!(ahead.claim(&v, 0), Claim::Fetch(_)));
        assert_eq!(ahead.held(), 0);
    }

    #[test]
    fn a_reader_that_gave_up_does_not_stop_the_fetch_from_finishing() {
        let ahead = ahead(4, 1000);
        let v = version(&ahead, "a");
        let Claim::Fetch(fetch) = ahead.claim(&v, 0) else {
            panic!("not a fetch");
        };
        drop(ahead.claim(&v, 0));
        fetch.finish(Ok(bytes(10, 1)));
        assert!(is_held(&ahead, &v, 0));
    }
}
