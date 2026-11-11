//! How a file is cut into parts, and the hash of the bytes a request sends.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use tokio::task::spawn_blocking;

use super::data::read_full_at;
use super::encode::hex;
use super::error::S3Error;
use super::retry::Stop;

/// Smallest part a multipart upload takes, except for its last one.
pub(super) const MIN_PART_SIZE: u64 = 5 << 20;

/// Largest part a store takes.
pub(super) const MAX_PART_SIZE: u64 = 5 << 30;

/// Most parts a multipart upload has.
const MAX_PARTS: u64 = 10_000;

/// The size of the pieces a range is hashed in.
const HASH_PIECE: usize = 256 * 1024;

/// The size of the parts of an object of `len` bytes: `part_size`, or more
/// when that would take more than 10,000 parts.
pub(super) fn part_size_for(len: u64, part_size: u64) -> u64 {
    part_size.max(len.div_ceil(MAX_PARTS))
}

/// The parts of an object of `len` bytes cut into pieces of `part_size`: the
/// number of each, counted from 1, and the bytes it holds.
pub(super) fn parts(len: u64, part_size: u64) -> impl Iterator<Item = (u32, Range<u64>)> {
    let count = len.div_ceil(part_size);
    (0..count).map(move |index| {
        let start = index * part_size;
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        (number, start..(start + part_size).min(len))
    })
}

/// The SHA-256 of the `range` bytes of `file` as hexadecimal, read in pieces
/// of bounded size on a blocking thread. Gives up with
/// [`S3Error::Stopped`] once `stop` is called, and with
/// [`S3Error::SourceChanged`] if the file ends before `range` does.
pub(super) async fn hash_range(
    file: Arc<File>,
    range: Range<u64>,
    stop: Stop,
) -> Result<String, S3Error> {
    spawn_blocking(move || hash_blocking(&file, range, &stop))
        .await
        .map_err(|e| S3Error::SourceRead(Arc::new(io::Error::other(e))))?
}

fn hash_blocking(file: &File, range: Range<u64>, stop: &Stop) -> Result<String, S3Error> {
    let size = file
        .metadata()
        .map_err(|e| S3Error::SourceRead(Arc::new(e)))?
        .len();
    if size < range.end {
        return Err(S3Error::SourceChanged);
    }
    let mut hasher = Sha256::new();
    let mut piece =
        vec![0; HASH_PIECE.min(usize::try_from(range.end - range.start).unwrap_or(HASH_PIECE))];
    let mut at = range.start;
    while at < range.end {
        if stop.is_stopped() {
            return Err(S3Error::Stopped);
        }
        let len = piece
            .len()
            .min(usize::try_from(range.end - at).unwrap_or(usize::MAX));
        read_full_at(file, &mut piece[..len], at).map_err(|e| S3Error::SourceRead(Arc::new(e)))?;
        hasher.update(&piece[..len]);
        at += len as u64;
    }
    Ok(hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn the_part_size_grows_to_keep_an_object_at_most_10000_parts() {
        let mib = 1u64 << 20;
        assert_eq!(part_size_for(0, 16 * mib), 16 * mib);
        assert_eq!(part_size_for(100 * mib, 16 * mib), 16 * mib);
        assert_eq!(part_size_for(10_000 * 16 * mib, 16 * mib), 16 * mib);
        assert_eq!(part_size_for(10_000 * 16 * mib + 1, 16 * mib), 16 * mib + 1);
        assert_eq!(
            part_size_for(1 << 40, 16 * mib),
            (1u64 << 40).div_ceil(10_000)
        );
        for len in [1u64 << 36, 5 << 40, 123_456_789_012_345] {
            let size = part_size_for(len, MIN_PART_SIZE);
            assert!(len.div_ceil(size) <= 10_000, "{len}");
            assert!(size >= MIN_PART_SIZE);
        }
    }

    #[test]
    fn parts_cover_the_object_in_order_with_a_short_last_one() {
        let all: Vec<_> = parts(25, 10).collect();
        assert_eq!(all, [(1, 0..10), (2, 10..20), (3, 20..25)]);
        let exact: Vec<_> = parts(20, 10).collect();
        assert_eq!(exact, [(1, 0..10), (2, 10..20)]);
        assert_eq!(parts(0, 10).count(), 0);
        assert_eq!(parts(1, 10).collect::<Vec<_>>(), [(1, 0..1)]);

        let len = 3 * (1u64 << 40) + 12_345;
        let size = part_size_for(len, MIN_PART_SIZE);
        let count = parts(len, size).count();
        let (last, range) = parts(len, size).last().unwrap();
        assert_eq!(last as usize, count);
        assert_eq!(range.end, len);
    }

    fn file_with(data: &[u8]) -> Arc<File> {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(data).unwrap();
        Arc::new(file)
    }

    #[tokio::test]
    async fn a_range_hashes_to_the_sha256_of_its_bytes() {
        let data: Vec<u8> = (0..=250).cycle().take(700_000).collect();
        let file = file_with(&data);
        let hash = hash_range(file.clone(), 1000..650_001, Stop::new())
            .await
            .unwrap();
        assert_eq!(hash, hex(&Sha256::digest(&data[1000..650_001])));
        let empty = hash_range(file, 5..5, Stop::new()).await.unwrap();
        assert_eq!(empty, hex(&Sha256::digest(b"")));
    }

    #[tokio::test]
    async fn a_range_past_the_end_of_the_file_has_changed_and_a_stopped_hash_ends() {
        let file = file_with(&[7; 100]);
        let short = hash_range(file.clone(), 0..101, Stop::new()).await;
        assert!(matches!(short, Err(S3Error::SourceChanged)));
        let stop = Stop::new();
        stop.stop();
        let stopped = hash_range(file, 0..100, stop).await;
        assert!(matches!(stopped, Err(S3Error::Stopped)));
    }
}
