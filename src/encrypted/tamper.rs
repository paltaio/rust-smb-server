//! Stored files, names and markers changed by someone who holds no key. Each
//! case runs over `MemFsBackend`, and over `LocalFsBackend` with the `localfs`
//! feature. It edits the stored bytes behind the backend, then reads them
//! through a new one.
//!
//! Offsets follow the stored format. The header is `HEADER_LEN` bytes. Block
//! `i` starts at `HEADER_LEN + i * (block size + OVERHEAD)` and holds a nonce
//! of `NONCE_LEN` bytes, the ciphertext and a tag of `TAG_LEN` bytes.

use std::fmt::Debug;
use std::io;
use std::ops::Range;

use super::backend::EncryptedBackend;
use super::error::EncryptionError;
use super::format::{MARKER_LEN, MARKER_NAME, NONCE_LEN, OVERHEAD, TAG_LEN};
use super::names::encode_name;
use super::testing::{
    B, BITS, C, H, KEPT, assert_key_mismatch, at, key, key_schedule, names, names_with, open,
    open_dir, open_dir_as, open_file, other_file_id, other_key, other_key_schedule, read_all,
    refused, refused_dir, shift, stored_at, stored_file, stored_len, stored_name,
};
use crate::backend::{
    DirEntry, FILE_ATTRIBUTE_READONLY, FileInfo, Handle, OpenAction, OpenIntent, OpenOptions,
    ShareBackend,
};
use crate::error::{SmbError, SmbResult};
use crate::tests::data::{nonzero_pattern, pattern};
use crate::tests::memfs::MemFsBackend;
use crate::tests::util::path;

/// Bytes of the file most cases use: two whole blocks and a partial one.
const LEN: usize = 2 * B + KEPT;
const FILE_ID: Range<usize> = 8..H;
/// 2001-09-09 01:46:40 UTC as a FILETIME.
const MODIFIED_FILETIME: u64 = 126_444_736_000_000_000;
const INVALID: io::ErrorKind = io::ErrorKind::InvalidData;

/// Stored bytes of block `index` of a file of `LEN` bytes.
fn sealed(index: usize) -> Range<usize> {
    let end = if index < 2 {
        at(index + 1)
    } else {
        stored_len(LEN)
    };
    at(index)..end
}

fn nonce(index: usize) -> Range<usize> {
    let start = sealed(index).start;
    start..start + NONCE_LEN
}

fn ciphertext(index: usize) -> Range<usize> {
    let block = sealed(index);
    block.start + NONCE_LEN..block.end - TAG_LEN
}

fn tag(index: usize) -> Range<usize> {
    let block = sealed(index);
    block.end - TAG_LEN..block.end
}

#[test]
fn offset_helpers_select_the_fields_of_each_block() {
    let bytes = stored_file(&key_schedule(), shift(), &nonzero_pattern(LEN));
    assert_eq!(bytes.len(), H + 2 * (B + OVERHEAD) + KEPT + OVERHEAD);
    for (index, plain_len) in [(0, B), (1, B), (2, KEPT)] {
        let start = H + index * (B + OVERHEAD);
        let data = start + NONCE_LEN..start + NONCE_LEN + plain_len;
        let nonce_bytes = [u8::try_from(index % 255 + 1).unwrap(); NONCE_LEN];
        assert_eq!(nonce(index), start..start + NONCE_LEN, "nonce {index}");
        assert_eq!(bytes[nonce(index)], nonce_bytes, "nonce bytes {index}");
        assert_eq!(ciphertext(index), data, "ciphertext {index}");
        assert_eq!(tag(index), data.end..data.end + TAG_LEN, "tag {index}");
        assert_eq!(sealed(index), start..data.end + TAG_LEN, "block {index}");
    }
    assert_eq!(tag(2).end, bytes.len());
}

/// Files a backend sits over, which a test can edit without the backend.
trait Store: Sized {
    type Inner: ShareBackend;

    fn new() -> Self;

    /// A backend over the files; each call makes a new one.
    fn inner(&self) -> Self::Inner;

    /// The bytes of the file `stored`, a backslash separated path.
    fn read(&self, stored: &str) -> Vec<u8>;

    /// Makes `stored` a file of `bytes`, in a directory that exists.
    fn write(&self, stored: &str, bytes: &[u8]);

    /// Removes a file or an empty directory.
    async fn remove(&self, stored: &str);

    async fn rename(&self, from: &str, to: &str);

    /// Sets the write time of the file to `MODIFIED_FILETIME`.
    fn set_old_write_time(&self, stored: &str);

    async fn make_read_only(&self, stored: &str);
}

struct Mem(MemFsBackend);

impl Store for Mem {
    type Inner = MemFsBackend;

    fn new() -> Self {
        Self(MemFsBackend::new())
    }

    fn inner(&self) -> MemFsBackend {
        self.0.clone()
    }

    fn read(&self, stored: &str) -> Vec<u8> {
        self.0
            .contents(stored)
            .unwrap_or_else(|| panic!("no stored file {stored}"))
    }

    fn write(&self, stored: &str, bytes: &[u8]) {
        self.0.clone().with_file(stored, bytes);
    }

    async fn remove(&self, stored: &str) {
        self.0.unlink(&path(stored)).await.unwrap();
    }

    async fn rename(&self, from: &str, to: &str) {
        self.0.rename(&path(from), &path(to), false).await.unwrap();
    }

    fn set_old_write_time(&self, stored: &str) {
        let (creation, _) = self.0.times(stored);
        self.0
            .clone()
            .with_times(stored, creation, MODIFIED_FILETIME);
    }

    async fn make_read_only(&self, stored: &str) {
        let opts = OpenOptions {
            write_attributes: true,
            ..OpenOptions::default()
        };
        let (handle, _) = self.0.open(&path(stored), opts).await.unwrap();
        handle
            .set_attributes(FILE_ATTRIBUTE_READONLY)
            .await
            .unwrap();
        handle.close().await.unwrap();
    }
}

#[cfg(feature = "localfs")]
struct Local(tempfile::TempDir);

#[cfg(feature = "localfs")]
impl Local {
    fn host(&self, stored: &str) -> std::path::PathBuf {
        stored
            .split('\\')
            .fold(self.0.path().to_path_buf(), |dir, name| dir.join(name))
    }
}

#[cfg(feature = "localfs")]
impl Store for Local {
    type Inner = crate::fs::LocalFsBackend;

    fn new() -> Self {
        Self(tempfile::tempdir().expect("a temporary directory"))
    }

    fn inner(&self) -> crate::fs::LocalFsBackend {
        crate::fs::LocalFsBackend::new(self.0.path()).expect("a backend over the directory")
    }

    fn read(&self, stored: &str) -> Vec<u8> {
        std::fs::read(self.host(stored)).unwrap_or_else(|error| panic!("read {stored}: {error}"))
    }

    fn write(&self, stored: &str, bytes: &[u8]) {
        std::fs::write(self.host(stored), bytes).unwrap();
    }

    async fn remove(&self, stored: &str) {
        let host = self.host(stored);
        if host.is_dir() {
            std::fs::remove_dir(host).unwrap();
        } else {
            std::fs::remove_file(host).unwrap();
        }
    }

    async fn rename(&self, from: &str, to: &str) {
        std::fs::rename(self.host(from), self.host(to)).unwrap();
    }

    fn set_old_write_time(&self, stored: &str) {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.host(stored))
            .unwrap();
        file.set_modified(time).unwrap();
    }

    async fn make_read_only(&self, stored: &str) {
        let host = self.host(stored);
        let mut permissions = std::fs::metadata(&host).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(host, permissions).unwrap();
    }
}

/// A backend over the files of `store`, with the names and block size of the
/// tests.
async fn share<S: Store>(store: &S) -> EncryptedBackend<S::Inner> {
    names_with(store.inner(), |builder| builder.block_size(B as u32)).await
}

async fn mkdir<I: ShareBackend>(layer: &EncryptedBackend<I>, name: &str) {
    let (handle, action) = open_dir_as(layer, name, OpenIntent::Create).await;
    assert_eq!(action, OpenAction::Created, "mkdir {name}");
    Box::new(handle).close().await.unwrap();
}

async fn write_at<T: Handle>(handle: &T, offset: usize, data: &[u8]) {
    let written = handle.write(offset as u64, data).await.unwrap();
    assert_eq!(written as usize, data.len(), "write at {offset}");
}

/// Creates the file `name` holding `data`.
async fn put<I: ShareBackend>(layer: &EncryptedBackend<I>, name: &str, data: &[u8]) {
    let (handle, action) = open(layer, name, OpenIntent::Create).await;
    assert_eq!(action, OpenAction::Created, "create {name}");
    write_at(&handle, 0, data).await;
    Box::new(handle).close().await.unwrap();
}

/// Writes `data` at `offset` of the existing file `name`.
async fn rewrite<I: ShareBackend>(
    layer: &EncryptedBackend<I>,
    name: &str,
    offset: usize,
    data: &[u8],
) {
    let handle = open_file(layer, name).await;
    write_at(&handle, offset, data).await;
    Box::new(handle).close().await.unwrap();
}

/// Everything the file `name` holds.
async fn contents<I: ShareBackend>(layer: &EncryptedBackend<I>, name: &str) -> Vec<u8> {
    let handle = open_file(layer, name).await;
    let bytes = read_all(&handle).await;
    Box::new(handle).close().await.unwrap();
    bytes
}

async fn list<I: ShareBackend>(layer: &EncryptedBackend<I>, dir: &str) -> Vec<DirEntry> {
    let handle = open_dir(layer, dir).await;
    let entries = handle.list_dir(None).await.unwrap();
    Box::new(handle).close().await.unwrap();
    entries
}

fn info<'a>(entries: &'a [DirEntry], name: &str) -> &'a FileInfo {
    &entries
        .iter()
        .find(|entry| entry.info.name == name)
        .unwrap_or_else(|| panic!("{name} is not listed"))
        .info
}

/// Creates the file `name` holding `plain` in a share of `store`, and
/// returns the bytes the backend stored for it.
async fn store_file<S: Store>(store: &S, name: &str, plain: &[u8]) -> Vec<u8> {
    put(&share(store).await, name, plain).await;
    let bytes = store.read(&stored_name(name));
    assert_eq!(
        bytes.len(),
        stored_len(plain.len()),
        "stored size of {name}"
    );
    bytes
}

#[track_caller]
fn assert_fails<T: Debug>(result: SmbResult<T>, kind: io::ErrorKind, what: &str) {
    match result {
        Err(SmbError::Io(error)) if error.kind() == kind => {}
        other => panic!("{what}: expected an Io error of kind {kind:?}, got {other:?}"),
    }
}

/// Reads the file `name`, which holds `plain`, block by block and whole. A
/// block in `bad` fails with an Io error of `kind` and the others read back;
/// the whole read fails when `bad` is not empty.
async fn assert_blocks<I: ShareBackend>(
    layer: &EncryptedBackend<I>,
    name: &str,
    plain: &[u8],
    bad: &[usize],
    kind: io::ErrorKind,
    what: &str,
) {
    let handle = open_file(layer, name).await;
    for index in 0..plain.len().div_ceil(B) {
        let range = index * B..plain.len().min((index + 1) * B);
        let read = handle.read(range.start as u64, B as u32).await;
        if bad.contains(&index) {
            assert_fails(read, kind, &format!("{what}: block {index}"));
        } else {
            assert_eq!(read.unwrap(), plain[range], "{what}: block {index}");
        }
    }
    let whole = handle.read(0, u32::try_from(plain.len()).unwrap()).await;
    if bad.is_empty() {
        assert_eq!(whole.unwrap(), plain, "{what}: whole file");
    } else {
        assert_fails(whole, kind, &format!("{what}: whole file"));
    }
    Box::new(handle).close().await.unwrap();
}

/// Flips one bit at the first, middle and last byte of `field` of each block,
/// one change at a time. The block fails and the others read back.
async fn a_flip_fails_only_its_block<S: Store>(store: S, field: fn(usize) -> Range<usize>) {
    let plain = pattern(LEN, 1);
    let good = store_file(&store, "data.bin", &plain).await;
    let stored = stored_name("data.bin");
    for index in 0..3 {
        let part = field(index);
        for offset in [part.start, (part.start + part.end) / 2, part.end - 1] {
            let mut bytes = good.clone();
            bytes[offset] ^= 0x01;
            store.write(&stored, &bytes);
            let what = format!("byte {offset}");
            let layer = share(&store).await;
            assert_blocks(&layer, "data.bin", &plain, &[index], INVALID, &what).await;
        }
    }
}

async fn a_flipped_byte_in_a_block_fails_the_reads_that_cover_it<S: Store>(store: S) {
    a_flip_fails_only_its_block(store, ciphertext).await;
}

async fn a_flipped_byte_in_a_nonce_fails_the_reads_that_cover_it<S: Store>(store: S) {
    a_flip_fails_only_its_block(store, nonce).await;
}

async fn a_flipped_byte_in_a_tag_fails_the_reads_that_cover_it<S: Store>(store: S) {
    a_flip_fails_only_its_block(store, tag).await;
}

/// Header bytes: magic 0..4, version 4, suite 5, block shift 6, reserved 7,
/// file id 8..24.
async fn a_flipped_byte_in_the_header_fails_reads_writes_and_truncates<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    let good = store_file(&store, "data.bin", &plain).await;
    let stored = stored_name("data.bin");
    for offset in 0..H {
        let kind = match offset {
            4 | 5 => io::ErrorKind::Unsupported,
            _ => INVALID,
        };
        let mut bytes = good.clone();
        bytes[offset] ^= 0x01;
        store.write(&stored, &bytes);
        let layer = share(&store).await;
        let what = format!("header byte {offset}");
        assert_blocks(&layer, "data.bin", &plain, &[0, 1, 2], kind, &what).await;

        let handle = open_file(&layer, "data.bin").await;
        assert_fails(handle.write(0, &[1]).await, kind, &format!("{what}: write"));
        let cut = handle.truncate(B as u64 + 1).await;
        assert_fails(cut, kind, &format!("{what}: truncate"));
        Box::new(handle).close().await.unwrap();
        assert_eq!(
            store.read(&stored),
            bytes,
            "{what}: the stored file is kept"
        );
    }
}

async fn a_block_moved_to_another_index_fails_its_read<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    let good = store_file(&store, "data.bin", &plain).await;
    let stored = stored_name("data.bin");

    let mut copied = good.clone();
    copied.copy_within(sealed(0), sealed(1).start);
    store.write(&stored, &copied);
    let layer = share(&store).await;
    let what = "block 0 copied to 1";
    assert_blocks(&layer, "data.bin", &plain, &[1], INVALID, what).await;

    let mut swapped = good.clone();
    swapped[sealed(0)].copy_from_slice(&good[sealed(1)]);
    swapped[sealed(1)].copy_from_slice(&good[sealed(0)]);
    store.write(&stored, &swapped);
    let layer = share(&store).await;
    let what = "blocks 0 and 1 swapped";
    assert_blocks(&layer, "data.bin", &plain, &[0, 1], INVALID, what).await;
}

async fn a_block_moved_to_another_file_fails_its_read<S: Store>(store: S) {
    let first = pattern(LEN, 1);
    let second = pattern(LEN, 2);
    let layer = share(&store).await;
    put(&layer, "first.bin", &first).await;
    put(&layer, "second.bin", &second).await;
    let (first_at, second_at) = (stored_name("first.bin"), stored_name("second.bin"));
    let from = store.read(&first_at);
    let mut into = store.read(&second_at);
    into[sealed(1)].copy_from_slice(&from[sealed(1)]);
    store.write(&second_at, &into);

    let layer = share(&store).await;
    assert_blocks(&layer, "second.bin", &second, &[1], INVALID, "second file").await;
    assert_blocks(&layer, "first.bin", &first, &[], INVALID, "first file").await;
}

async fn the_layer_accepts_a_zeroed_block_and_reads_zeros<S: Store>(store: S) {
    let plain = nonzero_pattern(LEN);
    let good = store_file(&store, "data.bin", &plain).await;
    let stored = stored_name("data.bin");
    for index in 0..3 {
        let mut bytes = good.clone();
        bytes[sealed(index)].fill(0);
        store.write(&stored, &bytes);
        let mut expected = plain.clone();
        expected[index * B..LEN.min((index + 1) * B)].fill(0);
        let layer = share(&store).await;
        assert_eq!(
            contents(&layer, "data.bin").await,
            expected,
            "block {index}"
        );
    }

    let mut bytes = good.clone();
    bytes[H..].fill(0);
    store.write(&stored, &bytes);
    let layer = share(&store).await;
    assert_eq!(
        contents(&layer, "data.bin").await,
        vec![0; LEN],
        "every block"
    );

    bytes[sealed(1)][C - 1] = 1;
    store.write(&stored, &bytes);
    let layer = share(&store).await;
    let zeros = vec![0; LEN];
    let what = "one byte set in a zeroed block";
    assert_blocks(&layer, "data.bin", &zeros, &[1], INVALID, what).await;
}

async fn the_layer_accepts_a_file_cut_at_a_block_boundary<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    let good = store_file(&store, "data.bin", &plain).await;
    let stored = stored_name("data.bin");
    for (cut, kept) in [(at(2), 2 * B), (at(1), B), (H, 0), (0, 0)] {
        store.write(&stored, &good[..cut]);
        let layer = share(&store).await;
        assert_eq!(
            contents(&layer, "data.bin").await,
            plain[..kept],
            "cut at {cut}"
        );
        let entries = list(&layer, "").await;
        assert_eq!(
            info(&entries, "data.bin").end_of_file,
            kept as u64,
            "cut at {cut}"
        );
    }
}

async fn a_file_cut_inside_a_block_fails_the_read_of_that_block<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    let good = store_file(&store, "data.bin", &plain).await;
    let kept = 12;
    store.write(
        &stored_name("data.bin"),
        &good[..at(1) + NONCE_LEN + kept + TAG_LEN],
    );
    let layer = share(&store).await;
    let cut = &plain[..B + kept];
    assert_blocks(&layer, "data.bin", cut, &[1], INVALID, "cut in block 1").await;
}

async fn the_layer_accepts_a_rolled_back_block<S: Store>(store: S) {
    let old = pattern(LEN, 1);
    let before = store_file(&store, "data.bin", &old).await;
    let stored = stored_name("data.bin");
    let newer = pattern(B, 9);
    rewrite(&share(&store).await, "data.bin", B, &newer).await;
    let after = store.read(&stored);
    assert_ne!(
        after[sealed(1)],
        before[sealed(1)],
        "the rewrite stores a new block"
    );
    let mut changed = old.clone();
    changed[B..2 * B].copy_from_slice(&newer);
    assert_eq!(contents(&share(&store).await, "data.bin").await, changed);

    let mut rolled_back = after.clone();
    rolled_back[sealed(1)].copy_from_slice(&before[sealed(1)]);
    store.write(&stored, &rolled_back);
    assert_eq!(contents(&share(&store).await, "data.bin").await, old);
}

async fn the_layer_accepts_a_rolled_back_file<S: Store>(store: S) {
    let old = pattern(LEN, 1);
    let before = store_file(&store, "data.bin", &old).await;
    let stored = stored_name("data.bin");

    let newer = pattern(B + 50, 2);
    let layer = share(&store).await;
    let (handle, action) = open(&layer, "data.bin", OpenIntent::OverwriteOrCreate).await;
    assert_eq!(action, OpenAction::Overwritten);
    write_at(&handle, 0, &newer).await;
    Box::new(handle).close().await.unwrap();
    let after = store.read(&stored);
    assert_ne!(
        after[FILE_ID], before[FILE_ID],
        "the overwrite gives the file a new id"
    );
    assert_eq!(contents(&share(&store).await, "data.bin").await, newer);

    store.write(&stored, &before);
    assert_eq!(contents(&share(&store).await, "data.bin").await, old);
}

async fn the_layer_accepts_zero_blocks_appended_to_a_file<S: Store>(store: S) {
    let plain = pattern(2 * B, 1);
    let good = store_file(&store, "data.bin", &plain).await;
    let stored = stored_name("data.bin");
    let appended = [
        ("one block", C, B),
        ("three blocks", 3 * C, 3 * B),
        ("a partial block", KEPT + OVERHEAD, KEPT),
    ];
    for (what, stored_extra, plain_extra) in appended {
        let bytes = [good.as_slice(), &vec![0; stored_extra]].concat();
        store.write(&stored, &bytes);
        let expected = [plain.as_slice(), &vec![0; plain_extra]].concat();
        let layer = share(&store).await;
        assert_eq!(contents(&layer, "data.bin").await, expected, "{what}");
        let entries = list(&layer, "").await;
        assert_eq!(
            info(&entries, "data.bin").end_of_file,
            expected.len() as u64,
            "{what}"
        );
    }
}

async fn the_layer_accepts_swapped_files<S: Store>(store: S) {
    let first = pattern(LEN, 1);
    let second = pattern(B + 7, 2);
    let layer = share(&store).await;
    put(&layer, "first.bin", &first).await;
    put(&layer, "second.bin", &second).await;
    let (first_at, second_at) = (stored_name("first.bin"), stored_name("second.bin"));
    let (first_bytes, second_bytes) = (store.read(&first_at), store.read(&second_at));
    store.write(&first_at, &second_bytes);
    store.write(&second_at, &first_bytes);

    let layer = share(&store).await;
    assert_eq!(contents(&layer, "first.bin").await, second);
    assert_eq!(contents(&layer, "second.bin").await, first);
    let entries = list(&layer, "").await;
    assert_eq!(info(&entries, "first.bin").end_of_file, second.len() as u64);
    assert_eq!(info(&entries, "second.bin").end_of_file, first.len() as u64);
}

async fn the_layer_accepts_an_entry_moved_to_another_directory<S: Store>(store: S) {
    let (file, inside) = (pattern(LEN, 1), pattern(B + 3, 2));
    let layer = share(&store).await;
    for dir in ["x", "y", "x\\d"] {
        mkdir(&layer, dir).await;
    }
    put(&layer, "x\\a.txt", &file).await;
    put(&layer, "x\\d\\f.txt", &inside).await;
    store
        .rename(&stored_at("x\\a.txt"), &stored_at("y\\a.txt"))
        .await;
    store.rename(&stored_at("x\\d"), &stored_at("y\\d")).await;

    let layer = share(&store).await;
    assert_eq!(names(&list(&layer, "x").await), Vec::<String>::new());
    assert_eq!(names(&list(&layer, "y").await), ["a.txt", "d"]);
    assert_eq!(names(&list(&layer, "y\\d").await), ["f.txt"]);
    assert_eq!(contents(&layer, "y\\a.txt").await, file);
    assert_eq!(contents(&layer, "y\\d\\f.txt").await, inside);
}

async fn the_layer_accepts_deleted_files_and_directories<S: Store>(store: S) {
    let layer = share(&store).await;
    put(&layer, "gone.txt", &pattern(LEN, 1)).await;
    put(&layer, "kept.txt", &pattern(10, 2)).await;
    mkdir(&layer, "gone").await;
    put(&layer, "gone\\inside.txt", &pattern(10, 3)).await;
    store.remove(&stored_name("gone.txt")).await;
    store.remove(&stored_at("gone\\inside.txt")).await;
    store.remove(&stored_name("gone")).await;

    let layer = share(&store).await;
    assert_eq!(names(&list(&layer, "").await), ["kept.txt"]);
    let missing = |error: SmbError, what: &str| {
        assert!(matches!(error, SmbError::NotFound), "{what}: {error:?}");
    };
    missing(refused(&layer, "gone.txt", OpenIntent::Open).await, "file");
    missing(
        refused_dir(&layer, "gone", OpenIntent::Open).await,
        "directory",
    );
    let nested = refused(&layer, "gone\\inside.txt", OpenIntent::Open).await;
    assert!(
        matches!(nested, SmbError::PathNotFound),
        "below it: {nested:?}"
    );
}

async fn the_layer_accepts_changed_times_and_attributes<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    store_file(&store, "data.bin", &plain).await;
    let stored = stored_name("data.bin");
    store.set_old_write_time(&stored);
    store.make_read_only(&stored).await;

    let layer = share(&store).await;
    let (handle, _) = layer
        .open(&path("data.bin"), OpenOptions::default())
        .await
        .unwrap();
    let stat = handle.stat().await.unwrap();
    assert_eq!(stat.last_write_time, MODIFIED_FILETIME);
    assert!(stat.read_only);
    assert_eq!(handle.read(0, LEN as u32).await.unwrap(), plain);
    handle.close().await.unwrap();

    assert!(info(&list(&layer, "").await, "data.bin").read_only);
}

/// A copy of a file keeps its file id, so a block of one is valid at the same
/// index in the other.
async fn the_layer_accepts_blocks_swapped_between_copies_of_one_file<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    let original = store_file(&store, "a.bin", &plain).await;
    let (a, b) = (stored_name("a.bin"), stored_name("b.bin"));
    store.write(&b, &original);
    assert_eq!(contents(&share(&store).await, "b.bin").await, plain);

    let newer = pattern(B, 9);
    rewrite(&share(&store).await, "a.bin", B, &newer).await;
    let rewritten = store.read(&a);
    assert_ne!(
        rewritten[sealed(1)],
        original[sealed(1)],
        "the rewrite stores a new block"
    );
    let mut copy = original.clone();
    copy[sealed(1)].copy_from_slice(&rewritten[sealed(1)]);
    store.write(&b, &copy);

    let mut expected = plain.clone();
    expected[B..2 * B].copy_from_slice(&newer);
    let layer = share(&store).await;
    assert_eq!(contents(&layer, "b.bin").await, expected);
    assert_eq!(contents(&layer, "a.bin").await, expected);
}

async fn the_layer_accepts_ciphertext_copied_in_from_a_share_with_the_same_key<S: Store>(store: S) {
    let other = S::new();
    let plain = pattern(LEN, 1);
    let bytes = store_file(&store, "doc.txt", &plain).await;
    share(&other).await;
    other.write(&stored_name("doc.txt"), &bytes);

    let layer = share(&other).await;
    assert_eq!(names(&list(&layer, "").await), ["doc.txt"]);
    assert_eq!(contents(&layer, "doc.txt").await, plain);
}

async fn files_and_names_under_another_key_fail_or_are_left_out<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    share(&store).await;
    let foreign = stored_file(&other_key_schedule(), shift(), &plain);
    store.write(&stored_name("data.bin"), &foreign);
    let other_name = encode_name(&other_key_schedule(), "other.bin", 255)
        .unwrap()
        .entry;
    store.write(&other_name, &foreign);

    let layer = share(&store).await;
    assert_blocks(&layer, "data.bin", &plain, &[0, 1, 2], INVALID, "other key").await;
    assert_eq!(names(&list(&layer, "").await), ["data.bin"]);
}

async fn a_planted_header_only_file_gets_a_new_file_id_on_its_first_write<S: Store>(store: S) {
    let mut planted = b"smbe".to_vec();
    planted.extend([1, 1, BITS, 0]);
    planted.extend(other_file_id());
    assert_eq!(planted.len(), H);
    share(&store).await;
    let stored = stored_name("f.txt");
    store.write(&stored, &planted);

    let layer = share(&store).await;
    let handle = open_file(&layer, "f.txt").await;
    assert_eq!(handle.stat().await.unwrap().end_of_file, 0);
    assert!(handle.read(0, 10).await.unwrap().is_empty());
    let data = pattern(5, 3);
    write_at(&handle, 0, &data).await;
    assert_eq!(read_all(&handle).await, data);
    Box::new(handle).close().await.unwrap();
    assert_eq!(contents(&share(&store).await, "f.txt").await, data);

    let bytes = store.read(&stored);
    assert_eq!(bytes.len(), stored_len(data.len()));
    assert_eq!(bytes[..FILE_ID.start], planted[..FILE_ID.start]);
    assert_ne!(bytes[FILE_ID], planted[FILE_ID]);
}

/// `name` with the character at `index` replaced by another letter of the
/// stored alphabet.
fn replace_char(name: &str, index: usize) -> String {
    let mut chars: Vec<char> = name.chars().collect();
    chars[index] = if chars[index] == 'a' { 'b' } else { 'a' };
    chars.into_iter().collect()
}

async fn a_renamed_stored_name_is_left_out_of_listings<S: Store>(store: S) {
    let plain = pattern(LEN, 1);
    let good = store_file(&store, "a.txt", &plain).await;
    let genuine = stored_name("a.txt");
    let last = genuine.len() - 1;
    let altered = [
        ("first character changed", replace_char(&genuine, 0)),
        ("middle character changed", replace_char(&genuine, last / 2)),
        ("last character changed", replace_char(&genuine, last)),
        ("last character dropped", genuine[..last].to_string()),
        ("spelled as the client spells it", "a.txt".to_string()),
    ];
    for (what, name) in altered {
        store.rename(&genuine, &name).await;
        let layer = share(&store).await;
        assert_eq!(
            names(&list(&layer, "").await),
            Vec::<String>::new(),
            "{what}"
        );
        let error = refused(&layer, "a.txt", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::NotFound), "{what}: {error:?}");
        store.rename(&name, &genuine).await;
    }

    let forged = "q".repeat(genuine.len());
    store.write(&forged, &good);
    let layer = share(&store).await;
    assert_eq!(names(&list(&layer, "").await), ["a.txt"]);
    let error = refused(&layer, &forged, OpenIntent::Open).await;
    assert!(
        matches!(error, SmbError::NotFound),
        "forged name: {error:?}"
    );
    assert_eq!(contents(&layer, "a.txt").await, plain);
}

async fn build_error<S: Store>(store: &S, key: [u8; 32]) -> EncryptionError {
    EncryptedBackend::builder(store.inner(), key)
        .block_size(B as u32)
        .build()
        .await
        .unwrap_err()
}

/// Marker bytes: magic 0..8, version 8, flags, block shift, threshold and
/// share id 9..28, MAC 28..60. The MAC covers every byte from 0 to 28.
async fn a_changed_or_resized_marker_is_refused<S: Store>(store: S) {
    share(&store).await;
    let good = store.read(MARKER_NAME);
    assert_eq!(good.len(), MARKER_LEN);
    for offset in 0..MARKER_LEN {
        let mut bytes = good.clone();
        bytes[offset] ^= 0x01;
        store.write(MARKER_NAME, &bytes);
        let error = build_error(&store, key()).await;
        match (offset, &error) {
            (0..8, EncryptionError::MarkerInvalid) => {}
            (8, EncryptionError::UnsupportedFormat { version: 0 }) => {}
            (9..MARKER_LEN, EncryptionError::KeyMismatch) => {}
            _ => panic!("byte {offset}: unexpected {error:?}"),
        }
    }
    for len in [0, MARKER_LEN - 1] {
        store.write(MARKER_NAME, &good[..len]);
        let error = build_error(&store, key()).await;
        assert!(
            matches!(error, EncryptionError::MarkerInvalid),
            "{len} bytes: {error:?}"
        );
    }
    store.write(MARKER_NAME, &[good.as_slice(), &[0]].concat());
    let error = build_error(&store, key()).await;
    assert!(
        matches!(error, EncryptionError::MarkerInvalid),
        "61 bytes: {error:?}"
    );
}

async fn a_deleted_marker_is_refused<S: Store>(store: S) {
    put(&share(&store).await, "a.txt", &pattern(10, 1)).await;
    store.remove(MARKER_NAME).await;
    let error = build_error(&store, key()).await;
    assert!(matches!(error, EncryptionError::MarkerMissing), "{error:?}");
}

async fn the_wrong_key_is_a_key_mismatch<S: Store>(store: S) {
    let plain = pattern(10, 1);
    put(&share(&store).await, "a.txt", &plain).await;
    let marker = store.read(MARKER_NAME);
    assert_key_mismatch(&build_error(&store, other_key()).await);
    assert_eq!(store.read(MARKER_NAME), marker, "the marker is kept");
    assert_eq!(contents(&share(&store).await, "a.txt").await, plain);
}

macro_rules! over_both_stores {
    ($($case:ident),* $(,)?) => {
        mod memfs {
            use super::Store as _;

            $(
                #[tokio::test]
                async fn $case() {
                    super::$case(super::Mem::new()).await;
                }
            )*
        }

        #[cfg(feature = "localfs")]
        mod localfs {
            use super::Store as _;

            $(
                #[tokio::test]
                async fn $case() {
                    super::$case(super::Local::new()).await;
                }
            )*
        }
    };
}

over_both_stores!(
    a_flipped_byte_in_a_block_fails_the_reads_that_cover_it,
    a_flipped_byte_in_a_nonce_fails_the_reads_that_cover_it,
    a_flipped_byte_in_a_tag_fails_the_reads_that_cover_it,
    a_flipped_byte_in_the_header_fails_reads_writes_and_truncates,
    a_block_moved_to_another_index_fails_its_read,
    a_block_moved_to_another_file_fails_its_read,
    the_layer_accepts_a_zeroed_block_and_reads_zeros,
    the_layer_accepts_a_file_cut_at_a_block_boundary,
    a_file_cut_inside_a_block_fails_the_read_of_that_block,
    the_layer_accepts_a_rolled_back_block,
    the_layer_accepts_a_rolled_back_file,
    the_layer_accepts_zero_blocks_appended_to_a_file,
    the_layer_accepts_swapped_files,
    the_layer_accepts_an_entry_moved_to_another_directory,
    the_layer_accepts_deleted_files_and_directories,
    the_layer_accepts_changed_times_and_attributes,
    the_layer_accepts_blocks_swapped_between_copies_of_one_file,
    the_layer_accepts_ciphertext_copied_in_from_a_share_with_the_same_key,
    files_and_names_under_another_key_fail_or_are_left_out,
    a_planted_header_only_file_gets_a_new_file_id_on_its_first_write,
    a_renamed_stored_name_is_left_out_of_listings,
    a_changed_or_resized_marker_is_refused,
    a_deleted_marker_is_refused,
    the_wrong_key_is_a_key_mismatch,
);
