//! Fixtures shared by the unit tests.

use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::io;
use std::mem;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::backend::{EncryptedBackend, Settings};
use super::block::FileCipher;
use super::builder::EncryptedBackendBuilder;
use super::cache::{Entry, NameCache, Snapshot};
use super::change::Random;
use super::error::EncryptionError;
use super::format::{BlockShift, FILE_ID_LEN, HEADER_LEN, MARKER_NAME, NONCE_LEN, OVERHEAD};
use super::handle::{EncryptedHandle, OpenResult};
use super::header::Header;
use super::keys::KeySchedule;
use super::marker::{MarkerSettings, parse_marker};
use super::names::{StoredName, encode_name, encode_unchecked};
use super::random::{random_file_id, random_nonces};
use super::size::stored_size;
use crate::backend::{
    BackendCapabilities, DirChange, DirChangeKind, DirEntry, DirWatch, FileInfo, FileTimes, Handle,
    OpenAction, OpenIntent, OpenOptions, ShareBackend, VolumeInfo,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use crate::tests::data::{apply, pattern};
use crate::tests::faulty::Faulty;
use crate::tests::gated::{Gate, Gated, Op};
use crate::tests::memfs::MemFsBackend;
use crate::tests::util::{dir_opts, opts, path};

pub(super) fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// The key 0x00..=0x1f.
pub(super) fn key() -> [u8; 32] {
    std::array::from_fn(|i| i as u8)
}

/// A key other than `key`.
pub(super) fn other_key() -> [u8; 32] {
    [7; 32]
}

/// Schedule of `key`.
pub(super) fn key_schedule() -> KeySchedule {
    KeySchedule::new(Zeroizing::new(key()))
}

/// Schedule of `other_key`.
pub(super) fn other_key_schedule() -> KeySchedule {
    KeySchedule::new(Zeroizing::new(other_key()))
}

/// File id 0xa0..=0xaf.
pub(super) fn file_id() -> [u8; 16] {
    std::array::from_fn(|i| 0xa0 + i as u8)
}

/// File id 0xb0..=0xbf.
pub(super) fn other_file_id() -> [u8; 16] {
    std::array::from_fn(|i| 0xb0 + i as u8)
}

pub(super) type Builder = EncryptedBackendBuilder<MemFsBackend>;

/// Builds an encrypted backend over `files` under `key`, with the builder
/// that `setup` returns, and checks that `build` closed every handle it
/// opened, whatever the outcome.
pub(super) async fn build(
    files: &MemFsBackend,
    setup: impl FnOnce(Builder) -> Builder,
) -> Result<EncryptedBackend<MemFsBackend>, EncryptionError> {
    let built = setup(EncryptedBackend::builder(files.clone(), key()))
        .build()
        .await;
    assert_eq!(files.open_handles(), 0, "build closed every handle");
    built
}

/// Builds a backend over `inner` that stores names as clients spell them.
pub(crate) async fn clear_over<B: ShareBackend>(inner: B) -> EncryptedBackend<B> {
    clear_blocks(inner, BlockShift::DEFAULT).await
}

/// Builds a backend over `inner` that stores names as clients spell them,
/// with blocks of `1 << shift` bytes.
pub(super) async fn clear_blocks<B: ShareBackend>(
    inner: B,
    shift: BlockShift,
) -> EncryptedBackend<B> {
    EncryptedBackend::builder(inner, key())
        .encrypt_names(false)
        .block_size(u32::try_from(shift.block_size()).expect("a block size fits in 32 bits"))
        .build()
        .await
        .expect("a backend with names in the clear")
}

/// The settings of a backend with names in the clear.
pub(super) fn clear_settings() -> Settings {
    Settings {
        encrypt_names: false,
        case_insensitive: false,
        block_shift: BlockShift::DEFAULT,
        long_name_threshold: 0,
        name_cache_ttl: Duration::from_secs(30),
    }
}

/// The settings of a backend that encrypts names, with the defaults of the
/// builder.
pub(super) fn names_settings() -> Settings {
    Settings {
        encrypt_names: true,
        case_insensitive: true,
        long_name_threshold: 255,
        ..clear_settings()
    }
}

/// Builds a backend that encrypts names over `inner`.
pub(crate) async fn names_over<B: ShareBackend>(inner: B) -> EncryptedBackend<B> {
    names_with(inner, |builder| builder).await
}

/// Builds a backend that encrypts names over `inner`, with the builder that
/// `setup` returns.
pub(crate) async fn names_with<B: ShareBackend>(
    inner: B,
    setup: impl FnOnce(EncryptedBackendBuilder<B>) -> EncryptedBackendBuilder<B>,
) -> EncryptedBackend<B> {
    setup(EncryptedBackend::builder(inner, key()))
        .build()
        .await
        .expect("a backend that encrypts names")
}

/// A store and a backend that encrypts names over it.
pub(super) async fn layer() -> (MemFsBackend, EncryptedBackend<MemFsBackend>) {
    let files = MemFsBackend::new();
    let layer = names_over(files.clone()).await;
    (files, layer)
}

/// A snapshot of `count` entries that are not directories.
pub(super) fn many_names(count: usize) -> Arc<Snapshot> {
    let entries = (0..count)
        .map(|n| Entry {
            plain: format!("n{n}"),
            stored: format!("s{n}"),
            directory: false,
        })
        .collect();
    Arc::new(Snapshot::new(entries, Instant::now()))
}

/// `layer` with a directory name cache that holds up to `limit` names in all.
/// One directory over the limit is kept alone. No clone of `layer` may exist.
pub(super) fn with_name_limit<B>(
    mut layer: EncryptedBackend<B>,
    limit: usize,
) -> EncryptedBackend<B> {
    let shared = Arc::get_mut(&mut layer.shared).expect("a backend nobody cloned");
    shared.names = NameCache::new(shared.settings.name_cache_ttl, limit);
    layer
}

/// The stored form of `name` under the test key, for a share with the
/// default threshold.
pub(super) fn stored_form(name: &str) -> StoredName {
    encode_name(&key_schedule(), name, 255).expect("a valid name")
}

/// The name an inner backend stores `name` under.
pub(super) fn stored_name(name: &str) -> String {
    stored_form(name).entry
}

/// The path, backslash separated, that an inner backend stores the client
/// path `plain` under.
pub(super) fn stored_at(plain: &str) -> String {
    plain
        .split('\\')
        .filter(|name| !name.is_empty())
        .map(stored_name)
        .collect::<Vec<_>>()
        .join("\\")
}

/// Adds the file or directory `plain`, and the directories above it, to the
/// store of `files` under encrypted names. The long names among them get
/// their side objects. A file holds `contents`; `None` makes a directory.
fn seed(files: &MemFsBackend, plain: &str, contents: Option<&[u8]>) {
    let names: Vec<_> = plain.split('\\').collect();
    let mut dir = String::new();
    for (index, name) in names.iter().enumerate() {
        let stored = stored_form(name);
        let beside = |name: &str| {
            if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}\\{name}")
            }
        };
        let at = beside(&stored.entry);
        match contents {
            Some(bytes) if index + 1 == names.len() => files.clone().with_file(&at, bytes),
            _ => files.clone().with_dir(&at),
        };
        if let Some(side) = &stored.side_object {
            files.clone().with_file(&beside(&side.name), &side.content);
        }
        dir = at;
    }
}

/// Adds the directory `plain` to the store of `files` under encrypted names.
pub(super) fn seed_dir(files: &MemFsBackend, plain: &str) {
    seed(files, plain, None);
}

/// Adds the file `plain` to the store of `files` under encrypted names, with
/// the stored bytes `bytes`.
pub(super) fn seed_file(files: &MemFsBackend, plain: &str, bytes: &[u8]) {
    seed(files, plain, Some(bytes));
}

/// A name whose stored form is a long entry and a side object.
pub(super) fn long_name(fill: &str) -> String {
    fill.repeat(150)
}

/// Puts the side object of the long name `name` into the stored directory
/// `dir` of `files`, with no entry. Returns the path of the object.
pub(super) fn seed_orphan(files: &MemFsBackend, dir: &str, name: &str) -> String {
    let side = stored_form(name).side_object.expect("a long name");
    let at = if dir.is_empty() {
        side.name
    } else {
        format!("{dir}\\{}", side.name)
    };
    files.clone().with_file(&at, &side.content);
    at
}

/// An error for a fault to answer with.
pub(super) fn injected() -> SmbError {
    SmbError::Io(io::Error::other("injected"))
}

/// The snapshot holds `name` under the stored name it encrypts to.
pub(super) fn has(names: &Snapshot, name: &str) -> bool {
    names.entry(name, &stored_name(name)).is_some()
}

/// A word in the plaintext of each name that `sealed_invalid_names` makes.
/// Nothing a listing or a watch logs holds it.
pub(super) const PRIVATE_WORD: &str = "secret";

/// Stored names sealed under the key of the share whose plaintexts are not
/// valid names.
pub(super) fn sealed_invalid_names() -> Vec<String> {
    ["slash/secret", "bell\u{7}secret"]
        .map(|plain| encode_unchecked(&key_schedule(), plain))
        .to_vec()
}

/// Puts into the root of `files` the stored names that no listing shows, besides
/// the marker: the side object of a long name that has no entry, and names that
/// are not the share's. Returns the names that are not the share's.
pub(super) fn seed_hidden_names(files: &MemFsBackend) -> Vec<String> {
    let orphan = "o".repeat(150);
    seed_file(files, &orphan, b"");
    files.remove(&stored_form(&orphan).entry);
    let other_key = encode_name(&other_key_schedule(), "other", 255)
        .expect("a valid name")
        .entry;
    let mut foreign = vec![
        "junk".to_string(),
        "UPPER-case.txt".to_string(),
        "a".repeat(28),
        format!("{}.n.n", "a".repeat(32)),
        other_key,
    ];
    foreign.extend(sealed_invalid_names());
    for name in &foreign {
        files.clone().with_file(name, b"");
    }
    foreign
}

/// Opens `name` in `layer` in a task, with write access and `intent`.
pub(super) fn spawn_open<B: ShareBackend>(
    layer: &EncryptedBackend<B>,
    name: &str,
    intent: OpenIntent,
) -> JoinHandle<OpenResult<B>> {
    let layer = layer.clone();
    let name = path(name);
    tokio::spawn(async move { layer.open_handle(&name, opts(intent)).await })
}

/// The two handles hold one node.
pub(super) fn shares_node<B: ShareBackend>(a: &EncryptedHandle<B>, b: &EncryptedHandle<B>) -> bool {
    Arc::ptr_eq(a.node(), b.node())
}

/// Opens `name` in `layer` with write access and `intent`.
pub(super) async fn open<B: ShareBackend>(
    layer: &EncryptedBackend<B>,
    name: &str,
    intent: OpenIntent,
) -> (EncryptedHandle<B>, OpenAction) {
    layer
        .open_handle(&path(name), opts(intent))
        .await
        .unwrap_or_else(|error| panic!("open {name} {intent:?}: {error:?}"))
}

/// Opens the existing file `name` in `layer`.
pub(super) async fn open_file<B: ShareBackend>(
    layer: &EncryptedBackend<B>,
    name: &str,
) -> EncryptedHandle<B> {
    open(layer, name, OpenIntent::Open).await.0
}

/// Opens the existing directory `name` in `layer`.
pub(super) async fn open_dir<B: ShareBackend>(
    layer: &EncryptedBackend<B>,
    name: &str,
) -> EncryptedHandle<B> {
    open_dir_as(layer, name, OpenIntent::Open).await.0
}

/// Opens the directory `name` in `layer` with `intent`.
pub(super) async fn open_dir_as<B: ShareBackend>(
    layer: &EncryptedBackend<B>,
    name: &str,
    intent: OpenIntent,
) -> (EncryptedHandle<B>, OpenAction) {
    layer
        .open_handle(&path(name), dir_opts(intent))
        .await
        .unwrap_or_else(|error| panic!("open directory {name} {intent:?}: {error:?}"))
}

/// The error of the open of the file `name` with `intent`.
pub(super) async fn refused<B: ShareBackend>(
    layer: &EncryptedBackend<B>,
    name: &str,
    intent: OpenIntent,
) -> SmbError {
    match layer.open_handle(&path(name), opts(intent)).await {
        Err(error) => error,
        Ok(_) => panic!("open {name} {intent:?} succeeded"),
    }
}

/// The error of the open of the directory `name` with `intent`.
pub(super) async fn refused_dir<B: ShareBackend>(
    layer: &EncryptedBackend<B>,
    name: &str,
    intent: OpenIntent,
) -> SmbError {
    match layer.open_handle(&path(name), dir_opts(intent)).await {
        Err(error) => error,
        Ok(_) => panic!("open directory {name} {intent:?} succeeded"),
    }
}

/// Lets every task that can make progress run until it waits.
pub(super) async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// The stored bytes of a file that holds `plain`: its header for `shift` and
/// the file id of `file_id`, then the sealed blocks. Block `i` has a nonce of
/// 12 bytes, each equal to `i % 255 + 1`.
pub(super) fn stored_file(keys: &KeySchedule, shift: BlockShift, plain: &[u8]) -> Vec<u8> {
    stored_file_with_id(keys, shift, file_id(), plain)
}

/// The stored bytes of a file that holds `plain`, in blocks of the default
/// size.
pub(super) fn stored_bytes(plain: &[u8]) -> Vec<u8> {
    stored_file(&key_schedule(), BlockShift::DEFAULT, plain)
}

/// `stored_file` for the file id `id`.
pub(super) fn stored_file_with_id(
    keys: &KeySchedule,
    shift: BlockShift,
    id: [u8; 16],
    plain: &[u8],
) -> Vec<u8> {
    let header = Header::new(shift, id).unwrap();
    let cipher = FileCipher::new(keys, header);
    let mut stored = header.as_bytes().to_vec();
    for (index, block) in plain.chunks(shift.block_len()).enumerate() {
        let nonce = [u8::try_from(index % 255 + 1).unwrap(); NONCE_LEN];
        let at = stored.len();
        stored.resize(at + block.len() + OVERHEAD, 0);
        cipher
            .seal_block(index as u64, &nonce, block, &mut stored[at..])
            .unwrap();
    }
    stored
}

/// The stored bytes of a file whose first block of `len` bytes is a hole.
pub(super) fn stored_hole(shift: BlockShift, len: usize) -> Vec<u8> {
    let header = Header::new(shift, file_id()).unwrap();
    let mut stored = header.as_bytes().to_vec();
    stored.resize(HEADER_LEN + len + OVERHEAD, 0);
    stored
}

/// Blocks of `1 << BITS` bytes, which the tests of file contents use.
pub(super) const BITS: u8 = 13;
/// Plaintext bytes of a full block.
pub(super) const B: usize = 1 << BITS;
pub(super) const H: usize = HEADER_LEN;

/// The block size of `BITS`.
pub(super) fn shift() -> BlockShift {
    BlockShift::new(BITS).unwrap()
}

/// The stored bytes of a file that holds `plain`, in blocks of `B` bytes.
pub(super) fn stored(plain: &[u8]) -> Vec<u8> {
    stored_file(&key_schedule(), shift(), plain)
}

/// A backend with blocks of `B` bytes over `inner`.
pub(super) async fn layer_over<I: ShareBackend>(inner: I) -> EncryptedBackend<I> {
    clear_blocks(inner, shift()).await
}

/// A backend over a store that holds the file `f` with the stored bytes
/// `bytes`, behind `Faulty`.
pub(super) async fn faulty_file(
    bytes: &[u8],
) -> (
    MemFsBackend,
    Faulty<MemFsBackend>,
    EncryptedBackend<Faulty<MemFsBackend>>,
) {
    faulty_file_in(shift(), bytes).await
}

/// `faulty_file` with blocks of `shift`.
pub(super) async fn faulty_file_in(
    shift: BlockShift,
    bytes: &[u8],
) -> (
    MemFsBackend,
    Faulty<MemFsBackend>,
    EncryptedBackend<Faulty<MemFsBackend>>,
) {
    let files = MemFsBackend::new();
    let faulty = Faulty::new(files.clone());
    let layer = clear_blocks(faulty.clone(), shift).await;
    files.clone().with_file("f", bytes);
    (files, faulty, layer)
}

/// Draws from the OS and counts the draws.
#[derive(Default)]
pub(super) struct Counting {
    /// Number of nonces in each draw.
    pub(super) draws: Vec<usize>,
    /// The file ids drawn.
    pub(super) ids: usize,
}

impl Random for Counting {
    fn nonces(&mut self, nonces: &mut [[u8; NONCE_LEN]]) -> Result<(), getrandom::Error> {
        self.draws.push(nonces.len());
        random_nonces(nonces)
    }

    fn file_id(&mut self) -> Result<[u8; FILE_ID_LEN], getrandom::Error> {
        self.ids += 1;
        random_file_id()
    }
}

/// A generator that does not answer.
pub(super) struct Down;

impl Random for Down {
    fn nonces(&mut self, _: &mut [[u8; NONCE_LEN]]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNEXPECTED)
    }

    fn file_id(&mut self) -> Result<[u8; FILE_ID_LEN], getrandom::Error> {
        Err(getrandom::Error::UNEXPECTED)
    }
}

/// Stored bytes of a full block of `B` bytes.
pub(super) const C: usize = B + OVERHEAD;

/// Where block `index` starts in the stored file.
pub(super) fn at(index: usize) -> usize {
    H + index * C
}

/// The stored size of a file of `logical` bytes.
pub(super) fn stored_len(logical: usize) -> usize {
    usize::try_from(stored_size(shift(), logical as u64).unwrap()).unwrap()
}

/// A new file `f` in a backend behind `Faulty`.
pub(super) async fn new_file() -> (
    MemFsBackend,
    Faulty<MemFsBackend>,
    EncryptedHandle<Faulty<MemFsBackend>>,
) {
    let files = MemFsBackend::new();
    let faulty = Faulty::new(files.clone());
    let layer = layer_over(faulty.clone()).await;
    let (handle, action) = open(&layer, "f", OpenIntent::Create).await;
    assert_eq!(action, OpenAction::Created);
    (files, faulty, handle)
}

/// Everything `handle` reads from the start.
pub(super) async fn read_all<H: Handle>(handle: &H) -> Vec<u8> {
    handle.read(0, u32::MAX).await.unwrap().to_vec()
}

/// The output of `call`, which ends without waiting for the lock of the
/// file.
pub(super) async fn assert_no_wait<T>(call: impl Future<Output = T>) -> T {
    tokio::select! {
        biased;
        output = call => output,
        () = std::future::ready(()) => panic!("the call waited for the lock"),
    }
}

/// Polls `call` until a call is parked at `gate`, then drops it.
pub(super) async fn drop_at<T>(gate: &Gate, call: impl Future<Output = SmbResult<T>>) {
    let mut call = Box::pin(call);
    tokio::select! {
        biased;
        _ = &mut call => panic!("the call ended before it reached the gate"),
        () = gate.reached() => {}
    }
}

/// The inner writes made since `from`.
pub(super) fn writes_since(faulty: &Faulty<MemFsBackend>, from: usize) -> Vec<(u64, usize)> {
    faulty.write_calls().split_off(from)
}

/// Fails the next open of an entry called `name`.
pub(super) fn fail_open_of(faulty: &Faulty<MemFsBackend>, name: &str) {
    let name = name.to_string();
    faulty.fail_open(
        1,
        move |at, _| at.file_name() == Some(name.as_str()),
        injected(),
    );
}

/// Bytes in the partial last block of the old file in the edit tests.
pub(super) const KEPT: usize = 100;

/// A write of `len` bytes at `offset`, or a truncate to `len` bytes.
#[derive(Clone, Copy)]
pub(super) enum Edit {
    Write { offset: usize, len: usize },
    Truncate { len: usize },
}

/// Makes `edit` through `handle`. A write stores `pattern(len, 2)`.
pub(super) async fn perform<H: Handle>(handle: &H, edit: Edit) -> SmbResult<()> {
    match edit {
        Edit::Write { offset, len } => handle
            .write(offset as u64, &pattern(len, 2))
            .await
            .map(|_| ()),
        Edit::Truncate { len } => handle.truncate(len as u64).await,
    }
}

/// `plain` as a file of `len` bytes: cut, or followed by zeros.
pub(super) fn resized(plain: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = plain.to_vec();
    bytes.resize(len, 0);
    bytes
}

/// The file `plain` after `edit`.
pub(super) fn edited(plain: &[u8], edit: Edit) -> Vec<u8> {
    match edit {
        Edit::Write { offset, len } => {
            let mut bytes = plain.to_vec();
            apply(&mut bytes, offset, &pattern(len, 2));
            bytes
        }
        Edit::Truncate { len } => resized(plain, len),
    }
}

/// The nonce of the block that starts at `start` in `bytes`.
pub(super) fn nonce_at(bytes: &[u8], start: usize) -> [u8; NONCE_LEN] {
    bytes[start..start + NONCE_LEN].try_into().unwrap()
}

/// A backend over a store that holds the file `f` with the stored bytes
/// `bytes`, behind `Gated`.
pub(super) async fn gated_file(
    bytes: &[u8],
) -> (
    MemFsBackend,
    Gated<MemFsBackend>,
    EncryptedBackend<Gated<MemFsBackend>>,
) {
    let files = MemFsBackend::new();
    let gated = Gated::new(files.clone());
    let layer = layer_over(gated.clone()).await;
    files.clone().with_file("f", bytes);
    (files, gated, layer)
}

/// Reads that asked for the header.
pub(super) fn header_reads<I: ShareBackend>(faulty: &Faulty<I>) -> usize {
    faulty
        .reads()
        .iter()
        .filter(|&&(offset, _)| offset == 0)
        .count()
}

/// Reads that asked for blocks.
pub(super) fn block_reads<I: ShareBackend>(faulty: &Faulty<I>) -> Vec<(u64, u32)> {
    faulty
        .reads()
        .into_iter()
        .filter(|&(offset, _)| offset != 0)
        .collect()
}

#[track_caller]
pub(super) fn assert_io<T: Debug>(result: SmbResult<T>, kind: io::ErrorKind) {
    match result {
        Err(SmbError::Io(error)) => assert_eq!(error.kind(), kind),
        other => panic!("expected an Io error of kind {kind:?}, got {other:?}"),
    }
}

/// `result` is an error of the same variant as `expected`.
#[track_caller]
pub(super) fn assert_err<T: Debug>(result: SmbResult<T>, expected: SmbError) {
    match result {
        Err(error) if mem::discriminant(&error) == mem::discriminant(&expected) => {}
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

/// The stored marker of `files`.
pub(super) fn marker_bytes(files: &MemFsBackend) -> Vec<u8> {
    files.contents(MARKER_NAME).expect("the root has a marker")
}

/// The settings in the marker of `files`, which `key` authenticates.
pub(super) fn marker_settings(files: &MemFsBackend) -> MarkerSettings {
    parse_marker(&marker_bytes(files), &key_schedule()).expect("a marker of the key")
}

/// `files` as an inner backend that reports itself read-only.
pub(super) fn read_only(files: &MemFsBackend) -> Reporting<MemFsBackend> {
    let caps = BackendCapabilities {
        is_read_only: true,
        ..files.capabilities()
    };
    Reporting::new(files.clone(), caps)
}

#[track_caller]
pub(super) fn assert_mismatch(error: &EncryptionError, setting: &str) {
    assert!(
        matches!(error, EncryptionError::SettingMismatch { setting: got } if *got == setting),
        "expected a mismatch of `{setting}`, got {error:?}"
    );
}

#[track_caller]
pub(super) fn assert_invalid(error: &EncryptionError, setting: &str) {
    assert!(
        matches!(error, EncryptionError::InvalidSetting { setting: got } if *got == setting),
        "expected `{setting}` to be invalid, got {error:?}"
    );
}

#[track_caller]
pub(super) fn assert_key_mismatch(error: &EncryptionError) {
    assert!(
        matches!(error, EncryptionError::KeyMismatch),
        "expected a key mismatch, got {error:?}"
    );
}

/// `files` as an inner backend that reports case-sensitive names.
pub(super) fn exact_names(files: &MemFsBackend) -> Reporting<MemFsBackend> {
    let caps = BackendCapabilities {
        case_sensitive: true,
        ..files.capabilities()
    };
    Reporting::new(files.clone(), caps)
}

/// Wraps `inner` and reports `caps` and `volume` in place of its own. When
/// `caps` say read-only, an open that would change the store fails with
/// `AccessDenied`.
#[derive(Clone)]
pub(super) struct Reporting<B> {
    inner: B,
    caps: BackendCapabilities,
    volume: Option<VolumeInfo>,
}

impl<B> Reporting<B> {
    pub(super) fn new(inner: B, caps: BackendCapabilities) -> Self {
        Self {
            inner,
            caps,
            volume: None,
        }
    }

    pub(super) fn with_volume(mut self, volume: VolumeInfo) -> Self {
        self.volume = Some(volume);
        self
    }
}

#[async_trait]
impl<B: ShareBackend> ShareBackend for Reporting<B> {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let writes = opts.write || opts.write_attributes || opts.delete_on_close;
        if self.caps.is_read_only && (writes || opts.intent != OpenIntent::Open) {
            return Err(SmbError::AccessDenied);
        }
        self.inner.open(path, opts).await
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.inner.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.inner.rename(from, to, replace_if_exists).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.caps
    }

    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        match &self.volume {
            Some(volume) => Ok(volume.clone()),
            None => self.inner.volume_info().await,
        }
    }
}

/// Wraps `inner` and refuses to unlink a directory that holds entries, with
/// `NotEmpty`.
#[derive(Clone)]
pub(super) struct Strict<B> {
    inner: B,
}

impl<B> Strict<B> {
    pub(super) fn new(inner: B) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<B: ShareBackend> ShareBackend for Strict<B> {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.inner.open(path, opts).await
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        if let Ok((handle, _)) = self.inner.open(path, dir_opts(OpenIntent::Open)).await {
            let listed = handle.list_dir(None).await;
            handle.close().await?;
            if !listed?.is_empty() {
                return Err(SmbError::NotEmpty);
            }
        }
        self.inner.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.inner.rename(from, to, replace_if_exists).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }
}

/// A directory handle that reports entries and lists none, as an inner
/// backend does when it hides some.
pub(super) struct Hiding;

#[async_trait]
impl Handle for Hiding {
    async fn read(&self, _offset: u64, _len: u32) -> SmbResult<Bytes> {
        Err(SmbError::NotSupported)
    }

    async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
        Err(SmbError::NotSupported)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        Ok(FileInfo::new(""))
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Ok(())
    }

    async fn set_attributes(&self, _attributes: u32) -> SmbResult<()> {
        Ok(())
    }

    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Ok(Vec::new())
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        Ok(false)
    }
}

/// The names of `entries`, sorted.
pub(super) fn names(entries: &[DirEntry]) -> Vec<String> {
    let mut names: Vec<_> = entries
        .iter()
        .map(|entry| entry.info.name.clone())
        .collect();
    names.sort();
    names
}

/// Name, end of file, allocation size and EA size of each entry, sorted.
pub(super) fn summary(entries: &[DirEntry]) -> Vec<(String, u64, u64, u32)> {
    let mut summary: Vec<_> = entries
        .iter()
        .map(|entry| {
            let info = &entry.info;
            (
                info.name.clone(),
                info.end_of_file,
                info.allocation_size,
                info.ea_size,
            )
        })
        .collect();
    summary.sort();
    summary
}

/// A backend over a store that parks listings, as `parked` makes one.
pub(super) type GatedLayer = EncryptedBackend<Gated<MemFsBackend>>;

/// A store with `a.txt` in the root, a backend over it that parks the next
/// listing of the root once the inner backend has answered, and the gate.
pub(super) async fn parked() -> (MemFsBackend, GatedLayer, Gate) {
    let files = MemFsBackend::new();
    let gated = Gated::new(files.clone());
    let layer = names_over(gated.clone()).await;
    seed_file(&files, "a.txt", b"");
    let gate = gated.arm_after_at(Op::ListDir, "");
    (files, layer, gate)
}

/// A change of `kind` to the entry `name`, which is not a directory.
pub(super) fn change(name: &str, kind: DirChangeKind) -> DirChange {
    DirChange::new(name, kind, false)
}

/// The rename of `from` to `to`.
pub(super) fn renamed(from: &str, to: &str) -> DirChange {
    change(
        to,
        DirChangeKind::Renamed {
            from: from.to_string(),
        },
    )
}

/// A watch that returns the batches it was given and then stops.
pub(super) struct Script {
    batches: VecDeque<Vec<DirChange>>,
}

impl Script {
    pub(super) fn new(batches: Vec<Vec<DirChange>>) -> Self {
        Self {
            batches: batches.into(),
        }
    }
}

#[async_trait]
impl DirWatch for Script {
    async fn next(&mut self) -> Option<Vec<DirChange>> {
        self.batches.pop_front()
    }
}

/// A watch that has its batch only once the test opens its gate.
pub(super) struct Parked {
    gate: Arc<Notify>,
    batch: Option<Vec<DirChange>>,
}

impl Parked {
    pub(super) fn new(gate: Arc<Notify>, batch: Vec<DirChange>) -> Self {
        Self {
            gate,
            batch: Some(batch),
        }
    }
}

#[async_trait]
impl DirWatch for Parked {
    async fn next(&mut self) -> Option<Vec<DirChange>> {
        self.gate.notified().await;
        self.batch.take()
    }
}

/// What an open of a hidden path answers.
#[derive(Clone, Copy)]
enum Answer {
    NotFound,
    PathNotFound,
}

/// An inner backend whose opens, unlinks and renames of chosen paths fail
/// while its listings still show them.
#[derive(Clone)]
pub(super) struct Hidden {
    inner: MemFsBackend,
    paths: Arc<Mutex<HashMap<String, Answer>>>,
}

impl Hidden {
    pub(super) fn new(inner: MemFsBackend) -> Self {
        Self {
            inner,
            paths: Arc::default(),
        }
    }

    /// Calls on `stored` answer `NotFound`.
    pub(super) fn hide(&self, stored: &str) {
        let mut paths = self.paths.lock().unwrap();
        paths.insert(stored.to_string(), Answer::NotFound);
    }

    /// Calls on `stored` answer `PathNotFound`, as if a directory above it
    /// were gone.
    pub(super) fn cut_off(&self, stored: &str) {
        let mut paths = self.paths.lock().unwrap();
        paths.insert(stored.to_string(), Answer::PathNotFound);
    }

    pub(super) fn show(&self, stored: &str) {
        self.paths.lock().unwrap().remove(stored);
    }

    /// What a call on `at` answers, if it is hidden.
    fn refusal(&self, at: &SmbPath) -> SmbResult<()> {
        let answer = self
            .paths
            .lock()
            .unwrap()
            .get(&at.display_backslash())
            .copied();
        match answer {
            Some(Answer::NotFound) => Err(SmbError::NotFound),
            Some(Answer::PathNotFound) => Err(SmbError::PathNotFound),
            None => Ok(()),
        }
    }
}

#[async_trait]
impl ShareBackend for Hidden {
    async fn open(
        &self,
        at: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.refusal(at)?;
        self.inner.open(at, opts).await
    }

    async fn unlink(&self, at: &SmbPath) -> SmbResult<()> {
        self.refusal(at)?;
        self.inner.unlink(at).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
        self.refusal(from)?;
        self.inner.rename(from, to, replace).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }
}
