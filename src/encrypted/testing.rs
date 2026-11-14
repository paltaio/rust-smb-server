//! Fixtures shared by the unit tests.

use std::fmt::Debug;
use std::io;
use std::mem;
use std::time::Duration;

use async_trait::async_trait;
use zeroize::Zeroizing;

use super::backend::{EncryptedBackend, Settings};
use super::block::FileCipher;
use super::builder::EncryptedBackendBuilder;
use super::change::Random;
use super::error::EncryptionError;
use super::format::{BlockShift, FILE_ID_LEN, HEADER_LEN, MARKER_NAME, NONCE_LEN, OVERHEAD};
use super::handle::EncryptedHandle;
use super::header::Header;
use super::keys::KeySchedule;
use super::marker::{MarkerSettings, parse_marker};
use super::random::{random_file_id, random_nonces};
use super::size::stored_size;
use crate::backend::{
    BackendCapabilities, Handle, OpenAction, OpenIntent, OpenOptions, ShareBackend, VolumeInfo,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use crate::tests::faulty::Faulty;
use crate::tests::gated::{Gate, Gated};
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

/// A xorshift64 generator; `seed` must not be zero.
pub(super) fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
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
pub(super) async fn clear_over<B: ShareBackend>(inner: B) -> EncryptedBackend<B> {
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
    layer
        .open_handle(&path(name), dir_opts(OpenIntent::Open))
        .await
        .unwrap_or_else(|error| panic!("open directory {name}: {error:?}"))
        .0
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

/// `model` after `data` is written at `offset`.
pub(super) fn apply(model: &mut Vec<u8>, offset: usize, data: &[u8]) {
    if model.len() < offset + data.len() {
        model.resize(offset + data.len(), 0);
    }
    model[offset..offset + data.len()].copy_from_slice(data);
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
