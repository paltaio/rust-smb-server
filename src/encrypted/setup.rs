//! What `build` does to the root of the inner backend: finds the marker of a
//! share, or writes one.

use super::error::EncryptionError;
use super::format::{BlockShift, MARKER_LEN, MARKER_NAME, SHARE_ID_LEN};
use super::inner::{close_after_reading, read_full, write_full};
use super::keys::KeySchedule;
use super::marker::{MarkerError, MarkerSettings, build_marker, parse_marker};
use super::restore;
use crate::backend::{Handle, OpenIntent, OpenOptions, ShareBackend};
use crate::error::SmbError;
use crate::path::SmbPath;

/// Long-name threshold of a new share that encrypts names.
const DEFAULT_LONG_NAME_THRESHOLD: u8 = 255;

/// Fills a buffer with random bytes.
pub(super) type FillRandom = fn(&mut [u8]) -> Result<(), getrandom::Error>;

/// The settings the builder was given, each checked against its range.
#[derive(Clone, Copy, Debug)]
pub(super) struct Requested {
    pub(super) encrypt_names: Option<bool>,
    pub(super) block_shift: Option<BlockShift>,
    pub(super) long_name_threshold: Option<u8>,
}

impl Requested {
    /// The settings of a new share: those given, else the defaults.
    fn for_new_share(&self) -> MarkerSettings {
        let encrypt_names = self.encrypt_names.unwrap_or(true);
        MarkerSettings {
            encrypt_names,
            block_shift: self.block_shift.unwrap_or(BlockShift::DEFAULT),
            long_name_threshold: if encrypt_names {
                self.long_name_threshold
                    .unwrap_or(DEFAULT_LONG_NAME_THRESHOLD)
            } else {
                0
            },
        }
    }

    /// The settings of the share whose marker holds `marker`. Fails when a
    /// setting that was given differs.
    fn against(&self, marker: MarkerSettings) -> Result<MarkerSettings, EncryptionError> {
        let mismatch = |setting| Err(EncryptionError::SettingMismatch { setting });
        if self
            .encrypt_names
            .is_some_and(|on| on != marker.encrypt_names)
        {
            return mismatch("encrypt_names");
        }
        if self
            .block_shift
            .is_some_and(|shift| shift != marker.block_shift)
        {
            return mismatch("block_size");
        }
        if self
            .long_name_threshold
            .is_some_and(|chars| chars != marker.long_name_threshold)
        {
            return mismatch("long_name_threshold");
        }
        Ok(marker)
    }
}

fn marker_path() -> SmbPath {
    MARKER_NAME
        .parse()
        .expect("the marker name is a valid path component")
}

fn marker_error(error: MarkerError) -> EncryptionError {
    match error {
        MarkerError::Invalid => EncryptionError::MarkerInvalid,
        MarkerError::Unsupported(version) => EncryptionError::UnsupportedFormat { version },
        MarkerError::KeyMismatch => EncryptionError::KeyMismatch,
    }
}

/// The settings of the share in the root of `inner`, from its marker or, for
/// a share that has none, from `requested`. A new share and a restored one
/// get a marker written, unless `inner` is read-only.
pub(super) async fn establish<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    requested: &Requested,
    restore_marker: bool,
    fill: FillRandom,
) -> Result<MarkerSettings, EncryptionError> {
    let root_opts = OpenOptions {
        directory: true,
        ..OpenOptions::default()
    };
    let (root, _) = inner
        .open(&SmbPath::root(), root_opts)
        .await
        .map_err(EncryptionError::Backend)?;
    let settled = settle(inner, root.as_ref(), keys, requested, restore_marker, fill).await;
    close_after_reading(root).await;
    settled
}

async fn settle<B: ShareBackend>(
    inner: &B,
    root: &dyn Handle,
    keys: &KeySchedule,
    requested: &Requested,
    restore_marker: bool,
    fill: FillRandom,
) -> Result<MarkerSettings, EncryptionError> {
    if let Some(marker) = read_marker(inner, keys).await? {
        return requested.against(marker);
    }
    let entries = root
        .list_dir(None)
        .await
        .map_err(EncryptionError::Backend)?;
    if entries.iter().any(|entry| entry.info.name == MARKER_NAME) {
        return settings_after_race(inner, keys, requested).await;
    }
    let settings = requested.for_new_share();
    if !entries.is_empty() {
        if !restore_marker {
            return Err(EncryptionError::MarkerMissing);
        }
        restore::check(inner, keys, entries, &settings).await?;
    }
    if inner.capabilities().is_read_only {
        return Ok(settings);
    }
    if write_marker(inner, keys, &settings, fill).await? {
        return Ok(settings);
    }
    settings_after_race(inner, keys, requested).await
}

/// The settings of the marker that another build wrote after this one found
/// none.
async fn settings_after_race<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    requested: &Requested,
) -> Result<MarkerSettings, EncryptionError> {
    let marker = read_marker(inner, keys)
        .await?
        .ok_or(EncryptionError::Backend(SmbError::NotFound))?;
    requested.against(marker)
}

/// The settings in the marker, or `None` when the root has no marker.
async fn read_marker<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
) -> Result<Option<MarkerSettings>, EncryptionError> {
    let handle = match inner.open(&marker_path(), OpenOptions::default()).await {
        Ok((handle, _)) => handle,
        Err(SmbError::NotFound) => return Ok(None),
        Err(error) => return Err(EncryptionError::Backend(error)),
    };
    let parsed = parse_stored_marker(handle.as_ref(), keys).await;
    close_after_reading(handle).await;
    parsed.map(Some)
}

async fn parse_stored_marker(
    handle: &dyn Handle,
    keys: &KeySchedule,
) -> Result<MarkerSettings, EncryptionError> {
    let info = handle.stat().await.map_err(EncryptionError::Backend)?;
    if info.is_directory || info.end_of_file != MARKER_LEN as u64 {
        return Err(EncryptionError::MarkerInvalid);
    }
    let bytes = read_full(handle, 0, MARKER_LEN)
        .await
        .map_err(EncryptionError::Backend)?;
    parse_marker(&bytes, keys).map_err(marker_error)
}

/// Creates the marker for `settings` with a random share id. Returns `false`
/// when the root already has one. A marker whose write fails is removed
/// again; one that was written in full stays when the flush or the close
/// fails.
async fn write_marker<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    settings: &MarkerSettings,
    fill: FillRandom,
) -> Result<bool, EncryptionError> {
    let mut share_id = [0u8; SHARE_ID_LEN];
    fill(&mut share_id).map_err(EncryptionError::Random)?;
    let marker = build_marker(settings, &share_id, keys)
        .expect("the threshold was checked against the names setting");

    let path = marker_path();
    let opts = OpenOptions {
        write: true,
        intent: OpenIntent::Create,
        ..OpenOptions::default()
    };
    let handle = match inner.open(&path, opts).await {
        Ok((handle, _)) => handle,
        Err(SmbError::Exists) => return Ok(false),
        Err(error) => return Err(EncryptionError::Backend(error)),
    };
    if let Err(error) = write_full(handle.as_ref(), 0, &marker).await {
        let _ = handle.close().await;
        let _ = inner.unlink(&path).await;
        return Err(EncryptionError::Backend(error));
    }
    let flushed = handle.flush().await;
    let closed = handle.close().await;
    flushed.and(closed).map_err(EncryptionError::Backend)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::backend::{EncryptedBackend, Settings};
    use super::super::builder::EncryptedBackendBuilder;
    use super::super::testing::{
        assert_key_mismatch, assert_mismatch, build, key, key_schedule, marker_bytes,
        marker_settings, other_key, read_only,
    };
    use super::*;
    use crate::tests::faulty::Faulty;
    use crate::tests::gated::{Gate, Gated, Op};
    use crate::tests::memfs::MemFsBackend;

    type GatedBuilder = EncryptedBackendBuilder<Gated<MemFsBackend>>;
    type Fail = fn(&Faulty<MemFsBackend>);

    fn defaults() -> MarkerSettings {
        MarkerSettings {
            encrypt_names: true,
            block_shift: BlockShift::DEFAULT,
            long_name_threshold: 255,
        }
    }

    /// The settings in force of a backend with the given marker values and
    /// the others at their defaults.
    fn settings(encrypt_names: bool, shift: u8, long_name_threshold: u8) -> Settings {
        Settings {
            encrypt_names,
            case_insensitive: encrypt_names,
            block_shift: BlockShift::new(shift).unwrap(),
            long_name_threshold,
            name_cache_ttl: Duration::from_secs(30),
        }
    }

    fn good_marker() -> [u8; MARKER_LEN] {
        build_marker(&defaults(), &[9; SHARE_ID_LEN], &key_schedule()).unwrap()
    }

    /// The error of a build over a root whose only entry is the marker file
    /// `bytes`.
    async fn failure_with_marker(bytes: &[u8]) -> EncryptionError {
        let files = MemFsBackend::new().with_file(MARKER_NAME, bytes);
        build(&files, |builder| builder).await.unwrap_err()
    }

    #[track_caller]
    fn assert_marker_invalid(error: &EncryptionError, what: &str) {
        assert!(
            matches!(error, EncryptionError::MarkerInvalid),
            "{what}: expected an invalid marker, got {error:?}"
        );
    }

    #[track_caller]
    fn assert_backend_error(
        error: &EncryptionError,
        what: &str,
        expected: impl Fn(&SmbError) -> bool,
    ) {
        assert!(
            matches!(error, EncryptionError::Backend(inner) if expected(inner)),
            "expected {what} from the inner backend, got {error:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_root_is_a_new_share_and_gets_a_marker() {
        let files = MemFsBackend::new();
        let backend = build(&files, |builder| builder).await.unwrap();
        assert_eq!(backend.shared.settings, settings(true, 16, 255));
        assert_eq!(marker_bytes(&files).len(), MARKER_LEN);
        assert_eq!(marker_settings(&files), defaults());
    }

    #[tokio::test]
    async fn every_share_gets_its_own_share_id() {
        let first = MemFsBackend::new();
        let second = MemFsBackend::new();
        build(&first, |builder| builder).await.unwrap();
        build(&second, |builder| builder).await.unwrap();
        let id = |files: &MemFsBackend| marker_bytes(files)[12..28].to_vec();
        assert_ne!(id(&first), id(&second));
        assert_ne!(id(&first), [0; SHARE_ID_LEN]);
    }

    #[tokio::test]
    async fn a_new_share_takes_the_settings_that_were_set() {
        let files = MemFsBackend::new();
        let backend = build(&files, |builder| {
            builder.block_size(8192).long_name_threshold(100)
        })
        .await
        .unwrap();
        assert_eq!(backend.shared.settings, settings(true, 13, 100));
        let marker = MarkerSettings {
            encrypt_names: true,
            block_shift: BlockShift::new(13).unwrap(),
            long_name_threshold: 100,
        };
        assert_eq!(marker_settings(&files), marker);

        let clear = MemFsBackend::new();
        let backend = build(&clear, |builder| builder.encrypt_names(false))
            .await
            .unwrap();
        assert_eq!(backend.shared.settings, settings(false, 16, 0));
        let marker = MarkerSettings {
            encrypt_names: false,
            block_shift: BlockShift::DEFAULT,
            long_name_threshold: 0,
        };
        assert_eq!(marker_settings(&clear), marker);
    }

    #[tokio::test]
    async fn an_existing_share_gives_its_settings_to_a_builder_that_sets_none() {
        let files = MemFsBackend::new();
        build(&files, |builder| {
            builder.block_size(131_072).long_name_threshold(100)
        })
        .await
        .unwrap();
        let written = marker_bytes(&files);

        let backend = build(&files, |builder| builder).await.unwrap();
        assert_eq!(backend.shared.settings, settings(true, 17, 100));
        assert_eq!(
            marker_bytes(&files),
            written,
            "the marker is never rewritten"
        );

        let clear = MemFsBackend::new();
        build(&clear, |builder| {
            builder.encrypt_names(false).block_size(8192)
        })
        .await
        .unwrap();
        let backend = build(&clear, |builder| builder).await.unwrap();
        assert_eq!(backend.shared.settings, settings(false, 13, 0));
    }

    #[tokio::test]
    async fn settings_equal_to_the_markers_are_accepted() {
        let files = MemFsBackend::new();
        build(&files, |builder| {
            builder.block_size(32_768).long_name_threshold(62)
        })
        .await
        .unwrap();
        let backend = build(&files, |builder| {
            builder
                .encrypt_names(true)
                .block_size(32_768)
                .long_name_threshold(62)
        })
        .await
        .unwrap();
        assert_eq!(backend.shared.settings, settings(true, 15, 62));
    }

    #[tokio::test]
    async fn a_setting_that_differs_from_the_markers_is_a_mismatch() {
        let files = MemFsBackend::new();
        build(&files, |builder| builder).await.unwrap();
        let written = marker_bytes(&files);

        let error = build(&files, |builder| builder.encrypt_names(false))
            .await
            .unwrap_err();
        assert_mismatch(&error, "encrypt_names");
        let error = build(&files, |builder| builder.block_size(8192))
            .await
            .unwrap_err();
        assert_mismatch(&error, "block_size");
        let error = build(&files, |builder| builder.long_name_threshold(100))
            .await
            .unwrap_err();
        assert_mismatch(&error, "long_name_threshold");
        assert_eq!(marker_bytes(&files), written, "the marker is kept");
    }

    #[tokio::test]
    async fn another_key_is_a_key_mismatch() {
        let files = MemFsBackend::new();
        build(&files, |builder| builder).await.unwrap();
        let error = EncryptedBackend::builder(files.clone(), other_key())
            .build()
            .await
            .unwrap_err();
        assert_key_mismatch(&error);
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_marker_of_another_length_is_invalid() {
        let good = good_marker();
        let longer = [good.as_slice(), &[0]].concat();
        for bytes in [&good[..MARKER_LEN - 1], longer.as_slice()] {
            let error = failure_with_marker(bytes).await;
            assert_marker_invalid(&error, &format!("{} bytes", bytes.len()));
        }
    }

    #[tokio::test]
    async fn a_marker_with_another_magic_is_invalid() {
        for at in [0, 7] {
            let mut bytes = good_marker();
            bytes[at] ^= 1;
            let error = failure_with_marker(&bytes).await;
            assert_marker_invalid(&error, &format!("byte {at}"));
        }
    }

    #[tokio::test]
    async fn a_marker_with_another_version_is_unsupported() {
        for version in [2, 255] {
            let mut bytes = good_marker();
            bytes[8] = version;
            let error = failure_with_marker(&bytes).await;
            assert!(
                matches!(error, EncryptionError::UnsupportedFormat { version: v } if v == version),
                "version {version}: expected an unsupported format, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_directory_named_like_the_marker_is_invalid() {
        let files = MemFsBackend::new().with_dir(MARKER_NAME);
        let error = build(&files, |builder| builder).await.unwrap_err();
        assert_marker_invalid(&error, "a directory");
    }

    #[tokio::test]
    async fn a_root_with_entries_and_no_marker_is_missing_its_marker() {
        let files = MemFsBackend::new().with_file("a", b"x");
        let error = build(&files, |builder| builder).await.unwrap_err();
        assert!(
            matches!(error, EncryptionError::MarkerMissing),
            "expected a missing marker, got {error:?}"
        );
        assert_eq!(files.contents(MARKER_NAME), None);
    }

    #[tokio::test]
    async fn restore_marker_changes_nothing_for_an_empty_root_or_a_root_with_a_marker() {
        let files = MemFsBackend::new();
        build(&files, |builder| builder.restore_marker())
            .await
            .unwrap();
        assert_eq!(marker_settings(&files), defaults());
        let written = marker_bytes(&files);
        files.clone().with_file("junk", b"not a share's file");
        build(&files, |builder| builder.restore_marker())
            .await
            .unwrap();
        assert_eq!(marker_bytes(&files), written);
    }

    #[tokio::test]
    async fn a_read_only_inner_backend_gets_no_marker() {
        let files = MemFsBackend::new();
        let backend = EncryptedBackend::builder(read_only(&files), key())
            .block_size(8192)
            .build()
            .await
            .unwrap();
        assert_eq!(backend.shared.settings, settings(true, 13, 255));
        assert_eq!(files.contents(MARKER_NAME), None);
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_read_only_inner_backend_reads_the_marker_it_has() {
        let files = MemFsBackend::new();
        build(&files, |builder| builder.block_size(8192))
            .await
            .unwrap();
        let backend = EncryptedBackend::builder(read_only(&files), key())
            .build()
            .await
            .unwrap();
        assert_eq!(backend.shared.settings, settings(true, 13, 255));
        let error = EncryptedBackend::builder(read_only(&files), key())
            .block_size(16_384)
            .build()
            .await
            .unwrap_err();
        assert_mismatch(&error, "block_size");
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_read_only_inner_backend_with_entries_and_no_marker_is_missing_its_marker() {
        let files = MemFsBackend::new().with_file("a", b"x");
        let error = EncryptedBackend::builder(read_only(&files), key())
            .build()
            .await
            .unwrap_err();
        assert!(
            matches!(error, EncryptionError::MarkerMissing),
            "expected a missing marker, got {error:?}"
        );
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn reads_and_writes_that_come_up_short_are_continued() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        faulty.short_reads(Some(7));
        faulty.short_writes(Some(10));
        EncryptedBackend::builder(faulty.clone(), key())
            .block_size(8192)
            .build()
            .await
            .unwrap();
        assert_eq!(marker_settings(&files).block_shift.get(), 13);
        assert_eq!(marker_bytes(&files).len(), MARKER_LEN);

        let again = EncryptedBackend::builder(faulty, key())
            .build()
            .await
            .unwrap();
        assert_eq!(again.shared.settings, settings(true, 13, 255));
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn an_inner_error_while_opening_the_root_or_the_marker_is_reported() {
        for nth in [1, 2] {
            let files = MemFsBackend::new();
            let faulty = Faulty::new(files.clone());
            faulty.fail_open(nth, |_, _| true, SmbError::AccessDenied);
            let error = EncryptedBackend::builder(faulty, key())
                .build()
                .await
                .unwrap_err();
            assert_backend_error(&error, &format!("AccessDenied on open {nth}"), |e| {
                matches!(e, SmbError::AccessDenied)
            });
            assert_eq!(files.contents(MARKER_NAME), None);
            assert_eq!(files.open_handles(), 0, "open {nth}");
        }
    }

    #[tokio::test]
    async fn an_inner_error_while_creating_the_marker_is_reported() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        faulty.fail_open(
            1,
            |_, opts| opts.intent == OpenIntent::Create,
            SmbError::DiskFull,
        );
        let error = EncryptedBackend::builder(faulty, key())
            .build()
            .await
            .unwrap_err();
        assert_backend_error(&error, "DiskFull", |e| matches!(e, SmbError::DiskFull));
        assert_eq!(files.contents(MARKER_NAME), None);
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_marker_that_could_not_be_written_in_full_is_removed() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        faulty.tear_write(1, 10, SmbError::DiskFull);
        let error = EncryptedBackend::builder(faulty.clone(), key())
            .build()
            .await
            .unwrap_err();
        assert_backend_error(&error, "DiskFull", |e| matches!(e, SmbError::DiskFull));
        assert_eq!(files.contents(MARKER_NAME), None, "the torn marker is gone");
        assert_eq!(files.open_handles(), 0);

        EncryptedBackend::builder(faulty, key())
            .build()
            .await
            .unwrap();
        assert_eq!(marker_settings(&files), defaults());
    }

    #[tokio::test]
    async fn a_marker_written_in_full_stays_when_the_flush_or_the_close_fails() {
        let failures: [(&str, Fail); 2] = [
            ("flush", |faulty| faulty.fail_flush(1, SmbError::DiskFull)),
            ("close", |faulty| faulty.fail_close(1, SmbError::DiskFull)),
        ];
        for (what, fail) in failures {
            let files = MemFsBackend::new();
            let faulty = Faulty::new(files.clone());
            fail(&faulty);
            let error = EncryptedBackend::builder(faulty.clone(), key())
                .build()
                .await
                .unwrap_err();
            assert_backend_error(&error, &format!("DiskFull on {what}"), |e| {
                matches!(e, SmbError::DiskFull)
            });
            assert_eq!(marker_bytes(&files).len(), MARKER_LEN, "{what}");
            assert_eq!(
                faulty.unlinks(),
                0,
                "the marker is not removed after a {what}"
            );
            assert_eq!(files.open_handles(), 0, "{what}");

            EncryptedBackend::builder(faulty, key())
                .build()
                .await
                .unwrap();
            assert_eq!(marker_settings(&files), defaults(), "{what}");
        }
    }

    #[tokio::test]
    async fn a_create_that_answers_exists_for_a_marker_that_is_not_there_fails() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        faulty.fail_open(
            1,
            |_, opts| opts.intent == OpenIntent::Create,
            SmbError::Exists,
        );
        let error = EncryptedBackend::builder(faulty, key())
            .build()
            .await
            .unwrap_err();
        assert_backend_error(&error, "NotFound", |e| matches!(e, SmbError::NotFound));
        assert_eq!(files.open_handles(), 0);
    }

    fn failing_fill(_: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNEXPECTED)
    }

    #[tokio::test]
    async fn a_failing_random_generator_is_reported_and_nothing_is_written() {
        let files = MemFsBackend::new();
        let requested = Requested {
            encrypt_names: None,
            block_shift: None,
            long_name_threshold: None,
        };
        let error = establish(&files, &key_schedule(), &requested, false, failing_fill)
            .await
            .unwrap_err();
        assert!(
            matches!(error, EncryptionError::Random(_)),
            "expected a random generator error, got {error:?}"
        );
        assert_eq!(files.contents(MARKER_NAME), None);
        assert_eq!(files.open_handles(), 0);
    }

    /// Parks the first build after the listing of the root answered.
    fn after_listing(gated: &Gated<MemFsBackend>) -> Gate {
        gated.arm_after(Op::ListDir)
    }

    /// Parks the first build after its look for the marker answered.
    fn after_marker_lookup(gated: &Gated<MemFsBackend>) -> Gate {
        gated.arm_after_at(Op::Open, MARKER_NAME)
    }

    /// Two builds over one empty root, the first parked at the gate that
    /// `park` arms until the second has finished.
    async fn race(
        park: fn(&Gated<MemFsBackend>) -> Gate,
        first: impl FnOnce(GatedBuilder) -> GatedBuilder + Send + 'static,
        second: impl FnOnce(GatedBuilder) -> GatedBuilder,
    ) -> (
        MemFsBackend,
        Result<EncryptedBackend<Gated<MemFsBackend>>, EncryptionError>,
    ) {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let gate = park(&gated);
        let parked = tokio::spawn({
            let gated = gated.clone();
            async move { first(EncryptedBackend::builder(gated, key())).build().await }
        });
        gate.reached().await;
        assert_eq!(files.contents(MARKER_NAME), None);
        second(EncryptedBackend::builder(gated, key()))
            .build()
            .await
            .unwrap();
        gate.release();
        let result = parked.await.unwrap();
        assert_eq!(files.open_handles(), 0);
        (files, result)
    }

    #[tokio::test]
    async fn a_build_that_loses_the_race_for_the_marker_takes_the_winners_settings() {
        let (files, result) = race(
            after_listing,
            |builder| builder,
            |builder| builder.block_size(8192),
        )
        .await;
        let first = result.unwrap();
        assert_eq!(first.shared.settings, settings(true, 13, 255));
        assert_eq!(marker_settings(&files).block_shift.get(), 13);
    }

    #[tokio::test]
    async fn a_build_that_finds_the_marker_in_the_listing_takes_the_winners_settings() {
        let (files, result) = race(
            after_marker_lookup,
            |builder| builder,
            |builder| builder.block_size(8192),
        )
        .await;
        let first = result.unwrap();
        assert_eq!(first.shared.settings, settings(true, 13, 255));
        assert_eq!(marker_settings(&files).block_shift.get(), 13);
    }

    #[tokio::test]
    async fn a_build_that_loses_the_race_for_the_marker_checks_its_own_settings() {
        let (files, result) = race(
            after_listing,
            |builder| builder.block_size(65_536),
            |builder| builder.block_size(8192),
        )
        .await;
        assert_mismatch(&result.unwrap_err(), "block_size");
        assert_eq!(marker_settings(&files).block_shift.get(), 13);
    }
}
