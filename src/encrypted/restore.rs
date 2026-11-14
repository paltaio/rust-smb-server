//! The checks that let `build` write a new marker into a root that has
//! entries: they look for a name or a block that the key authenticates.

use std::collections::VecDeque;

use super::block::FileCipher;
use super::error::EncryptionError;
use super::format::{BlockShift, HEADER_LEN, OVERHEAD};
use super::header::Header;
use super::inner::{close_after_reading, is_missing, read_full, read_side_object};
use super::keys::KeySchedule;
use super::marker::MarkerSettings;
use super::names::{StoredKind, classify, decode_long, decode_short, side_object_name};
use super::size::logical_size;
use crate::backend::{DirEntry, Handle, OpenOptions, ShareBackend};
use crate::error::SmbError;
use crate::path::SmbPath;

/// Most entries the search for a file to check looks at.
const MAX_VISITED: usize = 10_000;

/// Checks the entries of the root, `entries`, and the files below it against
/// the key and the block size of `settings`.
///
/// With encrypted names, at least one entry of the root has to decode under
/// the key, and the search passes over entries whose names do not decode.
/// Then the first file that holds a block, found breadth first, has to have
/// a header of the block size and a first block that is a hole or verifies
/// under the key. A tree without such a file passes.
pub(super) async fn check<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    entries: Vec<DirEntry>,
    settings: &MarkerSettings,
) -> Result<(), EncryptionError> {
    if settings.encrypt_names && !any_name_decodes(inner, keys, &entries).await? {
        return Err(EncryptionError::KeyMismatch);
    }
    check_first_block(
        inner,
        keys,
        entries,
        settings.block_shift,
        settings.encrypt_names,
    )
    .await
}

/// Whether one of the root's `entries` is a name that decodes under the key.
async fn any_name_decodes<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    entries: &[DirEntry],
) -> Result<bool, EncryptionError> {
    let root = SmbPath::root();
    for entry in entries {
        if name_decodes(inner, keys, &root, &entry.info.name).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `name`, an entry of the directory `dir`, is a stored name that
/// decodes under the key.
async fn name_decodes<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    dir: &SmbPath,
    name: &str,
) -> Result<bool, EncryptionError> {
    match classify(name, dir.is_root()) {
        StoredKind::ShortCandidate => Ok(decode_short(keys, name).is_ok()),
        StoredKind::LongEntry => long_name_decodes(inner, keys, dir, name).await,
        StoredKind::Marker | StoredKind::SideObject | StoredKind::Foreign => Ok(false),
    }
}

/// Whether the long entry `entry` of `dir` has a side object that decodes.
async fn long_name_decodes<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    dir: &SmbPath,
    entry: &str,
) -> Result<bool, EncryptionError> {
    let Some(side_object) = side_object_name(entry) else {
        return Ok(false);
    };
    let Ok(path) = dir.join(&side_object) else {
        return Ok(false);
    };
    let Some(content) = read_side_object(inner, &path)
        .await
        .map_err(EncryptionError::Backend)?
    else {
        return Ok(false);
    };
    Ok(decode_long(keys, entry, &content).is_ok())
}

/// Whether the search passes over the entry.
async fn skipped<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    dir: &SmbPath,
    name: &str,
    names_encrypted: bool,
) -> Result<bool, EncryptionError> {
    if names_encrypted {
        return Ok(!name_decodes(inner, keys, dir, name).await?);
    }
    Ok(matches!(
        classify(name, dir.is_root()),
        StoredKind::Marker | StoredKind::SideObject
    ))
}

/// Searches the tree breadth first, starting with the root's `entries`, and
/// checks the first file that holds a block. Looks at no more than
/// `MAX_VISITED` entries.
async fn check_first_block<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    entries: Vec<DirEntry>,
    shift: BlockShift,
    names_encrypted: bool,
) -> Result<(), EncryptionError> {
    let mut visited = 0;
    let mut dirs: VecDeque<SmbPath> = VecDeque::new();
    let mut next = Some((SmbPath::root(), entries));
    loop {
        let (dir, entries) = match next.take() {
            Some(listing) => listing,
            None => {
                let Some(dir) = dirs.pop_front() else {
                    return Ok(());
                };
                let entries = list_below(inner, &dir).await?;
                (dir, entries)
            }
        };
        for entry in &entries {
            if visited == MAX_VISITED {
                return Ok(());
            }
            visited += 1;
            let info = &entry.info;
            if skipped(inner, keys, &dir, &info.name, names_encrypted).await? {
                continue;
            }
            let Ok(path) = dir.join(&info.name) else {
                continue;
            };
            if info.is_directory {
                dirs.push_back(path);
            } else if logical_size(shift, info.end_of_file).size > 0
                && check_file(inner, keys, &path, info.end_of_file, shift).await?
            {
                return Ok(());
            }
        }
    }
}

/// The entries of the directory `dir`; none when it is gone.
async fn list_below<B: ShareBackend>(
    inner: &B,
    dir: &SmbPath,
) -> Result<Vec<DirEntry>, EncryptionError> {
    let opts = OpenOptions {
        directory: true,
        ..OpenOptions::default()
    };
    let handle = match inner.open(dir, opts).await {
        Ok((handle, _)) => handle,
        Err(error) if is_missing(&error) => return Ok(Vec::new()),
        Err(error) => return Err(EncryptionError::Backend(error)),
    };
    let listing = handle.list_dir(None).await;
    close_after_reading(handle).await;
    listing.map_err(EncryptionError::Backend)
}

/// Checks the header and the first block of the file `path`, which has
/// `stored_size` bytes and holds at least one block. `false` when the file is
/// gone.
async fn check_file<B: ShareBackend>(
    inner: &B,
    keys: &KeySchedule,
    path: &SmbPath,
    stored_size: u64,
    shift: BlockShift,
) -> Result<bool, EncryptionError> {
    let opts = OpenOptions {
        non_directory: true,
        ..OpenOptions::default()
    };
    let handle = match inner.open(path, opts).await {
        Ok((handle, _)) => handle,
        Err(SmbError::NotFound | SmbError::PathNotFound) => return Ok(false),
        Err(error) => return Err(EncryptionError::Backend(error)),
    };
    let checked = check_first_block_of(handle.as_ref(), keys, stored_size, shift).await;
    close_after_reading(handle).await;
    checked.map(|()| true)
}

async fn check_first_block_of(
    handle: &dyn Handle,
    keys: &KeySchedule,
    stored_size: u64,
    shift: BlockShift,
) -> Result<(), EncryptionError> {
    let header = read_full(handle, 0, HEADER_LEN)
        .await
        .map_err(EncryptionError::Backend)?;
    let header = parse_header(&header, shift)?;
    let plain_len = logical_size(shift, stored_size)
        .size
        .min(shift.block_size());
    let plain_len = usize::try_from(plain_len).expect("a block is at most 1 MiB");
    let stored = read_full(handle, HEADER_LEN as u64, plain_len + OVERHEAD)
        .await
        .map_err(EncryptionError::Backend)?;
    let mut plain = vec![0u8; plain_len];
    FileCipher::new(keys, header)
        .open_block(0, &stored, &mut plain)
        .map_err(|_| EncryptionError::KeyMismatch)
}

/// The header in `bytes`. A header of another block size is a mismatch of
/// the setting; anything else that is not a header is not the key's.
fn parse_header(bytes: &[u8], shift: BlockShift) -> Result<Header, EncryptionError> {
    Header::parse(bytes, shift).map_err(|_| {
        let other_size = (BlockShift::MIN..=BlockShift::MAX)
            .filter_map(BlockShift::new)
            .any(|other| Header::parse(bytes, other).is_ok());
        if other_size {
            EncryptionError::SettingMismatch {
                setting: "block_size",
            }
        } else {
            EncryptionError::KeyMismatch
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::backend::EncryptedBackend;
    use super::super::format::MARKER_NAME;
    use super::super::names::encode_name;
    use super::super::testing::{
        assert_key_mismatch, assert_mismatch, build, key, key_schedule, marker_settings,
        other_key_schedule, read_only, stored_file, stored_hole,
    };
    use super::*;
    use crate::backend::OpenIntent;
    use crate::tests::faulty::Faulty;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::util::dir_opts;

    const SHIFT: BlockShift = BlockShift::DEFAULT;

    /// The stored name of `name` under the key.
    fn stored(name: &str) -> String {
        encode_name(&key_schedule(), name, 255).unwrap().entry
    }

    /// Adds the file `path` holding `bytes`.
    fn with(files: &MemFsBackend, path: &str, bytes: &[u8]) {
        files.clone().with_file(path, bytes);
    }

    fn good_file() -> Vec<u8> {
        stored_file(&key_schedule(), SHIFT, b"hello")
    }

    fn wrong_key_file() -> Vec<u8> {
        stored_file(&other_key_schedule(), SHIFT, b"hello")
    }

    async fn root_entries(files: &MemFsBackend) -> Vec<DirEntry> {
        let (root, _) = files
            .open(&SmbPath::root(), dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        let entries = root.list_dir(None).await.unwrap();
        root.close().await.unwrap();
        entries
    }

    /// Restores the marker of a share with names in the clear.
    async fn restore_in_the_clear(
        files: &MemFsBackend,
    ) -> Result<EncryptedBackend<MemFsBackend>, EncryptionError> {
        build(files, |builder| {
            builder.encrypt_names(false).restore_marker()
        })
        .await
    }

    // Encrypted names.

    #[tokio::test]
    async fn a_root_entry_that_decodes_gets_the_marker_written() {
        let files = MemFsBackend::new();
        with(&files, "foreign.txt", b"x");
        with(&files, &stored("a.txt"), b"x");
        build(&files, |builder| builder.restore_marker())
            .await
            .unwrap();
        let settings = marker_settings(&files);
        assert!(settings.encrypt_names);
        assert_eq!(settings.block_shift, SHIFT);
        assert_eq!(settings.long_name_threshold, 255);
    }

    #[tokio::test]
    async fn the_marker_takes_the_settings_of_the_builder() {
        let shift = BlockShift::new(13).unwrap();
        let files = MemFsBackend::new();
        with(&files, &stored("a.txt"), b"x");
        with(
            &files,
            &stored("b.txt"),
            &stored_file(&key_schedule(), shift, b"data"),
        );
        build(&files, |builder| {
            builder
                .restore_marker()
                .block_size(8192)
                .long_name_threshold(100)
        })
        .await
        .unwrap();
        let settings = marker_settings(&files);
        assert_eq!(settings.block_shift, shift);
        assert_eq!(settings.long_name_threshold, 100);
    }

    #[tokio::test]
    async fn without_a_root_entry_that_decodes_the_key_does_not_match() {
        let other = encode_name(&other_key_schedule(), "a.txt", 255)
            .unwrap()
            .entry;
        for name in [other, "readme.txt".to_string()] {
            let files = MemFsBackend::new();
            with(&files, &name, b"x");
            let error = build(&files, |builder| builder.restore_marker())
                .await
                .unwrap_err();
            assert!(
                matches!(error, EncryptionError::KeyMismatch),
                "{name}: expected a key mismatch, got {error:?}"
            );
            assert_eq!(files.contents(MARKER_NAME), None);
        }
    }

    #[tokio::test]
    async fn a_root_of_directories_is_checked_by_name_too() {
        let files = MemFsBackend::new().with_dir(&stored("docs"));
        build(&files, |builder| builder.restore_marker())
            .await
            .unwrap();

        let files = MemFsBackend::new().with_dir("docs");
        let error = build(&files, |builder| builder.restore_marker())
            .await
            .unwrap_err();
        assert_key_mismatch(&error);
    }

    /// A name over 143 bytes: its long entry, its side object and the
    /// content of that.
    fn long_name_files(keys: &KeySchedule) -> (String, String, Vec<u8>) {
        let name = encode_name(keys, &"a".repeat(200), 255).unwrap();
        let side = name.side_object.expect("a long name has a side object");
        (name.entry, side.name, side.content)
    }

    #[tokio::test]
    async fn a_long_entry_with_a_side_object_that_decodes_counts() {
        let (entry, side_name, side) = long_name_files(&key_schedule());
        let files = MemFsBackend::new();
        with(&files, &entry, b"");
        with(&files, &side_name, &side);
        build(&files, |builder| builder.restore_marker())
            .await
            .unwrap();
        assert!(marker_settings(&files).encrypt_names);
    }

    #[tokio::test]
    async fn a_long_entry_whose_side_object_is_missing_or_does_not_decode_does_not_count() {
        let (entry, _, _) = long_name_files(&key_schedule());
        let (other_entry, other_side_name, other_side) = long_name_files(&other_key_schedule());
        let cases = [
            ("no side object", vec![(entry, vec![])]),
            (
                "a side object of another key",
                vec![(other_entry, vec![]), (other_side_name, other_side)],
            ),
        ];
        for (what, entries) in cases {
            let files = MemFsBackend::new();
            for (name, bytes) in &entries {
                with(&files, name, bytes);
            }
            let error = build(&files, |builder| builder.restore_marker())
                .await
                .unwrap_err();
            assert!(
                matches!(error, EncryptionError::KeyMismatch),
                "{what}: expected a key mismatch, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_directory_in_place_of_a_side_object_does_not_count() {
        let (entry, side_name, _) = long_name_files(&key_schedule());
        let files = MemFsBackend::new().with_dir(&side_name);
        with(&files, &entry, b"");
        let error = build(&files, |builder| builder.restore_marker())
            .await
            .unwrap_err();
        assert_key_mismatch(&error);
    }

    #[tokio::test]
    async fn side_objects_and_foreign_names_are_not_entries_and_not_files_to_check() {
        let (_, side_name, side) = long_name_files(&key_schedule());
        let files = MemFsBackend::new();
        with(&files, &side_name, &side);
        with(&files, "notes.txt", &[7; 100]);
        let error = build(&files, |builder| builder.restore_marker())
            .await
            .unwrap_err();
        assert_key_mismatch(&error);

        with(&files, &stored("a.txt"), b"x");
        build(&files, |builder| builder.restore_marker())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn entries_whose_names_do_not_decode_are_not_searched() {
        let (long_entry, _, _) = long_name_files(&key_schedule());
        let files = MemFsBackend::new()
            .with_dir("docs")
            .with_dir(&stored("sub"));
        with(&files, &stored("a.txt"), b"x");
        with(&files, "readme", &[7; 100]);
        with(&files, &long_entry, &[7; 100]);
        with(&files, "docs\\inner", &[7; 100]);
        with(&files, &format!("{}\\notes", stored("sub")), &[7; 100]);
        build(&files, |builder| builder.restore_marker())
            .await
            .unwrap();
        assert!(marker_settings(&files).encrypt_names);
    }

    #[tokio::test]
    async fn with_encrypted_names_a_first_block_of_another_key_is_a_key_mismatch() {
        let files = MemFsBackend::new();
        with(&files, &stored("a.txt"), &wrong_key_file());
        let error = build(&files, |builder| builder.restore_marker())
            .await
            .unwrap_err();
        assert_key_mismatch(&error);
        assert_eq!(files.contents(MARKER_NAME), None);
    }

    #[tokio::test]
    async fn with_encrypted_names_a_header_of_another_block_size_is_a_setting_mismatch() {
        let shift = BlockShift::new(13).unwrap();
        let files = MemFsBackend::new();
        with(
            &files,
            &stored("a.txt"),
            &stored_file(&key_schedule(), shift, b"hello"),
        );
        let error = build(&files, |builder| builder.restore_marker())
            .await
            .unwrap_err();
        assert_mismatch(&error, "block_size");
        assert_eq!(files.contents(MARKER_NAME), None);
    }

    // Names in the clear.

    #[tokio::test]
    async fn a_nested_file_with_an_authentic_first_block_passes() {
        let files = MemFsBackend::new().with_dir("docs");
        with(&files, "docs\\a.bin", &good_file());
        restore_in_the_clear(&files).await.unwrap();
        let settings = marker_settings(&files);
        assert!(!settings.encrypt_names);
        assert_eq!(settings.block_shift, SHIFT);
        assert_eq!(settings.long_name_threshold, 0);
    }

    #[tokio::test]
    async fn a_nested_file_of_another_key_is_a_key_mismatch() {
        let files = MemFsBackend::new().with_dir("docs");
        with(&files, "docs\\a.bin", &wrong_key_file());
        let error = restore_in_the_clear(&files).await.unwrap_err();
        assert_key_mismatch(&error);
        assert_eq!(files.contents(MARKER_NAME), None);
    }

    #[tokio::test]
    async fn a_file_that_is_not_a_header_is_a_key_mismatch() {
        let files = MemFsBackend::new();
        with(&files, "plain.txt", &[b'x'; 100]);
        let error = restore_in_the_clear(&files).await.unwrap_err();
        assert_key_mismatch(&error);
    }

    #[tokio::test]
    async fn a_header_of_another_block_size_is_a_setting_mismatch() {
        let shift = BlockShift::new(13).unwrap();
        let files = MemFsBackend::new();
        with(
            &files,
            "a.bin",
            &stored_file(&key_schedule(), shift, b"hello"),
        );
        let error = restore_in_the_clear(&files).await.unwrap_err();
        assert_mismatch(&error, "block_size");
        assert_eq!(files.contents(MARKER_NAME), None);

        build(&files, |builder| {
            builder
                .encrypt_names(false)
                .restore_marker()
                .block_size(8192)
        })
        .await
        .unwrap();
        assert_eq!(marker_settings(&files).block_shift, shift);

        let files = MemFsBackend::new();
        with(&files, "a.bin", &good_file());
        let error = build(&files, |builder| {
            builder
                .encrypt_names(false)
                .restore_marker()
                .block_size(8192)
        })
        .await
        .unwrap_err();
        assert_mismatch(&error, "block_size");
    }

    #[tokio::test]
    async fn a_first_block_that_is_a_hole_passes() {
        let files = MemFsBackend::new();
        with(&files, "a.bin", &stored_hole(SHIFT, 100));
        restore_in_the_clear(&files).await.unwrap();
        assert!(
            files.contents(MARKER_NAME).is_some(),
            "a marker was written"
        );
    }

    #[tokio::test]
    async fn only_the_first_block_is_read() {
        let mut bytes = stored_file(&key_schedule(), SHIFT, &[3u8; 65_536]);
        bytes.extend_from_slice(&[0xee; 40]);
        let files = MemFsBackend::new();
        with(&files, "a.bin", &bytes);
        restore_in_the_clear(&files).await.unwrap();
    }

    /// A root with files that hold no block and the directory `d`.
    fn files_without_a_block() -> MemFsBackend {
        let files = MemFsBackend::new().with_dir("d");
        with(&files, "empty", b"");
        with(&files, "header-only", &good_file()[..HEADER_LEN]);
        with(&files, "torn", &good_file()[..30]);
        files
    }

    #[tokio::test]
    async fn files_that_hold_no_block_are_passed_over() {
        let files = files_without_a_block();
        restore_in_the_clear(&files).await.unwrap();
        assert!(
            files.contents(MARKER_NAME).is_some(),
            "a marker was written"
        );

        let files = files_without_a_block();
        with(&files, "d\\bad", &wrong_key_file());
        let error = restore_in_the_clear(&files).await.unwrap_err();
        assert_key_mismatch(&error);
    }

    #[tokio::test]
    async fn the_search_goes_breadth_first() {
        // A file in the root is checked before any file below it.
        let files = MemFsBackend::new().with_dir("d");
        with(&files, "r", &good_file());
        with(&files, "d\\f", &wrong_key_file());
        restore_in_the_clear(&files).await.unwrap();

        let files = MemFsBackend::new().with_dir("d");
        with(&files, "r", &wrong_key_file());
        with(&files, "d\\f", &good_file());
        let error = restore_in_the_clear(&files).await.unwrap_err();
        assert_key_mismatch(&error);

        // A file two levels down is checked before one three levels down.
        let files = MemFsBackend::new()
            .with_dir("a")
            .with_dir("a\\b")
            .with_dir("x");
        with(&files, "a\\b\\deep", &wrong_key_file());
        with(&files, "x\\shallow", &good_file());
        restore_in_the_clear(&files).await.unwrap();
    }

    #[tokio::test]
    async fn the_search_looks_at_10000_entries_and_no_more() {
        // The directory is the 10,000th entry, so its file is never seen.
        let files = MemFsBackend::new().with_dir("d");
        for n in 0..MAX_VISITED - 1 {
            with(&files, &format!("f{n}"), b"");
        }
        with(&files, "d\\bad", &wrong_key_file());
        restore_in_the_clear(&files).await.unwrap();
        assert!(
            files.contents(MARKER_NAME).is_some(),
            "a marker was written"
        );

        // One entry fewer, and the file is the 10,000th.
        let files = MemFsBackend::new().with_dir("d");
        for n in 0..MAX_VISITED - 2 {
            with(&files, &format!("f{n}"), b"");
        }
        with(&files, "d\\bad", &wrong_key_file());
        let error = restore_in_the_clear(&files).await.unwrap_err();
        assert_key_mismatch(&error);
    }

    #[tokio::test]
    async fn the_marker_and_side_objects_are_not_files_to_check() {
        let settings = MarkerSettings {
            encrypt_names: false,
            block_shift: SHIFT,
            long_name_threshold: 0,
        };
        let files = MemFsBackend::new();
        with(&files, MARKER_NAME, &[7; 100]);
        with(&files, "abcdefghijklmnopqrstuvwxyz234567.n", &[7; 100]);
        let entries = root_entries(&files).await;
        check(&files, &key_schedule(), entries, &settings)
            .await
            .unwrap();

        // The marker is the marker in the root only.
        let files = MemFsBackend::new().with_dir("d");
        with(&files, "d\\.smb-encryption", &[7; 100]);
        let entries = root_entries(&files).await;
        let error = check(&files, &key_schedule(), entries, &settings)
            .await
            .unwrap_err();
        assert_key_mismatch(&error);
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_file_that_is_gone_when_it_is_opened_is_passed_over() {
        let files = MemFsBackend::new().with_dir("d");
        for path in ["d\\gone", "missing-dir\\gone"] {
            let path: SmbPath = path.parse().unwrap();
            let checked = check_file(&files, &key_schedule(), &path, 1000, SHIFT).await;
            assert!(matches!(checked, Ok(false)), "{path}: {checked:?}");
        }
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn short_reads_do_not_disturb_the_checks() {
        let files = MemFsBackend::new().with_dir("d");
        with(&files, "d\\a.bin", &good_file());
        let faulty = Faulty::new(files.clone());
        faulty.short_reads(Some(5));
        EncryptedBackend::builder(faulty, key())
            .encrypt_names(false)
            .restore_marker()
            .build()
            .await
            .unwrap();

        let files = MemFsBackend::new().with_dir("d");
        with(&files, "d\\a.bin", &wrong_key_file());
        let faulty = Faulty::new(files.clone());
        faulty.short_reads(Some(5));
        let error = EncryptedBackend::builder(faulty, key())
            .encrypt_names(false)
            .restore_marker()
            .build()
            .await
            .unwrap_err();
        assert_key_mismatch(&error);
        assert_eq!(files.open_handles(), 0);
    }

    // The inner backend is read-only.

    #[tokio::test]
    async fn a_read_only_inner_backend_is_checked_and_gets_no_marker() {
        let files = MemFsBackend::new().with_dir("d");
        with(&files, "d\\a.bin", &good_file());
        EncryptedBackend::builder(read_only(&files), key())
            .encrypt_names(false)
            .restore_marker()
            .build()
            .await
            .unwrap();
        assert_eq!(files.contents(MARKER_NAME), None);
        assert_eq!(files.open_handles(), 0);
    }
}
