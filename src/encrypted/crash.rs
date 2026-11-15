//! Edits and name changes that crash part way. Each inner call of an operation
//! fails in turn, a write also after a prefix of its bytes, and the store
//! keeps what the earlier calls stored, as after a crash. A fresh layer over
//! the same store then reads what is left.

use std::io;

use super::backend::EncryptedBackend;
use super::format::OVERHEAD;
use super::testing::{
    B, Edit, H, KEPT, Strict, at, edited, fail_open_of, faulty_file, injected, layer_over,
    long_name, names, names_over, open_dir, open_file, perform, read_all, refused, seed_dir,
    seed_file, stored, stored_at, stored_bytes, stored_form, writes_since,
};
use crate::backend::{Handle, OpenIntent, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::tests::data::pattern;
use crate::tests::faulty::Faulty;
use crate::tests::memfs::MemFsBackend;
use crate::tests::util::path;

/// Bytes the old last block gains when it is padded to a whole block.
const PAD: usize = B - KEPT;
/// Stored bytes of the old last block.
const OLD_BLOCK: usize = KEPT + OVERHEAD;

/// Bytes of the old file with `k` whole blocks before its partial one.
fn old_len(k: usize) -> usize {
    k * B + KEPT
}

/// Where the stored old file ends.
fn old_end(k: usize) -> usize {
    at(k) + OLD_BLOCK
}

#[derive(Clone, Copy, Debug)]
enum Call {
    Write {
        at: usize,
        len: usize,
    },
    Truncate {
        to: usize,
        /// Where the layer cuts the stored file back when this truncate
        /// fails, if it cuts at all.
        back: Option<usize>,
    },
}

/// What a fresh layer finds in the file after the crash.
enum Found {
    /// The file as it was before the edit.
    Intact,
    /// The first `size` bytes of the file as the edit makes it. The blocks in
    /// `torn` fail authentication and the others read back.
    Left { size: usize, torn: Vec<usize> },
}

/// A crash in the inner call `call` of an edit. `applied` bytes of it reach
/// the store when it is a write.
struct Crash {
    call: usize,
    applied: usize,
    found: Found,
}

fn intact(call: usize, applied: usize) -> Crash {
    Crash {
        call,
        applied,
        found: Found::Intact,
    }
}

/// A crash that leaves `size` bytes of the edited file, with the blocks in
/// `torn` unreadable.
fn left(call: usize, applied: usize, size: usize, torn: &[usize]) -> Crash {
    Crash {
        call,
        applied,
        found: Found::Left {
            size,
            torn: torn.to_vec(),
        },
    }
}

/// An edit of a file, the inner calls it makes in order, and the crash in
/// each of them.
struct Case {
    name: String,
    /// Bytes of the file before the edit; 0 is a new file.
    old: usize,
    edit: Edit,
    calls: Vec<Call>,
    crashes: Vec<Crash>,
}

impl Case {
    fn writes(&self) -> Vec<(u64, usize)> {
        self.calls
            .iter()
            .filter_map(|call| match *call {
                Call::Write { at, len } => Some((at as u64, len)),
                Call::Truncate { .. } => None,
            })
            .collect()
    }

    /// Runs the edit with no fault, then with each crash.
    async fn run(&self) {
        let old = pattern(self.old, 1);
        let bytes = if self.old == 0 {
            Vec::new()
        } else {
            stored(&old)
        };
        let new = edited(&old, self.edit);
        self.clean(&bytes, &new).await;
        for crash in &self.crashes {
            self.crash(&bytes, &old, &new, crash).await;
        }
    }

    /// The edit with no fault makes the calls of the case and the file `new`.
    async fn clean(&self, bytes: &[u8], new: &[u8]) {
        let (_files, faulty, layer) = faulty_file(bytes).await;
        let handle = open_file(&layer, "f").await;
        let before = faulty.write_calls().len();
        perform(&handle, self.edit).await.unwrap();
        assert!(read_all(&handle).await == new, "{}: the edit", self.name);
        assert_eq!(
            writes_since(&faulty, before),
            self.writes(),
            "{}: inner writes",
            self.name
        );
        let truncates: Vec<u64> = self
            .calls
            .iter()
            .filter_map(|call| match *call {
                Call::Write { .. } => None,
                Call::Truncate { to, .. } => Some(to as u64),
            })
            .collect();
        assert_eq!(
            faulty.truncate_calls(),
            truncates,
            "{}: inner truncates",
            self.name
        );
    }

    /// Bytes in the stored file after `crash`: what the calls before the
    /// failing one stored, and the prefix of that call.
    fn stored_end(&self, old_end: usize, crash: &Crash) -> usize {
        let mut end = old_end;
        for (n, call) in self.calls[..=crash.call].iter().enumerate() {
            let failing = n == crash.call;
            match *call {
                Call::Write { at, len } => {
                    let done = if failing { crash.applied } else { len };
                    if done > 0 {
                        end = end.max(at + done);
                    }
                }
                Call::Truncate { to, .. } if !failing => end = to,
                Call::Truncate { .. } => {}
            }
        }
        end
    }

    /// Makes the edit fail at the call of `crash` and reads the file back
    /// through a fresh layer. `old` and `new` are the file before and after
    /// the edit.
    async fn crash(&self, bytes: &[u8], old: &[u8], new: &[u8], crash: &Crash) {
        let call = self.calls[crash.call];
        let name = format!(
            "{}: {call:?} fails after {} bytes",
            self.name, crash.applied
        );
        let (files, faulty, layer) = faulty_file(bytes).await;
        let handle = open_file(&layer, "f").await;
        let before = faulty.write_calls().len();
        let failing_write = matches!(call, Call::Write { .. });
        let earlier = &self.calls[..crash.call];
        let writes_before = earlier
            .iter()
            .filter(|call| matches!(call, Call::Write { .. }))
            .count();
        let truncates_before = earlier.len() - writes_before;
        // The layer cuts the stored file back after a failed call, which a
        // crash never does.
        if failing_write {
            // The cut is the next truncate.
            faulty.tear_write(writes_before + 1, crash.applied, injected());
            faulty.fail_truncate(truncates_before + 1, injected());
        } else {
            // The failing call is the first truncate, and the cut is a later
            // one.
            assert_eq!(truncates_before, 0, "{name}");
            faulty.fail_truncate(1, injected());
            faulty.sink_truncates_from(Some(0));
        }

        let result = perform(&handle, self.edit).await;
        assert!(matches!(result, Err(SmbError::Io(_))), "{name}: {result:?}");
        assert_eq!(
            writes_since(&faulty, before),
            self.writes()[..writes_before + usize::from(failing_write)],
            "{name}: inner writes"
        );
        if let Call::Truncate { to, back } = call {
            // The failing truncate, then the cut the layer makes after it.
            let truncates: Vec<u64> = [Some(to), back]
                .into_iter()
                .flatten()
                .map(|len| len as u64)
                .collect();
            assert_eq!(
                faulty.truncate_calls(),
                truncates,
                "{name}: inner truncates"
            );
        }
        assert_eq!(
            files.contents("f").unwrap().len(),
            self.stored_end(bytes.len(), crash),
            "{name}: stored size"
        );
        drop((handle, layer));

        match &crash.found {
            Found::Intact => assert_found(&files, old, &[], &name).await,
            Found::Left { size, torn } => assert_found(&files, &new[..*size], torn, &name).await,
        }
    }
}

fn invalid_data<T>(result: &SmbResult<T>) -> bool {
    matches!(result, Err(SmbError::Io(error)) if error.kind() == io::ErrorKind::InvalidData)
}

/// Opens `f` through a fresh layer over `files`. The file has `model.len()`
/// bytes. The blocks in `torn` fail authentication and the other blocks read
/// back as `model`. A write that covers a torn block replaces it. A write that
/// covers part of it, and a truncate that has to rewrite it, fail.
async fn assert_found(files: &MemFsBackend, model: &[u8], torn: &[usize], name: &str) {
    let layer = layer_over(files.clone()).await;
    let handle = open_file(&layer, "f").await;
    let size = handle.stat().await.unwrap().end_of_file;
    assert_eq!(size, model.len() as u64, "{name}: size");
    for index in 0..model.len().div_ceil(B) {
        let read = handle.read((index * B) as u64, B as u32).await;
        if torn.contains(&index) {
            assert!(invalid_data(&read), "{name}: block {index} does not fail");
        } else {
            let end = ((index + 1) * B).min(model.len());
            let reads_back = read.is_ok_and(|bytes| bytes[..] == model[index * B..end]);
            assert!(reads_back, "{name}: block {index} does not read back");
        }
    }
    let whole = handle.read(0, u32::MAX).await;
    if torn.is_empty() {
        assert!(
            whole.is_ok_and(|bytes| bytes[..] == *model),
            "{name}: whole read"
        );
        return;
    }
    assert!(invalid_data(&whole), "{name}: a read over a torn block");

    let mut model = model.to_vec();
    for &index in torn {
        let start = index * B;
        let len = (model.len() - start).min(B);
        if len > 1 {
            let partial = handle.write(start as u64, &[1]).await;
            assert!(invalid_data(&partial), "{name}: write into block {index}");
            let shrink = handle.truncate(start as u64 + 1).await;
            assert!(invalid_data(&shrink), "{name}: truncate into block {index}");
        }
        let data = pattern(len, 9);
        let written = handle.write(start as u64, &data).await;
        assert!(written.is_ok(), "{name}: write over block {index}");
        model[start..start + len].copy_from_slice(&data);
    }
    assert!(
        read_all(&handle).await == model,
        "{name}: after the torn blocks are replaced"
    );
}

/// A write into a new file that starts in block 0: the header and the first
/// block go in one inner write.
fn new_file_from_the_start() -> Case {
    Case {
        name: "write at the start of a new file".to_string(),
        old: 0,
        edit: Edit::Write {
            offset: 0,
            len: 100,
        },
        calls: vec![Call::Write {
            at: 0,
            len: H + 100 + OVERHEAD,
        }],
        crashes: vec![
            intact(0, 0),
            // A header cut short, a header alone, and a header with a
            // fragment of a block: an empty file.
            left(0, 10, 0, &[]),
            left(0, H, 0, &[]),
            left(0, H + 1, 0, &[]),
            left(0, H + OVERHEAD, 0, &[]),
            // A block cut short.
            left(0, H + OVERHEAD + 1, 1, &[0]),
            left(0, H + 100 + OVERHEAD - 1, 99, &[0]),
        ],
    }
}

/// A write into a new file that starts in block 1: the header, then the block,
/// with a hole between them.
fn new_file_after_a_hole() -> Case {
    Case {
        name: "write into block 1 of a new file".to_string(),
        old: 0,
        edit: Edit::Write {
            offset: B + 3,
            len: 10,
        },
        calls: vec![
            Call::Write { at: 0, len: H },
            Call::Write {
                at: at(1),
                len: 13 + OVERHEAD,
            },
        ],
        crashes: vec![
            intact(0, 0),
            left(0, 10, 0, &[]),
            // The header alone reads as an empty file.
            intact(1, 0),
            // A fragment after the hole: the hole is a block of zeros.
            left(1, 1, B, &[]),
            left(1, OVERHEAD, B, &[]),
            left(1, OVERHEAD + 1, B + 1, &[1]),
            left(1, 13 + OVERHEAD - 1, B + 12, &[1]),
        ],
    }
}

#[tokio::test]
async fn a_crash_in_a_write_to_a_new_file_leaves_it_empty_or_ends_in_a_hole_or_a_torn_block() {
    for case in [new_file_from_the_start(), new_file_after_a_hole()] {
        case.run().await;
    }
}

/// A write of 10 bytes at byte 3 of block `k + 1`, past the partial last
/// block `k`. The padded block and the new block are next to each other, and
/// the part of both from the old end on is stored first.
fn write_into_the_next_block(k: usize) -> Case {
    Case {
        name: format!("write into the block after block {k}"),
        old: old_len(k),
        edit: Edit::Write {
            offset: (k + 1) * B + 3,
            len: 10,
        },
        calls: vec![
            Call::Write {
                at: old_end(k),
                len: PAD + 13 + OVERHEAD,
            },
            Call::Write {
                at: at(k),
                len: OLD_BLOCK,
            },
        ],
        crashes: vec![
            intact(0, 0),
            // The part below the old end is the old one and the part above
            // is new: block `k` fails. The blocks before it read back.
            left(0, 1, old_len(k) + 1, &[k]),
            left(0, PAD, (k + 1) * B, &[k]),
            left(0, PAD + OVERHEAD, (k + 1) * B, &[k]),
            left(0, PAD + OVERHEAD + 1, (k + 1) * B + 1, &[k, k + 1]),
            left(0, PAD + 13 + OVERHEAD - 1, (k + 1) * B + 12, &[k, k + 1]),
            // The part above the old end and the new block are in, and the
            // part below the old end is still the old one: the new block
            // reads back.
            left(1, 0, (k + 1) * B + 13, &[k]),
            left(1, 1, (k + 1) * B + 13, &[k]),
            left(1, OLD_BLOCK / 2, (k + 1) * B + 13, &[k]),
        ],
    }
}

/// A write of 10 bytes at byte 3 of block `k + 2`, with a hole of one block
/// between the padded last block `k` and the new block.
fn write_past_a_hole(k: usize) -> Case {
    Case {
        name: format!("write into block {} after block {k}", k + 2),
        old: old_len(k),
        edit: Edit::Write {
            offset: (k + 2) * B + 3,
            len: 10,
        },
        calls: vec![
            Call::Write {
                at: old_end(k),
                len: PAD,
            },
            Call::Write {
                at: at(k),
                len: OLD_BLOCK,
            },
            Call::Write {
                at: at(k + 2),
                len: 13 + OVERHEAD,
            },
        ],
        crashes: vec![
            intact(0, 0),
            left(0, 1, old_len(k) + 1, &[k]),
            left(0, PAD - 1, (k + 1) * B - 1, &[k]),
            left(0, PAD, (k + 1) * B, &[k]),
            left(1, 0, (k + 1) * B, &[k]),
            left(1, OLD_BLOCK / 2, (k + 1) * B, &[k]),
            // The old block is padded and whole: the file is longer by the
            // padding and ends at the next block boundary.
            left(2, 0, (k + 1) * B, &[]),
            // A fragment after a hole of zeros.
            left(2, 1, (k + 2) * B, &[]),
            left(2, OVERHEAD, (k + 2) * B, &[]),
            left(2, OVERHEAD + 1, (k + 2) * B + 1, &[k + 2]),
            left(2, 13 + OVERHEAD - 1, (k + 2) * B + 12, &[k + 2]),
        ],
    }
}

#[tokio::test]
async fn a_crash_in_a_write_past_the_last_block_tears_a_block_or_pads_the_old_one() {
    for k in [0, 1] {
        write_into_the_next_block(k).run().await;
        write_past_a_hole(k).run().await;
    }
}

#[tokio::test]
async fn a_crash_in_an_append_tears_the_partial_last_block() {
    for k in [0, 1] {
        let case = Case {
            name: format!("append inside block {k}"),
            old: old_len(k),
            edit: Edit::Write {
                offset: old_len(k),
                len: 50,
            },
            calls: vec![
                Call::Write {
                    at: old_end(k),
                    len: 50,
                },
                Call::Write {
                    at: at(k),
                    len: OLD_BLOCK,
                },
            ],
            crashes: vec![
                intact(0, 0),
                left(0, 1, old_len(k) + 1, &[k]),
                left(0, 49, old_len(k) + 49, &[k]),
                left(1, 0, old_len(k) + 50, &[k]),
                left(1, OLD_BLOCK / 2, old_len(k) + 50, &[k]),
            ],
        };
        case.run().await;
    }
}

/// A shrink of a file of `old` bytes to `len` bytes, which ends in the middle
/// of a block: the file is cut to the end of the block before it, and the new
/// last block is written.
fn shrink(old: usize, len: usize) -> Case {
    let (k, kept) = (len / B, len % B);
    Case {
        name: format!("shrink from {old} to {len} bytes"),
        old,
        edit: Edit::Truncate { len },
        calls: vec![
            Call::Truncate {
                to: at(k),
                back: None,
            },
            Call::Write {
                at: at(k),
                len: kept + OVERHEAD,
            },
        ],
        crashes: vec![
            // The cut does not happen.
            intact(0, 0),
            // The file ends at the block boundary with the block's bytes
            // gone, or a fragment or a torn block follows it.
            left(1, 0, k * B, &[]),
            left(1, 1, k * B, &[]),
            left(1, OVERHEAD, k * B, &[]),
            left(1, OVERHEAD + 1, k * B + 1, &[k]),
            left(1, kept + OVERHEAD - 1, k * B + kept - 1, &[k]),
        ],
    }
}

#[tokio::test]
async fn a_crash_in_a_shrink_leaves_a_block_boundary_or_a_torn_last_block() {
    for case in [
        shrink(3 * B + 50, B + 40),
        shrink(old_len(1), B + 40),
        shrink(2 * B + 7, 40),
    ] {
        case.run().await;
    }
}

/// An extension of the partial last block `k` to 300 bytes, which stays in
/// the block.
fn extension_within_the_block(k: usize) -> Case {
    let len = k * B + 300;
    Case {
        name: format!("extension inside block {k}"),
        old: old_len(k),
        edit: Edit::Truncate { len },
        calls: vec![
            Call::Write {
                at: old_end(k),
                len: 300 - KEPT,
            },
            Call::Write {
                at: at(k),
                len: OLD_BLOCK,
            },
        ],
        crashes: vec![
            intact(0, 0),
            left(0, 1, old_len(k) + 1, &[k]),
            left(0, 300 - KEPT - 1, len - 1, &[k]),
            left(1, 0, len, &[k]),
            left(1, OLD_BLOCK / 2, len, &[k]),
        ],
    }
}

/// An extension of the partial last block `k` to 7 bytes into block `k + 2`:
/// the block is padded and the stored file is then extended.
fn extension_past_the_block(k: usize) -> Case {
    Case {
        name: format!("extension past block {k}"),
        old: old_len(k),
        edit: Edit::Truncate {
            len: (k + 2) * B + 7,
        },
        calls: vec![
            Call::Write {
                at: old_end(k),
                len: PAD,
            },
            Call::Write {
                at: at(k),
                len: OLD_BLOCK,
            },
            Call::Truncate {
                to: at(k + 2) + 7 + OVERHEAD,
                back: Some(at(k + 1)),
            },
        ],
        crashes: vec![
            intact(0, 0),
            left(0, 1, old_len(k) + 1, &[k]),
            left(0, PAD, (k + 1) * B, &[k]),
            left(1, 0, (k + 1) * B, &[k]),
            left(1, OLD_BLOCK / 2, (k + 1) * B, &[k]),
            // The old block is padded and the truncate does not happen: the
            // file ends at the next block boundary.
            left(2, 0, (k + 1) * B, &[]),
        ],
    }
}

#[tokio::test]
async fn a_crash_in_an_extension_tears_the_last_block_or_ends_at_a_boundary() {
    for k in [0, 1] {
        extension_within_the_block(k).run().await;
        extension_past_the_block(k).run().await;
    }
}

#[tokio::test]
async fn a_crash_in_an_extension_of_a_new_file_leaves_it_empty() {
    let case = Case {
        name: "extension of a new file".to_string(),
        old: 0,
        edit: Edit::Truncate { len: 3 * B + 5 },
        calls: vec![
            Call::Write { at: 0, len: H },
            Call::Truncate {
                to: at(3) + 5 + OVERHEAD,
                back: Some(0),
            },
        ],
        crashes: vec![
            intact(0, 0),
            left(0, 10, 0, &[]),
            // The header alone reads as an empty file.
            intact(1, 0),
        ],
    };
    case.run().await;
}

const CONTENT: &[u8] = b"kept";

/// A store with the directory `Docs`, and a layer that encrypts names over
/// it, behind `Faulty`.
async fn docs() -> (
    MemFsBackend,
    Faulty<MemFsBackend>,
    EncryptedBackend<Faulty<MemFsBackend>>,
) {
    let files = MemFsBackend::new();
    let faulty = Faulty::new(files.clone());
    let layer = names_over(faulty.clone()).await;
    seed_dir(&files, "Docs");
    (files, faulty, layer)
}

/// What a fresh layer finds in `Docs` after a crash.
struct Remains<'a> {
    /// The files, with what each holds.
    files: &'a [(&'a str, &'a [u8])],
    /// Stored paths of the side objects that are in the store. No listing
    /// shows them.
    side_objects: &'a [&'a str],
    /// Names that do not open.
    missing: &'a [&'a str],
}

impl Remains<'_> {
    /// Reads `Docs` through a fresh layer over `store`, then deletes its
    /// files and `Docs`. The side objects go with the directory.
    async fn check(&self, store: &MemFsBackend, step: &str) {
        let layer = names_over(Strict::new(store.clone())).await;
        let dir = open_dir(&layer, "Docs").await;
        let mut expected: Vec<&str> = self.files.iter().map(|(name, _)| *name).collect();
        expected.sort_unstable();
        let found = names(&dir.list_dir(None).await.unwrap());
        assert_eq!(found, expected, "{step}: listing");
        assert_eq!(
            dir.dir_is_empty().await.unwrap(),
            expected.is_empty(),
            "{step}: dir_is_empty"
        );
        for side in self.side_objects {
            assert!(store.contents(side).is_some(), "{step}: {side}");
        }
        for name in self.missing {
            let error = refused(&layer, &format!("Docs\\{name}"), OpenIntent::Open).await;
            assert!(matches!(error, SmbError::NotFound), "{step}: {error:?}");
        }
        for (name, content) in self.files {
            let file = open_file(&layer, &format!("Docs\\{name}")).await;
            assert!(read_all(&file).await == *content, "{step}: {name}");
            assert_eq!(file.stat().await.unwrap().name, *name, "{step}: {name}");
        }

        for (name, _) in self.files {
            layer.unlink(&path(&format!("Docs\\{name}"))).await.unwrap();
        }
        layer.unlink(&path("Docs")).await.unwrap();
        for side in self.side_objects {
            assert_eq!(store.contents(side), None, "{step}: {side} stays");
        }
    }
}

/// The inner call of a long-name create that fails.
#[derive(Clone, Copy, Debug)]
enum CreateCrash {
    SideOpen,
    /// The write of the side object, after this many bytes.
    SideWrite(usize),
    EntryOpen,
}

#[tokio::test]
async fn a_crash_in_a_long_name_create_leaves_no_entry_and_at_most_a_hidden_side_object() {
    let long = long_name("x");
    let form = stored_form(&long);
    let side = form.side_object.clone().expect("a long name");
    let dir = stored_at("Docs");
    let side_at = format!("{dir}\\{}", side.name);
    let entry_at = format!("{dir}\\{}", form.entry);
    let len = side.content.len();

    for crash in [
        CreateCrash::SideOpen,
        CreateCrash::SideWrite(0),
        CreateCrash::SideWrite(len / 2),
        CreateCrash::EntryOpen,
    ] {
        let step = format!("{crash:?}");
        let (files, faulty, layer) = docs().await;
        match crash {
            CreateCrash::SideOpen => fail_open_of(&faulty, &side.name),
            CreateCrash::SideWrite(applied) => faulty.tear_write(1, applied, injected()),
            CreateCrash::EntryOpen => fail_open_of(&faulty, &form.entry),
        }
        let error = refused(&layer, &format!("Docs\\{long}"), OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Io(_)), "{step}: {error:?}");
        drop(layer);

        // The side object is written and the entry is not.
        if matches!(crash, CreateCrash::EntryOpen) {
            assert_eq!(
                files.contents(&side_at),
                Some(side.content.clone()),
                "{step}: side object"
            );
        }
        assert_eq!(files.contents(&entry_at), None, "{step}: entry");
        let side_objects = if matches!(crash, CreateCrash::SideOpen) {
            Vec::new()
        } else {
            vec![side_at.as_str()]
        };
        let want = Remains {
            files: &[],
            side_objects: &side_objects,
            missing: &[&long],
        };
        want.check(&files, &step).await;
    }
}

#[tokio::test]
async fn a_crash_in_a_long_name_unlink_keeps_the_file_or_leaves_a_hidden_side_object() {
    let long = long_name("x");
    let side = stored_form(&long).side_object.expect("a long name");
    let side_at = format!("{}\\{}", stored_at("Docs"), side.name);
    let doomed = format!("Docs\\{long}");

    for nth in [1, 2] {
        let step = format!("unlink {nth} fails");
        let (files, faulty, layer) = docs().await;
        seed_file(&files, &doomed, &stored_bytes(CONTENT));
        faulty.fail_unlink(nth, injected());
        let result = layer.unlink(&path(&doomed)).await;
        drop(layer);

        let want = if nth == 1 {
            // The entry goes first: it is still there, with its side object.
            assert!(matches!(result, Err(SmbError::Io(_))), "{step}: {result:?}");
            Remains {
                files: &[(&long, CONTENT)],
                side_objects: &[&side_at],
                missing: &[],
            }
        } else {
            // The entry is gone and its side object stays.
            result.unwrap();
            Remains {
                files: &[],
                side_objects: &[&side_at],
                missing: &[&long],
            }
        };
        want.check(&files, &step).await;
    }
}

/// The inner call of a long-name rename that fails.
#[derive(Clone, Copy, Debug)]
enum RenameCrash {
    NewSideOpen,
    /// The write of the new side object, after this many bytes.
    NewSideWrite(usize),
    EntryRename,
    OldSideUnlink,
}

#[tokio::test]
async fn a_crash_in_a_long_name_rename_keeps_one_name_and_leaves_hidden_side_objects() {
    let (old, new) = (long_name("x"), long_name("y"));
    let (old_form, new_form) = (stored_form(&old), stored_form(&new));
    let old_side = old_form.side_object.clone().expect("a long name");
    let new_side = new_form.side_object.clone().expect("a long name");
    let dir = stored_at("Docs");
    let old_side_at = format!("{dir}\\{}", old_side.name);
    let new_side_at = format!("{dir}\\{}", new_side.name);
    let old_entry_at = format!("{dir}\\{}", old_form.entry);
    let new_entry_at = format!("{dir}\\{}", new_form.entry);
    let (from, to) = (format!("Docs\\{old}"), format!("Docs\\{new}"));
    let len = new_side.content.len();

    for crash in [
        RenameCrash::NewSideOpen,
        RenameCrash::NewSideWrite(0),
        RenameCrash::NewSideWrite(len / 2),
        RenameCrash::EntryRename,
        RenameCrash::OldSideUnlink,
    ] {
        let step = format!("{crash:?}");
        let (files, faulty, layer) = docs().await;
        seed_file(&files, &from, &stored_bytes(CONTENT));
        match crash {
            RenameCrash::NewSideOpen => fail_open_of(&faulty, &new_side.name),
            RenameCrash::NewSideWrite(applied) => faulty.tear_write(1, applied, injected()),
            RenameCrash::EntryRename => faulty.fail_rename(1, injected()),
            RenameCrash::OldSideUnlink => faulty.fail_unlink(1, injected()),
        }
        let result = layer.rename(&path(&from), &path(&to), false).await;
        drop(layer);

        // The new side object is stored before the entry moves, and the old
        // one is removed after.
        let renamed = matches!(crash, RenameCrash::OldSideUnlink);
        let new_kept = match crash {
            RenameCrash::NewSideOpen => None,
            RenameCrash::NewSideWrite(applied) => Some(&new_side.content[..applied]),
            RenameCrash::EntryRename | RenameCrash::OldSideUnlink => Some(&new_side.content[..]),
        };
        assert_eq!(
            files.contents(&new_side_at).as_deref(),
            new_kept,
            "{step}: new side object"
        );
        assert_eq!(
            files.contents(&old_side_at),
            Some(old_side.content.clone()),
            "{step}: old side object"
        );
        assert_eq!(
            files.contents(&old_entry_at).is_some(),
            !renamed,
            "{step}: old entry"
        );
        assert_eq!(
            files.contents(&new_entry_at).is_some(),
            renamed,
            "{step}: new entry"
        );

        let mut side_objects = vec![old_side_at.as_str()];
        side_objects.extend(new_kept.map(|_| new_side_at.as_str()));
        let want = if renamed {
            result.unwrap();
            Remains {
                files: &[(&new, CONTENT)],
                side_objects: &side_objects,
                missing: &[&old],
            }
        } else {
            assert!(matches!(result, Err(SmbError::Io(_))), "{step}: {result:?}");
            Remains {
                files: &[(&old, CONTENT)],
                side_objects: &side_objects,
                missing: &[&new],
            }
        };
        want.check(&files, &step).await;
    }
}

#[tokio::test]
async fn a_crash_in_a_replace_onto_a_case_variant_keeps_the_old_spelling() {
    for nth in [1, 2] {
        let step = format!("rename {nth} fails");
        let (files, faulty, layer) = docs().await;
        seed_file(&files, "Docs\\report.TXT", &stored_bytes(b"old"));
        seed_file(&files, "Docs\\new.tmp", &stored_bytes(b"new!"));
        faulty.fail_rename(nth, injected());
        let result = layer
            .rename(&path("Docs\\NEW.tmp"), &path("Docs\\Report.txt"), true)
            .await;
        drop(layer);

        let want = if nth == 1 {
            // Neither file moves.
            assert!(matches!(result, Err(SmbError::Io(_))), "{step}: {result:?}");
            Remains {
                files: &[("new.tmp", b"new!"), ("report.TXT", b"old")],
                side_objects: &[],
                missing: &[],
            }
        } else {
            // The first rename put the file over the old one and the second
            // would give it the new spelling.
            result.unwrap();
            let reader = names_over(files.clone()).await;
            let asked = open_file(&reader, "Docs\\Report.txt").await;
            assert!(read_all(&asked).await == b"new!", "{step}: Report.txt");
            drop((asked, reader));
            Remains {
                files: &[("report.TXT", b"new!")],
                side_objects: &[],
                missing: &["new.tmp"],
            }
        };
        want.check(&files, &step).await;
    }
}
