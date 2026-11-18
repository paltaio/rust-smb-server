//! The `ShareBackend` and `Handle` contract, checked through the traits alone
//! over the instances listed at the end of this file. A test makes its state
//! with the backend's own calls.
//!
//! `instance!` turns a factory into the module of one backend and generates
//! one test per case in it, so a test name shows both. A factory is an async
//! function that returns a fresh, empty backend in a `Fixture`, or the reason
//! it could not make one. The fixture's `after` runs when the test ends,
//! whether it passed or not.
//!
//! `EXCLUDED` lists the cases an instance fails because the backend under it
//! does not keep the contract there. Such a case runs and must fail, so an
//! entry the instance passes stops the test.
//!
//! `rebuild` holds one test outside the instances: the layer over S3 across a
//! restart. On Windows, `namespace_changes_match_a_model_under_an_opener`
//! is another: the model run over a UNC root with each case-only rename run
//! while the new case is held open, which counts the names the backend
//! corrected.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::backend::ShareBackend;

mod case;
mod content;
mod handles;
mod helpers;
mod instances;
mod listing;
mod names;
mod namespace;
mod opens;
#[cfg(all(feature = "encryption", feature = "s3"))]
mod rebuild;
mod renames;
mod unlinks;

type Error = Box<dyn std::error::Error + Send + Sync>;
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type Make = fn() -> BoxFuture<'static, Result<Fixture, Error>>;
type Case = for<'a> fn(&'a dyn ShareBackend) -> BoxFuture<'a, ()>;

/// A backend for one test and what must run once the test is over.
struct Fixture {
    backend: Arc<dyn ShareBackend>,
    after: Option<BoxFuture<'static, ()>>,
}

impl Fixture {
    fn new(backend: impl ShareBackend) -> Self {
        Self {
            backend: Arc::new(backend),
            after: None,
        }
    }
}

/// The instance that is `MemFsBackend` itself.
const MEMFS: &[&str] = &["memfs"];
/// The instances over `MemFsBackend`.
const OVER_MEMFS: &[&str] = &["memfs", "layer_memfs"];
/// The instances over `S3Backend`.
const OVER_S3: &[&str] = &["s3", "layer_s3"];

/// The cases an instance fails, by name.
const EXCLUDED: &[(&str, &[&str])] = &[
    // MemFs ignores list patterns.
    ("wildcards_pick_the_names_they_match", MEMFS),
    ("a_literal_pattern_picks_one_name", MEMFS),
    (
        "a_literal_pattern_picks_a_name_of_any_length_or_script",
        MEMFS,
    ),
    // MemFs reports case-insensitive names and looks them up exactly.
    ("open_follows_the_case_rule", MEMFS),
    ("create_follows_the_case_rule", MEMFS),
    ("unlink_follows_the_case_rule", MEMFS),
    ("rename_source_follows_the_case_rule", MEMFS),
    ("rename_target_follows_the_case_rule", MEMFS),
    ("patterns_follow_the_case_rule", MEMFS),
    ("directories_on_the_way_follow_the_case_rule", MEMFS),
    ("files_and_directories_share_the_case_rule", MEMFS),
    ("namespace_changes_match_a_model", OVER_MEMFS),
    // MemFs handles find their file by the path they were opened with, so
    // after a rename or an unlink they fail with NotFound or report one link.
    ("a_file_handle_follows_a_rename", OVER_MEMFS),
    (
        "a_file_handle_follows_a_move_to_another_directory",
        OVER_MEMFS,
    ),
    ("a_directory_handle_follows_a_rename", OVER_MEMFS),
    (
        "link_count_is_zero_once_an_open_file_is_unlinked",
        OVER_MEMFS,
    ),
    // S3Backend leaves the link count of an unlinked open file at 1.
    ("link_count_is_zero_once_an_open_file_is_unlinked", OVER_S3),
    // MemFs and S3Backend report file_index 0.
    ("file_index_is_stable", OVER_MEMFS),
    ("file_index_is_stable", OVER_S3),
    // MemFs unlinks a directory that has entries.
    ("unlink_refuses_a_directory_with_entries", OVER_MEMFS),
    // MemFs renames into a directory that does not exist.
    ("rename_into_a_missing_directory_is_path_not_found", MEMFS),
    // MemFs renames the root.
    ("rename_of_the_root_is_refused", MEMFS),
];

fn excluded(instance: &str, case: &str) -> bool {
    EXCLUDED
        .iter()
        .any(|(name, instances)| *name == case && instances.contains(&instance))
}

async fn run(instance: &str, name: &str, make: Make, case: Case) {
    let Fixture { backend, after } = make()
        .await
        .unwrap_or_else(|error| panic!("{instance}: no backend: {error}"));
    let outcome = tokio::spawn(async move { case(&*backend).await }).await;
    let torn_down = match after {
        Some(after) => tokio::spawn(after).await,
        None => Ok(()),
    };
    let fails = excluded(instance, name);
    match outcome {
        Ok(()) if fails => panic!("{instance}::{name} passes: its entry in EXCLUDED is stale"),
        Err(error) if !fails => std::panic::resume_unwind(error.into_panic()),
        _ => {}
    }
    if let Err(error) = torn_down {
        std::panic::resume_unwind(error.into_panic());
    }
}

macro_rules! instance {
    ($instance:ident, $make:path) => {
        mod $instance {
            use super::*;

            instance!(@cases $instance, $make;
                opens::create_makes_a_file,
                opens::create_refuses_a_name_that_exists,
                opens::open_or_create_opens_what_exists_and_creates_the_rest,
                opens::open_finds_only_what_exists,
                opens::truncate_empties_an_existing_file,
                opens::overwrite_or_create_empties_or_creates,
                opens::directories_follow_their_intents,
                opens::a_file_does_not_open_as_a_directory,
                opens::a_directory_does_not_open_as_a_file,
                opens::a_missing_directory_on_the_way_is_path_not_found,
                opens::a_missing_last_name_is_not_found,
                opens::a_file_on_the_way_is_path_not_found,
                opens::a_write_only_open_writes,
                opens::the_root_is_a_directory_that_exists,
                opens::deep_trees_open_and_rename_whole,
                content::reads_fill_to_the_end,
                content::write_owned_and_flush_keep_the_data,
                content::a_write_past_the_end_leaves_a_gap_of_zeros,
                content::a_write_inside_the_file_keeps_the_rest,
                content::truncate_shrinks_the_file,
                content::truncate_extends_with_zeros,
                content::shrinking_then_extending_brings_back_no_data,
                content::truncating_to_the_size_changes_nothing,
                content::writes_and_truncates_match_a_model,
                content::writes_at_block_boundaries_match_a_model,
                content::stat_and_listings_report_the_size,
                content::handles_of_one_file_see_each_others_writes,
                content::two_handles_write_alternating_ranges,
                content::a_truncating_open_empties_the_file_for_other_handles,
                unlinks::unlink_removes_a_file,
                unlinks::unlink_removes_an_empty_directory,
                unlinks::unlink_refuses_a_directory_with_entries,
                unlinks::unlink_of_a_missing_name_is_not_found,
                unlinks::unlink_below_a_missing_directory_is_refused,
                unlinks::a_name_is_free_again_after_unlink,
                renames::rename_moves_a_file,
                renames::rename_moves_a_file_to_another_directory,
                renames::rename_moves_a_directory_with_its_entries,
                renames::rename_onto_a_file_needs_replace,
                renames::rename_onto_a_directory_with_replace_is_access_denied,
                renames::rename_onto_a_directory_without_replace_exists,
                renames::rename_of_a_missing_source_is_not_found,
                renames::rename_from_a_missing_directory_is_refused,
                renames::rename_into_a_missing_directory_is_path_not_found,
                renames::rename_of_the_root_is_refused,
                renames::rename_to_the_same_name_changes_nothing,
                renames::rename_changes_the_case_of_a_name,
                renames::an_editor_save_leaves_the_new_contents,
                renames::entries_below_a_renamed_directory_stay_reachable,
                renames::a_renamed_directory_leaves_its_name_free,
                handles::a_file_handle_follows_a_rename,
                handles::a_file_handle_follows_a_move_to_another_directory,
                handles::a_directory_handle_follows_a_rename,
                handles::link_count_is_one_for_a_file_and_a_directory,
                handles::link_count_is_zero_once_an_open_file_is_unlinked,
                handles::file_index_is_stable,
                listing::listings_report_every_entry,
                listing::listing_an_empty_directory_gives_nothing,
                listing::a_listing_holds_many_entries,
                listing::star_lists_every_entry,
                listing::wildcards_pick_the_names_they_match,
                listing::a_literal_pattern_picks_one_name,
                listing::listings_follow_creates_renames_and_unlinks,
                listing::dir_is_empty_follows_the_entries,
                names::names_of_every_length_round_trip,
                names::non_ascii_names_round_trip,
                names::a_literal_pattern_picks_a_name_of_any_length_or_script,
                namespace::namespace_changes_match_a_model,
                case::open_follows_the_case_rule,
                case::create_follows_the_case_rule,
                case::unlink_follows_the_case_rule,
                case::rename_source_follows_the_case_rule,
                case::rename_target_follows_the_case_rule,
                case::patterns_follow_the_case_rule,
                case::directories_on_the_way_follow_the_case_rule,
                case::files_and_directories_share_the_case_rule,
                case::a_directory_renamed_in_case_keeps_its_entries,
            );
        }
    };
    (@cases $instance:ident, $make:path; $($group:ident :: $name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                fn make() -> BoxFuture<'static, Result<Fixture, Error>> {
                    Box::pin($make())
                }
                fn case(backend: &dyn ShareBackend) -> BoxFuture<'_, ()> {
                    Box::pin(crate::tests::contract::$group::$name(backend))
                }
                run(stringify!($instance), stringify!($name), make, case).await;
            }
        )*
    };
}

instance!(memfs, instances::memfs);
#[cfg(feature = "localfs")]
instance!(localfs, instances::localfs);
#[cfg(all(windows, feature = "localfs"))]
instance!(localfs_unc, instances::localfs_unc);
#[cfg(feature = "encryption")]
instance!(layer_memfs, instances::layer_memfs);
#[cfg(all(feature = "encryption", feature = "localfs"))]
instance!(layer_localfs, instances::layer_localfs);
#[cfg(all(windows, feature = "encryption", feature = "localfs"))]
instance!(layer_localfs_unc, instances::layer_localfs_unc);
#[cfg(all(windows, feature = "localfs"))]
instance!(localfs_unc_contended, instances::localfs_unc_contended);
#[cfg(all(windows, feature = "encryption", feature = "localfs"))]
instance!(
    layer_localfs_unc_contended,
    instances::layer_localfs_unc_contended
);
#[cfg(all(feature = "encryption", feature = "localfs"))]
instance!(layer_clear_localfs, instances::layer_clear_localfs);
#[cfg(all(feature = "encryption", feature = "localfs"))]
instance!(layer_exact_localfs, instances::layer_exact_localfs);
#[cfg(feature = "s3")]
instance!(s3, instances::s3);
#[cfg(all(feature = "encryption", feature = "s3"))]
instance!(layer_s3, instances::layer_s3);

/// The model run of `namespace` over a share root on a UNC path, with each
/// rename that changes only the case of a name run while another handle
/// holds the name open in the new case, as a virus scanner can. The SMB
/// client can then leave the old case on the server, so such renames go
/// through the backend's correction, and the run still sees the names it
/// asked for.
#[cfg(all(windows, feature = "localfs"))]
#[tokio::test]
async fn namespace_changes_match_a_model_under_an_opener() {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    use crate::fs::LocalFsBackend;
    use crate::tests::util::{on_admin_share, scratch_dir};

    let dir = scratch_dir();
    let share = on_admin_share(dir.path());
    let held = Arc::new(AtomicUsize::new(0));
    let backend = {
        let (share, held) = (share.clone(), Arc::clone(&held));
        LocalFsBackend::new(&share).unwrap().before_rename(Box::new(
            move |parent, name, case_only| {
                if !case_only {
                    return None;
                }
                // A rename to the case the server stores already changes
                // nothing.
                let dir = share.join(parent);
                let name = name.to_str()?;
                let stored = std::fs::read_dir(&dir)
                    .ok()?
                    .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                    .find(|stored| stored.to_lowercase() == name.to_lowercase())?;
                if stored == name {
                    return None;
                }
                let open = std::fs::OpenOptions::new()
                    .access_mode(FILE_READ_ATTRIBUTES)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(dir.join(name))
                    .ok()?;
                held.fetch_add(1, Ordering::Relaxed);
                Some(open)
            },
        ))
    };
    namespace::namespace_changes_match_a_model(&backend).await;
    let held = held.load(Ordering::Relaxed);
    assert!(held > 0, "no case-only rename ran with its new case held");
    assert!(backend.corrections() > 0, "no name was corrected");
}
