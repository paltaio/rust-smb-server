//! Opens that overlap a create, an unlink or a rename of their file.
//!
//! An open has its inner handle before it has its node. Each scenario parks an
//! open between the two, after its inner `stat`, and starts the change that
//! could slip into the gap. The change must wait for the open. Afterwards the
//! handles of one file hold one node, and the handles of two files never hold
//! the same one.

use tokio::task::JoinHandle;

use super::backend::EncryptedBackend;
use super::handle::EncryptedHandle;
use super::node::HeaderKind;
use super::testing::{
    clear_over, names_over, open_file, seed_dir, seed_file, settle, shares_node, spawn_open,
    stored_at,
};
use crate::backend::{OpenAction, OpenIntent, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::tests::file_ids::FileIds;
use crate::tests::gated::{Gate, Gated, Op};
use crate::tests::memfs::MemFsBackend;
use crate::tests::util::path;

/// How the share stores names.
#[derive(Clone, Copy, Debug)]
enum Names {
    Encrypted,
    Clear,
}

impl Names {
    /// The path the inner backend stores the client path `plain` under.
    fn stored(self, plain: &str) -> String {
        match self {
            Self::Encrypted => stored_at(plain),
            Self::Clear => plain.to_string(),
        }
    }

    /// Puts the directory `plain` into `files`.
    fn seed_dir(self, files: &MemFsBackend, plain: &str) {
        match self {
            Self::Encrypted => seed_dir(files, plain),
            Self::Clear => {
                files.clone().with_dir(plain);
            }
        }
    }

    /// Puts the empty file `plain` into `files`. Its directory is there.
    fn seed_file(self, files: &MemFsBackend, plain: &str) {
        match self {
            Self::Encrypted => seed_file(files, plain, b""),
            Self::Clear => {
                files.clone().with_file(plain, b"");
            }
        }
    }
}

/// A share over a store that parks calls, with the file `other` open in it.
struct Scene<B> {
    names: Names,
    files: MemFsBackend,
    gated: Gated<B>,
    layer: EncryptedBackend<Gated<B>>,
    other: EncryptedHandle<Gated<B>>,
}

impl<B: ShareBackend + Clone> Scene<B> {
    /// A share over the inner backend that `make` builds from an empty store.
    async fn new(names: Names, make: impl FnOnce(MemFsBackend) -> B) -> Self {
        let files = MemFsBackend::new();
        let gated = Gated::new(make(files.clone()));
        let layer = match names {
            Names::Encrypted => names_over(gated.clone()).await,
            Names::Clear => clear_over(gated.clone()).await,
        };
        names.seed_file(&files, "other");
        let other = open_file(&layer, "other").await;
        Self {
            names,
            files,
            gated,
            layer,
            other,
        }
    }

    /// A gate that parks the open of `plain` once the inner backend has
    /// answered its `stat`, before the open gets its node.
    fn park_before_node(&self, plain: &str) -> Gate {
        self.gated.arm_after_at(Op::Stat, &self.names.stored(plain))
    }

    fn spawn_unlink(&self, plain: &str) -> JoinHandle<SmbResult<()>> {
        let layer = self.layer.clone();
        let plain = path(plain);
        tokio::spawn(async move { layer.unlink(&plain).await })
    }
}

/// The call is still waiting once every other task has run until it waits.
async fn assert_waits<T>(call: &JoinHandle<T>, names: Names, what: &str) {
    settle().await;
    assert!(!call.is_finished(), "{names:?}: {what} did not wait");
}

/// Handles of one file hold one node and handles of different files hold
/// different nodes. `files` lists the handles of each file.
fn assert_nodes<B: ShareBackend>(names: Names, files: &[Vec<&EncryptedHandle<B>>]) {
    for (n, handles) in files.iter().enumerate() {
        for handle in &handles[1..] {
            assert!(
                shares_node(handles[0], handle),
                "{names:?}: file {n} has two nodes"
            );
        }
        for (m, others) in files.iter().enumerate().skip(n + 1) {
            assert!(
                !shares_node(handles[0], others[0]),
                "{names:?}: files {n} and {m} share a node"
            );
        }
    }
}

async fn an_open_waits_for_a_create_that_has_no_node_yet<B: ShareBackend + Clone>(
    names: Names,
    make: impl FnOnce(MemFsBackend) -> B,
) {
    let scene = Scene::new(names, make).await;
    let gate = scene.park_before_node("f");
    let creating = spawn_open(&scene.layer, "f", OpenIntent::Create);
    gate.reached().await;
    assert_eq!(scene.files.contents(&names.stored("f")), Some(Vec::new()));
    assert_eq!(scene.layer.node_count(), 1, "only `other` has a node");

    let opening = spawn_open(&scene.layer, "f", OpenIntent::Open);
    assert_waits(&opening, names, "the open").await;
    gate.release();

    let (created, action) = creating.await.unwrap().unwrap();
    assert_eq!(action, OpenAction::Created);
    let (opened, action) = opening.await.unwrap().unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert_nodes(names, &[vec![&created, &opened], vec![&scene.other]]);
    assert_eq!(scene.layer.node_count(), 2);
    assert!(!created.node().is_detached());
    assert_eq!(created.node().header().await, Some(HeaderKind::Absent));
}

async fn a_create_waits_for_an_open_that_has_no_node_yet<B: ShareBackend + Clone>(
    names: Names,
    make: impl Fn(MemFsBackend) -> B,
) {
    let intents = [
        OpenIntent::Create,
        OpenIntent::OpenOrCreate,
        OpenIntent::OverwriteOrCreate,
    ];
    for intent in intents {
        let scene = Scene::new(names, &make).await;
        names.seed_file(&scene.files, "f");
        let gate = scene.park_before_node("f");
        let opening = spawn_open(&scene.layer, "f", OpenIntent::Open);
        gate.reached().await;

        let creating = spawn_open(&scene.layer, "f", intent);
        assert_waits(&creating, names, &format!("{intent:?}")).await;
        gate.release();

        let (opened, action) = opening.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Opened);
        let again = match (intent, creating.await.unwrap()) {
            (OpenIntent::Create, Err(SmbError::Exists)) => None,
            (OpenIntent::OpenOrCreate, Ok((handle, OpenAction::Opened)))
            | (OpenIntent::OverwriteOrCreate, Ok((handle, OpenAction::Overwritten))) => {
                Some(handle)
            }
            (_, other) => panic!(
                "{names:?} {intent:?}: {:?}",
                other.map(|(_, action)| action)
            ),
        };
        let mut file = vec![&opened];
        file.extend(&again);
        assert_nodes(names, &[file, vec![&scene.other]]);
        assert_eq!(scene.layer.node_count(), 2, "{names:?} {intent:?}");
        assert!(!opened.node().is_detached());
        let header = if intent == OpenIntent::OverwriteOrCreate {
            HeaderKind::Absent
        } else {
            HeaderKind::Unknown
        };
        assert_eq!(
            opened.node().header().await,
            Some(header),
            "{names:?} {intent:?}"
        );
    }
}

async fn an_unlink_and_a_create_wait_for_an_open_that_has_no_node_yet(names: Names) {
    an_unlink_and_a_create_wait_for(names, OpenIntent::Open).await;
}

async fn an_unlink_and_a_create_wait_for_a_truncating_open_that_has_no_node_yet(names: Names) {
    an_unlink_and_a_create_wait_for(names, OpenIntent::Truncate).await;
}

/// Parks an open of the file `f` with `intent`, queues an unlink and a create
/// of `f`, and releases the open. `intent` opens the existing file.
async fn an_unlink_and_a_create_wait_for(names: Names, intent: OpenIntent) {
    let scene = Scene::new(names, |files| files).await;
    names.seed_file(&scene.files, "f");
    let gate = scene.park_before_node("f");
    let opening = spawn_open(&scene.layer, "f", intent);
    gate.reached().await;

    let unlinking = scene.spawn_unlink("f");
    assert_waits(&unlinking, names, "the unlink").await;
    let creating = spawn_open(&scene.layer, "f", OpenIntent::Create);
    assert_waits(&creating, names, "the create").await;
    assert!(scene.files.contents(&names.stored("f")).is_some());
    gate.release();

    let (old, action) = opening.await.unwrap().unwrap();
    let (opened, header) = match intent {
        OpenIntent::Truncate => (OpenAction::Overwritten, HeaderKind::Absent),
        _ => (OpenAction::Opened, HeaderKind::Unknown),
    };
    assert_eq!(action, opened, "{names:?} {intent:?}");
    unlinking.await.unwrap().unwrap();
    let (new, action) = creating.await.unwrap().unwrap();
    assert_eq!(action, OpenAction::Created);
    assert_nodes(names, &[vec![&old], vec![&new], vec![&scene.other]]);
    assert!(old.node().is_detached());
    assert!(!new.node().is_detached());
    assert_eq!(
        old.node().header().await,
        Some(header),
        "{names:?} {intent:?}"
    );
    assert_eq!(new.node().header().await, Some(HeaderKind::Absent));
    assert_eq!(scene.layer.node_count(), 2);
}

async fn a_directory_rename_waits_for_an_open_below_it_that_has_no_node_yet(names: Names) {
    let scene = Scene::new(names, |files| files).await;
    names.seed_dir(&scene.files, "d");
    names.seed_file(&scene.files, "d\\f");
    let gate = scene.park_before_node("d\\f");
    let opening = spawn_open(&scene.layer, "d\\f", OpenIntent::Open);
    gate.reached().await;

    let renaming = tokio::spawn({
        let share = scene.layer.clone();
        async move { share.rename(&path("d"), &path("e"), false).await }
    });
    assert_waits(&renaming, names, "the rename").await;
    assert!(scene.files.contents(&names.stored("d\\f")).is_some());
    gate.release();

    let (below, action) = opening.await.unwrap().unwrap();
    assert_eq!(action, OpenAction::Opened);
    renaming.await.unwrap().unwrap();
    assert_eq!(below.node().path(), path(&names.stored("e\\f")));
    assert!(scene.files.contents(&names.stored("e\\f")).is_some());
    let again = open_file(&scene.layer, "e\\f").await;
    assert_nodes(names, &[vec![&below, &again], vec![&scene.other]]);
    assert!(!below.node().is_detached());
    assert_eq!(scene.layer.node_count(), 2);
}

/// Registers the scenarios as tests. Each scenario of `both` runs in four
/// modules: encrypted names and names in the clear, each over a plain store and
/// over a store that reports file ids. Each scenario of `memfs_only` runs in
/// the two modules over the plain store.
macro_rules! scenarios {
    (
        both: [$($both:ident),+ $(,)?],
        memfs_only: [$($memfs:ident),+ $(,)?] $(,)?
    ) => {
        mod encrypted_names_over_memfs {
            use super::*;
            $(
                #[tokio::test]
                async fn $both() {
                    super::$both(Names::Encrypted, |files| files).await;
                }
            )+
            $(
                #[tokio::test]
                async fn $memfs() {
                    super::$memfs(Names::Encrypted).await;
                }
            )+
        }

        mod names_in_clear_over_memfs {
            use super::*;
            $(
                #[tokio::test]
                async fn $both() {
                    super::$both(Names::Clear, |files| files).await;
                }
            )+
            $(
                #[tokio::test]
                async fn $memfs() {
                    super::$memfs(Names::Clear).await;
                }
            )+
        }

        mod encrypted_names_over_file_ids {
            use super::*;
            $(
                #[tokio::test]
                async fn $both() {
                    super::$both(Names::Encrypted, FileIds::new).await;
                }
            )+
        }

        mod names_in_clear_over_file_ids {
            use super::*;
            $(
                #[tokio::test]
                async fn $both() {
                    super::$both(Names::Clear, FileIds::new).await;
                }
            )+
        }
    };
}

scenarios! {
    both: [
        an_open_waits_for_a_create_that_has_no_node_yet,
        a_create_waits_for_an_open_that_has_no_node_yet,
    ],
    memfs_only: [
        an_unlink_and_a_create_wait_for_an_open_that_has_no_node_yet,
        an_unlink_and_a_create_wait_for_a_truncating_open_that_has_no_node_yet,
        a_directory_rename_waits_for_an_open_below_it_that_has_no_node_yet,
    ],
}
