//! Deletes of [`LocalFsBackend`](super::LocalFsBackend) on Windows.
//!
//! Where the volume of the share root deletes with POSIX semantics, as
//! NTFS does, a deleted name goes at once, while other handles of the
//! entry stay open. Where it refuses them, as an SMB share does, an entry
//! another handle keeps open would keep its name until that handle closes,
//! and a delete-pending entry cannot be renamed. So each delete there moves
//! the entry into the directory `.smb-deleted` in the share root, under a
//! random name, then marks it to be deleted when its last handle closes:
//! its name is free at once, and the file system removes the entry itself
//! at the last close, also when the server stops or the session to the
//! share drops. A directory with entries fails with
//! STATUS_DIRECTORY_NOT_EMPTY before it moves; one that gets an entry while
//! it moves comes back under the name the file system stored for it, and
//! fails the same way.
//!
//! `.smb-deleted` is made hidden by the first delete that needs it, and the
//! backend holds it open from then on. What earlier runs left there is
//! deleted when a backend first opens it; a directory there that still has
//! entries stays, with a warning. Clients cannot reach the name in the
//! share root on any volume.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tracing::{debug, error, warn};
use windows_sys::Win32::Foundation::STATUS_DELETE_PENDING;

use super::dir::Dir;
use super::windows_dir::{
    ERROR_DIR_NOT_EMPTY, delete_on_close, entries_of, nt_error, open_to_delete, random_name,
    refuses_posix,
};

/// The directory deleted entries go to, in the share root.
pub(super) const TRASH_NAME: &str = ".smb-deleted";

/// Where the deletes of a backend go.
pub(super) struct Trash {
    /// Host identity of the share root.
    root_key: Option<(u64, u64)>,
    /// Case rule of name lookups in the share root.
    case_sensitive: bool,
    /// The volume refused a delete with POSIX semantics.
    posix_refused: AtomicBool,
    dir: Mutex<State>,
}

/// The trash directory as a backend knows it.
enum State {
    /// Not opened yet.
    Unopened,
    Open(Arc<fs::File>),
    /// It could not be opened or made, or something else has its name.
    Unusable,
}

impl Trash {
    /// The trash of the share root with host identity `root_key`, whose
    /// names are looked up under the case rule `case_sensitive`.
    pub(super) fn new(root_key: Option<(u64, u64)>, case_sensitive: bool) -> Self {
        Self {
            root_key,
            case_sensitive,
            posix_refused: AtomicBool::new(false),
            dir: Mutex::new(State::Unopened),
        }
    }

    /// Makes deletes act as on a volume that refuses POSIX deletes.
    #[cfg(test)]
    pub(super) fn refuse_posix(&self) {
        self.posix_refused.store(true, Ordering::Relaxed);
    }

    /// The name a listing of `dir` leaves out, with its case rule: that of
    /// the trash when `dir` is the share root.
    pub(super) fn hidden_in(&self, dir: &Dir) -> Option<(&'static str, bool)> {
        let key = super::local::file_key(&dir.dir_metadata().ok()?);
        (key.is_some() && key == self.root_key).then_some((TRASH_NAME, self.case_sensitive))
    }

    /// Deletes the entry `rel` below the share root `root`, a link there
    /// itself: a directory, which must be empty, with `is_dir`, else a
    /// file. Once it returns Ok, the name is gone from its directory and
    /// free to be made again, whatever handles of the entry stay open.
    pub(super) fn remove(&self, root: &Dir, rel: &Path, is_dir: bool) -> io::Result<()> {
        let removal = root.open_removal(rel, is_dir)?;
        if !self.posix_refused.load(Ordering::Relaxed) {
            match removal.delete_posix() {
                Ok(()) => return Ok(()),
                Err(status) if refuses_posix(status) => {
                    self.posix_refused.store(true, Ordering::Relaxed);
                }
                Err(status) => return Err(nt_error(status)),
            }
        }
        let Some(trash) = self.dir(root) else {
            return removal.delete_on_close().map_err(nt_error);
        };
        if is_dir && removal.has_entries()? {
            return Err(io::Error::from_raw_os_error(ERROR_DIR_NOT_EMPTY));
        }
        let (stored, name) = match removal.stored_name().and_then(|s| Ok((s, random_name()?))) {
            Ok(names) => names,
            Err(e) => {
                debug!(error = %e, "deleted entry left in place");
                return removal.delete_on_close().map_err(nt_error);
            }
        };
        #[cfg(test)]
        if let Some(f) = BEFORE_MOVE
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            f(rel);
        }
        let wide: Vec<u16> = name.encode_utf16().collect();
        if let Err(status) = removal.move_to(&trash, &wide) {
            debug!(error = %nt_error(status), "deleted entry left in place");
            return removal.delete_on_close().map_err(nt_error);
        }
        let Err(status) = removal.delete_on_close() else {
            return Ok(());
        };
        if let Err(back) = removal.move_back(&stored) {
            error!(
                name = %name,
                error = %nt_error(back),
                "an entry that could not be deleted was left in .smb-deleted"
            );
        }
        Err(nt_error(status))
    }

    /// The trash directory of the share root `root`, opened or made on the
    /// first call, which deletes what is left in it; `None` when it is
    /// unusable.
    fn dir(&self, root: &Dir) -> Option<Arc<fs::File>> {
        let mut state = self.dir.lock().unwrap_or_else(PoisonError::into_inner);
        match &*state {
            State::Open(dir) => return Some(Arc::clone(dir)),
            State::Unusable => return None,
            State::Unopened => {}
        }
        match root.hold_dir(TRASH_NAME) {
            Ok(dir) => {
                sweep(&dir);
                let dir = Arc::new(dir);
                *state = State::Open(Arc::clone(&dir));
                Some(dir)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "deleted names stay until their last handle closes: .smb-deleted is not usable"
                );
                *state = State::Unusable;
                None
            }
        }
    }
}

/// What runs in a delete between the check that a directory is empty and
/// its move into `.smb-deleted`, with the path it deletes.
#[cfg(test)]
type Hook = Box<dyn Fn(&Path) + Send>;

/// Runs in a delete before the entry moves into `.smb-deleted`.
#[cfg(test)]
pub(super) static BEFORE_MOVE: Mutex<Option<Hook>> = Mutex::new(None);

/// Deletes each entry of the trash directory `dir` that is not already
/// waiting for its last handle to close, a read-only file and a link
/// included, without following links or going below a directory. A
/// directory with entries stays, with a warning.
fn sweep(dir: &fs::File) {
    let entries = match entries_of(dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!(error = %e, ".smb-deleted not listed");
            return;
        }
    };
    for entry in entries {
        let name: OsString = match entry {
            Ok(entry) => entry.file_name(),
            Err(e) => {
                warn!(error = %e, ".smb-deleted not listed to its end");
                return;
            }
        };
        let deleted = match open_to_delete(dir, &name) {
            Err(STATUS_DELETE_PENDING) => continue,
            Ok(file) => delete_on_close(&file),
            Err(status) => Err(status),
        };
        if let Err(status) = deleted {
            warn!(
                name = %name.display(),
                error = %nt_error(status),
                "an entry of .smb-deleted was not deleted"
            );
        }
    }
}

#[cfg(test)]
mod tests;
