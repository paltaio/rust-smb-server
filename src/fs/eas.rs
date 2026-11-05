//! Extended attributes of [`LocalFsBackend`](super::LocalFsBackend) on
//! Linux.
//!
//! The extended attribute `name` of a file or directory is its host
//! extended attribute `user.name`, the layout Samba uses. The
//! [`LocalFsBackend`](super::LocalFsBackend) docs give the rules for names,
//! case and the host attributes that stay hidden; `PRIVATE` and
//! `PRIVATE_PREFIXES` hold the server's and Samba's names among those.

use std::collections::HashMap;
use std::fs::File;
use std::io;

use rustix::fs::XattrFlags;
use rustix::io::Errno;

use super::streams::read_sized;
use crate::ea::{self, Ea};
use crate::error::SmbError;

const USER: &str = "user.";

/// Longest name of an extended attribute (XATTR_NAME_MAX).
const MAX_NAME: usize = 255;

/// Names under `user.` the server and Samba keep their own data in, and
/// the prefixes of such names.
const PRIVATE: [&str; 5] = [
    "DOSATTRIB",
    "SAMBA_PAI",
    "SAMBA_STREAMS",
    "SmbReparse",
    "org.netatalk.Metadata",
];
const PRIVATE_PREFIXES: [&str; 2] = ["DosStream.", "smb-server."];

/// True if `name`, the part after `user.`, holds data of the server or of
/// Samba.
fn private(name: &str) -> bool {
    PRIVATE.iter().any(|p| p.eq_ignore_ascii_case(name))
        || PRIVATE_PREFIXES.iter().any(|p| {
            name.get(..p.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(p))
        })
}

/// Where extended attributes are read: an open file, or a path.
pub(super) enum Source<'a> {
    File(&'a File),
    /// A path; with `follow`, a symlink at its end is followed.
    Path {
        path: String,
        follow: bool,
    },
}

impl Source<'_> {
    /// The entry `name` of the directory `dir` is open on, not followed
    /// when it is a symlink.
    pub(super) fn entry(dir: &impl std::os::fd::AsRawFd, name: &str) -> Source<'static> {
        Source::Path {
            path: format!("/proc/self/fd/{}/{name}", dir.as_raw_fd()),
            follow: false,
        }
    }

    /// The file or directory `fd` is open on, `O_PATH` descriptors
    /// included.
    pub(super) fn fd(fd: &impl std::os::fd::AsRawFd) -> Source<'static> {
        Source::Path {
            path: format!("/proc/self/fd/{}", fd.as_raw_fd()),
            follow: true,
        }
    }

    fn list(&self) -> io::Result<Vec<u8>> {
        read_sized(
            || match self {
                Source::File(fd) => rustix::fs::flistxattr_query(fd),
                Source::Path { path, follow: true } => rustix::fs::listxattr_query(path),
                Source::Path { path, .. } => rustix::fs::llistxattr_query(path),
            },
            |buf| match self {
                Source::File(fd) => rustix::fs::flistxattr(fd, buf),
                Source::Path { path, follow: true } => rustix::fs::listxattr(path, buf),
                Source::Path { path, .. } => rustix::fs::llistxattr(path, buf),
            },
        )
    }

    fn size(&self, attr: &str) -> io::Result<usize> {
        Ok(match self {
            Source::File(fd) => rustix::fs::fgetxattr_query(fd, attr),
            Source::Path { path, follow: true } => rustix::fs::getxattr_query(path, attr),
            Source::Path { path, .. } => rustix::fs::lgetxattr_query(path, attr),
        }?)
    }
}

/// One extended attribute as stored: the host names that differ only in
/// case, the one that sorts first in byte order first.
struct Stored {
    names: Vec<String>,
}

impl Stored {
    /// The host name the attribute is read from.
    fn main(&self) -> &str {
        &self.names[0]
    }

    /// The name clients see.
    fn ea_name(&self) -> &str {
        &self.main()[USER.len()..]
    }
}

/// The extended attributes of `source`, in the order the host lists them,
/// and where each is by its name as names compare. A filesystem without
/// user extended attributes has none.
fn stored(source: &Source<'_>) -> io::Result<(Vec<Stored>, HashMap<String, usize>)> {
    let list = match source.list() {
        Ok(list) => list,
        Err(e) if e.raw_os_error() == Some(Errno::NOTSUP.raw_os_error()) => Vec::new(),
        Err(e) => return Err(e),
    };
    let mut out: Vec<Stored> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for attr in list.split(|&b| b == 0) {
        let Some(name) = std::str::from_utf8(attr)
            .ok()
            .and_then(|a| a.strip_prefix(USER))
        else {
            continue;
        };
        if private(name) || !ea::valid_name(name.as_bytes()) {
            continue;
        }
        let attr = format!("{USER}{name}");
        match at.get(&ea::name_key(name)) {
            Some(&i) => out[i].names.push(attr),
            None => {
                at.insert(ea::name_key(name), out.len());
                out.push(Stored { names: vec![attr] });
            }
        }
    }
    for stored in &mut out {
        stored.names.sort();
    }
    Ok((out, at))
}

/// True if `e` says the attribute is gone.
fn is_gone(e: &io::Error) -> bool {
    e.raw_os_error() == Some(Errno::NODATA.raw_os_error())
}

/// The extended attributes of the file `fd` is open on, except those with
/// empty values or values longer than 65535 bytes.
pub(super) fn list(fd: &File) -> io::Result<Vec<Ea>> {
    let mut out = Vec::new();
    for stored in stored(&Source::File(fd))?.0 {
        let value = match get(fd, stored.main()) {
            Ok(value) => value,
            Err(e) if is_gone(&e) => continue,
            Err(e) => return Err(e),
        };
        if (1..=ea::MAX_VALUE).contains(&value.len()) {
            out.push(Ea::new(stored.ea_name(), value));
        }
    }
    Ok(out)
}

/// [`FileInfo::ea_size`](crate::FileInfo::ea_size) of `source`.
pub(super) fn size(source: &Source<'_>) -> io::Result<u32> {
    let mut sizes = Vec::new();
    for stored in stored(source)?.0 {
        match source.size(stored.main()) {
            Ok(len @ 1..=ea::MAX_VALUE) => sizes.push((stored.ea_name().len(), len)),
            Ok(_) => {}
            Err(e) if is_gone(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ea::list_length(sizes))
}

fn get(fd: &File, attr: &str) -> io::Result<Vec<u8>> {
    read_sized(
        || rustix::fs::fgetxattr_query(fd, attr),
        |buf| rustix::fs::fgetxattr(fd, attr, buf),
    )
}

/// The error a set answers for `e`.
fn to_smb(e: io::Error) -> SmbError {
    match e.raw_os_error().map(Errno::from_raw_os_error) {
        Some(Errno::TOOBIG | Errno::NOSPC) => SmbError::EaTooLarge,
        Some(Errno::NOTSUP) => SmbError::NotSupported,
        _ => super::local::io_to_smb(e),
    }
}

/// One host attribute as a set found it, to put back if a later one
/// fails.
struct Undo {
    attr: String,
    value: Option<Vec<u8>>,
}

/// Sets, replaces or, with an empty value, removes each of `eas` on the
/// file `fd` is open on, all or none: a failure puts back what the call
/// had changed. The caller holds the lock of the file's streams, so no
/// other change of its extended attributes runs meanwhile. If putting a
/// change back fails too, the set fails with an I/O error.
pub(super) fn set(fd: &File, eas: &[Ea]) -> Result<(), SmbError> {
    for ea in eas {
        if private(&ea.name) {
            return Err(SmbError::AccessDenied);
        }
        if USER.len() + ea.name.len() > MAX_NAME {
            return Err(SmbError::EaNameInvalid);
        }
    }
    let (current, at) = stored(&Source::File(fd)).map_err(to_smb)?;
    let mut undo = Vec::new();
    let Err(e) = apply(fd, eas, &current, &at, &mut undo) else {
        return Ok(());
    };
    let mut lost = false;
    for step in undo.into_iter().rev() {
        let back = match &step.value {
            Some(value) => rustix::fs::fsetxattr(fd, &step.attr, value, XattrFlags::empty()),
            None => rustix::fs::fremovexattr(fd, &step.attr),
        };
        if let Err(back) = back {
            tracing::warn!(error = %back, attr = %step.attr, "an extended attribute was not put back");
            lost = true;
        }
    }
    if lost {
        return Err(SmbError::Io(io::Error::other(format!(
            "extended attributes left half set after: {e}"
        ))));
    }
    Err(to_smb(e))
}

fn apply(
    fd: &File,
    eas: &[Ea],
    current: &[Stored],
    at: &HashMap<String, usize>,
    undo: &mut Vec<Undo>,
) -> io::Result<()> {
    for ea in eas {
        let names = match at.get(&ea::name_key(&ea.name)) {
            Some(&i) => current[i].names.clone(),
            None => vec![format!("{USER}{}", ea.name)],
        };
        for (n, attr) in names.iter().enumerate() {
            let old = match get(fd, attr) {
                Ok(value) => Some(value),
                Err(e) if is_gone(&e) => None,
                Err(e) => return Err(e),
            };
            if n == 0 && !ea.value.is_empty() {
                rustix::fs::fsetxattr(fd, attr, &ea.value, XattrFlags::empty())?;
            } else if old.is_some() {
                match rustix::fs::fremovexattr(fd, attr) {
                    Ok(()) | Err(Errno::NODATA) => {}
                    Err(e) => return Err(e.into()),
                }
            } else {
                continue;
            }
            undo.push(Undo {
                attr: attr.clone(),
                value: old,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_names_match_in_any_case() {
        for name in [
            "DosStream.s:$DATA",
            "dosstream.x",
            "DOSATTRIB",
            "dosattrib",
            "smb-server.streams",
            "SMB-SERVER.other",
            "org.netatalk.metadata",
        ] {
            assert!(private(name), "{name}");
        }
        for name in [
            "DosStream",
            "DOSATTRIB2",
            "smb-server",
            "test",
            "xdg.origin.url",
        ] {
            assert!(!private(name), "{name}");
        }
    }
}
