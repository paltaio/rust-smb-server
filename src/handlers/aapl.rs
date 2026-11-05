//! Apple's SMB2 extensions: the reply to the `AAPL` server query, which
//! macOS clients put in the CREATE of a share's root when they mount it,
//! and the Finder data of directory listings for a client sent
//! READ_DIR_ATTR.

use std::sync::atomic::Ordering;

use tracing::debug;

use crate::access_mask::{DELETE, FILE_APPEND_DATA, FILE_EXECUTE, FILE_WRITE_DATA, FILE_WRITE_EA};
use crate::backend::{DirEntry, FileInfo, Handle};
use crate::conn::state::Connection;
use crate::error::SmbError;
use crate::info_class::FinderData;
use crate::proto::messages::aapl::{
    AAPL_CASE_SENSITIVE, AAPL_SERVER_CAPS, AAPL_SUPPORTS_READ_DIR_ATTR, AAPL_UNIX_BASED,
};
use crate::proto::messages::{AaplQuery, AaplReply, CreateContext};
use crate::server::ShareBindings;
use crate::stream::StreamName;

/// The server caps of every reply. With UNIX_BASED the client relies on
/// the server to zero-fill gaps past the end of a file.
const SERVER_CAPS: u64 = if cfg!(unix) { AAPL_UNIX_BASED } else { 0 };

/// Size of an `AFP_AfpInfo` stream, and where in it the 32 bytes of
/// Finder info are.
const AFP_INFO_SIZE: usize = 60;
const FINDER_INFO_AT: usize = 16;

/// Date added of an entry whose date is unknown, as AppleDouble keeps it.
const NO_DATE: i32 = i32::MIN;

/// FILETIME of 2000-01-01, where AppleDouble dates count from.
const FILETIME_2000: i64 = 125_911_584_000_000_000;

const AFP_AFP_INFO: &str = "AFP_AfpInfo";
const AFP_RESOURCE: &str = "AFP_Resource";

/// The file type bits of a POSIX mode, and those of a regular file and a
/// directory.
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;

/// The `AAPL` response context to `query` on `share`, with `model`.
/// READ_DIR_ATTR goes to a client that has it on a share with named
/// streams, and from then on with every reply on `conn` that carries
/// server caps: the client keeps the caps of the last such reply for its
/// session and reads FileIdBothDirectoryInformation on every share by
/// them.
pub(super) fn reply(
    conn: &Connection,
    share: &ShareBindings,
    query: &AaplQuery,
    model: &str,
) -> CreateContext {
    let mut server_caps = SERVER_CAPS;
    if query.bitmap & AAPL_SERVER_CAPS != 0 {
        let grant = query.client_caps & AAPL_SUPPORTS_READ_DIR_ATTR != 0 && share.named_streams;
        if conn.aapl_read_dir_attr.fetch_or(grant, Ordering::AcqRel) || grant {
            server_caps |= AAPL_SUPPORTS_READ_DIR_ATTR;
        }
    }
    let volume_caps = if share.backend.capabilities().case_sensitive {
        AAPL_CASE_SENSITIVE
    } else {
        0
    };
    CreateContext {
        name: CreateContext::NAME_AAPL.to_vec(),
        data: AaplReply {
            bitmap: query.bitmap,
            server_caps,
            volume_caps,
            model,
        }
        .encode(),
    }
}

/// True if the client on `conn` reads directory listings with Finder data.
pub(super) fn reads_finder_data(conn: &Connection) -> bool {
    conn.aapl_read_dir_attr.load(Ordering::Acquire)
}

/// The Finder data of `entries`, the entries one response to a listing
/// of the directory open as `dir` carries, on a share whose tree grants
/// `maximal`. The Finder info and resource fork come from each entry's
/// `AFP_AfpInfo` and `AFP_Resource` streams, read in one backend call when
/// `peek` is set, for regular files and directories only; "." and ".."
/// get none. A backend that does not read streams clears `peek`.
pub(super) async fn finder_data(
    dir: Option<&dyn Handle>,
    entries: &[DirEntry],
    maximal: u32,
    peek: &mut bool,
) -> Vec<FinderData> {
    let mut found = vec![Vec::new(); entries.len()];
    if let Some(dir) = dir
        && *peek
    {
        let streams = [
            (stream(AFP_AFP_INFO), AFP_INFO_SIZE as u32),
            (stream(AFP_RESOURCE), 0),
        ];
        let (at, asked): (Vec<usize>, Vec<_>) = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| has_streams(&entry.info))
            .map(|(i, entry)| {
                // A directory has no resource fork.
                let wanted = if entry.info.is_directory {
                    &streams[..1]
                } else {
                    &streams[..]
                };
                (i, (entry.info.name.as_str(), wanted))
            })
            .unzip();
        if !asked.is_empty() {
            match dir.peek_streams(&asked).await {
                Ok(peeked) => {
                    for (i, streams) in at.into_iter().zip(peeked) {
                        found[i] = streams;
                    }
                }
                Err(SmbError::NotSupported) => {
                    debug!("backend reads no streams for listings");
                    *peek = false;
                }
                Err(e) => debug!(error = %e, "streams not read for a listing"),
            }
        }
    }
    entries
        .iter()
        .zip(found)
        .map(|(entry, streams)| {
            let info = &entry.info;
            let mut streams = streams.into_iter();
            let afp_info = streams.next().flatten();
            let fork = streams.next().flatten();
            FinderData {
                max_access: max_access(maximal, info),
                resource_fork_size: fork.map_or(0, |(size, _)| size),
                finder_info: compressed_finder_info(
                    info,
                    afp_info.as_ref().map(|(_, data)| &data[..]),
                ),
                unix_mode: info.unix_mode.map_or(0, |mode| (mode & 0xFFFF) as u16),
            }
        })
        .collect()
}

fn stream(name: &str) -> StreamName {
    name.parse().expect("a valid stream name")
}

/// True if the entry `info` is one whose streams a listing reads: not "."
/// or "..", and a regular file or a directory where its mode says.
fn has_streams(info: &FileInfo) -> bool {
    info.name != "."
        && info.name != ".."
        && info
            .unix_mode
            .is_none_or(|mode| matches!(mode & S_IFMT, S_IFREG | S_IFDIR))
}

/// The access a client may ask for on `info` on a tree whose maximal
/// access is `maximal`: no deleting a read-only file or directory, no
/// writing a read-only file, and no running a file whose mode has no
/// execute bit. A read-only directory still takes new entries.
fn max_access(maximal: u32, info: &FileInfo) -> u32 {
    let mut access = maximal;
    if info.read_only {
        access &= !DELETE;
        if !info.is_directory {
            access &= !(FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA);
        }
    }
    if !info.is_directory && info.unix_mode.is_some_and(|mode| mode & 0o111 == 0) {
        access &= !FILE_EXECUTE;
    }
    access
}

/// The 16 bytes of Finder info a listing carries for `info`, from its
/// `AFP_AfpInfo` stream `afp_info`: type and creator (zeros for a
/// directory), the Finder flags, the extended Finder flags and the date
/// added, big-endian seconds since 2000. A stream that is not 60 bytes
/// starting with `AFP\0` counts as none; with none, everything is zero
/// and the date unknown.
fn compressed_finder_info(info: &FileInfo, afp_info: Option<&[u8]>) -> [u8; 16] {
    let mut out = [0u8; 16];
    let finder = afp_info
        .filter(|data| data.len() == AFP_INFO_SIZE && data.starts_with(b"AFP\0"))
        .map(|data| &data[FINDER_INFO_AT..FINDER_INFO_AT + 32]);
    let date = match finder {
        Some(finder) => {
            if !info.is_directory {
                out[..8].copy_from_slice(&finder[..8]);
            }
            out[8..10].copy_from_slice(&finder[8..10]);
            out[10..12].copy_from_slice(&finder[24..26]);
            date_added(info.creation_time)
        }
        None => NO_DATE,
    };
    out[12..].copy_from_slice(&date.to_be_bytes());
    out
}

/// `filetime` as seconds since 2000, unknown when it is 0 or out of range.
fn date_added(filetime: u64) -> i32 {
    let Ok(filetime) = i64::try_from(filetime) else {
        return NO_DATE;
    };
    if filetime == 0 {
        return NO_DATE;
    }
    i32::try_from((filetime - FILETIME_2000).div_euclid(10_000_000)).unwrap_or(NO_DATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_mask::FILE_ALL_ACCESS;

    /// An `AFP_AfpInfo` stream holding `finder`.
    fn afp_info(finder: &[u8; 32]) -> Vec<u8> {
        let mut out = b"AFP\0\0\0\x01\0\0\0\0\0\x80\0\0\0".to_vec();
        out.extend_from_slice(finder);
        out.extend_from_slice(&[0; 12]);
        out
    }

    fn file(creation_time: u64) -> FileInfo {
        let mut info = FileInfo::new("f.txt");
        info.creation_time = creation_time;
        info.unix_mode = Some(0o100_644);
        info
    }

    #[test]
    fn a_file_carries_type_creator_flags_and_date() {
        let mut finder = [0u8; 32];
        finder[..8].copy_from_slice(b"TEXTttxt");
        finder[8..10].copy_from_slice(&[0x04, 0x0C]);
        finder[10..16].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        finder[20..24].copy_from_slice(&[7, 7, 7, 7]);
        finder[24..26].copy_from_slice(&[0x80, 0x01]);
        // 2026-11-04 01:02:27.7 UTC.
        let created = 134_382_277_477_044_582;
        let expected: [u8; 16] = [
            b'T', b'E', b'X', b'T', b't', b't', b'x', b't', 0x04, 0x0C, 0x80, 0x01, 0x32, 0x7D,
            0x40, 0xA3,
        ];
        assert_eq!(
            compressed_finder_info(&file(created), Some(&afp_info(&finder))),
            expected
        );
    }

    #[test]
    fn a_directory_carries_flags_without_type_or_creator() {
        let mut finder = [0u8; 32];
        finder[..8].copy_from_slice(b"fldrMACS");
        finder[8..10].copy_from_slice(&[0x00, 0x0E]);
        let mut dir = file(FILETIME_2000 as u64 + 10_000_000);
        dir.is_directory = true;
        assert_eq!(
            compressed_finder_info(&dir, Some(&afp_info(&finder))),
            [0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x0E, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn without_a_valid_stream_there_is_no_finder_info() {
        let unknown = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0];
        let good = afp_info(&[0x41; 32]);
        let mut bad_magic = good.clone();
        bad_magic[0] = b'B';
        for data in [None, Some(&good[..59]), Some(&bad_magic[..]), Some(&[][..])] {
            assert_eq!(compressed_finder_info(&file(1), data), unknown, "{data:?}");
        }
        // A file created at an unknown or unrepresentable time.
        for created in [0, 1, u64::MAX] {
            assert_eq!(
                compressed_finder_info(&file(created), Some(&good))[12..],
                [0x80, 0, 0, 0]
            );
        }
    }

    /// FileIdBothDirectoryInformation with Finder data for the 16-byte
    /// file "f-finfo.txt" with type TEXT and creator ttxt, mode 0644, a
    /// zero file id and attributes ARCHIVE.
    const ENTRY: &str = concat!(
        "8000000000000000",
        "66912029f86bdd0166912029f86bdd0166912029f86bdd0166912029f86bdd01",
        "1000000000000000002000000000000020000000160000009f011700",
        "1800",
        "0000000000000000544558547474787400000000327d40a3",
        "a481",
        "0000000000000000",
        "66002d00660069006e0066006f002e00740078007400",
    );

    #[test]
    fn an_entry_carries_the_finder_data_where_macos_reads_it() {
        let mut info = FileInfo::new("f-finfo.txt");
        let time = 134_382_277_477_044_582;
        info.creation_time = time;
        info.last_access_time = time;
        info.last_write_time = time;
        info.change_time = time;
        info.end_of_file = 16;
        info.allocation_size = 8192;
        info.file_index = 0x0123_4567_89AB_CDEF;
        info.unix_mode = Some(0o100_644);
        let mut finder = [0u8; 32];
        finder[..8].copy_from_slice(b"TEXTttxt");
        let data = FinderData {
            max_access: 0x0017_019F,
            resource_fork_size: 0,
            finder_info: compressed_finder_info(&info, Some(&afp_info(&finder))),
            unix_mode: 0o100_644,
        };
        let entry = crate::backend::DirEntry { info };
        let mut expected = hex::decode(ENTRY).unwrap();
        // NextEntryOffset is set when entries are chained, the attributes
        // are the ones this server reports, and FileIndex and FileId are
        // the file's.
        expected[..4].fill(0);
        expected[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
        expected[56..60].copy_from_slice(&0x80u32.to_le_bytes());
        expected[96..104].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
        assert_eq!(
            hex::encode(crate::info_class::encode_finder_dir_entry(&entry, &data)),
            hex::encode(expected)
        );
    }

    #[test]
    fn read_only_entries_and_files_without_execute_bits_lose_those_rights() {
        let all = FILE_ALL_ACCESS;
        let mut info = file(0);
        assert_eq!(max_access(all, &info), all & !FILE_EXECUTE);
        info.unix_mode = Some(0o100_744);
        assert_eq!(max_access(all, &info), all);
        info.unix_mode = None;
        assert_eq!(max_access(all, &info), all);
        info.read_only = true;
        assert_eq!(max_access(all, &info), 0x001E_01E9);
        let mut dir = FileInfo::new("d");
        dir.is_directory = true;
        dir.unix_mode = Some(0o040_700);
        assert_eq!(max_access(all, &dir), all);
        dir.read_only = true;
        assert_eq!(max_access(all, &dir), all & !DELETE);
    }
}
