//! File and filesystem info-class encoders used by QUERY_INFO, SET_INFO and
//! QUERY_DIRECTORY.
//!
//! Wire encodings per MS-FSCC 2.4 (file info) and MS-FSCC 2.5 (filesystem
//! info).

use crate::backend::{DirEntry, FileInfo};
use crate::stream::StreamInfo;
use crate::utils::utf16le;

// ---------------------------------------------------------------------------
// File info classes (MS-FSCC §2.4)
// ---------------------------------------------------------------------------

pub const FILE_DIRECTORY_INFORMATION: u8 = 0x01;
pub const FILE_FULL_DIRECTORY_INFORMATION: u8 = 0x02;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 0x03;
pub const FILE_BASIC_INFORMATION: u8 = 0x04;
pub const FILE_STANDARD_INFORMATION: u8 = 0x05;
pub const FILE_INTERNAL_INFORMATION: u8 = 0x06;
pub const FILE_EA_INFORMATION: u8 = 0x07;
pub const FILE_ACCESS_INFORMATION: u8 = 0x08;
pub const FILE_NAME_INFORMATION: u8 = 0x09;
pub const FILE_NAMES_INFORMATION: u8 = 0x0C;
pub const FILE_POSITION_INFORMATION: u8 = 0x0E;
pub const FILE_FULL_EA_INFORMATION: u8 = 0x0F;
pub const FILE_MODE_INFORMATION: u8 = 0x10;
pub const FILE_ALIGNMENT_INFORMATION: u8 = 0x11;
pub const FILE_ALL_INFORMATION: u8 = 0x12;
pub const FILE_ALLOCATION_INFORMATION: u8 = 0x13;
pub const FILE_END_OF_FILE_INFORMATION: u8 = 0x14;
pub const FILE_ALTERNATE_NAME_INFORMATION: u8 = 0x15;
pub const FILE_STREAM_INFORMATION: u8 = 0x16;
pub const FILE_DISPOSITION_INFORMATION: u8 = 0x0D;
pub const FILE_RENAME_INFORMATION: u8 = 0x0A;
pub const FILE_NETWORK_OPEN_INFORMATION: u8 = 0x22;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 0x26;

// ---------------------------------------------------------------------------
// FileBasicInformation (MS-FSCC §2.4.7) - 40 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_basic_information(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    out.extend_from_slice(&info.attributes().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out
}

// ---------------------------------------------------------------------------
// FileStandardInformation (MS-FSCC §2.4.41) - 24 bytes
// ---------------------------------------------------------------------------

/// `links` is NumberOfLinks. DeletePending is set when `delete_pending` is
/// or no link is left (MS-FSA 2.1.5.12.27).
pub fn encode_file_standard_information(
    info: &FileInfo,
    links: u32,
    delete_pending: bool,
) -> Vec<u8> {
    let (end_of_file, allocation_size) = info.sizes();
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&allocation_size.to_le_bytes());
    out.extend_from_slice(&end_of_file.to_le_bytes());
    out.extend_from_slice(&links.to_le_bytes());
    out.push(u8::from(delete_pending || links == 0));
    out.push(if info.is_directory { 1 } else { 0 }); // Directory
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    out
}

// ---------------------------------------------------------------------------
// FileInternalInformation (MS-FSCC §2.4.20) - 8 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_internal_information(file_index: u64) -> Vec<u8> {
    file_index.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileEaInformation (MS-FSCC §2.4.12) - 4 bytes
// ---------------------------------------------------------------------------

/// EaSize `ea_size`, as [`FileInfo::ea_size`] counts it: the size
/// directory listings carry, without the 4 bytes MS-FSA 2.1.5.12.10 adds.
pub fn encode_file_ea_information(ea_size: u32) -> Vec<u8> {
    ea_size.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileAccessInformation (MS-FSCC §2.4.1) - 4 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_access_information(access_mask: u32) -> Vec<u8> {
    access_mask.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FilePositionInformation (MS-FSCC §2.4.32) - 8 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_position_information() -> Vec<u8> {
    0u64.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileModeInformation (MS-FSCC §2.4.24) - 4 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_mode_information(mode: u32) -> Vec<u8> {
    mode.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileAlignmentInformation (MS-FSCC §2.4.3) - 4 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_alignment_information() -> Vec<u8> {
    // FILE_BYTE_ALIGNMENT (0) - no alignment requirement.
    0u32.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// FileAllInformation (MS-FSCC §2.4.2) - concatenation of basic, standard,
// internal, EA, access, position, mode, alignment, name.
// ---------------------------------------------------------------------------

/// The name part is empty, as MS-SMB2 3.3.5.20.1 asks of servers. The EA
/// part is FileEaInformation for `ea_size`.
pub fn encode_file_all_information(
    info: &FileInfo,
    access_mask: u32,
    links: u32,
    delete_pending: bool,
    ea_size: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_file_basic_information(info));
    out.extend_from_slice(&encode_file_standard_information(
        info,
        links,
        delete_pending,
    ));
    out.extend_from_slice(&encode_file_internal_information(info.file_index));
    out.extend_from_slice(&encode_file_ea_information(ea_size));
    out.extend_from_slice(&encode_file_access_information(access_mask));
    out.extend_from_slice(&encode_file_position_information());
    out.extend_from_slice(&encode_file_mode_information(0));
    out.extend_from_slice(&encode_file_alignment_information());
    out.extend_from_slice(&0u32.to_le_bytes()); // FileNameLength
    // Linux cifs checks FileAllInformation against its struct with
    // FileName[1], so the empty name still takes one byte.
    out.push(0);
    out
}

// ---------------------------------------------------------------------------
// FileNetworkOpenInformation (MS-FSCC §2.4.30) - 56 bytes
// ---------------------------------------------------------------------------

pub fn encode_file_network_open_information(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    let (end_of_file, allocation_size) = info.sizes();
    out.extend_from_slice(&allocation_size.to_le_bytes());
    out.extend_from_slice(&end_of_file.to_le_bytes());
    out.extend_from_slice(&info.attributes().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out
}

// ---------------------------------------------------------------------------
// FileStreamInformation (MS-FSCC 2.4.49)
// ---------------------------------------------------------------------------

/// FILE_STREAM_INFORMATION entries for the default stream, with its size
/// and allocation size when the file has one, then for each named stream
/// as `:name:$DATA`. Entries start on 8-byte boundaries; the last is not
/// padded. A directory with no named streams gives an empty buffer.
pub fn encode_file_stream_information(
    default: Option<(u64, u64)>,
    streams: &[StreamInfo],
) -> Vec<u8> {
    let mut entries: Vec<(Vec<u8>, u64, u64)> = Vec::with_capacity(streams.len() + 1);
    if let Some((size, allocation)) = default {
        entries.push((utf16le("::$DATA"), size, allocation));
    }
    for stream in streams {
        let name = utf16le(&format!(":{}:$DATA", stream.name.as_str()));
        entries.push((name, stream.size, stream.allocation_size));
    }
    let mut out = Vec::new();
    let count = entries.len();
    for (at, (name, size, allocation)) in entries.into_iter().enumerate() {
        let start = out.len();
        let len = STREAM_ENTRY_HEADER + name.len();
        let next = if at + 1 == count {
            0
        } else {
            len.next_multiple_of(8)
        };
        out.extend_from_slice(&(next as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&allocation.to_le_bytes());
        out.extend_from_slice(&name);
        if next != 0 {
            out.resize(start + next, 0);
        }
    }
    out
}

/// Bytes of a FILE_STREAM_INFORMATION entry before its name.
const STREAM_ENTRY_HEADER: usize = 24;

/// Cuts FILE_STREAM_INFORMATION entries down to the whole entries that fit
/// in `cap` bytes, the last of them unpadded with NextEntryOffset 0
/// (MS-SMB2 3.3.5.20.1). No entry may fit.
pub fn fit_stream_entries(buf: &mut Vec<u8>, cap: usize) {
    let field = |buf: &[u8], at: usize| {
        buf.get(at..at + 4).map_or(0, |b| {
            u32::from_le_bytes(b.try_into().expect("four bytes")) as usize
        })
    };
    let mut at = 0;
    let mut kept = None;
    while at + STREAM_ENTRY_HEADER <= buf.len() {
        let end = at + STREAM_ENTRY_HEADER + field(buf, at + 4);
        if end > cap {
            break;
        }
        kept = Some((at, end));
        let next = field(buf, at);
        if next == 0 {
            break;
        }
        at += next;
    }
    match kept {
        Some((last, end)) => {
            buf.truncate(end);
            buf[last..last + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        None => buf.clear(),
    }
}

// ---------------------------------------------------------------------------
// FS info classes (MS-FSCC §2.5)
// ---------------------------------------------------------------------------

pub const FS_VOLUME_INFORMATION: u8 = 0x01;
pub const FS_SIZE_INFORMATION: u8 = 0x03;
pub const FS_DEVICE_INFORMATION: u8 = 0x04;
pub const FS_ATTRIBUTE_INFORMATION: u8 = 0x05;
pub const FS_FULL_SIZE_INFORMATION: u8 = 0x07;
pub const FS_SECTOR_SIZE_INFORMATION: u8 = 0x0B;

/// Volume serial number of a backend that reports none of its own.
pub const VOLUME_SERIAL_NUMBER: u32 = 0xCAFE_BABE;

/// FileFsVolumeInformation (MS-FSCC §2.5.9). Volume creation time, serial,
/// label.
pub fn encode_fs_volume_information(creation_time: u64, serial: u32, label: &str) -> Vec<u8> {
    let label_u16 = utf16le(label);
    let mut out = Vec::new();
    out.extend_from_slice(&creation_time.to_le_bytes());
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&(label_u16.len() as u32).to_le_bytes());
    out.push(0); // SupportsObjects
    out.push(0); // Reserved
    out.extend_from_slice(&label_u16);
    out
}

/// FileFsSizeInformation (MS-FSCC §2.5.7) - 24 bytes.
pub fn encode_fs_size_information(
    total_alloc_units: u64,
    avail_alloc_units: u64,
    sectors_per_unit: u32,
    bytes_per_sector: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&total_alloc_units.to_le_bytes());
    out.extend_from_slice(&avail_alloc_units.to_le_bytes());
    out.extend_from_slice(&sectors_per_unit.to_le_bytes());
    out.extend_from_slice(&bytes_per_sector.to_le_bytes());
    out
}

/// FileFsDeviceInformation (MS-FSCC §2.5.10) - 8 bytes.
pub fn encode_fs_device_information(device_type: u32, characteristics: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&device_type.to_le_bytes());
    out.extend_from_slice(&characteristics.to_le_bytes());
    out
}

/// FileFsAttributeInformation (MS-FSCC §2.5.1) - variable.
pub fn encode_fs_attribute_information(
    attributes: u32,
    max_component_len: u32,
    fs_name: &str,
) -> Vec<u8> {
    let name_u16 = utf16le(fs_name);
    let mut out = Vec::new();
    out.extend_from_slice(&attributes.to_le_bytes());
    out.extend_from_slice(&max_component_len.to_le_bytes());
    out.extend_from_slice(&(name_u16.len() as u32).to_le_bytes());
    out.extend_from_slice(&name_u16);
    out
}

/// FileFsFullSizeInformation (MS-FSCC §2.5.4) - 32 bytes.
pub fn encode_fs_full_size_information(
    total_alloc_units: u64,
    caller_avail_alloc_units: u64,
    actual_avail_alloc_units: u64,
    sectors_per_unit: u32,
    bytes_per_sector: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&total_alloc_units.to_le_bytes());
    out.extend_from_slice(&caller_avail_alloc_units.to_le_bytes());
    out.extend_from_slice(&actual_avail_alloc_units.to_le_bytes());
    out.extend_from_slice(&sectors_per_unit.to_le_bytes());
    out.extend_from_slice(&bytes_per_sector.to_le_bytes());
    out
}

/// FileFsSectorSizeInformation (MS-FSCC §2.5.8) - 28 bytes. Every sector
/// size is `bytes_per_sector`, and the device and partition are reported
/// aligned.
pub fn encode_fs_sector_size_information(bytes_per_sector: u32) -> Vec<u8> {
    const SSINFO_FLAGS_ALIGNED_DEVICE: u32 = 0x0000_0001;
    const SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE: u32 = 0x0000_0002;
    let mut out = Vec::with_capacity(28);
    for _ in 0..4 {
        out.extend_from_slice(&bytes_per_sector.to_le_bytes());
    }
    let flags = SSINFO_FLAGS_ALIGNED_DEVICE | SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE;
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ByteOffsetForSectorAlignment
    out.extend_from_slice(&0u32.to_le_bytes()); // ByteOffsetForPartitionAlignment
    out
}

// ---------------------------------------------------------------------------
// Directory information classes (MS-FSCC §2.4.{8,14,17,30,31})
// ---------------------------------------------------------------------------

/// Encode one directory entry in info class `class`, with EaSize `ea_size`
/// in the classes that have it; empty for unsupported classes. The caller
/// patches `NextEntryOffset` for chained entries.
pub fn encode_dir_entry(class: u8, entry: &DirEntry, ea_size: u32) -> Vec<u8> {
    let info = &entry.info;
    let name_u16 = utf16le(&info.name);
    match class {
        FILE_DIRECTORY_INFORMATION => {
            // 64 bytes fixed + name
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, name_u16.len());
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_FULL_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, name_u16.len());
            out.extend_from_slice(&ea_size.to_le_bytes());
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_BOTH_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, name_u16.len());
            out.extend_from_slice(&ea_size.to_le_bytes());
            out.push(0); // ShortNameLength
            out.push(0); // Reserved1
            // ShortName: 24 bytes (12 UTF-16 chars).
            out.extend_from_slice(&[0u8; 24]);
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_BOTH_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, name_u16.len());
            out.extend_from_slice(&ea_size.to_le_bytes());
            out.push(0); // ShortNameLength
            out.push(0); // Reserved1
            out.extend_from_slice(&[0u8; 24]); // ShortName
            out.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
            out.extend_from_slice(&info.file_index.to_le_bytes()); // FileId
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_ID_FULL_DIRECTORY_INFORMATION => {
            let mut out = Vec::new();
            write_dir_entry_prefix(&mut out, info, name_u16.len());
            out.extend_from_slice(&ea_size.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            out.extend_from_slice(&info.file_index.to_le_bytes()); // FileId
            out.extend_from_slice(&name_u16);
            out
        }
        FILE_NAMES_INFORMATION => {
            let mut out = Vec::new();
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(info.file_index as u32).to_le_bytes());
            out.extend_from_slice(&(name_u16.len() as u32).to_le_bytes());
            out.extend_from_slice(&name_u16);
            out
        }
        _ => Vec::new(),
    }
}

/// What a FileIdBothDirectoryInformation entry for a macOS client sent
/// READ_DIR_ATTR carries in EaSize, ShortName and Reserved2.
pub struct FinderData {
    /// The access the client may ask for.
    pub max_access: u32,
    pub resource_fork_size: u64,
    /// Type, creator, Finder flags, extended Finder flags and date added.
    pub finder_info: [u8; 16],
    /// The low 16 bits of the POSIX mode, 0 when there is none.
    pub unix_mode: u16,
}

/// Encode one FileIdBothDirectoryInformation entry with `finder` in place
/// of the EaSize, ShortNameLength, ShortName and Reserved2 the class
/// defines. ShortNameLength is 24 and Reserved1 0.
pub fn encode_finder_dir_entry(entry: &DirEntry, finder: &FinderData) -> Vec<u8> {
    let info = &entry.info;
    let name_u16 = utf16le(&info.name);
    let mut out = Vec::with_capacity(104 + name_u16.len());
    write_dir_entry_prefix(&mut out, info, name_u16.len());
    out.extend_from_slice(&finder.max_access.to_le_bytes());
    out.push(24);
    out.push(0);
    out.extend_from_slice(&finder.resource_fork_size.to_le_bytes());
    out.extend_from_slice(&finder.finder_info);
    out.extend_from_slice(&finder.unix_mode.to_le_bytes());
    out.extend_from_slice(&info.file_index.to_le_bytes());
    out.extend_from_slice(&name_u16);
    out
}

fn write_dir_entry_prefix(out: &mut Vec<u8>, info: &FileInfo, name_len: usize) {
    out.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched later)
    out.extend_from_slice(&(info.file_index as u32).to_le_bytes()); // FileIndex
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    let (end_of_file, allocation_size) = info.sizes();
    out.extend_from_slice(&end_of_file.to_le_bytes());
    out.extend_from_slice(&allocation_size.to_le_bytes());
    out.extend_from_slice(&info.attributes().to_le_bytes());
    out.extend_from_slice(&(name_len as u32).to_le_bytes());
}

/// Offset of FileName in a directory entry of info class `class`: the size
/// of its fixed part. `None` for classes `encode_dir_entry` does not encode.
pub fn dir_entry_name_offset(class: u8) -> Option<usize> {
    Some(match class {
        FILE_DIRECTORY_INFORMATION => 64,
        FILE_FULL_DIRECTORY_INFORMATION => 68,
        FILE_BOTH_DIRECTORY_INFORMATION => 94,
        FILE_NAMES_INFORMATION => 12,
        FILE_ID_BOTH_DIRECTORY_INFORMATION => 104,
        FILE_ID_FULL_DIRECTORY_INFORMATION => 80,
        _ => return None,
    })
}

/// Round up `n` to the next multiple of 8.
pub fn align8(n: usize) -> usize {
    (n + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_info() -> FileInfo {
        FileInfo {
            name: "file.txt".to_string(),
            end_of_file: 100,
            allocation_size: 100,
            creation_time: 0x01D9_0000_0000_0000,
            last_access_time: 0x01D9_0000_0000_0000,
            last_write_time: 0x01D9_0000_0000_0000,
            change_time: 0x01D9_0000_0000_0000,
            is_directory: false,
            read_only: false,
            file_index: 1,
            unix_mode: None,
            ea_size: 0,
            file_attributes: 0,
        }
    }

    #[test]
    fn basic_information_is_40_bytes() {
        let bytes = encode_file_basic_information(&fake_info());
        assert_eq!(bytes.len(), 40);
    }

    #[test]
    fn standard_information_is_24_bytes() {
        let bytes = encode_file_standard_information(&fake_info(), 1, false);
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn standard_information_reports_links_and_delete_pending() {
        let bytes = encode_file_standard_information(&fake_info(), 3, false);
        assert_eq!(bytes[16..20], 3u32.to_le_bytes());
        assert_eq!(bytes[20], 0);
        assert_eq!(
            encode_file_standard_information(&fake_info(), 1, true)[20],
            1
        );
        // No link left: the file is being deleted.
        assert_eq!(
            encode_file_standard_information(&fake_info(), 0, false)[20],
            1
        );
    }

    #[test]
    fn network_open_information_is_56_bytes() {
        let bytes = encode_file_network_open_information(&fake_info());
        assert_eq!(bytes.len(), 56);
    }

    #[test]
    fn file_all_information_empty_name_keeps_linux_minimum_size() {
        let bytes = encode_file_all_information(&fake_info(), 0x001F_01FF, 1, false, 0);
        assert_eq!(bytes.len(), 101);
        // FileNameLength
        assert_eq!(bytes[96..100], [0; 4]);
    }

    #[test]
    fn dir_entry_name_offsets_match_the_encoders() {
        let entry = DirEntry { info: fake_info() };
        let name_len = utf16le(&entry.info.name).len();
        for class in [
            FILE_DIRECTORY_INFORMATION,
            FILE_FULL_DIRECTORY_INFORMATION,
            FILE_BOTH_DIRECTORY_INFORMATION,
            FILE_NAMES_INFORMATION,
            FILE_ID_BOTH_DIRECTORY_INFORMATION,
            FILE_ID_FULL_DIRECTORY_INFORMATION,
        ] {
            let offset = dir_entry_name_offset(class).unwrap();
            assert_eq!(encode_dir_entry(class, &entry, 0).len(), offset + name_len);
        }
        assert_eq!(dir_entry_name_offset(0x3C), None);
    }

    #[test]
    fn sector_size_information_is_28_bytes() {
        let bytes = encode_fs_sector_size_information(4096);
        assert_eq!(bytes.len(), 28);
        assert_eq!(bytes[0..4], 4096u32.to_le_bytes());
    }

    #[test]
    fn stream_information_aligns_entries_and_leaves_the_last_unpadded() {
        let stream = |name: &str, size| StreamInfo::new(name.parse().unwrap(), size, 8);
        let buf = encode_file_stream_information(
            Some((5, 4096)),
            &[stream("s", 3), stream("\u{F022}x", 0)],
        );
        // `::$DATA` is 38 bytes, `:s:$DATA` 40, `:\u{F022}x:$DATA` 42.
        assert_eq!(buf.len(), 40 + 40 + 42);
        assert_eq!(buf[0..4], 40u32.to_le_bytes());
        assert_eq!(buf[4..8], 14u32.to_le_bytes());
        assert_eq!(buf[8..16], 5u64.to_le_bytes());
        assert_eq!(buf[16..24], 4096u64.to_le_bytes());
        assert_eq!(buf[24..38], utf16le("::$DATA")[..]);
        assert_eq!(buf[38..40], [0, 0]);
        assert_eq!(buf[40..44], 40u32.to_le_bytes());
        assert_eq!(buf[64..80], utf16le(":s:$DATA")[..]);
        assert_eq!(buf[80..84], 0u32.to_le_bytes());
        assert_eq!(buf[104..], utf16le(":\u{F022}x:$DATA")[..]);

        assert!(encode_file_stream_information(None, &[]).is_empty());
        let dir = encode_file_stream_information(None, &[stream("s", 3)]);
        assert_eq!(dir.len(), 40);
        assert_eq!(dir[0..4], 0u32.to_le_bytes());
    }
}
