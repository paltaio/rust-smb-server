//! QUERY_INFO handler (MS-SMB2 3.3.5.20).

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, InfoType, QueryInfoRequest, QueryInfoResponse};

use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::server::{ServerState, ShareBindings};

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;

// FS attribute flags (MS-FSCC §2.5.1)
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;

// Access mask bits (MS-SMB2 2.2.13.1.1)
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

/// How a reply longer than OutputBufferLength is cut down.
#[derive(Clone, Copy)]
enum Overflow {
    /// Fixed size: the minimum length is the whole reply.
    Never,
    /// The trailing name is cut to fit, with STATUS_BUFFER_OVERFLOW.
    Truncate,
    /// Only whole entries are returned, with STATUS_BUFFER_OVERFLOW.
    WholeEntries,
}

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match req.info_type_enum() {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    // NEGOTIATE advertises MaxTransactSize equal to MaxReadSize.
    if req.output_buffer_length > *conn.max_read_size.read().await {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let smb311 = *conn.dialect.read().await == Some(Dialect::Smb311);
    let cap = req.output_buffer_length as usize;

    let open = open_arc.read().await;
    let result = match info_type {
        InfoType::File => query_file(&open, req.file_information_class, cap).await,
        InfoType::FileSystem => {
            let share = Arc::clone(&tree_arc.read().await.share);
            query_filesystem(&open, &share, req.file_information_class, cap).await
        }
        // MS-FSA 2.1.5.14: the store keeps no security descriptors.
        InfoType::Security => Err(ntstatus::STATUS_INVALID_DEVICE_REQUEST),
        InfoType::Quota => Err(ntstatus::STATUS_NOT_SUPPORTED),
    };
    drop(open);
    let (mut buf, overflow) = match result {
        Ok(reply) => reply,
        Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH) => return info_length_mismatch(smb311),
        Err(status) => return HandlerResponse::err(status),
    };

    let mut status = ntstatus::STATUS_SUCCESS;
    if buf.len() > cap {
        match overflow {
            Overflow::Never => return info_length_mismatch(smb311),
            Overflow::Truncate => buf.truncate(cap),
            Overflow::WholeEntries => buf.clear(),
        }
        status = ntstatus::STATUS_BUFFER_OVERFLOW;
    }

    let resp = QueryInfoResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out)
        .expect("QUERY_INFO response encodes");
    let mut response = HandlerResponse::ok(out);
    response.status = status;
    response
}

/// STATUS_INFO_LENGTH_MISMATCH with the error data of MS-SMB2 3.3.5.20.1:
/// on SMB 3.1.1 one empty error context, otherwise none.
pub(super) fn info_length_mismatch(smb311: bool) -> HandlerResponse {
    let mut response = HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    if smb311 {
        // StructureSize, ErrorContextCount, Reserved, ByteCount, then an
        // ERROR Context with ErrorDataLength 0 and ErrorId 0.
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&9u16.to_le_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&[0; 8]);
        response.body = body;
    }
    response
}

/// A reply and how to cut it down when it is longer than OutputBufferLength.
type Reply = Result<(Vec<u8>, Overflow), u32>;

/// SMB2_0_INFO_FILE (MS-SMB2 3.3.5.20.1) for an OutputBufferLength of `cap`.
async fn query_file(open: &Open, class: u8, cap: usize) -> Reply {
    let (min_len, overflow, access) = match class {
        ic::FILE_BASIC_INFORMATION => (40, Overflow::Never, FILE_READ_ATTRIBUTES),
        ic::FILE_STANDARD_INFORMATION => (24, Overflow::Never, 0),
        ic::FILE_INTERNAL_INFORMATION => (8, Overflow::Never, 0),
        ic::FILE_EA_INFORMATION => (4, Overflow::Never, 0),
        ic::FILE_ACCESS_INFORMATION => (4, Overflow::Never, 0),
        ic::FILE_POSITION_INFORMATION => (8, Overflow::Never, 0),
        ic::FILE_MODE_INFORMATION => (4, Overflow::Never, 0),
        ic::FILE_ALIGNMENT_INFORMATION => (4, Overflow::Never, 0),
        // BlockAlign(FieldOffset(NameInformation.FileName) + 2, 8).
        ic::FILE_ALL_INFORMATION => (104, Overflow::Truncate, FILE_READ_ATTRIBUTES),
        ic::FILE_NETWORK_OPEN_INFORMATION => (56, Overflow::Never, FILE_READ_ATTRIBUTES),
        ic::FILE_STREAM_INFORMATION => (24, Overflow::WholeEntries, 0),
        ic::FILE_FULL_EA_INFORMATION => (0, Overflow::Never, FILE_READ_EA),
        ic::FILE_ALTERNATE_NAME_INFORMATION => (8, Overflow::Never, 0),
        // MS-FSA 2.1.5.12.19: not available to remote clients.
        ic::FILE_NAME_INFORMATION => return Err(ntstatus::STATUS_NOT_SUPPORTED),
        c if is_file_class(c) => return Err(ntstatus::STATUS_NOT_SUPPORTED),
        _ => return Err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };
    if open.granted_access & access != access {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if cap < min_len {
        return Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let info = handle.stat().await.map_err(|e| e.to_nt_status())?;
    let buf = match class {
        ic::FILE_BASIC_INFORMATION => ic::encode_file_basic_information(&info),
        ic::FILE_STANDARD_INFORMATION | ic::FILE_ALL_INFORMATION => {
            let links = handle.link_count().await.map_err(|e| e.to_nt_status())?;
            if class == ic::FILE_STANDARD_INFORMATION {
                ic::encode_file_standard_information(&info, links, open.delete_pending())
            } else {
                ic::encode_file_all_information(
                    &info,
                    open.granted_access,
                    links,
                    open.delete_pending(),
                )
            }
        }
        ic::FILE_INTERNAL_INFORMATION => ic::encode_file_internal_information(info.file_index),
        ic::FILE_EA_INFORMATION => ic::encode_file_ea_information(),
        ic::FILE_ACCESS_INFORMATION => ic::encode_file_access_information(open.granted_access),
        ic::FILE_POSITION_INFORMATION => ic::encode_file_position_information(),
        ic::FILE_MODE_INFORMATION => ic::encode_file_mode_information(0),
        ic::FILE_ALIGNMENT_INFORMATION => ic::encode_file_alignment_information(),
        ic::FILE_NETWORK_OPEN_INFORMATION => ic::encode_file_network_open_information(&info),
        ic::FILE_STREAM_INFORMATION => ic::encode_file_stream_information(&info),
        ic::FILE_FULL_EA_INFORMATION => return Err(ntstatus::STATUS_NO_EAS_ON_FILE),
        // MS-FSA 2.1.5.12.4. Files here have no 8.3 short name.
        ic::FILE_ALTERNATE_NAME_INFORMATION => return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND),
        _ => unreachable!("class checked above"),
    };
    Ok((buf, overflow))
}

/// SMB2_0_INFO_FILESYSTEM (MS-SMB2 3.3.5.20.2) for an OutputBufferLength
/// of `cap`.
async fn query_filesystem(open: &Open, share: &ShareBindings, class: u8, cap: usize) -> Reply {
    let (min_len, overflow) = match class {
        // BlockAlign(FieldOffset(VolumeLabel), 8).
        ic::FS_VOLUME_INFORMATION => (24, Overflow::Truncate),
        ic::FS_SIZE_INFORMATION => (24, Overflow::Never),
        ic::FS_DEVICE_INFORMATION => (8, Overflow::Never),
        // BlockAlign(FieldOffset(FileSystemName), 4).
        ic::FS_ATTRIBUTE_INFORMATION => (12, Overflow::Truncate),
        ic::FS_FULL_SIZE_INFORMATION => (32, Overflow::Never),
        ic::FS_SECTOR_SIZE_INFORMATION => (28, Overflow::Never),
        // FileFsLabelInformation through FileFsVolumeFlagsInformation.
        2 | 6 | 8 | 9 | 10 => return Err(ntstatus::STATUS_NOT_SUPPORTED),
        _ => return Err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };
    if cap < min_len {
        return Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }
    if class == ic::FS_DEVICE_INFORMATION {
        let buf = ic::encode_fs_device_information(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE);
        return Ok((buf, overflow));
    }
    let volume = share
        .backend
        .volume_info()
        .await
        .map_err(|e| e.to_nt_status())?;
    let buf = match class {
        ic::FS_VOLUME_INFORMATION => {
            let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
            let creation_time = handle.stat().await.map_or(0, |i| i.creation_time);
            let label = volume.label.as_deref().unwrap_or(&share.name);
            ic::encode_fs_volume_information(creation_time, volume.serial_number, label)
        }
        ic::FS_SIZE_INFORMATION => ic::encode_fs_size_information(
            volume.total_allocation_units,
            volume.caller_available_allocation_units,
            volume.sectors_per_allocation_unit,
            volume.bytes_per_sector,
        ),
        ic::FS_ATTRIBUTE_INFORMATION => {
            let case_sensitive = if share.backend.capabilities().case_sensitive {
                FILE_CASE_SENSITIVE_SEARCH
            } else {
                0
            };
            ic::encode_fs_attribute_information(
                case_sensitive | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK,
                volume.max_name_length,
                "NTFS",
            )
        }
        ic::FS_FULL_SIZE_INFORMATION => ic::encode_fs_full_size_information(
            volume.total_allocation_units,
            volume.caller_available_allocation_units,
            volume.actual_available_allocation_units,
            volume.sectors_per_allocation_unit,
            volume.bytes_per_sector,
        ),
        ic::FS_SECTOR_SIZE_INFORMATION => {
            ic::encode_fs_sector_size_information(volume.bytes_per_sector)
        }
        _ => unreachable!("class checked above"),
    };
    Ok((buf, overflow))
}

/// True if MS-FSCC 2.4 documents `class` as a file information class.
fn is_file_class(class: u8) -> bool {
    matches!(class, 1..=29 | 31..=40 | 44..=46 | 48 | 50 | 54 | 59 | 60 | 64 | 65 | 78..=81)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_error_on_smb311_carries_one_empty_error_context() {
        let response = info_length_mismatch(true);
        assert_eq!(response.status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(
            response.body,
            [9, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let response = info_length_mismatch(false);
        assert_eq!(response.body, [9, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
