//! QUERY_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, QueryInfoRequest, QueryInfoResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::server::ServerState;

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;

// FS attribute flags (MS-FSCC §2.5.1)
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;

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

    let (info_res, granted_access) = {
        let open = open_arc.read().await;
        match open.handle.as_ref() {
            Some(h) => (h.stat().await, open.granted_access),
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        }
    };

    let buf: Vec<u8> = match info_type {
        InfoType::File => {
            let info = match info_res {
                Ok(i) => i,
                Err(e) => return HandlerResponse::err(e.to_nt_status()),
            };
            match req.file_information_class {
                ic::FILE_BASIC_INFORMATION => ic::encode_file_basic_information(&info),
                ic::FILE_STANDARD_INFORMATION => ic::encode_file_standard_information(&info),
                ic::FILE_INTERNAL_INFORMATION => {
                    ic::encode_file_internal_information(info.file_index)
                }
                ic::FILE_EA_INFORMATION => ic::encode_file_ea_information(),
                ic::FILE_FULL_EA_INFORMATION => {
                    return HandlerResponse::err(ntstatus::STATUS_NO_EAS_ON_FILE);
                }
                ic::FILE_ACCESS_INFORMATION => ic::encode_file_access_information(granted_access),
                ic::FILE_POSITION_INFORMATION => ic::encode_file_position_information(),
                ic::FILE_MODE_INFORMATION => ic::encode_file_mode_information(0),
                ic::FILE_ALIGNMENT_INFORMATION => ic::encode_file_alignment_information(),
                ic::FILE_NAME_INFORMATION => ic::encode_file_name_information(&info.name),
                ic::FILE_ALL_INFORMATION => ic::encode_file_all_information(&info, granted_access),
                ic::FILE_NETWORK_OPEN_INFORMATION => {
                    ic::encode_file_network_open_information(&info)
                }
                ic::FILE_STREAM_INFORMATION => ic::encode_file_stream_information(&info),
                ic::FILE_ALTERNATE_NAME_INFORMATION => {
                    // MS-FSA 2.1.5.12.4. Files here have no 8.3 short name.
                    let status = if req.output_buffer_length < 8 {
                        ntstatus::STATUS_INFO_LENGTH_MISMATCH
                    } else {
                        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
                    };
                    return HandlerResponse::err(status);
                }
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::FileSystem => {
            // Filesystem info is fixed apart from the volume creation time
            // and the case-sensitive flag.
            let creation_time = info_res.as_ref().map(|i| i.creation_time).unwrap_or(0);
            match req.file_information_class {
                ic::FS_VOLUME_INFORMATION => ic::encode_fs_volume_information(
                    creation_time,
                    ic::VOLUME_SERIAL_NUMBER,
                    "smb-server",
                ),
                ic::FS_SIZE_INFORMATION => {
                    // Fixed 4 PiB volume, 2 PiB free, 4 KiB clusters.
                    ic::encode_fs_size_information(
                        1u64 << 40, // total
                        1u64 << 39, // free
                        1,          // sectors per cluster
                        4096,       // bytes per sector
                    )
                }
                ic::FS_DEVICE_INFORMATION => {
                    ic::encode_fs_device_information(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE)
                }
                ic::FS_ATTRIBUTE_INFORMATION => {
                    let caps = tree_arc.read().await.share.backend.capabilities();
                    let case_sensitive = if caps.case_sensitive {
                        FILE_CASE_SENSITIVE_SEARCH
                    } else {
                        0
                    };
                    ic::encode_fs_attribute_information(
                        case_sensitive | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK,
                        255,
                        "NTFS",
                    )
                }
                ic::FS_FULL_SIZE_INFORMATION => {
                    ic::encode_fs_full_size_information(1u64 << 40, 1u64 << 39, 1u64 << 39, 1, 4096)
                }
                _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
            }
        }
        InfoType::Security => ic::encode_minimal_security_descriptor(),
        InfoType::Quota => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };

    if buf.len() as u32 > req.output_buffer_length {
        return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
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
    HandlerResponse::ok(out)
}
