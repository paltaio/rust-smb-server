//! Related compounded requests (MS-SMB2 3.3.5.2.7.2).

use crate::dispatch::{read_u32, read_u64};
use crate::ntstatus;
use crate::proto::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_HEADER_LEN, Smb2Header,
};

/// What a related request takes from the request before it in the chain.
#[derive(Default)]
pub struct RelatedContext {
    session_id: u64,
    tree_id: u32,
    /// FileId the previous request carried or created.
    file_id: Option<[u8; 16]>,
    failed: Failed,
    /// Status of a failed CREATE whose FileId the rest of the chain uses.
    create_failed: Option<u32>,
}

/// A failed previous request, and which later requests fail with it.
#[derive(Default)]
enum Failed {
    #[default]
    None,
    /// A SESSION_SETUP: every request that needs a session.
    SessionSetup,
    /// A TREE_CONNECT: every request that needs a tree.
    TreeConnect,
}

/// How a related request fails without running.
pub struct Failure {
    pub status: u32,
    /// Whether every later request in the chain fails with it too.
    pub rest_of_chain: bool,
}

impl RelatedContext {
    /// Puts the previous request's SessionId, TreeId and FileId into a
    /// related request, both in `request` and in `hdr`, or returns how it
    /// fails instead.
    pub fn apply(&self, request: &mut [u8], hdr: &mut Smb2Header) -> Result<(), Failure> {
        let command = hdr.command;
        let refused = match self.failed {
            Failed::None => false,
            Failed::SessionSetup => needs_session(command),
            Failed::TreeConnect => needs_tree(command),
        };
        if refused {
            return Err(Failure {
                status: ntstatus::STATUS_INVALID_PARAMETER,
                rest_of_chain: true,
            });
        }
        if let Some(offset) = file_id_body_offset(command) {
            if let Some(status) = self.create_failed {
                return Err(Failure {
                    status,
                    rest_of_chain: false,
                });
            }
            let Some(file_id) = self.file_id else {
                return Err(Failure {
                    status: ntstatus::STATUS_INVALID_HANDLE,
                    rest_of_chain: true,
                });
            };
            let offset = SMB2_HEADER_LEN + offset;
            if let Some(field) = request.get_mut(offset..offset + 16) {
                field.copy_from_slice(&file_id);
            }
        }
        request[0x28..0x30].copy_from_slice(&self.session_id.to_le_bytes());
        hdr.session_id = self.session_id;
        if let HeaderTail::Sync { reserved, .. } = hdr.tail {
            request[0x24..0x28].copy_from_slice(&self.tree_id.to_le_bytes());
            hdr.tail = HeaderTail::Sync {
                reserved,
                tree_id: self.tree_id,
            };
        }
        Ok(())
    }

    /// Records the ids `request` used and the ones its `response` created.
    pub fn update(&mut self, command: Command, request: &[u8], response: &[u8]) {
        let status = read_u32(response, 0x08);
        let failed = status >> 30 == 3 && status != ntstatus::STATUS_MORE_PROCESSING_REQUIRED;
        self.session_id = read_u64(response, 0x28);
        // An asynchronous response carries its AsyncId where the TreeId
        // would be; the request has the TreeId then.
        self.tree_id = if read_u32(response, 0x10) & SMB2_FLAGS_ASYNC_COMMAND != 0 {
            read_u32(request, 0x24)
        } else {
            read_u32(response, 0x24)
        };
        self.failed = match command {
            Command::SessionSetup if failed => Failed::SessionSetup,
            Command::TreeConnect if failed => Failed::TreeConnect,
            _ => Failed::None,
        };
        if command == Command::Create {
            self.file_id = created_file_id(response);
            self.create_failed = failed.then_some(status);
        } else {
            self.file_id = file_id_body_offset(command).and_then(|offset| {
                let offset = SMB2_HEADER_LEN + offset;
                request.get(offset..offset + 16)?.try_into().ok()
            });
        }
    }
}

pub(crate) fn needs_session(command: Command) -> bool {
    !matches!(
        command,
        Command::Negotiate | Command::SessionSetup | Command::Echo | Command::Cancel
    )
}

pub(crate) fn needs_tree(command: Command) -> bool {
    command == Command::Create
        || command == Command::TreeDisconnect
        || file_id_body_offset(command).is_some()
}

/// Offset of the FileId in the request body of commands that carry one.
fn file_id_body_offset(command: Command) -> Option<usize> {
    match command {
        Command::Close
        | Command::Flush
        | Command::Lock
        | Command::Ioctl
        | Command::QueryDirectory
        | Command::ChangeNotify
        | Command::OplockBreak => Some(8),
        Command::Read | Command::Write => Some(16),
        Command::QueryInfo => Some(24),
        Command::SetInfo => Some(16),
        _ => None,
    }
}

/// FileId of a successful CREATE response.
fn created_file_id(response: &[u8]) -> Option<[u8; 16]> {
    if read_u32(response, 0x08) != ntstatus::STATUS_SUCCESS {
        return None;
    }
    let offset = SMB2_HEADER_LEN + 64;
    response.get(offset..offset + 16)?.try_into().ok()
}
