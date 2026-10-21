//! File access mask bits (MS-SMB2 2.2.13.1.1) and the rights an open is
//! granted from a CREATE DesiredAccess.

use crate::builder::Access;

pub const FILE_READ_DATA: u32 = 0x0000_0001;
/// FILE_LIST_DIRECTORY shares its bit with FILE_READ_DATA.
pub const FILE_LIST_DIRECTORY: u32 = FILE_READ_DATA;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// TreeConnect.MaximalAccess for a share access level.
pub fn maximal_access(access: Access) -> u32 {
    match access {
        Access::Read => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        Access::ReadWrite => FILE_ALL_ACCESS,
    }
}

/// Open.GrantedAccess for a CREATE DesiredAccess on a tree whose
/// MaximalAccess is `maximal`. Generic bits map to file rights,
/// MAXIMUM_ALLOWED adds all of `maximal`, and FILE_EXECUTE brings
/// FILE_READ_DATA. `None` if `desired` asks for a file right outside
/// `maximal`.
pub fn granted_access(desired: u32, maximal: u32) -> Option<u32> {
    let mut requested = desired;
    if desired & GENERIC_READ != 0 {
        requested |= FILE_GENERIC_READ;
    }
    if desired & GENERIC_WRITE != 0 {
        requested |= FILE_GENERIC_WRITE;
    }
    if desired & GENERIC_EXECUTE != 0 {
        requested |= FILE_GENERIC_EXECUTE;
    }
    if desired & GENERIC_ALL != 0 {
        requested |= FILE_ALL_ACCESS;
    }
    if requested & FILE_ALL_ACCESS & !maximal != 0 {
        return None;
    }
    let mut granted = requested & maximal;
    if desired & MAXIMUM_ALLOWED != 0 {
        granted |= maximal;
    }
    if granted & FILE_EXECUTE != 0 {
        granted |= FILE_READ_DATA;
    }
    Some(granted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_rights_map_to_file_rights() {
        let rw = maximal_access(Access::ReadWrite);
        assert_eq!(granted_access(GENERIC_READ, rw), Some(FILE_GENERIC_READ));
        assert_eq!(granted_access(GENERIC_ALL, rw), Some(FILE_ALL_ACCESS));
        assert_eq!(granted_access(MAXIMUM_ALLOWED, rw), Some(FILE_ALL_ACCESS));
        assert_eq!(granted_access(GENERIC_WRITE, rw).unwrap() & DELETE, 0);
        assert_eq!(
            granted_access(FILE_EXECUTE, rw),
            Some(FILE_EXECUTE | FILE_READ_DATA)
        );
    }

    #[test]
    fn read_tree_refuses_write_rights_and_caps_maximum_allowed() {
        let ro = maximal_access(Access::Read);
        for desired in [GENERIC_ALL, GENERIC_WRITE, DELETE] {
            assert_eq!(granted_access(desired, ro), None, "{desired:#x}");
        }
        assert_eq!(granted_access(MAXIMUM_ALLOWED, ro), Some(ro));
        assert_eq!(
            granted_access(FILE_GENERIC_READ, ro),
            Some(FILE_GENERIC_READ)
        );
    }
}
