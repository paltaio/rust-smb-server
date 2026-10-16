//! File access mask bits (MS-SMB2 2.2.13.1.1) and the rights an open is
//! granted from a CREATE DesiredAccess.

use crate::builder::Access;

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
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

/// Maps the generic bits of `desired` to file rights and limits the result
/// to `maximal`. GENERIC_ALL and MAXIMUM_ALLOWED grant all of `maximal`.
pub fn granted_access(desired: u32, maximal: u32) -> u32 {
    let mut granted = desired;
    if desired & GENERIC_READ != 0 {
        granted |= FILE_GENERIC_READ;
    }
    if desired & GENERIC_WRITE != 0 {
        granted |= FILE_GENERIC_WRITE;
    }
    if desired & GENERIC_EXECUTE != 0 {
        granted |= FILE_GENERIC_EXECUTE;
    }
    if desired & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        granted |= FILE_ALL_ACCESS;
    }
    granted & maximal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_rights_map_to_file_rights() {
        let rw = maximal_access(Access::ReadWrite);
        assert_eq!(granted_access(GENERIC_READ, rw), FILE_GENERIC_READ);
        assert_eq!(granted_access(GENERIC_ALL, rw), FILE_ALL_ACCESS);
        assert_eq!(granted_access(MAXIMUM_ALLOWED, rw), FILE_ALL_ACCESS);
        assert_eq!(granted_access(GENERIC_WRITE, rw) & DELETE, 0);
    }

    #[test]
    fn read_tree_never_grants_delete_or_writes() {
        let ro = maximal_access(Access::Read);
        let granted = granted_access(GENERIC_ALL | DELETE | FILE_WRITE_ATTRIBUTES, ro);
        assert_eq!(
            granted & (DELETE | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA),
            0
        );
    }
}
