# Server-side copy

Windows Explorer, `cp` on a Linux cifs mount and the macOS Finder ask the server to copy file data.

| Request | Does |
|---|---|
| COPYCHUNK, COPYCHUNK_WRITE | Copies ranges within a share, or between two shares of one session |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | Clones a range, on a backend that shares blocks between files |
| Apple whole-file copy | Copies a file with its last write time, its creation time except on Linux, and its named streams when both shares have them. Offered on shares with named streams |

| Call | Turns off |
|---|---|
| `.server_side_copy(false)` on `Share` | All of it on that share; clients copy the data themselves |
| `apple_copyfile(false)` on the builder | The whole-file copy only |

## LocalFsBackend

| Host | Copy | Cloning |
|---|---|---|
| Linux | `copy_file_range(2)`: shares blocks where the filesystem can, copies in the kernel otherwise, falls back to reads and writes. Named streams by reads and writes | Btrfs, XFS with reflinks: FSCTL_DUPLICATE_EXTENTS_TO_FILE and FILE_SUPPORTS_BLOCK_REFCOUNTING |
| Windows | Reads and writes | Volumes that report block cloning, such as ReFS |
| macOS | Reads and writes | None |

No cloning on a `.read_only()` backend, or on a share root the server cannot create files in.
