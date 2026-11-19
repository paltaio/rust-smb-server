# Server-side copy

Windows Explorer, `cp` on a Linux CIFS mount, and macOS Finder ask the server to copy file data directly.

| Request | Behavior |
|---|---|
| `COPYCHUNK`, `COPYCHUNK_WRITE` | Copies byte ranges within a share or between two shares in the same session |
| `FSCTL_DUPLICATE_EXTENTS_TO_FILE` | Clones a byte range on a backend that shares blocks between files |
| Apple whole-file copy | Copies a file with its last write time, its creation time (except on Linux), and its named streams when both shares support them. Advertised on shares with named streams |

| Call | Disables |
|---|---|
| `.server_side_copy(false)` on `Share` | All server-side copy on that share; clients copy data themselves |
| `apple_copyfile(false)` on the builder | Apple whole-file copy only |

## LocalFsBackend

| Host | Copy | Cloning |
|---|---|---|
| Linux | `copy_file_range(2)`: shares blocks where the filesystem supports it, copies in the kernel otherwise, and falls back to reads and writes. Named streams always use reads and writes | Btrfs and XFS with reflinks: supports `FSCTL_DUPLICATE_EXTENTS_TO_FILE` and reports `FILE_SUPPORTS_BLOCK_REFCOUNTING` |
| Windows | Reads and writes | Volumes that report block cloning, such as ReFS |
| macOS | Reads and writes | None |

Block cloning is unavailable on a `.read_only()` backend, or when the server cannot create files in the share root.
