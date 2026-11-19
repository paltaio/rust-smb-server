# Extended attributes

A share whose backend supports extended attributes serves them and reports `FILE_SUPPORTS_EXTENDED_ATTRIBUTES`. Calling `.extended_attributes(false)` on the `Share` disables them.

Linux clients read and set them as `user.*` attributes on a CIFS mount.

## Where LocalFsBackend keeps them

| Host | Storage |
|---|---|
| Linux | xattrs named `user.<name>` (Samba layout), when the filesystem supports user xattrs |
| Windows | NTFS extended attributes |
| macOS | Unsupported; macOS xattrs are exposed as [named streams](streams.md) instead |

## Limits on Linux

These namespaces are hidden from clients, and setting them fails with `STATUS_ACCESS_DENIED`:

- `user.DosStream.*`
- `user.smb-server.*`
- `user.DOSATTRIB`
- `user.SAMBA_PAI`
- `user.SAMBA_STREAMS`
- `user.SmbReparse`
- `user.org.netatalk.Metadata`

| Operation | Error |
|---|---|
| Exceeds the file's available xattr space | `STATUS_EA_TOO_LARGE` |
| Set on a read-only file | `STATUS_ACCESS_DENIED`, unless the server runs as a user that can write to any file (such as root) |
