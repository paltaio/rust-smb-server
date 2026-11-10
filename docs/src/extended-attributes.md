# Extended attributes

A share whose backend stores extended attributes serves them and reports FILE_SUPPORTS_EXTENDED_ATTRIBUTES. `.extended_attributes(false)` on the `Share` turns them off.

Linux clients read and set them as `user.*` attributes on a cifs mount.

## Where LocalFsBackend keeps them

| Host | Storage |
|---|---|
| Linux | xattrs named `user.<name>` (Samba layout), when the filesystem has user xattrs |
| Windows | NTFS extended attributes |
| macOS | None. Every xattr there is a [named stream](streams.md) |

## Limits on Linux

Hidden from clients; setting them fails with STATUS_ACCESS_DENIED:

- `user.DosStream.*`
- `user.smb-server.*`
- `user.DOSATTRIB`
- `user.SAMBA_PAI`
- `user.SAMBA_STREAMS`
- `user.SmbReparse`
- `user.org.netatalk.Metadata`

| Set | Fails with |
|---|---|
| Too large for the file's xattr room | STATUS_EA_TOO_LARGE |
| On a read-only file | STATUS_ACCESS_DENIED, unless the server runs as a user that can write any file, such as root |
