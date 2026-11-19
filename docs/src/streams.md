# Named streams and macOS

A share whose backend supports named streams serves them and reports `FILE_NAMED_STREAMS`. Calling `.named_streams(false)` on the `Share` disables them; a `CREATE` naming a stream then fails with `STATUS_OBJECT_NAME_INVALID`.

| Client | Uses streams for |
|---|---|
| Windows | Alternate data streams such as `file.txt:name`. `dir /r` and `Get-Item -Stream *` list them; `copy` and `robocopy` copy them |
| macOS | Finder info, resource forks, tags, comments, and other xattrs on files and folders, avoiding `._` files |

## Where LocalFsBackend keeps them

| Host | Storage | Limits |
|---|---|---|
| Linux | xattr `user.DosStream.<name>:$DATA` (Samba `vfs_streams_xattr` layout) | Large streams use the [stream store](#stream-store). Requires user xattrs; without them, macOS clients fall back to `._` files |
| macOS | The file's own xattrs (`AFP_AfpInfo` maps to `com.apple.FinderInfo`, `AFP_Resource` maps to `com.apple.ResourceFork`, others keep their name) | Resource fork: 16 MiB; other streams: 1 MiB. Exceeding either returns `STATUS_DISK_FULL` |
| Windows | NTFS alternate data streams | Unsupported on FAT and exFAT |

On a macOS host, the host's Finder displays the tags, labels, comments, and icons set by clients.

## Stream store

Linux only. Stores streams that outgrow an xattr: larger than 65,535 bytes or beyond the filesystem's xattr space for the file (on ext4, one block shared by all of a file's xattrs). Each xattr stores the stream data plus a trailing NUL byte.

- Stored in `.smb-streams` in the share root (mode `0700`), created on the first request to a writable share. `LocalFsBackend::stream_store(path)` moves it outside the share.
- Clients cannot list, open, or create `.smb-streams`.
- Each file with streams in the store records its entry in the `user.smb-server.streams` xattr.
- Streams follow renames and hard links, including those made on the host.
- A copy made with xattrs shares the original's stored streams until either file modifies a stream; that file then gets its own copy.
- Back up and move shares with xattrs and the stream store intact (for example, `rsync -aX`). Copies made without xattrs lose their streams.
- Samba serving the same directory sees only xattr-held streams and lists `.smb-streams` as a regular folder.

Cleanup: the store retains streams for deleted files and for files replaced on the host without their xattrs. `LocalFsBackend::sweep_streams` frees a stored stream once two consecutive calls find no file referencing it and no request touched it in between.

## Apple AAPL context

macOS clients send Apple's `AAPL` create context in the first `CREATE` on a share. The server:

- replies with the model string `smb-server`, or the value set by `apple_model`
- reports itself as a Unix server on Unix hosts
- on shares with named streams, includes each entry's Finder info, resource fork size, and Unix mode in Finder listings

Setting `apple_extensions(false)` on the builder ignores the `AAPL` context.

## Existing `._` files

`._` files written while a share had streams disabled remain and list as ordinary files. Run `dot_clean -m` on the mounted share from a Mac to move them into streams.
