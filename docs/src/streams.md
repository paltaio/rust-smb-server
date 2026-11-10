# Named streams and macOS

A share whose backend stores named streams serves them and reports FILE_NAMED_STREAMS. `.named_streams(false)` on the `Share` turns them off; a CREATE naming a stream then fails with STATUS_OBJECT_NAME_INVALID.

| Client | Uses streams for |
|---|---|
| Windows | Alternate data streams such as `file.txt:name`. `dir /r` and `Get-Item -Stream *` list them; `copy` and `robocopy` copy them |
| macOS | Finder info, resource forks, tags, comments, other xattrs of files and folders. No `._` files |

## Where LocalFsBackend keeps them

| Host | Storage | Limits |
|---|---|---|
| Linux | xattr `user.DosStream.<name>:$DATA`, Samba `vfs_streams_xattr` layout | Large streams: [stream store](#stream-store). Needs user xattrs; without them macOS clients write `._` files |
| macOS | The file's own xattrs. `AFP_AfpInfo` is `com.apple.FinderInfo`, `AFP_Resource` is `com.apple.ResourceFork`, others keep their name | Resource fork 16 MiB, other streams 1 MiB; past that STATUS_DISK_FULL |
| Windows | NTFS alternate data streams | None on FAT or exFAT |

On a macOS host, the host's Finder shows the tags, labels, comments and icons clients set.

## Stream store

Linux only. Holds streams that outgrow their xattr: past 65535 bytes, or past the xattr room the filesystem gives a file (on ext4, one block shared by all of a file's xattrs). An xattr holds the stream data plus a NUL byte.

- Location: `.smb-streams` in the share root, mode 0700, created on the first request to a writable share. `LocalFsBackend::stream_store(path)` puts it outside the share.
- Clients cannot list, open or create it.
- Each file with streams in the store records its entry in the xattr `user.smb-server.streams`.
- Streams follow renames and hard links, including those made on the host.
- A copy made with xattrs shares the original's stored streams until either file changes a stream; that file then gets its own copy.
- Back up and move shares with xattrs and the store, for example `rsync -aX`. A copy without xattrs has no streams.
- Samba on the same directory sees only the xattr-held streams, and lists `.smb-streams` as a folder.

Cleanup: the store keeps streams of deleted files, and of files replaced on the host without their xattrs. `LocalFsBackend::sweep_streams` frees a stored stream when two calls in a row find no file using it and no request touched it between the calls.

## Apple AAPL context

macOS clients send Apple's `AAPL` create context in the first CREATE on a share. The server:

- answers with the model string `smb-server`, or the one `apple_model` sets
- reports itself as a Unix server on Unix hosts
- on shares with named streams, adds each entry's Finder info, resource fork size and Unix mode to Finder listings

`apple_extensions(false)` on the builder ignores the context.

## Existing `._` files

`._` files written while a share had no streams stay, and list as ordinary files. Run `dot_clean -m` on the mounted share from a Mac to move them into streams.
