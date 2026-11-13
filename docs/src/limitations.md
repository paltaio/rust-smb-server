# Limitations

Not supported:

- SMB1
- Kerberos, NTLMv1
- Oplocks, directory leases
- Answering a replayed CREATE with its original open
- Persistent and resilient handles
- Change notifications for changes outside the server, except `LocalFsBackend` on Linux for entries directly in a watched folder
- Named pipes other than `srvsvc`; RPC beyond listing shares and describing the server
- DFS
- Multichannel, compression
- Transports other than direct TCP: NetBIOS sessions, QUIC, RDMA
- SMB extended attributes with `LocalFsBackend` on macOS. macOS xattrs travel as named streams there
- Security descriptors, quotas
- Reparse points
- Previous Versions snapshots
- Time Machine
- Discovery over NetBIOS

## S3 backend

The settings named here, and how `S3Backend` works, are in [backends](backends.md#s3backend).

### Writers and storage

- One server per bucket prefix. Other writers to the same keys are last-writer-wins. Only a file the server changed in part, whose object has since changed or been deleted, moves to the `conflicts` directory of the cache directory; the bucket keeps the other version.
- A crash, or a stop without `sync`, can lose file data written since it was last recorded in the cache directory. A file never recorded is gone if it is new, and reads as the bucket has it if it was changed. See [cache directory](backends.md#cache-directory) for when data is recorded.
- The largest file is the free space of the cache disk. A write that does not fit fails with STATUS_DISK_FULL.
- Changing part of a large file downloads the rest of it and uploads all of it.
- Server-side copy reads and writes the data through the server.
- On Windows hosts the directory entries of the cache directory are not fsynced.
- The times and attributes of the share root are kept in memory only and reset on restart.

### Renames and deletes

- Renames and deletes show at once. The bucket follows in the background: a renamed file is stored at its new key, and its old key is deleted once the new key holds its content. The objects of deleted files are deleted in batches once nothing has been deleted for `upload_delay`, at most a minute after the first was due.
- A directory rename moves at most `max_dir_rename_objects` objects, counting the entries the server holds for it. A larger directory fails with STATUS_ACCESS_DENIED and nothing changes.
- A rename fails with STATUS_ACCESS_DENIED when the new name is an existing directory, and a directory cannot replace a file.
- A directory rename also fails with STATUS_ACCESS_DENIED when:
  - a key below the directory has a name no client could open
  - two keys would get the same name
  - the move is too large to save in the cache directory
  - the new name differs from the old in case only and a directory with the new spelling is beside it
- A directory rename or delete in progress makes these fail with STATUS_SHARING_VIOLATION:
  - a rename or delete of a directory above or below it
  - a create or rename of anything below it
  - while a rename moves the entries, an open of an existing name below it that the server holds nothing of
- A directory rename also fails with STATUS_SHARING_VIOLATION when:
  - a directory below it is still being made
  - the keys below it keep changing while they are listed
- A renamed directory tree gains a marker object for each of its directories.
- Renames that form a cycle, such as two names swapped through a third, download and upload one file per cycle; that file must fit in the free space of the cache disk.
- A copy for a rename or a time change gives the new object the default ACL of the bucket, not the original's.
- A copy request has no ETag condition on its source. When another writer replaces the source meanwhile, the copy takes the replacement.
- When the store refuses to copy an object onto itself, times and attributes set on a file larger than `part_size` are not stored. The server logs a warning.

### Names and listings

- By default names match without regard to case: a name that no key spells exactly opens the first key that differs in case only. Uploads and deletes of keys that differ in case only wait for each other, and a directory create waits for deletes of such a key and fails with STATUS_UNEXPECTED_IO_ERROR after `request_timeout`.
- On a store that treats names differing in case as one object, a file renamed to a new spelling of its name keeps the old spelling in the bucket.
- `case_insensitive(false)` needs a store that keeps case. On a store that treats `Doc` and `doc` as one object, a change to one overwrites or deletes the other.
- A directory whose listing, every page included, takes longer than `request_timeout` fails to list with STATUS_UNEXPECTED_IO_ERROR. With case-insensitive names, a name in it that no key spells exactly fails the same way: a new name, or an existing one in other case.
- A listing reads the stored times of up to `listing_metadata_max` entries whose metadata the backend does not hold yet. Past that, or when the read of an entry fails or runs out of time, a file reports the time the store modified it and a directory the time the backend was built.
- Keys no client could open, such as a name with `:` or an empty path component (`a//b`), are not listed. A path whose key is longer than 1024 bytes fails with STATUS_OBJECT_NAME_INVALID.
- A file and a directory with the same name show as the directory.
- No named streams or extended attributes. macOS clients store Finder data in `._` files, which are objects in the bucket.

### Reads and the store

- Store requests for one client request stop at `request_timeout`. A slow store fails them with STATUS_UNEXPECTED_IO_ERROR.
- Changes made outside the server raise no change notification, and show up to `metadata_ttl` late.
- When an object is replaced outside the server, an open handle keeps reading the cached chunks of the old version (up to 4 per version, 128 MiB in all) until it needs a chunk that is not cached. That read fetches the new version.
- Versioned buckets: see [lifecycle rules](backends.md#lifecycle-rules).
