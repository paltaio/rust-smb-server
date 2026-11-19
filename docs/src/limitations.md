# Limitations

Not supported:

- SMB1
- Kerberos, NTLMv1
- Oplocks, directory leases
- Answering a replayed `CREATE` with its original open
- Persistent and resilient handles
- Change notifications for changes made outside the server, except with `LocalFsBackend` on Linux for entries directly in a watched folder
- Named pipes other than `srvsvc`; RPC beyond listing shares and describing the server
- DFS
- Multichannel, compression
- Transports other than direct TCP (NetBIOS sessions, QUIC, RDMA)
- SMB extended attributes with `LocalFsBackend` on macOS (macOS xattrs are exposed as named streams instead)
- Security descriptors, quotas
- Reparse points
- Previous Versions snapshots
- Time Machine
- Discovery over NetBIOS

## S3 backend

See [backends](backends.md#s3backend) for how `S3Backend` works and for the settings referenced below.

### Writers and storage

- Run only one server per bucket prefix. Concurrent writers to the same keys are last-writer-wins. Only a file partially modified by the server whose object was concurrently changed or deleted is moved to the `conflicts` subdirectory of the cache directory; the bucket keeps the other version.
- A crash, or stopping without `sync()`, can lose file data written since it was last recorded in the cache directory. An unrecorded new file is lost; an unrecorded modification reverts to what is in the bucket. See [cache directory](backends.md#cache-directory) for when data is recorded.
- The maximum file size is bounded by the free space on the cache disk. Writes that do not fit fail with `STATUS_DISK_FULL`.
- Modifying part of a large file downloads the rest of the file and re-uploads the entire object.
- Server-side copy reads and writes data through the server.
- On Windows hosts, directory entries in the cache directory are not fsynced.
- Timestamps and attributes of the share root are kept in memory only and reset on restart.

### Renames and deletes

- Renames and deletes take effect immediately for clients and sync to the bucket in the background: a renamed file is written to its new key, and the old key is deleted once the new key holds its content. Deleted objects are removed in batches once no deletes have occurred for `upload_delay` (at most one minute after the first delete became due).
- A directory rename moves at most `max_dir_rename_objects` objects, including entries held locally by the server. Larger directories fail with `STATUS_ACCESS_DENIED` without making any changes.
- A directory cannot replace a file: renaming a directory over a file with `ReplaceIfExists` set fails with `STATUS_ACCESS_DENIED`.
- A directory rename also fails with `STATUS_ACCESS_DENIED` when:
  - a key below the directory has a name no client can open
  - two keys would map to the same name
  - the move is too large to record in the cache directory
  - the new name differs from the old in case only and a sibling directory with the new spelling already exists
- While a directory rename or delete is in progress, these operations fail with `STATUS_SHARING_VIOLATION`:
  - renaming or deleting a directory above or below it
  - creating or renaming anything below it
  - while a rename is moving entries, opening an existing entry below it that the server does not hold in memory
- A directory rename also fails with `STATUS_SHARING_VIOLATION` when:
  - a subdirectory below it is still being created
  - the keys below it keep changing while being listed
- Renaming a directory tree adds a marker object for each directory in the tree.
- Renames that form a cycle (such as swapping two names through a third) download and re-upload one file per cycle; that file must fit in the free space on the cache disk.
- When a file takes the name of a directory (or vice versa), the new object is uploaded after the old name's object is deleted. If that delete can only happen after the new object is written (for example, swapping a file and a directory, or moving a directory's only file onto the directory's name), the new object is written without waiting. Object stores that represent directories as real folders reject this, leaving the entry in `failures()` until the next backend is built.
- Copying an object for a rename or timestamp update applies the bucket's default ACL rather than preserving the original ACL.
- Copy requests do not attach an ETag condition to the source; if another writer replaces the source concurrently, the copy uses the replacement.
- If the store rejects copying an object onto itself, timestamp and attribute changes on files larger than `part_size` are not persisted, and the server logs a warning.

### Names and listings

- By default, names are matched case-insensitively: a lookup that does not match any key exactly opens the first key that differs only in case. Uploads and deletes of keys differing only in case wait on each other, and creating a directory waits for pending deletes of any colliding key (failing with `STATUS_UNEXPECTED_IO_ERROR` after `request_timeout`).
- On stores that treat names differing only in case as the same object, renaming a file to change only its casing keeps the old spelling in the bucket.
- `case_insensitive(false)` requires a case-sensitive store. On a case-insensitive store, changing `Doc` overwrites or deletes `doc`.
- A directory whose full listing (across all pages) exceeds `request_timeout` fails with `STATUS_UNEXPECTED_IO_ERROR`. With case-insensitive names, looking up a non-exact match in that directory (either a new name or an existing one with different casing) fails the same way.
- A listing fetches stored timestamps for up to `listing_metadata_max` entries whose metadata is not yet cached. Beyond that limit, or if fetching an entry fails or times out, files report the store's object modification time and directories report the time the backend was built.
- Keys no client can open, such as names containing `:` or empty path components (`a//b`), are omitted from listings. Paths whose key exceeds 1024 bytes fail with `STATUS_OBJECT_NAME_INVALID`.
- If a file and a directory have the same name, only the directory is shown.
- Named streams and extended attributes are not supported. macOS clients store Finder metadata in `._` files, which are stored as regular objects in the bucket.

### Reads and the store

- Store requests for a single client request stop at `request_timeout`; slow responses fail with `STATUS_UNEXPECTED_IO_ERROR`.
- Changes made outside the server do not trigger change notifications and can take up to `metadata_ttl` to become visible.
- If an object is replaced outside the server, an open handle keeps reading cached chunks of the old version (up to 4 chunks per version, 128 MiB total) until it requests an uncached chunk, which fetches the new version.
- For versioned buckets, see [lifecycle rules](backends.md#lifecycle-rules).

## Encrypted storage

See [encrypted storage](encrypted-storage.md) for how `EncryptedBackend` works and for the settings referenced below.

### Integrity and visibility

- These changes go undetected: restoring an older block or file, truncating a file at a block boundary, zeroing a block, appending zero blocks, swapping files, moving or copying a stored file, deleting files, and changing timestamps or attributes.
- File sizes, timestamps, attributes, directory structure, and name lengths remain visible in the inner backend. See [what is protected](encrypted-storage.md#what-is-protected).
- The backend does not enforce the per-key block encryption limit. See [limits](encrypted-storage.md#limits).

### Writers and crashes

- Run only one backend instance per stored tree. Another writer (such as a second backend built over the same tree) can cause read errors and lost updates. Clones of one backend share state, so multiple shares can safely serve the same tree through clones.
- With case-insensitive names, case-variant lookups and creates use a cached directory listing refreshed every `name_cache_ttl`. Names added by another writer can go unseen for that duration.
- With encrypted names, foreign entries (such as files placed in the inner backend manually) are omitted from listings, and clients cannot delete a directory that contains one. With plaintext names, every entry listed by the inner backend (except the marker) is visible.
- A crash or power loss can render blocks being written unreadable. Power loss can also drop or tear any write since the last `FLUSH`.
- After a crash involving a partial last block, an append or a write past it can render the old last block unreadable.
- After a crash, a write into a new file starting at block 0 can leave an empty file.
- A write that leaves a gap of blocks after a partial last block first pads that block with zeros. A crash between padding and writing can leave the file extended by the padding alone.
- A write that fails at or past the previous end of the stored file truncates the file back to that end (or to the end of the padded last block once written), keeping existing data blocks readable. If that truncation also fails, a trailing fragment remains. The next write or truncate strips fragments up to 28 bytes; longer fragments are read as a partial last block and fail authentication.
- A write that fails while overwriting existing blocks can tear them (for example, on a full disk where overwriting requires allocating new space).
- Reading a damaged block fails with `STATUS_UNEXPECTED_IO_ERROR`. See [damaged blocks](encrypted-storage.md#damaged-blocks).

### Names

- An encrypted name is roughly 1.6 characters per UTF-8 byte of the original name, plus 26 characters. Host path limits apply to stored names: ext4 limits names to 255 bytes, NTFS limits names to 255 UTF-16 units, and S3 keys are limited to 1024 bytes (which deep trees reach sooner). Encrypted names are ASCII, so byte and UTF-16 lengths match. On S3, keys exceeding 1024 bytes fail with `STATUS_OBJECT_NAME_INVALID`. Lowering `long_name_threshold` caps each stored name at that many characters.
- At the default threshold, names longer than 143 UTF-8 bytes are stored as two objects. Listing a directory reads the second object for each such name the backend has not seen yet.
- Names are stored exactly as the client spells them, without Unicode normalization, so composed and decomposed forms of the same name are distinct.
- Windows rejects certain names as path components, such as DOS device names (`con`, `nul.txt`). A tree written on another OS and served from a Windows host omits those entries from listings, and directories containing them cannot be deleted as empty.
- With plaintext names, clients cannot create or open `.smb-encryption` in the share root.

### Features

- Named streams and extended attributes are not supported. macOS clients store Finder metadata in `._` files, which are encrypted like any other file.
- Block cloning is not supported. Server-side copy runs as reads and writes through the backend.
- On aarch64, AES and GHASH run in software unless built with the flags in [aarch64](encrypted-storage.md#aarch64).
