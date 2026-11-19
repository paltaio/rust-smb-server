# Backends

A share serves any type that implements `ShareBackend`. To write one, see `ShareBackend` in the [API docs](https://docs.rs/smb-server).

## LocalFsBackend

Feature `localfs`, on by default. Serves a directory on the host.

```rust
LocalFsBackend::new("/srv/home")?
```

Paths and symlinks cannot reach outside the directory.

| Call | Effect |
|---|---|
| `.read_only()` | Refuses writes |
| `.watch_host_changes(false)` | Stops reporting host-side changes. Linux only, on by default. See [change notifications](change-notify.md) |
| `.stream_store(path)` | Keeps large named streams in `path`. Linux only. See [named streams](streams.md#stream-store) |

`sweep_streams()` frees stored stream data no file uses. See [named streams](streams.md#stream-store).

On Windows, the directory may be a UNC path or a mapped drive, and the server account needs traverse rights on the share's directories. On volumes that reject POSIX deletes (such as an SMB share), deleted entries are moved to a hidden `.smb-deleted` directory in the share root until their last handle closes, freeing the original name immediately. Clients cannot list, open, or create `.smb-deleted`.

On Windows, a rename that fails with `STATUS_ACCESS_DENIED` (for example, renaming a directory while another program has an entry below it open) is retried for up to one second before failing.

When the directory lives on another machine, the Windows SMB client can store a new name in the casing another program (such as a virus scanner) uses to open it at the same moment, and can ignore a rename that changes only letter case. After each create or rename of a file, directory, or named stream, the backend reads back the stored name. If the casing differs, it renames the entry to a temporary name (`~smb-<32 hex digits>`) and then to the requested name.

While this two-step rename is in progress, the entry appears under the temporary name; if the server stops mid-rename, that temporary name stays in the directory. A case-only rename that cannot be corrected fails and leaves the name unchanged. If another program holds a newly created entry open without delete sharing, the create succeeds under the stored casing and logs a warning. If another client claims the requested name during the correction, the create fails with `STATUS_SHARING_VIOLATION` and deletes the entry.

## S3Backend

Feature `s3`, off by default. Serves a bucket, or the keys under a prefix, as a share. Each file maps to an object and each directory maps to a key prefix. The object store must support `ListObjectsV2`, `HeadObject`, ranged `GetObject`, `PutObject`, `CopyObject`, multipart uploads with `UploadPartCopy`, and `DeleteObjects`, all signed with SigV4.

Changes land in a local cache directory and upload to the bucket in the background. Reads fetch byte ranges from the object. A file's modification time comes from its `mtime` metadata, falling back to `src_last_modified_millis`, and then to the store's object modification time.

```toml
smb-server = { version = "0.12", features = ["s3"] }
```

```rust
use smb_server::{Access, S3Backend, Share};

let s3 = S3Backend::builder("https://s3.example.com", "us-east-1", "example-bucket")
    .credentials("access-key", "secret-key")
    .cache_dir("/path/to/cache")
    .build()
    .await?;

let share = Share::new("s3", s3.clone()).user("alice", Access::ReadWrite);
```

`builder(endpoint, region, bucket)` takes an `https://` or `http://` endpoint URL with no path and the region used to sign requests. `build()` validates the settings, locks the cache directory, lists one key from the bucket, recovers any pending state from the cache directory, and starts background uploads. It fails if any setting or the cache directory is unusable, or if the store rejects or does not respond for the bucket. A `prefix` with an empty, `.`, or `..` component, or one that leaves no room for a name under 1024 bytes, is rejected.

| Call | Default | Effect |
|---|---|---|
| `credentials(access_key, secret_key)` | Required | Signs requests |
| `session_token(token)` | None | Session token for temporary credentials |
| `prefix(prefix)` | Whole bucket | Serves only the keys under `prefix`. Leading and trailing `/` are stripped |
| `cache_dir(dir)` | Required unless read-only | See [cache directory](#cache-directory) |
| `read_only()` | Off | See [read-only](#read-only) |
| `path_style(bool)` | Automatic | Places the bucket in the URL path (`true`) or host name (`false`). Automatic uses the host name for `amazonaws.com` endpoints with a DNS-label bucket name, and the path otherwise |
| `case_insensitive(bool)` | `true` | Matches names without regard to case. See [names and listings](limitations.md#names-and-listings) |
| `request_timeout(duration)` | 30 s | Time limit on store requests for a single client request, retries included |
| `metadata_ttl(duration)` | 30 s | How long the server trusts a listing or object metadata read from the store |
| `listing_metadata_max(n)` | 1000 | Maximum entries per listing whose stored times are fetched (one request each). `0` fetches none |
| `upload_delay(duration)` | 5 s | Delay after the last change before uploading to the bucket |
| `part_size(bytes)` | 16 MiB | Multipart upload part size, 5 MiB to 5 GiB. Files up to this size upload in one request. Files that would exceed 10,000 parts use larger parts |
| `upload_concurrency(n)` | 4 | Maximum concurrent uploads and in-flight parts per upload. Must be at least 1 |
| `read_chunk(bytes)` | 8 MiB | Size of ranged object reads, 64 KiB to 32 MiB |
| `max_dir_rename_objects(n)` | 10000 | Maximum objects a renamed directory may contain. See [limitations](limitations.md#renames-and-deletes) |

### Cache directory

Stores every change that has not reached the bucket yet: file data, times, attributes, renames, and deletes. It must live on durable local storage; losing the directory loses those changes. On Windows, it must be on a local NTFS or ReFS volume; `build()` rejects paths on an SMB share or mapped network drive.

- Created if missing. Only one backend can use a cache directory at a time. It stays locked until every clone of the backend is dropped, all handles opened through it are closed, and all in-flight requests and background saves of closed files have finished.
- Bound to one endpoint, bucket, prefix, and case setting; `build()` rejects a directory created with different settings.
- Written data is recorded when a client flushes the file or closes its last handle. For files kept open (such as under a lease or durable handle), it is recorded when the upload starts: `upload_delay` after the last write, or later while `upload_concurrency` uploads are running. Records for closed files are written in the background. The next `build()` deletes data files that were never recorded. Renames and deletes are recorded before the client receives a reply. See [limitations](limitations.md#writers-and-storage) for what a crash can lose.
- Clients see the total size and free space of the cache disk as the share's size and free space.
- Building a backend on a cache directory with pending changes restores those files, times, renames, and deletes and uploads them without waiting for `upload_delay`. It also retries previously failed uploads and aborts leftover multipart uploads.
- Data that cannot be read back is moved to the `conflicts` subdirectory inside the cache directory, with an error logged.

### Uploads and shutdown

A file is uploaded `upload_delay` after its last modification, whether open or closed. Opening a file without overwriting it, or closing it, does not count as a modification.

`sync()` waits until every change made before the call reaches the bucket. It waits through transient errors and a full cache disk, but returns early with an error if a change fails permanently (other changes may still be in flight). `failures()` lists paths that failed permanently along with their errors. Listed paths are not retried until the next `build()` on the cache directory. Files moved to `conflicts` and deletes rejected by the store do not appear in `failures()`; they only cause `sync()` to fail.

Dropping the last clone of the backend stops background uploads. Call `sync()` after `serve()` returns, even if `serve()` failed:

```rust
let served = server.serve().await;
let synced = s3.sync().await;
for (path, error) in s3.failures() {
    eprintln!("{path}: {error}");
}
served?;
synced?;
```

### Read-only

`read_only()` serves the bucket without a cache directory; `build()` fails if `cache_dir` is also set. All writes fail with `STATUS_ACCESS_DENIED`. The share reports the default volume size (4 PiB total, 2 PiB free), and `sync()` returns `Ok` immediately.

### Lifecycle rules

- Add a lifecycle rule to abort incomplete multipart uploads. A crash, or a retried request whose response was lost, can leave one in the bucket, and the store retains its parts until aborted.
- Versioned buckets retain old versions of objects that the backend overwrites, deletes, renames, or updates metadata on. Add a lifecycle rule that keeps only the latest version.

### Example

The example serves a bucket when `SMB_S3_BUCKET` is set, exposing one share (`s3`) with `alice` read-write and `bob` read-only. After the server stops, it calls `sync()` and logs the result and any `failures()`. A second Ctrl-C interrupts the wait; anything recorded in `SMB_S3_CACHE` uploads on the next run. See [cache directory](#cache-directory).

| Variable | Effect |
|---|---|
| `SMB_S3_BUCKET` | Bucket to serve |
| `SMB_S3_ENDPOINT` | Endpoint URL |
| `SMB_S3_REGION` | Signing region |
| `SMB_S3_ACCESS_KEY`, `SMB_S3_SECRET_KEY` | Credentials |
| `SMB_S3_CACHE` | Cache directory |
| `SMB_S3_PREFIX` | Serve only the keys under this prefix (optional) |

When `SMB_S3_BUCKET` is set, every variable except `SMB_S3_PREFIX` is required. Without `--features s3`, `SMB_S3_BUCKET` is ignored with a warning.

```sh
SMB_S3_BUCKET='<bucket>' SMB_S3_ENDPOINT=https://s3.example.com SMB_S3_REGION=us-east-1 \
SMB_S3_ACCESS_KEY='<access key>' SMB_S3_SECRET_KEY='<secret key>' SMB_S3_CACHE='<cache directory>' \
cargo run -p minimal-smb-example --features s3
```
