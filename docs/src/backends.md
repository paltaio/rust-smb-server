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

## S3Backend

Feature `s3`, off by default. Serves a bucket, or the keys below a prefix, as a share. A file is an object and a directory is a key prefix. The store must offer ListObjectsV2, HeadObject, ranged GetObject, PutObject, CopyObject, multipart uploads with UploadPartCopy and DeleteObjects, all signed with SigV4.

Changes land in a cache directory on the host and reach the bucket in the background. Reads fetch byte ranges of the object. The write time of a file is its `mtime` metadata, else `src_last_modified_millis`, else the time the store last modified the object.

```toml
smb-server = { version = "0.10", features = ["s3"] }
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

`builder(endpoint, region, bucket)` takes the endpoint as an `https://` or `http://` URL with no path, and the region requests are signed for. `build` checks the settings, locks the cache directory, lists one key of the bucket, reads back what the cache directory holds and starts the background uploads. It fails on a setting or cache directory it cannot use, or on a bucket the store refuses or does not answer for. A `prefix` with an empty, `.` or `..` component, or one that leaves no room for a name under 1024 bytes, is refused.

| Call | Default | Effect |
|---|---|---|
| `credentials(access_key, secret_key)` | Required | Signs requests |
| `session_token(token)` | None | Session token of temporary credentials |
| `prefix(prefix)` | Whole bucket | Serves the keys below `prefix`. Leading and trailing `/` are dropped |
| `cache_dir(dir)` | Required unless read-only | See [cache directory](#cache-directory) |
| `read_only()` | Off | See [read-only](#read-only) |
| `path_style(bool)` | Automatic | Bucket in the URL path (`true`) or the host name (`false`). Automatic picks the host name for an `amazonaws.com` endpoint with a DNS-label bucket name, and the path otherwise |
| `case_insensitive(bool)` | `true` | Match names without regard to case. See [names and listings](limitations.md#names-and-listings) |
| `request_timeout(duration)` | 30 s | Time limit on the store requests for one client request, retries included |
| `metadata_ttl(duration)` | 30 s | How long the server trusts a listing or object description it read from the store |
| `listing_metadata_max(n)` | 1000 | Entries per listing whose stored times are read, one request each. `0` reads none |
| `upload_delay(duration)` | 5 s | Wait after the last change before it goes to the bucket |
| `part_size(bytes)` | 16 MiB | Part size of multipart uploads, 5 MiB to 5 GiB. A file up to this size goes up in one request. A file that would need more than 10,000 parts uses larger parts |
| `upload_concurrency(n)` | 4 | Uploads at once, and parts in flight per upload. At least 1 |
| `read_chunk(bytes)` | 8 MiB | Size of the ranged reads of object data, 64 KiB to 32 MiB |
| `max_dir_rename_objects(n)` | 10000 | Most objects a renamed directory may hold. See [limitations](limitations.md#renames-and-deletes) |

### Cache directory

Holds every change that is not in the bucket yet: file data, times, attributes, renames and deletes. It must be on durable local storage. If the directory is lost, so are those changes.

- Made if missing. One backend uses it at a time. It stays locked until every clone of the backend is dropped, the handles opened through it are closed and the requests in flight have ended.
- Belongs to one endpoint, bucket, prefix and case setting. `build` refuses it with another.
- Written data is recorded when a client flushes the file, and otherwise when its upload starts: `upload_delay` after the last change, or later while `upload_concurrency` uploads are running. Closing a file does not record it. A crash, or a stop without `sync`, loses data not recorded by then: a new file is gone, and a changed existing file reads as the bucket has it. The next `build` deletes data files that were never recorded. Renames and deletes are recorded before the client gets its answer.
- Clients see the size and free space of its disk as the size and free space of the share.
- A backend built on a directory that holds changes brings the files, times, renames and deletes back and stores them without waiting for `upload_delay`. It also retries uploads that failed for good and aborts multipart uploads left running.
- Data that cannot be read back moves to the `conflicts` directory inside it, with an error in the log.

### Uploads and shutdown

A file goes up `upload_delay` after its last change, open or not. Opening a file without overwriting it, or closing it, is not a change.

`sync()` waits until every change made before the call is in the bucket. It waits through failures that a retry may fix and through a full cache disk. It returns early with the error of a change that failed for good, and other changes may still be in flight then. `failures()` lists the paths whose upload failed for good, with the error. A listed path gets no further upload until the next `build` on the cache directory, which tries it again. A file moved to `conflicts` and a delete the store refuses are not listed; they only fail `sync`.

Dropping the last clone of the backend ends the uploads. Call `sync` after `serve` returns, whether or not `serve` failed:

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

`read_only()` serves the bucket without a cache directory; `build` fails if `cache_dir` is also set. Every change fails with STATUS_ACCESS_DENIED. The share reports the default volume size (4 PiB, 2 PiB free), and `sync` returns Ok at once.

### Lifecycle rules

- Add a lifecycle rule that aborts incomplete multipart uploads. A crash, or a retried request whose answer was lost, can leave one in the bucket, and the store keeps its parts until it is aborted.
- Versioned buckets keep the old versions of objects the backend overwrites, deletes, renames or changes the times of. Add a lifecycle rule that keeps only the last version.

### Example

The example serves a bucket when `SMB_S3_BUCKET` is set. It serves one share, `s3`, with `alice` read-write and `bob` read-only. After the server stops it calls `sync` and logs the result and `failures()`. A second ctrl-c ends the wait. What `SMB_S3_CACHE` recorded goes up on the next run. See [cache directory](#cache-directory).

| Variable | Effect |
|---|---|
| `SMB_S3_BUCKET` | Bucket to serve |
| `SMB_S3_ENDPOINT` | Endpoint URL |
| `SMB_S3_REGION` | Signing region |
| `SMB_S3_ACCESS_KEY`, `SMB_S3_SECRET_KEY` | Credentials |
| `SMB_S3_CACHE` | Cache directory |
| `SMB_S3_PREFIX` | Serve only the keys below this prefix. Optional |

With `SMB_S3_BUCKET` set, every variable except `SMB_S3_PREFIX` is required. Without `--features s3`, `SMB_S3_BUCKET` is ignored with a warning.

```sh
SMB_S3_BUCKET='<bucket>' SMB_S3_ENDPOINT=https://s3.example.com SMB_S3_REGION=us-east-1 \
SMB_S3_ACCESS_KEY='<access key>' SMB_S3_SECRET_KEY='<secret key>' SMB_S3_CACHE='<cache directory>' \
cargo run -p minimal-smb-example --features s3
```
