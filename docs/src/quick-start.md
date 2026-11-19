# Quick start

## Install

```sh
cargo add smb-server
```

| Feature | Default | Adds |
|---|---|---|
| `localfs` | on | `LocalFsBackend` |
| `discovery` | off | mDNS and WS-Discovery announcements |
| `s3` | off | `S3Backend` |
| `encryption` | off | `EncryptedBackend` |

```toml
[dependencies]
smb-server = { version = "0.12", features = ["discovery"] }
```

## Serve a directory

```rust
use smb_server::{Access, LocalFsBackend, Share, SmbServer};

let server = SmbServer::builder()
    .listen("0.0.0.0:4445".parse()?)
    .user("alice", "password")
    .share(
        Share::new("home", LocalFsBackend::new("/srv/home")?)
            .user("alice", Access::ReadWrite),
    )
    .build()?;

server.bind().await?;
server.serve().await?;
```

## Stop

Call `server.shutdown()`, or use `server.shutdown_handle()` from another task. Once triggered, `serve()`:

- stops accepting new connections
- closes each active connection after its current request finishes
- returns once every connection and disconnected durable handle has closed

## Run the example

```sh
cargo run -p minimal-smb-example
```

The example listens on `127.0.0.1:4445` and serves directories under `smb-example` in the system temp directory.

| Share | Access |
|---|---|
| `public` | anonymous read-write |
| `media` | anonymous read-only |
| `home` | `alice` read-write, `bob` read-only |

| Variable | Effect |
|---|---|
| `SMB_LISTEN` | Listen address |
| `SMB_ROOT` | Root directory for the shares |
| `SMB_PASSWORD` | Password for `alice` and `bob`. If unset, a password is generated and logged at startup |
| `SMB_DISCOVERY=1` | Announce the server on the network. Requires `--features discovery` and a non-loopback address |
| `SMB_STREAMS=0` | Disable named streams |
| `SMB_COPY=0` | Disable server-side copy |
| `SMB_S3_BUCKET` | Serve this S3 bucket as the only share (`s3`). Requires `--features s3`. See [backends](backends.md#example) |
| `SMB_ENCRYPTION_KEY` | 64-hex-digit encryption key. Adds an encrypted `vault` share, or encrypts `s3` when `SMB_S3_BUCKET` is also set. Requires `--features encryption`. See [encrypted storage](encrypted-storage.md#example) |

```sh
SMB_DISCOVERY=1 SMB_LISTEN='[::]:4445' cargo run -p minimal-smb-example --features discovery
```
