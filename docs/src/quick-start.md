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

```toml
[dependencies]
smb-server = { version = "0.10", features = ["discovery"] }
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

`server.shutdown()`, or `server.shutdown_handle()` from another task. `serve()` then:

- stops accepting connections
- closes each connection after its current request
- returns once every connection and every disconnected durable handle is closed

## Run the example

```sh
cargo run -p minimal-smb-example
```

Listens on `127.0.0.1:4445`. Serves directories under `smb-example` in the system temp directory.

| Share | Access |
|---|---|
| `public` | anonymous read-write |
| `media` | anonymous read-only |
| `home` | `alice` read-write, `bob` read-only |

| Variable | Effect |
|---|---|
| `SMB_LISTEN` | Listen address |
| `SMB_ROOT` | Root directory for the shares |
| `SMB_PASSWORD` | Password for `alice` and `bob`. Unset: generated and logged at startup |
| `SMB_DISCOVERY=1` | Announce on the network. Needs `--features discovery` and a non-loopback address |
| `SMB_STREAMS=0` | Named streams off |
| `SMB_COPY=0` | Server-side copy off |
| `SMB_S3_BUCKET` | Serve this S3 bucket as the only share, `s3`. Needs `--features s3`. See [backends](backends.md#example) |

```sh
SMB_DISCOVERY=1 SMB_LISTEN='[::]:4445' cargo run -p minimal-smb-example --features discovery
```
