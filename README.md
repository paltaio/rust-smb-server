# rust-smb-server

SMB server in Rust. Three crates:

- `paltaio-smb-proto` — wire format, auth, crypto.
- `paltaio-smb-server` — connection handling, dispatch, share config.
- `paltaio-smb-fs` — `LocalFsBackend` over `cap-std`.

Imported as `smb_proto`, `smb_server`, `smb_fs`.

## Install

```sh
cargo add paltaio-smb-server paltaio-smb-fs
```

Or in `Cargo.toml`:

```toml
[dependencies]
paltaio-smb-server = "0.1"
paltaio-smb-fs = "0.1"
```

## Run the example

```sh
cargo run -p minimal-smb-example
```

Listens on `0.0.0.0:4445`. Override with `SMB_LISTEN` and `SMB_ROOT`.

Shares: `public` (anon rw), `media` (anon ro), `home` (alice rw, bob ro).

## Embed

```rust
use smb_fs::LocalFsBackend;
use smb_server::{Share, SmbServer};

let server = SmbServer::builder()
    .listen("0.0.0.0:4445".parse()?)
    .user("alice", "password")
    .share(Share::new("public", LocalFsBackend::new("/srv/public")?).public())
    .build()?;

server.bind().await?;
server.serve().await?;
```

## License

MIT.
