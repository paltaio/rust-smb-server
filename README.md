# rust-smb-server

SMB server in Rust. Workspace with three crates:

- `smb-proto` — wire format, auth, crypto.
- `smb-server` — connection handling, dispatch, share config.
- `smb-fs` — `LocalFsBackend` over `cap-std`.

## Run the example

```sh
cargo run -p minimal-smb-example
```

Listens on `0.0.0.0:4445`. Override with `SMB_LISTEN` and `SMB_ROOT`.

Shares: `public` (anon rw), `media` (anon ro), `home` (alice rw, bob ro).

See `docs/SMOKE.md` for mount commands.

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
