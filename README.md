# rust-smb-server

SMB server in Rust. Three crates:

- `paltaio-smb-proto` — wire format, auth, crypto.
- `paltaio-smb-server` — connection handling, dispatch, share config, runtime updates.
- `paltaio-smb-fs` — `LocalFsBackend` over `cap-std`.

Imported as `smb_proto`, `smb_server`, `smb_fs`.

## Install

```sh
cargo add paltaio-smb-server paltaio-smb-fs
```

Or in `Cargo.toml`:

```toml
[dependencies]
paltaio-smb-server = "0.1.4"
paltaio-smb-fs = "0.1.4"
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
use smb_server::{Access, Share, SmbServer};

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

## Runtime config

Create a `ConfigHandle` before `serve()` and keep it in the task that owns admin/config updates:

```rust
use smb_fs::LocalFsBackend;
use smb_server::{Access, Share, SmbServer};

let server = SmbServer::builder()
    .listen("0.0.0.0:4445".parse()?)
    .share(Share::new("public", LocalFsBackend::new("/srv/public")?).public())
    .build()?;

let config = server.config_handle();

config.add_user("alice", "password").await?;
let home = Share::new("home", LocalFsBackend::new("/srv/home")?)
    .user("alice", Access::ReadWrite);
config
    .add_share(home)
    .await?;
config.revoke_share_user("home", "alice").await?;
config.remove_user("alice").await?;

server.serve().await?;
```

Removing a user revokes that user's active sessions. Removing a share or revoking share access closes matching active tree connections and open handles.

## License

MIT.
