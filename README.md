# rust-smb-server

SMB 2 and 3 file-sharing server library for Rust.

[docs](https://paltaio.github.io/rust-smb-server/) | [api](https://docs.rs/smb-server) | [crate](https://crates.io/crates/smb-server)

## Install

```sh
cargo add smb-server
```

## Usage

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

Serve an encrypted share backed by an S3 bucket (with `cargo add smb-server --features s3,encryption`):

```rust
use smb_server::{Access, EncryptedBackend, S3Backend, Share, SmbServer};

let key: [u8; 32] = std::fs::read("/etc/smb/vault.key")?
    .try_into()
    .map_err(|_| "the key file must hold 32 bytes")?;

let s3 = S3Backend::builder("https://s3.example.com", "us-east-1", "vault-bucket")
    .credentials("access-key", "secret-key")
    .cache_dir("/var/cache/smb-vault")
    .case_insensitive(false)
    .build()
    .await?;
let vault = EncryptedBackend::builder(s3.clone(), key).build().await?;

let server = SmbServer::builder()
    .listen("0.0.0.0:4445".parse()?)
    .user("alice", "password")
    .share(Share::new("vault", vault).user("alice", Access::ReadWrite))
    .build()?;

server.bind().await?;
let served = server.serve().await;
s3.sync().await?;
served?;
```

## Example

```sh
cargo run -p minimal-smb-example
```

## License

MIT.
