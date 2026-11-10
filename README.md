# rust-smb-server

SMB 2 and 3 file-sharing server library for Rust.

Docs: [paltaio.github.io/rust-smb-server](https://paltaio.github.io/rust-smb-server/). API: [docs.rs/smb-server](https://docs.rs/smb-server).

## Install

```sh
cargo add smb-server
```

## Use

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

## Example

```sh
cargo run -p minimal-smb-example
```

## License

MIT.
