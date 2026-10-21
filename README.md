# rust-smb-server

SMB server in Rust.

## Install

```sh
cargo add smb-server
```

Or in `Cargo.toml`:

```toml
[dependencies]
smb-server = "0.6"
```

## Run the example

```sh
cargo run -p minimal-smb-example
```

Listens on `127.0.0.1:4445` and serves directories under `smb-example` in the system temp directory. Override with `SMB_LISTEN` and `SMB_ROOT`.

Shares: `public` (anon rw), `media` (anon ro), `home` (alice rw, bob ro).

`alice` and `bob` use the password in `SMB_PASSWORD`. Without it, the example generates one and logs it at startup.

## Embed

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

## Runtime config

Create a `ConfigHandle` before `serve()` and keep it in the task that owns admin/config updates:

```rust
use smb_server::{Access, LocalFsBackend, Share, SmbServer};

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

## Encryption

SMB 3.1.1 clients negotiate AES-128 or AES-256 in CCM or GCM mode; SMB 3.0 and 3.0.2 clients with the encryption capability use AES-128-CCM. A client that sends encrypted requests gets encrypted replies.

To require encryption on one share:

```rust
use smb_server::{Access, LocalFsBackend, Share, SmbServer};

let server = SmbServer::builder()
    .listen("0.0.0.0:4445".parse()?)
    .user("alice", "password")
    .share(
        Share::new("secret", LocalFsBackend::new("/srv/secret")?)
            .user("alice", Access::ReadWrite)
            .encrypt_data(),
    )
    .build()?;
```

To require it for every session, call `.encrypt_data(true)` on the builder.

Where encryption is required, clients that cannot encrypt are refused: SMB 2.x, SMB 3.x without a cipher in common, and anonymous sessions, which get a session but no tree. `reject_unencrypted_access(false)` serves them unencrypted instead.

## Leases

Files on every share get SMB2 leases with read, handle and write caching: a client caches what it reads, keeps files open after its applications close them, and caches writes while every other open of the file holds the same lease or only reads attributes. An open, write, lock, rename or delete through any open that doesn't hold the lease, including the same client's opens under another lease key or none, breaks it when it needs what the lease caches. An open or rename that needs the client to write back or close its handles first waits until the client acknowledges or closes, or until 35 seconds after the break is sent; a lock is refused until the client has written back.

Changes made outside the server, or through another share over the same directory, break no lease, so clients keep serving their cached copies. Call `.leases(false)` on such a `Share` to turn leases off there.

## Limitations

Not supported:

- Kerberos; authentication is NTLM only
- oplocks, directory leases and durable handles
- change notifications
- named pipes and RPC, so clients can't list a server's shares
- DFS
- multichannel and compression
- alternate data streams and extended attributes
- network discovery (mDNS, NetBIOS, WS-Discovery): clients connect by name or address

## License

MIT.
