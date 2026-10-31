# rust-smb-server

SMB server in Rust.

Serves SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1 over TCP.

## Install

```sh
cargo add smb-server
```

Or in `Cargo.toml`:

```toml
[dependencies]
smb-server = "0.8"
```

With network discovery:

```toml
[dependencies]
smb-server = { version = "0.8", features = ["discovery"] }
```

## Run the example

```sh
cargo run -p minimal-smb-example
```

Listens on `127.0.0.1:4445` and serves directories under `smb-example` in the system temp directory. Override with `SMB_LISTEN` and `SMB_ROOT`.

Shares: `public` (anon rw), `media` (anon ro), `home` (alice rw, bob ro).

`alice` and `bob` use the password in `SMB_PASSWORD`. Without it, the example generates one and logs it at startup.

`SMB_DISCOVERY=1` announces the example on the network. It needs the `discovery` feature and a listen address other than loopback:

```sh
SMB_DISCOVERY=1 SMB_LISTEN='[::]:4445' cargo run -p minimal-smb-example --features discovery
```

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

Shares marked `.public()` or `.public_read_only()` are open to anonymous sessions. A logon as `guest` with an empty password, which the Finder sends for Connect As Guest, gets the same access unless a user of that name is configured; the name matches in any case. Guest and anonymous traffic is neither signed nor encrypted, so a client that requires signing gets no guest session.

`shutdown()` on the server, or on the handle `server.shutdown_handle()` returns, stops it: `serve()` stops accepting connections, closes each one once its current request is answered, and returns once every connection and every file kept for a reconnect has closed.

## Backends

A share serves any type that implements `ShareBackend`; the crate documentation describes what the server does around each backend call. `LocalFsBackend`, from the default `localfs` feature, serves a directory on the host, and paths and symlinks cannot reach outside it. `.read_only()` makes it refuse writes.

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

## Limits and timeouts

`max_connections` (default 1024), `max_sessions_per_connection` (64), `max_trees_per_session` (128), `max_opens_per_connection` (16384) and `max_locks_per_open` (1024) on the builder cap what clients hold at once. A request past a limit fails with STATUS_INSUFFICIENT_RESOURCES, and a connection past `max_connections` is closed. `ConfigHandle::set_max_opens_per_connection` changes the open limit at run time.

`handshake_timeout` (30 seconds) closes a connection still without a session, `idle_timeout` (15 minutes) one that has sent no request and has no open files, and `io_timeout` (60 seconds) one that takes longer to receive the rest of a request or to send a response. `tcp_keepalive` sets the idle time before TCP keepalive probes, 60 seconds by default. `max_read_size` and `max_write_size` set the largest READ and WRITE, 1 MiB by default and between 64 KiB and 8 MiB.

After 10 failed logons for one user name, each within 60 seconds of the one before, logons with that name fail with STATUS_ACCOUNT_LOCKED_OUT until 60 seconds have passed since the last failure. A client address is locked out the same way after 100 failed logons under any names, and a connection is closed after 10. Unknown names count the same as configured ones. `logon_throttle(max_failures, lockout)` sets both numbers; 0 failures turns the throttle off.

## Signing

Signed sessions use HMAC-SHA-256 on SMB 2.0.2 and 2.1 and AES-CMAC on SMB 3.x. `require_signing(true)` on the builder makes every authenticated session sign its requests and tells clients in the NEGOTIATE response that signing is required. With it off, a client can still require signing for its own sessions.

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

Where encryption is required, clients that cannot encrypt are refused: SMB 2.x, SMB 3.x without a cipher in common, and anonymous and guest sessions, which get a session but no tree. `reject_unencrypted_access(false)` serves them unencrypted instead.

## Leases

Files on every share get SMB2 leases with read, handle and write caching: a client caches what it reads, keeps files open after its applications close them, and caches writes while every other open of the file holds the same lease or only reads attributes. An open, write, lock, rename or delete through any open that doesn't hold the lease, including the same client's opens under another lease key or none, breaks it when it needs what the lease caches. An open or rename that needs the client to write back or close its handles first waits until the client acknowledges or closes, or until 35 seconds after the break is sent; a lock is refused until the client has written back.

Changes made outside the server, or through another share over the same directory, break no lease, so clients keep serving their cached copies. Call `.leases(false)` on such a `Share` to turn leases off there.

## Durable handles

A file opened with a durable handle request, version 1 or 2, and a lease that caches handles stays open, for 2 minutes by default or the time a version 2 request asks for, up to 5 minutes or the configured time if that is longer, after the client's connection drops or it logs off, with its share mode, byte-range locks and lease. When the same user reconnects from the same client, it takes the file back and carries on with the same handle, locks and lease. An open, write, lock, rename or delete that needs what the lease caches closes a kept file at once, and so do `ConfigHandle` calls that remove the user or the share, revoke the user's access or lower it to read-only, change the share's mode, or change the user's password.

`durable_handle_timeout` and `max_disconnected_opens` on the builder set the time and the most files kept at once. Call `.durable_handles(false)` on a `Share` to turn them off there.

## Change notifications

A client watching a folder, as Explorer and the Finder do for an open window, hears when a file or folder in it, or below it when the client watches the whole tree, is created, deleted, renamed, written, truncated or overwritten, or has its attributes or times set, through any connection to the share. A write is reported when the open that wrote closes. New contents are reported under SIZE, LAST_WRITE and ATTRIBUTES.

Changes made outside the server, or through another share over the same directory, are reported only by a backend that watches for them. `LocalFsBackend` does on Linux, through inotify, for the entries directly in a watched folder; `.watch_host_changes(false)` on the backend turns that off. One backend holds at most 4096 kernel watches, and a folder past that, or past `fs.inotify.max_user_watches` or `fs.inotify.max_user_instances`, gets only the changes made through the server, with a warning logged once. Call `.change_notify(false)` on a `Share` to turn change notifications off there.

## Share listing

Clients that list a server's shares, such as Explorer and `net view` on Windows, the Finder and `smbutil view` on macOS, and `smbclient -L`, get the shares they may connect to, in the order they were added, and IPC$. An anonymous session gets the public shares, and a session that cannot encrypt does not get shares whose traffic is encrypted. Shares whose name ends in `$` are listed too; clients hide them from ordinary lists.

```rust
use smb_server::{Access, LocalFsBackend, Share, SmbServer};

let server = SmbServer::builder()
    .listen("0.0.0.0:4445".parse()?)
    .user("alice", "password")
    .share(
        Share::new("photos", LocalFsBackend::new("/srv/photos")?)
            .user("alice", Access::Read)
            .remark("Family photos"),
    )
    .share(
        Share::new("archive", LocalFsBackend::new("/srv/archive")?)
            .user("alice", Access::Read)
            .listed(false),
    )
    .build()?;
```

`remark` sets the comment shown next to a share. `listed(false)` leaves a share out of the list; it is still reachable and can be looked up by name, so it is not access control. `share_listing(false)` on the builder turns listing off.

## Network discovery

With the `discovery` feature, `.discovery(Discovery::new())` on the builder announces the server while `serve()` runs and withdraws it before `serve()` returns. The listen address must not be a loopback address.

```rust
use smb_server::{Discovery, LocalFsBackend, Share, SmbServer};

let server = SmbServer::builder()
    .listen("[::]:445".parse()?)
    .share(Share::new("public", LocalFsBackend::new("/srv/public")?).public())
    .discovery(Discovery::new())
    .build()?;
```

The server is announced over mDNS and DNS-SD as an `_smb._tcp` service with the port it listens on, under its NetBIOS name unless `Discovery::name` sets another; on macOS, with neither a name nor a model set, under the computer name. It shows up in the Finder sidebar and in Linux file managers such as GNOME Files and Dolphin. On Linux it registers with Avahi when Avahi runs, on macOS with mDNSResponder, on Windows with the DNS Client service; otherwise the server answers mDNS itself.

On hosts other than Windows, a server listening on port 445 also answers WS-Discovery and shows up in the Network view of Windows Explorer, under its NetBIOS name and workgroup. Windows opens computers it finds that way on port 445 only and by their NetBIOS name, so the server is announced to Windows only on port 445 and only when its NetBIOS name is the host name. When the NetBIOS name is not the host name, the server logs a warning. The NetBIOS name defaults to the first label of the host name in upper case, cut to 15 characters; `netbios_name` on the builder sets another. Listen on `[::]:445` as above: Windows may resolve the name to an IPv6 address too and then connect over IPv6 alone, so it lists a server that listens on IPv4 only but cannot open it. Explorer lists the server only where network discovery is turned on for the client's network profile. On macOS, run the server as root for WS-Discovery: as a non-root user, macOS may refuse to send its messages or not deliver the probes to it, and Windows then does not list the server.

On the host firewall, open UDP port 5353 for mDNS, and UDP port 3702 and TCP port 5357 for WS-Discovery. When another program holds TCP port 5357, the server serves on a free port instead and logs a warning.

## Limitations

Not supported:

- SMB1
- Kerberos and NTLMv1; authentication is NTLMv2 only
- oplocks and directory leases
- answering a replayed CREATE with the open it repeats, and persistent and resilient handles
- change notifications for changes made outside the server or through another share over the same directory, except with `LocalFsBackend` on Linux for the entries directly in a watched folder
- named pipes other than `srvsvc`, and RPC calls other than listing shares and describing the server
- DFS
- multichannel and compression
- transports other than direct TCP: NetBIOS sessions, QUIC and RDMA
- alternate data streams and extended attributes
- security descriptors and quotas
- server-side copy and reparse points
- snapshots for Previous Versions
- network discovery over NetBIOS

## License

MIT.
