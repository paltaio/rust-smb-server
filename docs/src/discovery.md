# Network discovery

Requires the `discovery` feature. The server is announced while `serve()` runs and withdrawn before it returns. The listen address must not be loopback.

```rust
SmbServer::builder()
    .listen("[::]:445".parse()?)
    .share(Share::new("public", LocalFsBackend::new("/srv/public")?).public())
    .discovery(Discovery::new())
    .build()?
```

## mDNS and DNS-SD

Advertises `_smb._tcp` on the listen port. Appears in the macOS Finder sidebar, GNOME Files, and Dolphin.

| Host | Registers with |
|---|---|
| Linux | Avahi, when running |
| macOS | mDNSResponder |
| Windows | DNS Client service |
| Otherwise | Built-in mDNS responder |

The advertised name is `Discovery::name` if set. Otherwise it defaults to the [NetBIOS name](#netbios-name), except on macOS with neither `name` nor `model` set, where it uses the computer name.

## WS-Discovery (Windows Explorer)

Appears in the Windows Explorer Network view under the NetBIOS name and workgroup.

Requirements:

- a host other than Windows
- port 445
- a NetBIOS name matching the host name (otherwise a warning is logged)
- network discovery enabled for the client's network profile

Additional setup:

- Listen on `[::]:445`. Windows may resolve the host name to IPv6 and connect over IPv6 only.
- On macOS, run as root, or the OS may block the announcements.

## NetBIOS name

Defaults to the first label of the host name in uppercase, truncated to 15 characters. Override it with `netbios_name` on the builder.

## Firewall

| Port | Purpose |
|---|---|
| UDP 5353 | mDNS |
| UDP 3702 | WS-Discovery |
| TCP 5357 | WS-Discovery. If already in use, a free port is chosen and a warning is logged |

## Options

Configure `Discovery::new()` with:

| Call | Sets |
|---|---|
| `.name(name)` | Name displayed by file managers |
| `.model(code)` | Model code macOS Finder uses to choose the server icon |
| `.ws_discovery(bool)` | `false` disables WS-Discovery; `true` requires it and fails `build()` if it cannot be announced. When unset, it is announced whenever the requirements above are met |
| `.workgroup(name)` | Workgroup shown in Windows (`WORKGROUP` by default) |
| `.manufacturer`, `.model_name`, `.firmware_version` | Fields shown in the server's Windows properties |
