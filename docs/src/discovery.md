# Network discovery

Needs the `discovery` feature. The server is announced while `serve()` runs and withdrawn before it returns. The listen address must not be loopback.

```rust
SmbServer::builder()
    .listen("[::]:445".parse()?)
    .share(Share::new("public", LocalFsBackend::new("/srv/public")?).public())
    .discovery(Discovery::new())
    .build()?
```

## mDNS and DNS-SD

`_smb._tcp` service on the listen port. Shows up in the Finder sidebar, GNOME Files and Dolphin.

| Host | Registers with |
|---|---|
| Linux | Avahi, when running |
| macOS | mDNSResponder |
| Windows | DNS Client service |
| Otherwise | Built-in mDNS responder |

Name: `Discovery::name` if set. Otherwise the [NetBIOS name](#netbios-name), except on macOS with neither `name` nor `model` set, where it is the computer name.

## WS-Discovery (Windows Explorer)

Shows up in the Explorer Network view, under the NetBIOS name and workgroup.

Requires:

- a host other than Windows
- port 445
- a NetBIOS name equal to the host name; otherwise a warning is logged
- network discovery on for the client's network profile

Also:

- Listen on `[::]:445`. Windows may resolve the name to IPv6 and connect over IPv6 only.
- On macOS, run as root, or macOS may block the messages.

## NetBIOS name

First label of the host name, upper case, cut to 15 characters. `netbios_name` on the builder sets another.

## Firewall

| Port | For |
|---|---|
| UDP 5353 | mDNS |
| UDP 3702 | WS-Discovery |
| TCP 5357 | WS-Discovery. If taken, a free port is used and a warning logged |

## Options

`Discovery::new()` then:

| Call | Sets |
|---|---|
| `.name(name)` | Name file managers list the server under |
| `.model(code)` | Model code the Finder picks the server's icon by |
| `.ws_discovery(bool)` | `false`: off. `true`: required, `build()` fails if it cannot be announced. Unset: announced when the requirements above are met |
| `.workgroup(name)` | Workgroup Windows lists it in, `WORKGROUP` by default |
| `.manufacturer`, `.model_name`, `.firmware_version` | What Windows shows in the server's properties |
