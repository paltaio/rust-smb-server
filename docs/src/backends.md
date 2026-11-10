# Backends

A share serves any type that implements `ShareBackend`. To write one, see `ShareBackend` in the [API docs](https://docs.rs/smb-server).

## LocalFsBackend

Feature `localfs`, on by default. Serves a directory on the host.

```rust
LocalFsBackend::new("/srv/home")?
```

Paths and symlinks cannot reach outside the directory.

| Call | Effect |
|---|---|
| `.read_only()` | Refuses writes |
| `.watch_host_changes(false)` | Stops reporting host-side changes. Linux only, on by default. See [change notifications](change-notify.md) |
| `.stream_store(path)` | Keeps large named streams in `path`. Linux only. See [named streams](streams.md#stream-store) |

`sweep_streams()` frees stored stream data no file uses. See [named streams](streams.md#stream-store).
