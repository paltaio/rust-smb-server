# Share listing

Windows Explorer, `net view`, macOS Finder, `smbutil view`, and `smbclient -L` can list a server's shares. Each session sees the shares it is allowed to connect to, in the order they were added, plus `IPC$`. Sessions that cannot encrypt do not see shares that require encryption. Shares ending in `$` are included in the list; clients hide them by convention.

```rust
Share::new("photos", LocalFsBackend::new("/srv/photos")?)
    .user("alice", Access::Read)
    .remark("Family photos")
```

| Call | Effect |
|---|---|
| `.remark(text)` on `Share` | Comment shown next to the share |
| `.listed(false)` on `Share` | Omits the share from listings. Still reachable by name; this is not access control |
| `share_listing(false)` on the builder | Disables share listing |
