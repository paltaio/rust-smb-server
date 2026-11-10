# Share listing

Explorer, `net view`, the Finder, `smbutil view` and `smbclient -L` list a server's shares. Each session sees the shares it may connect to, in the order added, plus IPC$. Sessions that cannot encrypt don't see shares that require encryption. Shares ending in `$` are listed too; clients hide them.

```rust
Share::new("photos", LocalFsBackend::new("/srv/photos")?)
    .user("alice", Access::Read)
    .remark("Family photos")
```

| Call | Effect |
|---|---|
| `.remark(text)` on `Share` | Comment shown next to the share |
| `.listed(false)` on `Share` | Left out of the list. Still reachable by name: not access control |
| `share_listing(false)` on the builder | Listing off |
