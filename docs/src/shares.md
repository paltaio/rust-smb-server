# Shares and users

```rust
SmbServer::builder()
    .user("alice", "password")
    .share(Share::new("home", backend).user("alice", Access::ReadWrite))
```

## Access

| Call on `Share` | Who gets in |
|---|---|
| `.user(name, Access::ReadWrite)` | That user, read-write |
| `.user(name, Access::Read)` | That user, read-only |
| `.public()` | Anonymous and guest, read-write |
| `.public_read_only()` | Anonymous and guest, read-only |

- Without `.public()` or `.public_read_only()`, only listed users can connect.
- A public share cannot also list `.user()` entries; `build()` fails with `PublicMixedWithUsers`.

## Guest

- Logging on as `guest` with an empty password grants anonymous access, unless a user named `guest` (any case) is configured. macOS Finder sends this for Connect As Guest.
- Guest and anonymous sessions are neither signed nor encrypted. Clients that require signing cannot establish a guest session.

## Per-share switches

All options are enabled by default.

| Call on `Share` | Disables |
|---|---|
| `.leases(false)` | [Leases](leases.md) |
| `.durable_handles(false)` | [Durable handles](durable-handles.md) |
| `.change_notify(false)` | [Change notifications](change-notify.md) |
| `.named_streams(false)` | [Named streams](streams.md) |
| `.extended_attributes(false)` | [Extended attributes](extended-attributes.md) |
| `.server_side_copy(false)` | [Server-side copy](copy.md) |
| `.listed(false)` | Showing the share in [share listings](share-listing.md) |

Other calls on `Share`:

| Call on `Share` | Effect |
|---|---|
| `.encrypt_data()` | Require [encryption](security.md) on this share |
| `.remark(text)` | Comment shown next to the share in listings |
