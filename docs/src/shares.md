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

- Without `.public()` or `.public_read_only()`, only listed users get in.
- A public share takes no `.user()` entries; `build()` fails with `PublicMixedWithUsers`.

## Guest

- Logon as `guest` with an empty password gets anonymous access, unless a user named `guest` (any case) is configured. The Finder sends this for Connect As Guest.
- Guest and anonymous sessions are neither signed nor encrypted. A client that requires signing gets no guest session.

## Per-share switches

All on by default.

| Call on `Share` | Turns off |
|---|---|
| `.leases(false)` | [Leases](leases.md) |
| `.durable_handles(false)` | [Durable handles](durable-handles.md) |
| `.change_notify(false)` | [Change notifications](change-notify.md) |
| `.named_streams(false)` | [Named streams](streams.md) |
| `.extended_attributes(false)` | [Extended attributes](extended-attributes.md) |
| `.server_side_copy(false)` | [Server-side copy](copy.md) |
| `.listed(false)` | The share in [share listings](share-listing.md) |

Other calls on `Share`:

| Call on `Share` | Effect |
|---|---|
| `.encrypt_data()` | Require [encryption](security.md) on this share |
| `.remark(text)` | Comment shown next to the share in listings |
