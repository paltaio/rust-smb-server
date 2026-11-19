# Signing and encryption

## Signing

| Dialect | Algorithm |
|---|---|
| SMB 2.0.2, 2.1 | HMAC-SHA-256 |
| SMB 3.x | AES-CMAC |

`require_signing(true)` on the builder is off by default. When enabled:

- every authenticated session must sign requests
- `NEGOTIATE` advertises signing as required

When it is off, a client can still require signing for its own sessions. Anonymous and guest sessions are never signed.

## Encryption

| Dialect | Ciphers |
|---|---|
| SMB 3.1.1 | AES-128 or AES-256, CCM or GCM |
| SMB 3.0, 3.0.2 | AES-128-CCM, for clients that advertise encryption |

Clients that send encrypted requests receive encrypted replies.

Require encryption on a single share:

```rust
Share::new("secret", LocalFsBackend::new("/srv/secret")?)
    .user("alice", Access::ReadWrite)
    .encrypt_data()
```

Require encryption for every session with `encrypt_data(true)` on the builder.

When encryption is required, these clients are refused:

- SMB 2.x clients
- SMB 3.x clients with no cipher in common
- Anonymous and guest sessions (they can establish a session, but tree connections are refused)

Setting `reject_unencrypted_access(false)` on the builder serves all of these unencrypted instead.

## Storage encryption

`encrypt_data` encrypts SMB 3.x traffic in transit between client and server. `EncryptedBackend` encrypts file contents and, by default, file names at rest in its inner backend. A share can use both. See [encrypted storage](encrypted-storage.md).

## Logon throttle

See [Limits and timeouts](limits.md#logon-throttle).
