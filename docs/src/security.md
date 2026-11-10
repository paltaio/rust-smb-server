# Signing and encryption

## Signing

| Dialect | Algorithm |
|---|---|
| SMB 2.0.2, 2.1 | HMAC-SHA-256 |
| SMB 3.x | AES-CMAC |

`require_signing(true)` on the builder, off by default:

- every authenticated session must sign
- NEGOTIATE says signing is required

With it off, a client can still require signing for its own sessions. Anonymous and guest sessions are never signed.

## Encryption

| Dialect | Ciphers |
|---|---|
| SMB 3.1.1 | AES-128 or AES-256, CCM or GCM |
| SMB 3.0, 3.0.2 | AES-128-CCM, for clients that advertise encryption |

A client that sends encrypted requests gets encrypted replies.

Require it on one share:

```rust
Share::new("secret", LocalFsBackend::new("/srv/secret")?)
    .user("alice", Access::ReadWrite)
    .encrypt_data()
```

Require it for every session: `encrypt_data(true)` on the builder.

Where encryption is required, these clients are refused:

- SMB 2.x
- SMB 3.x without a cipher in common
- Anonymous and guest sessions: they get a session but no tree connection

`reject_unencrypted_access(false)` on the builder serves all of these unencrypted instead.

## Logon throttle

See [Limits and timeouts](limits.md#logon-throttle).
