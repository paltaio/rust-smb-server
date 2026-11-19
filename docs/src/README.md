# smb-server

SMB file-sharing server library for Rust.

- Dialects: SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 over TCP
- Auth: NTLMv2, anonymous, guest
- Signing and encryption (AES-CCM, AES-GCM)
- Leases, durable handles, change notifications
- Named streams, macOS metadata, extended attributes
- Server-side copy and block cloning
- Share listing, mDNS and WS-Discovery
- Users and shares can be added, updated, and removed at runtime
- Pluggable storage: implement `ShareBackend`, or use the built-in `LocalFsBackend` or `S3Backend`
- Encrypted storage: [`EncryptedBackend`](encrypted-storage.md) wraps another backend to encrypt file contents and, by default, file names

Works with Windows Explorer, macOS Finder, Linux CIFS mounts, and `smbclient`.

API reference: [docs.rs/smb-server](https://docs.rs/smb-server).
