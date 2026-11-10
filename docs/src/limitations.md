# Limitations

Not supported:

- SMB1
- Kerberos, NTLMv1
- Oplocks, directory leases
- Answering a replayed CREATE with its original open
- Persistent and resilient handles
- Change notifications for changes outside the server, except `LocalFsBackend` on Linux for entries directly in a watched folder
- Named pipes other than `srvsvc`; RPC beyond listing shares and describing the server
- DFS
- Multichannel, compression
- Transports other than direct TCP: NetBIOS sessions, QUIC, RDMA
- SMB extended attributes with `LocalFsBackend` on macOS. macOS xattrs travel as named streams there
- Security descriptors, quotas
- Reparse points
- Previous Versions snapshots
- Time Machine
- Discovery over NetBIOS
