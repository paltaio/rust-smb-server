# Runtime config

Get a `ConfigHandle` before `serve()` and use it from another task while the server runs:

```rust
let config = server.config_handle();
let home = Share::new("home", LocalFsBackend::new("/srv/home")?)
    .user("alice", Access::ReadWrite);

tokio::spawn(async move {
    config.add_user("alice", "password").await?;
    config.add_share(home).await?;
    Ok::<_, smb_server::ConfigError>(())
});

server.serve().await?;
```

| Call | Effect |
|---|---|
| `add_user(name, password)` | Adds a user, or replaces the password and disconnects active sessions for an existing user |
| `remove_user(name)` | Removes the user and disconnects their active sessions |
| `add_share(share)` | Adds a share and makes it available to new tree connections |
| `remove_share(name)` | Removes the share and closes its tree connections and open handles |
| `grant_share_user(share, user, access)` | Grants or updates a user's access on the share; lowering access disconnects their tree connections to that share |
| `revoke_share_user(share, user)` | Revokes a user's access and closes their tree connections and open handles on that share |
| `set_share_mode(share, ShareMode)` | Changes the share's access mode and closes its tree connections. Switching a share with listed users to a public mode fails |
| `set_max_opens_per_connection(n)` | Updates the per-connection open-handle limit; already open handles stay open |

Any call that disconnects a user also closes their [disconnected durable handles](durable-handles.md).
