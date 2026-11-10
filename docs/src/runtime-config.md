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
| `add_user(name, password)` | Adds a user. On an existing user, replaces the password and ends their sessions |
| `remove_user(name)` | Ends the user's sessions |
| `add_share(share)` | Open to new tree connections |
| `remove_share(name)` | Closes its tree connections and open handles |
| `grant_share_user(share, user, access)` | Lowering access ends the user's tree connections on the share |
| `revoke_share_user(share, user)` | Closes the user's tree connections and handles on the share |
| `set_share_mode(share, ShareMode)` | Closes the share's tree connections. A public mode on a share with users fails |
| `set_max_opens_per_connection(n)` | New limit; opens already held stay open |

Each call that cuts a user off also closes that user's [disconnected durable handles](durable-handles.md).
