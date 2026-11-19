# Limits and timeouts

All limits and timeouts are configured on `SmbServer::builder()`.

## Limits

| Option | Default | Past the limit |
|---|---|---|
| `max_connections` | 1024 | Connection closed |
| `max_sessions_per_connection` | 64 | `STATUS_INSUFFICIENT_RESOURCES` |
| `max_trees_per_session` | 128 | `STATUS_INSUFFICIENT_RESOURCES` |
| `max_opens_per_connection` | 16384 | `STATUS_INSUFFICIENT_RESOURCES` |
| `max_locks_per_open` | 1024 | `STATUS_INSUFFICIENT_RESOURCES` |
| `max_disconnected_opens` | 4096 | See [durable handles](durable-handles.md) |

`max_read_size` and `max_write_size` set the largest allowed `READ` and `WRITE` sizes. The default is 1 MiB, with a range of 64 KiB to 8 MiB.

`ConfigHandle::set_max_opens_per_connection` updates the open-handle limit at runtime.

## Timeouts

| Option | Default | Effect |
|---|---|---|
| `handshake_timeout` | 30 s | Closes a connection that has not established a session |
| `idle_timeout` | 15 min | Closes a connection with no requests and no open files |
| `io_timeout` | 60 s | Closes a connection that stalls while sending a request or reading a response |
| `tcp_keepalive` | 60 s | Idle time before sending TCP keepalive probes. `None` disables keepalive |
| `durable_handle_timeout` | 2 min | See [durable handles](durable-handles.md) |

## Logon throttle

`logon_throttle(max_failures, lockout)` defaults to `10` failures and a `60 s` lockout.

| Scope | Locked out after | Result |
|---|---|---|
| Single username | `max_failures` failures, each within `lockout` of the previous one | `STATUS_ACCOUNT_LOCKED_OUT` until `lockout` elapses |
| Single client address | 10 x `max_failures` failures across any usernames | `STATUS_ACCOUNT_LOCKED_OUT` until `lockout` elapses |
| Single connection | `max_failures` failures | Connection closed |

- Unknown usernames count the same as configured ones.
- Setting `max_failures` to `0` disables the throttle.
