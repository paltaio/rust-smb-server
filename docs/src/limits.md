# Limits and timeouts

All set on the builder.

## Limits

| Option | Default | Past the limit |
|---|---|---|
| `max_connections` | 1024 | Connection closed |
| `max_sessions_per_connection` | 64 | STATUS_INSUFFICIENT_RESOURCES |
| `max_trees_per_session` | 128 | STATUS_INSUFFICIENT_RESOURCES |
| `max_opens_per_connection` | 16384 | STATUS_INSUFFICIENT_RESOURCES |
| `max_locks_per_open` | 1024 | STATUS_INSUFFICIENT_RESOURCES |
| `max_disconnected_opens` | 4096 | See [durable handles](durable-handles.md) |

`max_read_size`, `max_write_size`: largest READ and WRITE. Default 1 MiB, range 64 KiB to 8 MiB.

`ConfigHandle::set_max_opens_per_connection` changes the open limit at run time.

## Timeouts

| Option | Default | Effect |
|---|---|---|
| `handshake_timeout` | 30 s | Closes a connection still without a session |
| `idle_timeout` | 15 min | Closes a connection with no requests and no open files |
| `io_timeout` | 60 s | Closes a connection slow to send the rest of a request or to take a response |
| `tcp_keepalive` | 60 s | Idle time before TCP keepalive probes. `None` turns keepalive off |
| `durable_handle_timeout` | 2 min | See [durable handles](durable-handles.md) |

## Logon throttle

`logon_throttle(max_failures, lockout)`, default `10` and 60 s.

| Scope | Locked out after | Result |
|---|---|---|
| One user name | `max_failures` failures, each within `lockout` of the last | STATUS_ACCOUNT_LOCKED_OUT until `lockout` passes |
| One client address | 10 x `max_failures` failures, any names | Same |
| One connection | `max_failures` failures | Connection closed |

- Unknown names count the same as configured ones.
- `max_failures = 0` turns the throttle off.
