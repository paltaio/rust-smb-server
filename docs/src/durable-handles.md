# Durable handles

A file opened with a durable handle request (v1 or v2) and a handle-caching lease stays open after the connection drops or the client logs off. It retains its share mode, byte-range locks, and lease.

When the same user reconnects from the same client, the client reopens the file with the same handle, locks, and lease. Until then, the server keeps it as a disconnected durable handle.

## How long

| Request | Kept for |
|---|---|
| v1, or v2 without a timeout | `durable_handle_timeout`, 2 min by default |
| v2 with a timeout | The requested timeout, up to 5 min or `durable_handle_timeout`, whichever is longer |

`durable_handle_timeout` accepts values from 1 ms to 49 days.

## How many

`max_disconnected_opens` defaults to 4096 across all clients. A single user can hold at most a quarter of that limit, rounded up. Files that would exceed either limit are closed on disconnect.

## Closed early by

- An open, write, lock, rename, or delete that conflicts with what the lease caches
- `ConfigHandle` calls that:
  - remove the user or the share
  - revoke the user's access or lower it to read-only
  - change the share's mode
  - change the user's password

Disable on a single share with `.durable_handles(false)`.
