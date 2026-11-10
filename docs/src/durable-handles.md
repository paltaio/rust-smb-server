# Durable handles

A file opened with a durable handle request (v1 or v2) and a lease that caches handles stays open after the connection drops or the client logs off. It keeps its share mode, byte-range locks and lease.

When the same user reconnects from the same client, the client reopens the file with the same handle, locks and lease. Until then it is a disconnected durable handle.

## How long

| Request | Kept for |
|---|---|
| v1, or v2 without a time | `durable_handle_timeout`, 2 min by default |
| v2 with a time | That time, up to 5 min or `durable_handle_timeout`, whichever is longer |

`durable_handle_timeout` takes 1 ms to 49 days.

## How many

`max_disconnected_opens`, 4096 by default, counting every client. One user gets at most a quarter, rounded up. A file that would go past either limit is closed at disconnect.

## Closed early by

- An open, write, lock, rename or delete that needs what the lease caches
- `ConfigHandle` calls that:
  - remove the user or the share
  - revoke the user's access or lower it to read-only
  - change the share's mode
  - change the user's password

Turn off on one share: `.durable_handles(false)`.
