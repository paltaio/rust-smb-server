# Leases

By default, every share grants SMB2 leases with read, handle and write caching. Clients:

- cache what they read
- keep files open after their applications close them
- cache writes while every other open of the file holds the same lease or only reads attributes

## Breaks

A lease breaks when an open that does not hold it opens, writes, locks, renames or deletes in a way that needs what the lease caches. This includes the same client's opens with a different lease key or no lease.

| Operation | While the break is pending |
|---|---|
| Open, rename | Waits until the client writes back or closes, up to 35 s |
| Lock | Refused until the client writes back |

## Named streams

- Each named stream of a file has its own leases.
- Opens of the file or its other streams break none of them.
- An overwrite of the file breaks their handle caching.

## Changes outside the server

Changes made on the host, or through another share over the same directory, break no lease, so clients keep serving cached copies. Turn leases off on such a share:

```rust
Share::new("shared", backend).leases(false)
```
