# Leases

By default, every share grants SMB2 leases with read, handle, and write caching. Clients can:

- cache data they read
- keep files open after applications close them
- cache writes while every other open of the file holds the same lease or only reads attributes

## Breaks

A lease breaks when another open that does not hold the lease opens, writes, locks, renames, or deletes the file in a way that conflicts with the cached state. This includes opens from the same client with a different lease key or no lease.

| Operation | While the break is pending |
|---|---|
| Open, rename | Waits until the client writes back or closes, up to 35 s |
| Lock | Refused until the client writes back |

## Named streams

- Each named stream of a file has its own leases.
- Opening the base file or its other streams does not break those leases.
- Overwriting the base file breaks handle caching on its streams.

## Changes outside the server

Changes made directly on the host, or through another share backed by the same directory, do not break leases, so clients may keep serving cached copies. Disable leases on such a share:

```rust
Share::new("shared", backend).leases(false)
```
