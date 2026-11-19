# Change notifications

Windows Explorer and macOS Finder watch each open folder. Watching clients receive notifications for changes made through any connection to the share, either directly in the folder or anywhere below it when watching a subtree.

| Change | Reported |
|---|---|
| Create, delete, rename | Immediately |
| Attributes or times set | Immediately |
| Write, truncate, overwrite | When the writing handle closes, as `SIZE`, `LAST_WRITE`, and `ATTRIBUTES` changes |

Disable on a single share with `.change_notify(false)`.

## Changes outside the server

Changes made directly on the host, or through another share backed by the same directory, are reported only if the backend watches for them.

On Linux, `LocalFsBackend` watches via inotify:

- Watches entries directly inside a watched folder only.
- Uses at most 4096 kernel watches per backend.
- If a folder exceeds that limit, or hits `fs.inotify.max_user_watches` or `fs.inotify.max_user_instances`, it only receives changes made through the server and a warning is logged once.
- Call `.watch_host_changes(false)` on the backend to disable host watching.

On other platforms, only changes made through the server are reported.
