# Change notifications

Explorer and the Finder watch each open folder. A watching client hears about changes made through any connection to the share, to entries in the folder, or below it when it watches the whole tree.

| Change | Reported |
|---|---|
| Create, delete, rename | At once |
| Attributes or times set | At once |
| Write, truncate, overwrite | When the writing open closes, as SIZE, LAST_WRITE and ATTRIBUTES changes |

Turn off on one share: `.change_notify(false)`.

## Changes outside the server

Changes made on the host, or through another share over the same directory, are reported only by a backend that watches for them.

`LocalFsBackend` on Linux watches through inotify:

- Entries directly in a watched folder only
- At most 4096 kernel watches per backend
- A folder past that, or past `fs.inotify.max_user_watches` or `fs.inotify.max_user_instances`, gets only changes made through the server. A warning is logged once.
- `.watch_host_changes(false)` on the backend turns it off

Other hosts: changes made through the server only.
