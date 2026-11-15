# Encrypted storage

Feature `encryption`, off by default. `EncryptedBackend` wraps another backend and stores file contents, and by default names, encrypted under a 32-byte key. The inner backend holds ciphertext and clients see plaintext.

```toml
smb-server = { version = "0.11", features = ["encryption"] }
```

## Local directory

```rust
use smb_server::{Access, EncryptedBackend, LocalFsBackend, Share};

let key: [u8; 32] = load_key()?;
let vault = EncryptedBackend::builder(LocalFsBackend::new("/srv/vault")?, key)
    .build()
    .await?;

let share = Share::new("vault", vault).user("alice", Access::ReadWrite);
```

The key is 32 raw bytes supplied by the program. The backend does not derive it from a passphrase.

## S3 bucket

```rust
use smb_server::{Access, EncryptedBackend, S3Backend, Share};

let key: [u8; 32] = load_key()?;
let s3 = S3Backend::builder("https://s3.example.com", "us-east-1", "vault-bucket")
    .credentials("access-key", "secret-key")
    .cache_dir("/var/cache/smb-vault")
    .case_insensitive(false)
    .build()
    .await?;

let vault = EncryptedBackend::builder(s3.clone(), key).build().await?;
let share = Share::new("vault", vault).user("alice", Access::ReadWrite);
```

Build the inner `S3Backend` with `case_insensitive(false)`. With the default `true`, a lookup of a key the bucket does not hold also lists the directory. The cache directory records the case setting, and `build` refuses one made with the other value. Call `s3.sync()` after `serve` returns, as in [backends](backends.md#uploads-and-shutdown).

## What is protected

Contents are encrypted in blocks with AES-256-GCM, each file under a key of its own. Names are encrypted with AES-SIV unless `encrypt_names(false)` is set.

Someone who reads the inner storage still learns:

- the exact size of every file, and where it has holes
- the number of files and directories, and the shape of the tree
- times, attributes and POSIX modes
- the length of every name, and which names are equal in different directories
- the block size and whether names are encrypted
- between two copies of the storage, which blocks were rewritten and which files were truncated to zero
- every name, with `encrypt_names(false)`

A changed byte inside a block, a block moved to another position or to a file with another file id, a changed file header and a file made under another key fail the read. A forged or altered name is left out of listings and does not open. [Limitations](limitations.md#integrity-and-visibility) lists the changes that go undetected. Every user who can open the share can read every file in it.

## Settings

| Call | Default | Effect |
|---|---|---|
| `encrypt_names(bool)` | `true` | Store names encrypted. Fixed when the share is created |
| `block_size(bytes)` | 64 KiB | Plaintext bytes in a block, a power of two from 8 KiB to 1 MiB. Fixed when the share is created |
| `long_name_threshold(chars)` | 255 | Longest stored name, 62 to 255. A name whose encrypted form is longer is stored as `<hash>.l`, 34 characters, beside a `<hash>.n` object that holds the encrypted name. Fixed when the share is created. Not allowed with `encrypt_names(false)` |
| `case_insensitive(bool)` | `true` | Match encrypted names without regard to case. With names in the clear the inner backend's rule decides |
| `name_cache_ttl(duration)` | 30 s | How long the decrypted names of a directory are trusted for changes made outside this backend. `Duration::ZERO` lists the directory again on every lookup that needs it. Applies only to encrypted names that match without regard to case |
| `restore_marker()` | Off | Lets `build` write a new [marker](#marker) |

`encrypt_names`, `block_size` and `long_name_threshold` are stored in the marker. One that is not set takes the share's value, or its default in a new share, and one that differs from the share's fails `build` with `SettingMismatch`. A value outside its range fails with `InvalidSetting`. `case_insensitive` and `name_cache_ttl` are not stored: each takes its default unless set.

## Marker

The root of the inner backend holds `.smb-encryption`, 60 bytes: the format version, the settings fixed at creation, a random share id and an HMAC-SHA-256 of them under a key derived from the share key. Clients cannot list or open it.

`build` writes it into an empty root, unless the inner backend is read-only, and reads it from any other root. It fails when:

| Root | Error |
|---|---|
| Marker of the right size, magic and version whose HMAC fails: another key, or a changed byte after the version | `KeyMismatch` |
| Marker of the wrong size or with other magic, or a directory | `MarkerInvalid` |
| Marker of a format version this release does not read | `UnsupportedFormat` |
| Entries and no marker | `MarkerMissing` |

A crash during the first build can leave a short marker, which gives `MarkerInvalid`. Delete it and build again.

`restore_marker()` writes a new marker into a root that has entries and no marker. The marker takes the settings set on the builder, else the defaults: pass the settings the share was made with. Before `build` writes, it checks the key and the block size:

- With encrypted names, at least one entry of the root must decode under the key.
- The first file that holds data, found breadth first among at most 10,000 entries, must have a header of the chosen block size and a first block that is a hole or verifies under the key.

A failed check is `KeyMismatch`, or `SettingMismatch` for the block size, and nothing is written. With names in the clear any file counts: a stray file such as `.DS_Store` that comes first in the root fails with `KeyMismatch` until it is removed. With names in the clear and no file that holds data, no check can reject a wrong key.

## Keys

- Give each share a key of its own. With one key, a stored file copied into another share's storage reads back through that share when both use the same block size.
- The key is not stored anywhere. Losing it loses the data. Losing the marker loses no data. `restore_marker()` does not check `encrypt_names` or `long_name_threshold`, so keep a record of them.
- `build` wipes the builder's copy of the key once the derived keys exist, and the derived keys and AES key schedules are wiped when dropped. A copy the caller keeps is the caller's to wipe. Not wiped: the `hmac` and `sha2` crates' internal state, and the GHASH subkey of `aes-gcm`.

## Damaged blocks

A read of a block that fails authentication returns STATUS_UNEXPECTED_IO_ERROR and logs a warning with the path, the stored path and the block number. Reads elsewhere in the file work, and a write that covers the whole block replaces it. Clients show:

| Client | Result |
|---|---|
| Windows Explorer | "Interrupted Action" (0x8007045D) with Try Again, Skip and Cancel |
| `robocopy` | Retries every 30 seconds up to a million times by default. Pass `/R` and `/W`, for example `/R:2 /W:1` |
| macOS Finder | Error -8084. The copy is left at full size, with zeros after the point of failure |
| `cp` on macOS and Linux | "Input/output error" |

A copy inside the share fails the same way. Finder shows error -36 and leaves no file.

## Limits

- Contents: with random nonces, NIST SP 800-38D allows 2^32 block encryptions under one key. The limit applies to each file's key: 256 TiB written to one file at 64 KiB blocks, 32 TiB at 8 KiB, 4 PiB at 1 MiB, every rewrite of a block counted. A truncation to zero, or an open that overwrites the file, starts a new key. The backend does not count writes.
- Names: RFC 5297 advises at most 2^48 distinct AES-SIV invocations per key. The share uses one for each distinct name.

## aarch64

AES and GHASH run in software unless the crate is built with both flags:

```sh
RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8" cargo build --release
```

On aarch64 targets other than Linux, Android and Apple platforms, the `aes` target feature must also be enabled, for example with `-C target-feature=+aes` in `RUSTFLAGS`. Linux and Android detect it at run time, and Apple platforms assume it.

## Example

With `--features encryption` and `SMB_ENCRYPTION_KEY` set to 64 hex digits, the example adds `vault`, a share over the `vault` directory of `SMB_ROOT`, with `alice` read-write and `bob` read-only. With `SMB_S3_BUCKET` set, which needs `--features s3,encryption`, it encrypts the `s3` share instead. A value that is not 64 hex digits stops the example, and so does the variable without the feature.

```sh
SMB_ENCRYPTION_KEY='<64 hex digits>' cargo run -p minimal-smb-example --features encryption
```

- Any 64 hex digits work as a key, such as the output of `openssl rand -hex 32`.
- Switching the variable on or off for an `SMB_S3_CACHE` an earlier run used fails on the cache directory's case setting.
