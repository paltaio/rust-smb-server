# Encrypted storage

Feature `encryption`, off by default. `EncryptedBackend` wraps another backend and encrypts file contents and, by default, file names under a 32-byte key. The inner backend stores ciphertext while clients see plaintext.

```toml
smb-server = { version = "0.12", features = ["encryption"] }
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

The key must be 32 raw bytes supplied by the caller; the backend does not derive it from a passphrase.

## S3 bucket

```toml
smb-server = { version = "0.12", features = ["s3", "encryption"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use smb_server::{Access, EncryptedBackend, S3Backend, Share, SmbServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; 32] = std::fs::read("/etc/smb/vault.key")?
        .try_into()
        .map_err(|_| "the key file must hold 32 bytes")?;

    let s3 = S3Backend::builder("https://s3.example.com", "us-east-1", "vault-bucket")
        .credentials("access-key", "secret-key")
        .cache_dir("/var/cache/smb-vault")
        .case_insensitive(false)
        .build()
        .await?;
    let vault = EncryptedBackend::builder(s3.clone(), key).build().await?;

    let server = SmbServer::builder()
        .listen("0.0.0.0:4445".parse()?)
        .user("alice", "password")
        .share(Share::new("vault", vault).user("alice", Access::ReadWrite))
        .build()?;
    server.bind().await?;

    let served = server.serve().await;
    s3.sync().await?;
    served?;
    Ok(())
}
```

When encrypting names, configure the inner `S3Backend` with `case_insensitive(false)`. With the default `true`, looking up a missing key also lists the directory. The cache directory records the case setting, so `build()` rejects a cache created with the opposite value. Call `sync()` after `serve()` returns so pending changes reach the bucket; see [backends](backends.md#uploads-and-shutdown).

## What is protected

File contents are encrypted in blocks with AES-256-GCM, using a separate key per file. Every non-empty file starts with a header carrying a random file ID from which that file's key is derived. File names are encrypted with AES-SIV unless `encrypt_names(false)` is set.

Someone with access to the inner backend's storage still learns:

- the exact size of every file and where it has holes (blocks never written)
- the number of files and directories, and the shape of the directory tree
- timestamps, attributes, and POSIX modes
- the length of every name, and which names are identical across different directories
- the block size and whether names are encrypted
- between two snapshots of the storage, which blocks were rewritten and which files were truncated to zero
- every file name, if `encrypt_names(false)` is set

Modifying bytes inside a block, moving a block to another offset or to a file with a different file ID, altering a file header, or reading a file encrypted under another key all cause reads to fail. Forged or altered names are omitted from listings and cannot be opened. See [limitations](limitations.md#integrity-and-visibility) for changes that go undetected. Every user allowed to open the share can read every file in it.

## Settings

| Call | Default | Effect |
|---|---|---|
| `encrypt_names(bool)` | `true` | Encrypts file and directory names. Fixed when the share is created |
| `block_size(bytes)` | 64 KiB | Plaintext bytes per block, a power of two from 8 KiB to 1 MiB. Fixed when the share is created |
| `long_name_threshold(chars)` | 255 | Longest stored name, 62 to 255 characters. Longer encrypted names are stored as `<hash>.l` (34 characters) next to a `<hash>.n` object holding the encrypted name. Fixed when the share is created; not allowed with `encrypt_names(false)` |
| `case_insensitive(bool)` | `true` | Matches encrypted names without regard to case. With plaintext names, the inner backend's rule applies |
| `name_cache_ttl(duration)` | 30 s | How long decrypted directory names are trusted against changes made outside this backend. `Duration::ZERO` re-lists the directory on every lookup that needs it. Applies only to case-insensitive encrypted names |
| `restore_marker()` | Off | Allows `build()` to write a new [marker](#marker) |

`encrypt_names`, `block_size`, and `long_name_threshold` are stored in the marker. Any setting not specified on the builder uses the marker's value (or its default for a new share), and specifying a value that differs from the marker fails `build()` with `SettingMismatch`. Out-of-range values fail with `InvalidSetting`. `case_insensitive` and `name_cache_ttl` are not stored in the marker and take their defaults unless set.

## Marker

The root of the inner backend stores a 60-byte `.smb-encryption` marker containing the format version, the settings fixed at creation, a random 16-byte share ID, and an HMAC-SHA-256 over those fields using a key derived from the share key. Clients cannot list or open this file.

`build()` writes the marker into an empty root (unless the inner backend is read-only) and reads it from any non-empty root. It fails in these cases:

| Root state | Error |
|---|---|
| Marker has the right size, magic, and version, but HMAC verification fails (wrong key or tampered bytes after the version) | `KeyMismatch` |
| Marker has the wrong size, wrong magic, or is a directory | `MarkerInvalid` |
| Marker uses a format version this release does not support | `UnsupportedFormat` |
| Root has entries but no marker | `MarkerMissing` |

A crash during the first build can leave a truncated marker, causing `MarkerInvalid`. Delete it and build again.

`restore_marker()` writes a new marker into a non-empty root that is missing one. The marker records the settings configured on the builder (or defaults), so pass the same settings the share was created with. Before writing, `build()` verifies the key and block size:

- With encrypted names, at least one entry in the root must decode under the key.
- The first non-empty file, found breadth-first within the first 10,000 entries, must have a header matching the chosen block size and a first block that is either a hole or verifies under the key.

If verification fails, `build()` returns `KeyMismatch` (or `SettingMismatch` for the block size) and writes nothing. With plaintext names, any file counts: a stray file such as `.DS_Store` encountered first in the root causes `KeyMismatch` until removed. With plaintext names and no non-empty files, no check can reject a wrong key.

## Keys

- Give each share its own key. If two shares share a key and block size, a stored file copied from one share's storage can be read through the other.
- The key is not stored anywhere. Losing the key loses the data. Losing the marker loses no data, but `restore_marker()` does not verify `encrypt_names` or `long_name_threshold`, so keep a record of those settings.
- `build()` wipes the builder's copy of the key once derived keys are created, and derived keys and AES key schedules are wiped on drop. Any copy retained by the caller is the caller's responsibility to wipe. Not wiped: internal state in the `hmac` and `sha2` crates, and the GHASH subkey in `aes-gcm` (which lives in each cipher and in copies made during setup and per operation; `aes-gcm` wipes only one temporary copy).

## Damaged blocks

Reading a block that fails authentication returns `STATUS_UNEXPECTED_IO_ERROR` and logs a warning with the path, stored path, and block number. Reads elsewhere in the file still work, and a write covering the entire block replaces it. Client behavior:

| Client | Result |
|---|---|
| Windows Explorer | "Interrupted Action" (`0x8007045D`) with Try Again, Skip, and Cancel |
| `robocopy` | Retries every 30 seconds up to a million times by default. Pass `/R` and `/W` (for example, `/R:2 /W:1`) |
| macOS Finder | Error `-8084`. Leaves a full-size copy filled with zeros after the point of failure |
| `cp` on macOS and Linux | "Input/output error" |

A copy inside the share fails the same way; Finder shows error `-36` and leaves no file.

## Limits

- Contents: with random nonces, NIST SP 800-38D allows up to 2^32 block encryptions per key. This limit applies per file key: 256 TiB written to one file at 64 KiB blocks, 32 TiB at 8 KiB, or 4 PiB at 1 MiB, counting every block rewrite. Truncating a file to zero or overwriting it on open starts a new key. The backend does not track write counts.
- Names: RFC 5297 advises at most 2^48 distinct AES-SIV invocations per key. The share uses one invocation per distinct name.

## aarch64

On aarch64, AES and GHASH run in software unless the crate is built with both flags:

```sh
RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8" cargo build --release
```

On aarch64 targets other than Linux, Android, and Apple platforms, also enable the `aes` target feature (for example, `-C target-feature=+aes` in `RUSTFLAGS`). Linux and Android detect it at runtime, and Apple platforms assume it.

## Example

With `--features encryption` and `SMB_ENCRYPTION_KEY` set to 64 hex digits, the example adds a `vault` share backed by the `vault` directory inside `SMB_ROOT`, with `alice` read-write and `bob` read-only. When `SMB_S3_BUCKET` is also set (requiring `--features s3,encryption`), it encrypts the `s3` share instead. An invalid key length or setting `SMB_ENCRYPTION_KEY` without the `encryption` feature stops the example.

```sh
SMB_ENCRYPTION_KEY='<64 hex digits>' cargo run -p minimal-smb-example --features encryption
```

- Any 64 hex digits work as a key, such as the output of `openssl rand -hex 32`.
- Toggling `SMB_ENCRYPTION_KEY` on or off while reusing an existing `SMB_S3_CACHE` fails due to the cache directory's recorded case setting.
