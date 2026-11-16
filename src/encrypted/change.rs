//! The steps writes and truncates share under the lock of a file: the size
//! of the stored file, the header the change works under, and the retry after
//! a block that does not open.

use std::io;
use std::mem;

use tokio::sync::RwLock;

use super::block::FileCipher;
use super::format::{FILE_ID_LEN, NONCE_LEN};
use super::handle::EncryptedHandle;
use super::header::Header;
use super::node::{FileMeta, HeaderState};
use super::random::{random_file_id, random_nonces};
use super::size::{logical_size, stored_size};
use crate::backend::ShareBackend;
use crate::error::{SmbError, SmbResult};

/// Where a change draws its random bytes.
pub(super) trait Random: Send {
    /// One nonce for each of `nonces`, none of them all zero.
    fn nonces(&mut self, nonces: &mut [[u8; NONCE_LEN]]) -> Result<(), getrandom::Error>;

    /// A file id that is not all zero.
    fn file_id(&mut self) -> Result<[u8; FILE_ID_LEN], getrandom::Error>;
}

/// The OS generator.
pub(super) struct OsRandom;

impl Random for OsRandom {
    fn nonces(&mut self, nonces: &mut [[u8; NONCE_LEN]]) -> Result<(), getrandom::Error> {
        random_nonces(nonces)
    }

    fn file_id(&mut self) -> Result<[u8; FILE_ID_LEN], getrandom::Error> {
        random_file_id()
    }
}

/// The generator failed.
pub(super) fn random_error(error: getrandom::Error) -> SmbError {
    SmbError::Io(io::Error::other(error))
}

/// A change of the contents of a file.
#[derive(Clone, Copy)]
pub(super) enum Change<'a> {
    Write {
        offset: u64,
        data: &'a [u8],
    },
    /// Sets the length to `len`, which takes `target` stored bytes.
    Truncate {
        len: u64,
        target: u64,
    },
}

/// How one try at a change ended.
pub(super) enum Attempt {
    Done,
    /// The block with that index, in the file with that id, does not open.
    Corrupt {
        block: u64,
        used: [u8; FILE_ID_LEN],
    },
}

/// The sizes of a stored file after `normalize`.
#[derive(Clone, Copy)]
pub(super) struct Normal {
    /// Bytes of the file as clients see it.
    pub(super) logical: u64,
    /// Bytes of the stored file: the size `logical` gives.
    pub(super) end: u64,
}

/// The header a change works under, and the cipher of its key.
pub(super) struct Taken {
    pub(super) header: Header,
    pub(super) cipher: Box<FileCipher>,
    /// The header is new and not in the stored file yet.
    pub(super) fresh: bool,
}

impl Taken {
    /// Puts the header back into `meta`. A new header goes back only when
    /// the change is `done`, which means it is in the stored file.
    pub(super) fn put_back(self, meta: &mut FileMeta, done: bool) {
        if !self.fresh || done {
            meta.header = HeaderState::Present(self.header, self.cipher);
        }
    }
}

impl<B: ShareBackend> EncryptedHandle<B> {
    /// Cuts the stored file to the size its logical size gives: a torn
    /// header, a header alone or a fragment after the last block does not
    /// stay in the file. A stored size that passes the largest one fails with
    /// `InvalidParameter`.
    pub(super) async fn normalize(&self) -> SmbResult<Normal> {
        let shift = self.shared.settings.block_shift;
        let stored = self.stored_size().await?;
        let logical = logical_size(shift, stored).size;
        let end = stored_size(shift, logical).ok_or(SmbError::InvalidParameter)?;
        if end != stored {
            self.inner.truncate(end).await?;
        }
        Ok(Normal { logical, end })
    }

    /// The header a change works under, for a stored file of `end` bytes. A
    /// file without data gets a header with a new file id, which
    /// `Taken::put_back` caches once it is stored. The header of a file with
    /// data is taken out of `meta` while the change runs; a change that is
    /// dropped leaves it to be read again.
    pub(super) async fn take_header(
        &self,
        meta: &mut FileMeta,
        end: u64,
        random: &mut dyn Random,
    ) -> SmbResult<Taken> {
        if end == 0 {
            meta.header = HeaderState::Absent;
            let id = random.file_id().map_err(random_error)?;
            let header = Header::new(self.shared.settings.block_shift, id)
                .expect("the generator returns a non-zero file id");
            let cipher = Box::new(FileCipher::new(&self.shared.keys, header));
            return Ok(Taken {
                header,
                cipher,
                fresh: true,
            });
        }
        let (header, cipher) = match mem::replace(&mut meta.header, HeaderState::Unknown) {
            HeaderState::Present(header, cipher) => (header, cipher),
            HeaderState::Unknown | HeaderState::Absent => self.read_header().await?,
        };
        Ok(Taken {
            header,
            cipher,
            fresh: false,
        })
    }

    /// Applies `change` to the file under its exclusive lock. A block that
    /// does not open makes the header reload, once. The change runs again if
    /// the stored file has a different file id, or none, and fails with the
    /// block error otherwise. An error of the reload is returned instead.
    pub(super) async fn change_file(
        &self,
        file: &RwLock<FileMeta>,
        change: Change<'_>,
        random: &mut dyn Random,
    ) -> SmbResult<()> {
        let mut meta = file.write().await;
        let mut reloaded = false;
        loop {
            let attempt = match change {
                Change::Write { offset, data } => {
                    self.write_once(&mut meta, offset, data, &mut *random)
                        .await?
                }
                Change::Truncate { len, target } => {
                    self.truncate_once(&mut meta, len, target, &mut *random)
                        .await?
                }
            };
            let Attempt::Corrupt { block, used } = attempt else {
                return Ok(());
            };
            if !reloaded && self.reload(&mut meta, used).await? {
                reloaded = true;
                continue;
            }
            return Err(self.block_error(block));
        }
    }
}
