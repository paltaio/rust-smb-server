//! Random block nonces and file ids. A value drawn all zero is drawn again:
//! an all-zero nonce marks a corrupt block and an all-zero file id is not a
//! valid header.

use getrandom::Error;

use super::format::{FILE_ID_LEN, NONCE_LEN, is_zero};
use crate::utils::fill_random;

/// Most draws one value gets before the call fails: the first draw and the
/// redraws.
const MAX_DRAWS: usize = 8;

/// Draws into `bytes` again until it is not all zero.
fn redraw_zero<const N: usize, F>(bytes: &mut [u8; N], fill: &mut F) -> Result<(), Error>
where
    F: FnMut(&mut [u8]) -> Result<(), Error>,
{
    for _ in 1..MAX_DRAWS {
        if !is_zero(bytes) {
            return Ok(());
        }
        fill(bytes)?;
    }
    if is_zero(bytes) {
        Err(Error::UNEXPECTED)
    } else {
        Ok(())
    }
}

/// Fills `nonces` with one call to `fill`, then redraws each all-zero nonce.
fn fill_nonces<F>(nonces: &mut [[u8; NONCE_LEN]], mut fill: F) -> Result<(), Error>
where
    F: FnMut(&mut [u8]) -> Result<(), Error>,
{
    if nonces.is_empty() {
        return Ok(());
    }
    fill(nonces.as_flattened_mut())?;
    nonces
        .iter_mut()
        .try_for_each(|nonce| redraw_zero(nonce, &mut fill))
}

/// A file id from `fill`, drawn again while it is all zero.
fn fill_file_id<F>(mut fill: F) -> Result<[u8; FILE_ID_LEN], Error>
where
    F: FnMut(&mut [u8]) -> Result<(), Error>,
{
    let mut id = [0u8; FILE_ID_LEN];
    fill(&mut id)?;
    redraw_zero(&mut id, &mut fill)?;
    Ok(id)
}

/// One nonce for each of `nonces`, from the OS generator.
pub(crate) fn random_nonces(nonces: &mut [[u8; NONCE_LEN]]) -> Result<(), Error> {
    fill_nonces(nonces, fill_random)
}

/// A file id from the OS generator that is not all zero.
pub(crate) fn random_file_id() -> Result<[u8; FILE_ID_LEN], Error> {
    fill_file_id(fill_random)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic stand-in for the OS generator: the n-th nonce of the
    /// buffer is the byte n + 1 repeated. A buffer holds at most 255 nonces.
    fn counting_fill(out: &mut [u8]) -> Result<(), Error> {
        for (n, nonce) in out.chunks_mut(NONCE_LEN).enumerate() {
            nonce.fill(u8::try_from(n + 1).expect("at most 255 nonces"));
        }
        Ok(())
    }

    /// A source that answers each call with the next scripted chunk.
    fn scripted(script: Vec<Vec<u8>>) -> impl FnMut(&mut [u8]) -> Result<(), Error> {
        let mut calls = script.into_iter();
        move |out| {
            let next = calls.next().expect("more calls than scripted");
            assert_eq!(next.len(), out.len());
            out.copy_from_slice(&next);
            Ok(())
        }
    }

    #[test]
    fn one_call_fills_every_nonce() {
        let mut calls = 0;
        let mut nonces = [[0u8; NONCE_LEN]; 5];
        fill_nonces(&mut nonces, |out| {
            calls += 1;
            assert_eq!(out.len(), 5 * NONCE_LEN);
            counting_fill(out)
        })
        .unwrap();
        assert_eq!(calls, 1);
        for (n, nonce) in (1u8..).zip(&nonces) {
            assert_eq!(nonce, &[n; NONCE_LEN]);
        }
    }

    #[test]
    fn no_nonces_draw_nothing() {
        fill_nonces(&mut [], |_| panic!("drew for no nonces")).unwrap();
    }

    #[test]
    fn all_zero_nonces_are_drawn_again() {
        let mut nonces = [[0u8; NONCE_LEN]; 3];
        let source = scripted(vec![
            [[1u8; NONCE_LEN], [0; NONCE_LEN], [2; NONCE_LEN]].concat(),
            vec![0; NONCE_LEN],
            vec![3; NONCE_LEN],
        ]);
        fill_nonces(&mut nonces, source).unwrap();
        assert_eq!(nonces, [[1; NONCE_LEN], [3; NONCE_LEN], [2; NONCE_LEN]]);
    }

    #[test]
    fn a_generator_that_returns_only_zeros_fails() {
        let mut nonces = [[0u8; NONCE_LEN]; 2];
        let mut calls = 0;
        let got = fill_nonces(&mut nonces, |out| {
            calls += 1;
            out.fill(0);
            Ok(())
        });
        assert_eq!(got, Err(Error::UNEXPECTED));
        assert_eq!(calls, MAX_DRAWS);
    }

    #[test]
    fn a_file_id_is_drawn_again_while_it_is_all_zero() {
        let source = scripted(vec![
            vec![0; FILE_ID_LEN],
            vec![0; FILE_ID_LEN],
            vec![5; FILE_ID_LEN],
        ]);
        assert_eq!(fill_file_id(source), Ok([5; FILE_ID_LEN]));
    }

    #[test]
    fn a_generator_that_returns_only_zeros_gives_no_file_id() {
        let mut calls = 0;
        let got = fill_file_id(|out| {
            calls += 1;
            out.fill(0);
            Ok(())
        });
        assert_eq!(got, Err(Error::UNEXPECTED));
        assert_eq!(calls, MAX_DRAWS);
    }
}
