//! Byte patterns, a model of file contents and volume sizes for tests.

/// `len` bytes whose values follow their offset, and `seed`.
pub(crate) fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 8) as u8) ^ seed)
        .collect()
}

/// `len` bytes that are never zero and change from block to block.
pub(crate) fn nonzero_pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251 + 1) as u8).collect()
}

/// `model` after `data` is written at `offset`.
pub(crate) fn apply(model: &mut Vec<u8>, offset: usize, data: &[u8]) {
    if model.len() < offset + data.len() {
        model.resize(offset + data.len(), 0);
    }
    model[offset..offset + data.len()].copy_from_slice(data);
}

/// A xorshift64 generator; `seed` must not be zero.
pub(crate) fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

/// Bytes in an allocation unit of the volume of `backend`.
#[cfg(all(feature = "localfs", any(target_os = "linux", windows)))]
pub(crate) async fn allocation_unit(backend: &impl crate::backend::ShareBackend) -> u64 {
    backend.volume_info().await.unwrap().allocation_unit()
}
