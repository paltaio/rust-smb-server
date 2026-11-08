//! Byte patterns and volume sizes for tests.

/// `len` bytes whose values follow their offset, and `seed`.
pub(crate) fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 8) as u8) ^ seed)
        .collect()
}

/// Bytes in an allocation unit of the volume of `backend`.
#[cfg(all(feature = "localfs", any(target_os = "linux", windows)))]
pub(crate) async fn allocation_unit(backend: &impl crate::backend::ShareBackend) -> u64 {
    backend.volume_info().await.unwrap().allocation_unit()
}
