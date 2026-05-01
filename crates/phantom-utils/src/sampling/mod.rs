//! Secure byte sampling helpers.

use rand_core::{CryptoRng, RngCore};

/// Fills `out` with bytes from a cryptographically secure RNG.
pub fn fill_bytes<R>(rng: &mut R, out: &mut [u8])
where
    R: RngCore + CryptoRng,
{
    rng.fill_bytes(out);
}

/// Returns `len` bytes sampled from a cryptographically secure RNG.
pub fn random_bytes<R>(rng: &mut R, len: usize) -> Vec<u8>
where
    R: RngCore + CryptoRng,
{
    let mut out = vec![0u8; len];
    fill_bytes(rng, &mut out);
    out
}

/// Samples bytes from the operating-system CSPRNG.
#[cfg(feature = "std")]
pub fn random_bytes_from_os(len: usize) -> Vec<u8> {
    let mut rng = rand_core::OsRng;
    random_bytes(&mut rng, len)
}
