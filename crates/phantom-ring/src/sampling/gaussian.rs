//! Small discrete Gaussian-like sampler.
//!
//! This is a correctness-oriented placeholder. Production cryptographic
//! sampling must replace this with a constant-time, parameterized sampler.

use rand_core::{CryptoRng, RngCore};

use crate::sampling::uniform::sample_bounded;
use crate::{Poly, Ring};

/// Samples from a centered narrow distribution and represents values modulo q.
pub fn sample_discrete_gaussian<R>(ring: &Ring, rng: &mut R, bound: u64) -> Poly
where
    R: RngCore + CryptoRng,
{
    let width = 2 * bound + 1;
    let mut poly = ring.zero();
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value();
        for coeff in &mut poly.coeffs_mut()[j] {
            let sample = sample_bounded(rng, width) as i128 - bound as i128;
            *coeff = if sample < 0 {
                q - ((-sample) as u64 % q)
            } else {
                sample as u64 % q
            };
        }
    }
    poly
}
