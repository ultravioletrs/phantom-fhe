//! Ternary polynomial sampling.

use rand_core::{CryptoRng, RngCore};

use crate::sampling::uniform::sample_bounded;
use crate::{Poly, Ring};

/// Samples coefficients from {-1, 0, 1} represented modulo each RNS modulus.
pub fn sample_ternary<R>(ring: &Ring, rng: &mut R) -> Poly
where
    R: RngCore + CryptoRng,
{
    let mut poly = ring.zero();
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value();
        for coeff in &mut poly.coeffs_mut()[j] {
            *coeff = match sample_bounded(rng, 3) {
                0 => 0,
                1 => 1,
                _ => q - 1,
            };
        }
    }
    poly
}
