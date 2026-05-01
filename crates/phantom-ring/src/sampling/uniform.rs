//! Uniform polynomial sampling.

use rand_core::{CryptoRng, RngCore};

use crate::{Poly, Ring};

/// Samples a polynomial uniformly modulo every RNS modulus.
pub fn sample_uniform<R>(ring: &Ring, rng: &mut R) -> Poly
where
    R: RngCore + CryptoRng,
{
    let mut poly = ring.zero();
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value();
        for coeff in &mut poly.coeffs_mut()[j] {
            *coeff = sample_bounded(rng, q);
        }
    }
    poly
}

pub(crate) fn sample_bounded<R>(rng: &mut R, bound: u64) -> u64
where
    R: RngCore + CryptoRng,
{
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let value = rng.next_u64();
        if value < zone {
            return value % bound;
        }
    }
}
