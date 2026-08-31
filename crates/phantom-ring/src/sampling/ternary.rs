//! Ternary polynomial sampling.

use rand_core::{CryptoRng, RngCore};

use crate::sampling::uniform::sample_bounded;
use crate::{Poly, Ring};

/// Samples coefficients from `{-1, 0, 1}`, represented modulo each RNS
/// modulus.
///
/// Each *true* ternary value is sampled once per coefficient and then
/// reduced into every RNS component identically - not sampled
/// independently per component. This matters for any ring with more than
/// one modulus: RNS represents a single polynomial redundantly across all
/// moduli, reconstructible via CRT, so every component must be a reduction
/// of the *same* true coefficient value. Independent per-component sampling
/// (an earlier version of this function did exactly that) would produce a
/// secret key whose components don't reconstruct to any single coherent
/// polynomial at all - invisible on the single-modulus rings this crate's
/// tests happened to use so far, but a real correctness break for any
/// genuinely multi-modulus (multi-level) parameter set, e.g. what RNS
/// hybrid key-switching needs.
pub fn sample_ternary<R>(ring: &Ring, rng: &mut R) -> Poly
where
    R: RngCore + CryptoRng,
{
    let degree = ring.degree();
    let choices: Vec<u8> = (0..degree).map(|_| sample_bounded(rng, 3) as u8).collect();

    let mut poly = ring.zero();
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value();
        for (i, coeff) in poly.coeffs_mut()[j].iter_mut().enumerate() {
            *coeff = match choices[i] {
                0 => 0,
                1 => 1,
                _ => q - 1,
            };
        }
    }
    poly
}
