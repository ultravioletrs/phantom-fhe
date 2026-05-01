//! RNS basis extension.

use crate::rns::crt::reconstruct_poly;
use crate::{Poly, Result, RnsBasis};

/// Extends `poly` from `source` basis into `target` basis.
///
/// This initial implementation reconstructs through `u128` and is intended for
/// small/debug parameter sets. Production basis extension will replace this with
/// full RNS arithmetic.
pub fn extend_basis(poly: &Poly, source: &RnsBasis, target: &RnsBasis) -> Result<Poly> {
    let values = reconstruct_poly(poly, source)?;
    let mut coeffs = vec![vec![0u64; values.len()]; target.moduli().len()];

    for (j, modulus) in target.moduli().iter().enumerate() {
        let q = modulus.value() as u128;
        for (i, value) in values.iter().enumerate() {
            coeffs[j][i] = (value % q) as u64;
        }
    }

    Poly::from_coeffs(coeffs)
}
