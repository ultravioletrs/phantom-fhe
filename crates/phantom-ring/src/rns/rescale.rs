//! RNS rescaling and modulus dropping helpers.

use crate::{Poly, Result, RingError};

/// Drops the last RNS component.
pub fn drop_last_modulus(poly: &Poly) -> Result<Poly> {
    if poly.moduli_count() <= 1 {
        return Err(RingError::DimensionMismatch);
    }
    let mut coeffs = poly.coeffs().to_vec();
    coeffs.pop();
    Poly::from_coeffs(coeffs)
}
