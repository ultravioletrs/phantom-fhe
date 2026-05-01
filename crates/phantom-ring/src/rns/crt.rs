//! CRT reconstruction helpers.

use crate::reduce::{inv_mod, mul_mod};
use crate::{Poly, Result, RingError, RnsBasis};

/// Reconstructs one RNS residue vector into a `u128`.
///
/// This debug helper is intended for tests and small parameter sets.
pub fn reconstruct_residue(residues: &[u64], basis: &RnsBasis) -> Result<u128> {
    if residues.len() != basis.moduli().len() {
        return Err(RingError::DimensionMismatch);
    }

    let mut product = 1u128;
    for modulus in basis.moduli() {
        product = product
            .checked_mul(modulus.value() as u128)
            .ok_or(RingError::CrtOverflow)?;
    }

    let mut out = 0u128;
    for (&residue, modulus) in residues.iter().zip(basis.moduli()) {
        let q = modulus.value();
        let partial = product / q as u128;
        let inv = inv_mod((partial % q as u128) as u64, q);
        let term = (residue as u128 * partial * inv as u128) % product;
        out = (out + term) % product;
    }

    Ok(out)
}

/// Reconstructs all coefficients of an RNS polynomial into `u128` values.
pub fn reconstruct_poly(poly: &Poly, basis: &RnsBasis) -> Result<Vec<u128>> {
    if poly.moduli_count() != basis.moduli().len() {
        return Err(RingError::DimensionMismatch);
    }
    let mut out = Vec::with_capacity(poly.degree());
    for i in 0..poly.degree() {
        let residues: Vec<u64> = poly.coeffs().iter().map(|component| component[i]).collect();
        out.push(reconstruct_residue(&residues, basis)?);
    }
    Ok(out)
}

/// Decomposes an integer into residues over `basis`.
pub fn decompose_value(value: u128, basis: &RnsBasis) -> Vec<u64> {
    basis
        .moduli()
        .iter()
        .map(|q| (value % q.value() as u128) as u64)
        .collect()
}

/// Multiplies two residues using the corresponding basis modulus.
pub fn mul_residue(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    mul_mod(lhs, rhs, modulus)
}
