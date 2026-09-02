//! Negacyclic NTT backend abstraction.

pub mod backend;
pub mod cpu;
pub mod table;

pub use backend::NttBackend;
pub use cpu::CpuNttBackend;
pub use table::NttTable;

use crate::{Result, RingError};

/// Computes the negacyclic forward NTT of `buf` in place against `table`:
/// evaluates the polynomial with coefficients `buf` at the odd powers of
/// `table`'s own `2N`-th root (`buf[j] -> m(psi^(2j+1)) mod table.modulus()`
/// for `j = 0..table.degree()`) - the same transform [`crate::Ring::mul`]'s
/// NTT multiplication path uses internally for a *ciphertext* modulus,
/// exposed standalone here for callers that need the transform itself
/// against an arbitrary NTT-friendly modulus not necessarily tied to any
/// `Ring` - e.g. BGV/BFV SIMD plaintext batching, which needs this over the
/// *plaintext* modulus `t`.
pub fn negacyclic_forward(buf: &mut [u64], table: &NttTable) -> Result<()> {
    if buf.len() != table.degree() {
        return Err(RingError::DimensionMismatch);
    }
    cpu::forward_transform_in_place(buf, table);
    Ok(())
}

/// Computes the negacyclic inverse NTT of `buf` in place against `table` -
/// the exact inverse of [`negacyclic_forward`], recovering coefficients
/// from evaluations at the odd powers of `table`'s own `2N`-th root.
pub fn negacyclic_inverse(buf: &mut [u64], table: &NttTable) -> Result<()> {
    if buf.len() != table.degree() {
        return Err(RingError::DimensionMismatch);
    }
    cpu::inverse_transform_in_place(buf, table);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reduce::pow_mod;
    use crate::Modulus;

    /// Direct, independent-oracle check of `negacyclic_forward`'s own
    /// documented contract (`buf[j] -> m(psi^(2j+1))`) - the pre-existing
    /// NTT tests only check round-trip consistency and equivalence with
    /// `Ring::schoolbook_mul`'s multiplication result, neither of which
    /// pins down this specific "evaluates at odd powers of psi" claim on
    /// its own.
    #[test]
    fn negacyclic_forward_matches_direct_evaluation_at_odd_psi_powers() {
        let degree = 8usize;
        let modulus = Modulus::new(97).unwrap(); // 96 = 2*8*6, NTT-friendly
        let table = NttTable::new(degree, modulus).unwrap();
        let q = modulus.value();
        let psi = table.psi();

        let coeffs: Vec<u64> = vec![3, 1, 4, 1, 5, 9, 2, 6];
        let mut buf = coeffs.clone();
        negacyclic_forward(&mut buf, &table).unwrap();

        for (j, &actual) in buf.iter().enumerate() {
            let exp_base = pow_mod(psi, (2 * j + 1) as u64, q);
            let mut direct = 0u64;
            let mut power = 1u64;
            for &c in &coeffs {
                direct = (direct + c * power) % q;
                power = (power * exp_base) % q;
            }
            assert_eq!(actual, direct, "mismatch at j={j}");
        }

        let mut back = buf.clone();
        negacyclic_inverse(&mut back, &table).unwrap();
        assert_eq!(back, coeffs);
    }

    #[test]
    fn negacyclic_transforms_reject_a_mismatched_buffer_length() {
        let table = NttTable::new(8, Modulus::new(97).unwrap()).unwrap();
        let mut short = vec![0u64; 4];
        assert!(negacyclic_forward(&mut short, &table).is_err());
        assert!(negacyclic_inverse(&mut short, &table).is_err());
    }
}
