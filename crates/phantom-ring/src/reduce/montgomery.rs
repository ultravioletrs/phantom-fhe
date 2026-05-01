//! Montgomery reduction placeholder.
//!
//! The initial implementation exposes the shape of a reducer while using
//! widened modular multiplication for correctness.

use super::mul_mod;

/// Montgomery reducer for one modulus.
#[derive(Clone, Copy, Debug)]
pub struct MontgomeryReducer {
    modulus: u64,
}

impl MontgomeryReducer {
    /// Creates a reducer.
    pub const fn new(modulus: u64) -> Self {
        Self { modulus }
    }

    /// Multiplies two residues modulo this reducer's modulus.
    pub fn mul(self, lhs: u64, rhs: u64) -> u64 {
        mul_mod(lhs, rhs, self.modulus)
    }
}
