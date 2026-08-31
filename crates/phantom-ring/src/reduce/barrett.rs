//! Barrett reduction.
//!
//! Replaces hardware division with a precomputed multiply-and-shift:
//! `mu = floor(2^64 / modulus)` is computed once per modulus, and reducing a
//! value `x < modulus^2` estimates `q = floor(x / modulus)` as
//! `floor(x * mu / 2^64)`, correcting the (at most off-by-two) estimate with
//! up to two conditional subtractions.
//!
//! Current range: moduli below [`FAST_REDUCER_MAX_MODULUS`]. Restricting to
//! this range keeps every intermediate product within `u128` without needing
//! wide (>128-bit) multiplication - `modulus^2 < 2^64` and
//! `modulus^2 * mu < 2^128` both hold throughout. Extending to the full
//! 64-bit modulus range `phantom_ring::Modulus` otherwise allows would need
//! either wide multiplication or the "drop the lowest partial product"
//! technique production Barrett implementations use; that's follow-up work,
//! not yet implemented here.

use super::FAST_REDUCER_MAX_MODULUS;
use crate::{Result, RingError};

/// Barrett reducer for one modulus.
///
/// `reduce` requires its input to be less than `modulus^2` (e.g. the product
/// of two residues already reduced modulo `modulus`, as every call site in
/// this crate produces) - checked with `debug_assert!` rather than at every
/// call, since this type exists specifically for hot-path reduction.
#[derive(Clone, Copy, Debug)]
pub struct BarrettReducer {
    modulus: u64,
    /// `floor(2^64 / modulus)`.
    mu: u64,
}

impl BarrettReducer {
    /// Creates a reducer, rejecting moduli at or above [`FAST_REDUCER_MAX_MODULUS`].
    pub fn new(modulus: u64) -> Result<Self> {
        if modulus == 0 || modulus >= FAST_REDUCER_MAX_MODULUS {
            return Err(RingError::ModulusTooLargeForReducer {
                modulus,
                max: FAST_REDUCER_MAX_MODULUS,
            });
        }
        let mu = ((1u128 << 64) / modulus as u128) as u64;
        Ok(Self { modulus, mu })
    }

    /// Reduces `value` modulo this reducer's modulus.
    ///
    /// Precondition: `value < modulus^2`.
    pub fn reduce(self, value: u128) -> u64 {
        debug_assert!(
            value < self.modulus as u128 * self.modulus as u128,
            "BarrettReducer::reduce precondition violated: value must be < modulus^2"
        );
        // Safe: value < modulus^2 < 2^64 under the precondition above.
        let x = value as u64;
        let q = ((x as u128 * self.mu as u128) >> 64) as u64;
        let mut r = x.wrapping_sub(q.wrapping_mul(self.modulus));
        if r >= self.modulus {
            r -= self.modulus;
        }
        if r >= self.modulus {
            r -= self.modulus;
        }
        r
    }
}
