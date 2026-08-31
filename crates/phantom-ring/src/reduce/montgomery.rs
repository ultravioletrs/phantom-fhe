//! Montgomery reduction.
//!
//! Implements REDC (Montgomery, 1985): for `R = 2^64` and odd `modulus`,
//! precomputes `m' = -modulus^-1 mod R` (via Newton-Raphson iteration on the
//! 2-adic inverse) and `r2 = R^2 mod modulus` (to convert plain residues into
//! Montgomery form, `a -> a*R mod modulus`). `redc(t)` computes `t * R^-1 mod
//! modulus` for `t < modulus * R`, the primitive every other operation here
//! is built from.
//!
//! Current range: moduli below [`MONTGOMERY_MAX_MODULUS`] (`2^63`). `redc`'s
//! `t2 = t + u * modulus` step needs `t2 < 2^128` to fit its `u128`
//! accumulator: with `t < modulus * 2^64` (the precondition) and
//! `u * modulus < 2^64 * modulus`, `t2 < 2 * 2^64 * modulus = 2^65 *
//! modulus`, which stays under `2^128` exactly when `modulus < 2^63` - the
//! bound is derived from that headroom, not chosen arbitrarily. Going past
//! `2^63` would need a genuinely wider (192+ bit) accumulator for this step,
//! which is real follow-up work, not implemented here. Unlike
//! [`super::barrett::BarrettReducer`], which now supports the full 64-bit
//! range via wide multiplication.
//!
//! `mul` round-trips plain inputs through Montgomery form and back on every
//! call (four `redc` calls total), which is correct but not the efficient
//! use of Montgomery arithmetic - real speedups come from keeping a chain of
//! operations in Montgomery form throughout and converting once at each end.
//! `to_montgomery`/`from_montgomery`/`mul_montgomery` expose that lower-level
//! path for callers (e.g. a future NTT butterfly hot path) that can do so.

use super::MONTGOMERY_MAX_MODULUS;
use crate::{Result, RingError};

/// Montgomery reducer for one modulus.
#[derive(Clone, Copy, Debug)]
pub struct MontgomeryReducer {
    modulus: u64,
    /// `-modulus^-1 mod 2^64`.
    m_prime: u64,
    /// `2^128 mod modulus`, i.e. `R^2 mod modulus`.
    r2: u64,
}

impl MontgomeryReducer {
    /// Creates a reducer, rejecting moduli at or above [`MONTGOMERY_MAX_MODULUS`]
    /// or even moduli (Montgomery form requires `modulus` coprime to `R = 2^64`).
    pub fn new(modulus: u64) -> Result<Self> {
        if modulus == 0 || modulus % 2 == 0 || modulus >= MONTGOMERY_MAX_MODULUS {
            return Err(RingError::ModulusTooLargeForReducer {
                modulus,
                max: MONTGOMERY_MAX_MODULUS,
            });
        }
        let m_prime = neg_inv_mod_pow2_64(modulus);
        let r2 = ((1u128 << 64) % modulus as u128) as u64;
        let r2 = ((r2 as u128 * r2 as u128) % modulus as u128) as u64;
        Ok(Self {
            modulus,
            m_prime,
            r2,
        })
    }

    /// REDC: computes `t * R^-1 mod modulus` for `t < modulus * 2^64`.
    fn redc(self, t: u128) -> u64 {
        debug_assert!(
            t < (self.modulus as u128) << 64,
            "MontgomeryReducer::redc precondition violated: t must be < modulus * 2^64"
        );
        let t_lo = t as u64;
        let u = t_lo.wrapping_mul(self.m_prime);
        let t2 = t + u as u128 * self.modulus as u128;
        let result = (t2 >> 64) as u64;
        if result >= self.modulus {
            result - self.modulus
        } else {
            result
        }
    }

    /// Converts a plain residue into Montgomery form (`a * R mod modulus`).
    pub fn to_montgomery(self, a: u64) -> u64 {
        self.redc(a as u128 * self.r2 as u128)
    }

    /// Converts a Montgomery-form residue back to a plain residue.
    pub fn from_montgomery(self, a_mont: u64) -> u64 {
        self.redc(a_mont as u128)
    }

    /// Multiplies two Montgomery-form residues, returning a Montgomery-form result.
    pub fn mul_montgomery(self, lhs_mont: u64, rhs_mont: u64) -> u64 {
        self.redc(lhs_mont as u128 * rhs_mont as u128)
    }

    /// Multiplies two plain residues modulo this reducer's modulus.
    pub fn mul(self, lhs: u64, rhs: u64) -> u64 {
        let lhs_mont = self.to_montgomery(lhs);
        let rhs_mont = self.to_montgomery(rhs);
        self.from_montgomery(self.mul_montgomery(lhs_mont, rhs_mont))
    }
}

/// Computes `-value^-1 mod 2^64` for odd `value`, via Newton-Raphson
/// iteration on the 2-adic inverse (each iteration doubles the number of
/// correct low bits; six iterations take the one correct bit `value` starts
/// with - any odd number is its own inverse mod 2 - to all 64).
fn neg_inv_mod_pow2_64(value: u64) -> u64 {
    let mut x = value;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(value.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

#[cfg(test)]
mod tests {
    use super::neg_inv_mod_pow2_64;

    #[test]
    fn neg_inv_mod_pow2_64_satisfies_m_times_neg_inv_is_minus_one() {
        // m * (-m^-1) == -1 (mod 2^64), i.e. u64::MAX in wrapping arithmetic.
        for m in [1u64, 3, 5, 7, 255, 65535, u32::MAX as u64, u64::MAX] {
            let m = m | 1; // ensure odd
            let neg_inv = neg_inv_mod_pow2_64(m);
            assert_eq!(m.wrapping_mul(neg_inv), u64::MAX, "failed for m = {m}");
        }

        let mut rng_state = 0x2545F4914F6CDD1Du64;
        for _ in 0..1000 {
            // xorshift64* - deterministic, dependency-free source of odd u64s.
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let m = rng_state.wrapping_mul(0x2545F4914F6CDD1D) | 1;
            let neg_inv = neg_inv_mod_pow2_64(m);
            assert_eq!(m.wrapping_mul(neg_inv), u64::MAX, "failed for m = {m}");
        }
    }
}
