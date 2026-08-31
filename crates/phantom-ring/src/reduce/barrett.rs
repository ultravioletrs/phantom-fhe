//! Barrett reduction.
//!
//! Replaces hardware division with a precomputed multiply-and-shift:
//! `mu = floor(2^128 / modulus)` is computed once per modulus (exactly, via
//! `BigUint`'s long division), and reducing a value
//! `x < modulus * 2^64` estimates `q = floor(x / modulus)` as `floor(x * mu /
//! 2^128)`, correcting the (at most off-by-two, standard Barrett bound)
//! estimate with up to two conditional subtractions.
//!
//! Supports the full 64-bit modulus range (any `modulus >= 2`), unlike an
//! earlier version of this reducer that used the narrower `mu = floor(2^64 /
//! modulus)` variant and was consequently restricted to moduli that keep
//! every intermediate product within `u128` unassisted. The `x * mu` step
//! here multiplies two values that can each be up to 128 bits, so it needs a
//! real 128x128->256-bit wide multiply - `mul_wide_128` below, implemented
//! as four 64x64->128-bit partial products combined with explicit carry
//! propagation, entirely on the stack (fixed-size `[u64; 4]`, no heap
//! allocation), since this sits on the hot reduction path.

use crate::bignum::BigUint;
use crate::{Result, RingError};

/// Barrett reducer for one modulus, supporting the full 64-bit range
/// (`modulus >= 2`).
///
/// `reduce` requires `value < modulus * 2^64` (e.g. the product of two
/// residues already reduced modulo `modulus`, as every call site in this
/// crate produces, satisfies the tighter `value < modulus^2 < modulus *
/// 2^64`) - checked with `debug_assert!` rather than at every call, since
/// this type exists specifically for hot-path reduction. This bound is what
/// guarantees the estimated quotient `q3` fits a `u64`: `q3 <=
/// floor(value/modulus) < 2^64` exactly when `value < modulus * 2^64` - the
/// `product_hi as u64` truncation in `reduce` below is only sound under that
/// bound. The full `u128` range does not work: for a small modulus and
/// `value` near `u128::MAX`, the true quotient itself needs far more than 64
/// bits, which is not this implementation's regime.
#[derive(Clone, Copy, Debug)]
pub struct BarrettReducer {
    modulus: u64,
    /// `floor(2^128 / modulus)`.
    mu: u128,
}

impl BarrettReducer {
    /// Creates a reducer. Rejects `modulus < 2` (division by `0` is
    /// undefined, and `modulus == 1` would require representing `2^128`
    /// itself, which overflows `mu`'s `u128` storage since every value
    /// reduces to `0` anyway).
    pub fn new(modulus: u64) -> Result<Self> {
        if modulus < 2 {
            return Err(RingError::ModulusTooSmall(modulus));
        }
        // mu = floor(2^128 / modulus), computed exactly via bignum long
        // division rather than approximated - see BigUint::divmod_u64.
        let two_pow_128 = BigUint::from_u64(1).shl_limbs(2);
        let (mu_big, _remainder) = two_pow_128.divmod_u64(modulus);
        let mu = mu_big.to_u128();
        Ok(Self { modulus, mu })
    }

    /// Reduces `value` modulo this reducer's modulus.
    ///
    /// Precondition: `value < modulus * 2^64` (see the type-level doc
    /// comment for the bound's derivation; `value < modulus^2` - the
    /// product of two already-reduced residues - always satisfies it).
    pub fn reduce(self, value: u128) -> u64 {
        debug_assert!(
            value < self.modulus as u128 * (1u128 << 64),
            "BarrettReducer::reduce precondition violated: value must be < modulus * 2^64"
        );

        let (product_hi, _product_lo) = mul_wide_128(value, self.mu);
        // q3 = floor(value * mu / 2^128) = the wide product's high 128 bits.
        // Standard Barrett bound: q3 <= true_quotient = floor(value/modulus)
        // < 2^64 under the precondition above, so q3 always fits a u64
        // despite product_hi being a full u128 in general.
        debug_assert!(product_hi < 1u128 << 64);
        let q3 = product_hi as u64;

        debug_assert!(
            value >= q3 as u128 * self.modulus as u128,
            "Barrett quotient estimate exceeded the true value - implementation bug"
        );
        let mut r = value - q3 as u128 * self.modulus as u128;
        if r >= self.modulus as u128 {
            r -= self.modulus as u128;
        }
        if r >= self.modulus as u128 {
            r -= self.modulus as u128;
        }
        r as u64
    }
}

/// Computes the exact 256-bit product of two 128-bit values, returned as
/// `(high, low)` 128-bit halves. Stack-only (a fixed `[u64; 4]` limb
/// accumulator, no heap allocation): four 64x64->128-bit partial products
/// combined with explicit carry propagation, the same schoolbook technique
/// `BigUint` uses, specialized to a fixed two-limb size so
/// it can live entirely on the stack for `BarrettReducer::reduce`'s hot
/// path.
fn mul_wide_128(a: u128, b: u128) -> (u128, u128) {
    let a_limbs = [a as u64, (a >> 64) as u64];
    let b_limbs = [b as u64, (b >> 64) as u64];
    let mut result = [0u64; 4];

    for (i, &a_limb) in a_limbs.iter().enumerate() {
        let mut carry: u128 = 0;
        for (j, &b_limb) in b_limbs.iter().enumerate() {
            let idx = i + j;
            let sum = a_limb as u128 * b_limb as u128 + result[idx] as u128 + carry;
            result[idx] = sum as u64;
            carry = sum >> 64;
        }
        let mut k = i + b_limbs.len();
        while carry > 0 {
            let sum = result[k] as u128 + carry;
            result[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
    }

    let low = result[0] as u128 | ((result[1] as u128) << 64);
    let high = result[2] as u128 | ((result[3] as u128) << 64);
    (high, low)
}

#[cfg(test)]
mod tests {
    use super::mul_wide_128;
    use crate::bignum::BigUint;

    #[test]
    fn mul_wide_128_matches_native_u128_multiplication_when_the_product_fits() {
        // Keep operands small enough that native u128 multiplication doesn't
        // itself overflow, so it can serve as a direct oracle here.
        let cases: [(u128, u128); 5] = [
            (0, 0),
            (1, 1),
            (u64::MAX as u128, u64::MAX as u128),
            (12289, 3329),
            (1 << 63, 3),
        ];
        for (a, b) in cases {
            let (high, low) = mul_wide_128(a, b);
            assert_eq!(high, 0, "a={a}, b={b}");
            assert_eq!(low, a * b, "a={a}, b={b}");
        }
    }

    #[test]
    fn mul_wide_128_matches_biguint_mul_for_products_exceeding_u128() {
        // BigUint::mul is an independently-written general bignum multiply
        // (schoolbook, heap-based) already verified against native u128
        // arithmetic in bignum.rs's own tests - a genuine second
        // implementation to cross-check mul_wide_128's stack-only carry
        // logic against, not a self-consistency check.
        let mut rng_state = 0x5DEE_CE04_6D80_A04Fu64;
        for _ in 0..2000 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let a_hi = rng_state;
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let a_lo = rng_state;
            let a = ((a_hi as u128) << 64) | a_lo as u128;

            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let b_hi = rng_state;
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let b_lo = rng_state;
            let b = ((b_hi as u128) << 64) | b_lo as u128;

            let (high, low) = mul_wide_128(a, b);
            let expected = BigUint::from_u128(a).mul(&BigUint::from_u128(b));
            let actual = BigUint::from_u128(high)
                .shl_limbs(2)
                .add(&BigUint::from_u128(low));
            assert_eq!(actual, expected, "a={a}, b={b}");
        }
    }

    #[test]
    fn mul_wide_128_matches_a_python_verified_reference_product() {
        // u128::MAX * u128::MAX, computed independently in Python:
        //   a = 2**128 - 1; product = a * a
        //   high = product >> 128  ->  340282366920938463463374607431768211454
        //                           == 2^128 - 2 == u128::MAX - 1
        //   low  = product & (2**128 - 1)  ->  1
        let a = u128::MAX;
        let (high, low) = mul_wide_128(a, a);
        assert_eq!(high, u128::MAX - 1);
        assert_eq!(low, 1);
    }
}
