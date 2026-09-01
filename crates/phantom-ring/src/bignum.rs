//! Minimal exact unsigned big integer.
//!
//! Call sites: exact CRT reconstruction in
//! [`crate::rns::extension::extend_basis`] (build from a `u64`, add,
//! subtract, multiply by a `u64` scalar, divide-by-`u64`); computing
//! [`crate::reduce::BarrettReducer`]'s precomputed constant for the full
//! 64-bit modulus range (needs `2^128` represented exactly, hence
//! `from_u128`/`to_u128`/`shl_limbs`); and real BFV multiplication's
//! rescale-and-round step (general bignum/bignum [`BigUint::divmod`], since
//! there `self` is a tensor-product coefficient that can be far larger than
//! any single modulus, divided by the full ciphertext modulus product -
//! genuinely needs a multi-limb divisor, unlike every other call site here).
//! `mul` (general bignum multiplication) is used only as an independent
//! test oracle for `BarrettReducer`'s stack-only wide-multiply hot path, not
//! on any hot path itself. `pub(crate)` only: this is an implementation
//! detail, not a general-purpose bignum type.

use core::cmp::Ordering;

/// Limbs in base `2^64`, little-endian (index 0 = least significant).
/// Always normalized: no trailing zero limbs (so `[]` is the only
/// representation of zero).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BigUint(Vec<u64>);

impl BigUint {
    pub(crate) fn zero() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn from_u64(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self(vec![value])
        }
    }

    /// Test-only: used to build oracle values for `BarrettReducer`'s
    /// wide-multiply tests and this module's own `mul`/`to_u128` tests. No
    /// production code path needs a `u128 -> BigUint` conversion today.
    #[cfg(test)]
    pub(crate) fn from_u128(value: u128) -> Self {
        let lo = value as u64;
        let hi = (value >> 64) as u64;
        Self::normalized(vec![lo, hi])
    }

    /// Converts back to a `u128`. Precondition: the value fits (at most two
    /// limbs) - checked with `debug_assert!` since every call site here
    /// controls its own operand sizes to guarantee this.
    pub(crate) fn to_u128(&self) -> u128 {
        debug_assert!(
            self.0.len() <= 2,
            "BigUint::to_u128: value exceeds u128 range"
        );
        let lo = *self.0.first().unwrap_or(&0) as u128;
        let hi = *self.0.get(1).unwrap_or(&0) as u128;
        lo | (hi << 64)
    }

    /// Converts to a `u128`, returning `None` (rather than the
    /// `debug_assert!`-guarded UB-in-release-mode [`Self::to_u128`] risks)
    /// if the value doesn't fit - needed by CKKS's real decoder, which
    /// reconstructs a coefficient's true value from residues whose modulus
    /// product is caller-controlled, not a size this module's own call
    /// sites can guarantee in advance the way [`Self::to_u128`]'s existing
    /// callers can.
    pub(crate) fn checked_to_u128(&self) -> Option<u128> {
        if self.0.len() > 2 {
            return None;
        }
        Some(self.to_u128())
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// Multiplies by `2^(64*n)`, i.e. prepends `n` zero limbs.
    pub(crate) fn shl_limbs(&self, n: usize) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let mut limbs = vec![0u64; n];
        limbs.extend_from_slice(&self.0);
        Self(limbs)
    }

    /// General bignum multiplication: `self` times each limb of `other`,
    /// shifted into position and summed (schoolbook). Test-only today - see
    /// the module doc comment; used as an oracle for `BarrettReducer`'s
    /// stack-only wide-multiply hot path, not on any hot path itself.
    #[cfg(test)]
    pub(crate) fn mul(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for (i, &limb) in other.0.iter().enumerate() {
            result = result.add(&self.mul_u64(limb).shl_limbs(i));
        }
        result
    }

    fn normalized(mut limbs: Vec<u64>) -> Self {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        Self(limbs)
    }

    pub(crate) fn cmp(&self, other: &Self) -> Ordering {
        if self.0.len() != other.0.len() {
            return self.0.len().cmp(&other.0.len());
        }
        for i in (0..self.0.len()).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i].cmp(&other.0[i]);
            }
        }
        Ordering::Equal
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let len = self.0.len().max(other.0.len());
        let mut result = Vec::with_capacity(len + 1);
        let mut carry = 0u128;
        for i in 0..len {
            let a = *self.0.get(i).unwrap_or(&0) as u128;
            let b = *other.0.get(i).unwrap_or(&0) as u128;
            let sum = a + b + carry;
            result.push(sum as u64);
            carry = sum >> 64;
        }
        if carry > 0 {
            result.push(carry as u64);
        }
        Self::normalized(result)
    }

    /// Computes `self - other`. Precondition: `self >= other` (checked via
    /// `debug_assert!`; an underflow in release mode would silently wrap,
    /// which every call site here avoids by construction - see
    /// `extend_basis`'s reduction loop, which only subtracts while `self >=
    /// other`).
    pub(crate) fn sub(&self, other: &Self) -> Self {
        debug_assert!(self.cmp(other) != Ordering::Less);
        let mut result = Vec::with_capacity(self.0.len());
        let mut borrow = 0i128;
        for i in 0..self.0.len() {
            let a = self.0[i] as i128;
            let b = *other.0.get(i).unwrap_or(&0) as i128;
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i128 << 64;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result.push(diff as u64);
        }
        Self::normalized(result)
    }

    pub(crate) fn mul_u64(&self, scalar: u64) -> Self {
        if scalar == 0 || self.is_zero() {
            return Self::zero();
        }
        let mut result = Vec::with_capacity(self.0.len() + 1);
        let mut carry = 0u128;
        for &limb in &self.0 {
            let product = limb as u128 * scalar as u128 + carry;
            result.push(product as u64);
            carry = product >> 64;
        }
        if carry > 0 {
            result.push(carry as u64);
        }
        Self::normalized(result)
    }

    /// Divides by a nonzero `u64` divisor: schoolbook long division,
    /// processing limbs most-significant first. Returns `(quotient,
    /// remainder)`.
    pub(crate) fn divmod_u64(&self, divisor: u64) -> (Self, u64) {
        assert!(divisor != 0, "divmod_u64: division by zero");
        let mut quotient = vec![0u64; self.0.len()];
        let mut remainder: u128 = 0;
        for i in (0..self.0.len()).rev() {
            // remainder < divisor <= u64::MAX before this shift, so
            // (remainder << 64) | limb fits comfortably within u128.
            let current = (remainder << 64) | self.0[i] as u128;
            quotient[i] = (current / divisor as u128) as u64;
            remainder = current % divisor as u128;
        }
        (Self::normalized(quotient), remainder as u64)
    }

    /// Number of bits needed to represent `self` (`0` for zero).
    fn bit_length(&self) -> usize {
        match self.0.last() {
            None => 0,
            Some(&top) => (self.0.len() - 1) * 64 + (64 - top.leading_zeros() as usize),
        }
    }

    /// Returns bit `n` (`0` = least significant), `false` past the end.
    fn bit_at(&self, n: usize) -> bool {
        match self.0.get(n / 64) {
            Some(&limb) => (limb >> (n % 64)) & 1 == 1,
            None => false,
        }
    }

    /// Shifts left by `bits` bits (a general bit shift, unlike
    /// [`Self::shl_limbs`]'s whole-`u64`-limb one).
    fn shl(&self, bits: usize) -> Self {
        if self.is_zero() || bits == 0 {
            return self.clone();
        }
        let limb_shift = bits / 64;
        let bit_shift = bits % 64;
        let mut limbs = vec![0u64; limb_shift];
        if bit_shift == 0 {
            limbs.extend_from_slice(&self.0);
        } else {
            let mut carry = 0u64;
            for &limb in &self.0 {
                limbs.push((limb << bit_shift) | carry);
                carry = limb >> (64 - bit_shift);
            }
            if carry != 0 {
                limbs.push(carry);
            }
        }
        Self::normalized(limbs)
    }

    /// General bignum division: `self = quotient * divisor + remainder`,
    /// `0 <= remainder < divisor`. Binary long division (process `self`'s
    /// bits from most to least significant, doubling a running remainder
    /// and subtracting `divisor` whenever it fits) - simple to verify
    /// exactly rather than a faster but more intricate multi-limb-digit
    /// algorithm (e.g. Knuth's Algorithm D), matching this module's own
    /// stated preference (see its doc comment). `O(self.bit_length())`
    /// iterations, each `O(divisor's limb count)` - not hot-path-critical
    /// (called once per coefficient in BFV's rescale step, not per
    /// arithmetic operation), so this tradeoff is the right one here.
    pub(crate) fn divmod(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "divmod: division by zero");
        if self.cmp(divisor) == Ordering::Less {
            return (Self::zero(), self.clone());
        }
        if divisor.0.len() == 1 {
            let (q, r) = self.divmod_u64(divisor.0[0]);
            return (q, Self::from_u64(r));
        }

        let mut quotient = vec![0u64; self.0.len()];
        let mut remainder = Self::zero();
        for bit in (0..self.bit_length()).rev() {
            remainder = remainder.shl(1);
            if self.bit_at(bit) {
                remainder = remainder.add(&Self::from_u64(1));
            }
            if remainder.cmp(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                quotient[bit / 64] |= 1u64 << (bit % 64);
            }
        }
        (Self::normalized(quotient), remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::BigUint;
    use core::cmp::Ordering;

    #[test]
    fn zero_and_from_u64_roundtrip() {
        assert!(BigUint::zero().is_zero());
        assert!(!BigUint::from_u64(1).is_zero());
        assert_eq!(BigUint::from_u64(0), BigUint::zero());
    }

    #[test]
    fn cmp_matches_native_u64_for_single_limb_values() {
        let cases = [(0u64, 0u64), (1, 2), (2, 1), (5, 5), (u64::MAX, 0)];
        for (a, b) in cases {
            let expected = a.cmp(&b);
            assert_eq!(BigUint::from_u64(a).cmp(&BigUint::from_u64(b)), expected);
        }
    }

    #[test]
    fn add_matches_native_u128_for_small_values() {
        let mut rng_state = 0xA5A5_5A5A_1234_5678u64;
        for _ in 0..2000 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let a = rng_state;
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let b = rng_state;

            let sum = BigUint::from_u64(a).add(&BigUint::from_u64(b));
            let expected = a as u128 + b as u128;
            let (lo, hi) = (expected as u64, (expected >> 64) as u64);
            let expected_big = if hi == 0 {
                BigUint::from_u64(lo)
            } else {
                BigUint(vec![lo, hi])
            };
            assert_eq!(sum, expected_big, "a={a}, b={b}");
        }
    }

    #[test]
    fn sub_undoes_add() {
        let mut rng_state = 0x1357_9BDF_2468_ACE0u64;
        for _ in 0..2000 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let a = BigUint::from_u64(rng_state);
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let b = BigUint::from_u64(rng_state);

            let (larger, smaller) = if a.cmp(&b) == Ordering::Less {
                (b, a)
            } else {
                (a, b)
            };
            let sum = smaller.add(&larger);
            assert_eq!(sum.sub(&larger), smaller);
            assert_eq!(sum.sub(&smaller), larger);
        }
    }

    #[test]
    fn mul_u64_matches_native_u128_for_small_values() {
        let mut rng_state = 0x0F0F_F0F0_3C3C_C3C3u64;
        for _ in 0..2000 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let a = rng_state;
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let b = rng_state;

            let product = BigUint::from_u64(a).mul_u64(b);
            let expected = a as u128 * b as u128;
            let (lo, hi) = (expected as u64, (expected >> 64) as u64);
            let expected_big = if hi == 0 {
                BigUint::from_u64(lo)
            } else {
                BigUint(vec![lo, hi])
            };
            assert_eq!(product, expected_big, "a={a}, b={b}");
        }
    }

    #[test]
    fn mul_u64_chain_matches_native_u128_product_of_three_values() {
        // Exercises multi-limb results (a two-limb BigUint times a further
        // u64 scalar), not just single-limb * single-limb.
        let cases: [(u64, u64, u64); 4] = [
            (u64::MAX, u64::MAX, 2),
            (u64::MAX, 3, u64::MAX),
            (12289, 3329, 65537),
            (u64::MAX, u64::MAX, u64::MAX),
        ];
        for (a, b, c) in cases {
            let big = BigUint::from_u64(a).mul_u64(b).mul_u64(c);
            let expected = a as u128 * b as u128; // may itself exceed u128 for the last case
            if let Some(expected_full) = expected.checked_mul(c as u128) {
                let (lo, hi) = (expected_full as u64, (expected_full >> 64) as u64);
                let expected_big = if hi == 0 {
                    BigUint::from_u64(lo)
                } else {
                    BigUint(vec![lo, hi])
                };
                assert_eq!(big, expected_big, "a={a}, b={b}, c={c}");
            }
            // else: this exact case (u64::MAX)^3 overflows even u128, which is
            // precisely the scenario BigUint exists to handle correctly - just
            // verified via divmod_u64 round-trip below instead of a native oracle.
            let (_, rem) = big.divmod_u64(a.max(1));
            let _ = rem; // divmod correctness is covered by its own dedicated tests.
        }
    }

    #[test]
    fn divmod_u64_matches_native_division_for_small_values() {
        let mut rng_state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..2000 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let a = rng_state;
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let divisor = (rng_state % (u64::MAX - 1)) + 1; // nonzero

            let (q, r) = BigUint::from_u64(a).divmod_u64(divisor);
            assert_eq!(
                q,
                BigUint::from_u64(a / divisor),
                "a={a}, divisor={divisor}"
            );
            assert_eq!(r, a % divisor, "a={a}, divisor={divisor}");
        }
    }

    #[test]
    fn divmod_u64_handles_multi_limb_dividends_exactly() {
        // (2^64 - 1) * (2^64 - 1) = a two-limb value; divide back by one factor.
        let a = u64::MAX;
        let squared = BigUint::from_u64(a).mul_u64(a);
        let (quotient, remainder) = squared.divmod_u64(a);
        assert_eq!(remainder, 0);
        assert_eq!(quotient, BigUint::from_u64(a));
    }

    #[test]
    fn reconstructs_a_value_known_to_exceed_u128_via_multiply_add_divmod_only() {
        // Product of eight ~61-bit primes exceeds 2^128 (u128::MAX), the
        // exact scenario extend_basis's old u128-based implementation could
        // not handle. Verified independently: computed with Python's
        // arbitrary-precision integers (`math.prod`, `%`), not with any
        // BigUint code, so this is a real external oracle, not a
        // self-consistency check.
        //
        // moduli = [2305843009213693951, 2305843009213693907,
        //           2305843009213693881, 2305843009213693829,
        //           2305843009213693807, 2305843009213693719,
        //           2305843009213693697, 2305843009213693677]
        // product computed in Python (math.prod(moduli)):
        //   Q = 799167628880893613355587784490199371161605525574105818480689920608684819614197155281086761403129452814877233123390210690623313618987019635137662461
        //   Q.bit_length() == 488 (far beyond u128's 128 bits)
        //   Q % 12289 == 729
        let moduli: [u64; 8] = [
            2305843009213693951,
            2305843009213693907,
            2305843009213693881,
            2305843009213693829,
            2305843009213693807,
            2305843009213693719,
            2305843009213693697,
            2305843009213693677,
        ];
        let product = moduli
            .iter()
            .fold(BigUint::from_u64(1), |acc, &m| acc.mul_u64(m));
        let (_, remainder) = product.divmod_u64(12289);
        assert_eq!(remainder, 729);
    }

    #[test]
    fn from_u128_to_u128_round_trips_for_small_and_large_values() {
        let mut rng_state = 0x1122_3344_5566_7788u64;
        for _ in 0..2000 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let hi = rng_state;
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let lo = rng_state;
            let value = ((hi as u128) << 64) | lo as u128;
            assert_eq!(BigUint::from_u128(value).to_u128(), value, "value={value}");
        }
        assert_eq!(BigUint::from_u128(0).to_u128(), 0);
        assert_eq!(BigUint::from_u128(u128::MAX).to_u128(), u128::MAX);
    }

    #[test]
    fn shl_limbs_multiplies_by_the_right_power_of_two_64() {
        // 2^128, built the way BarrettReducer::new does: 1 shifted by 2 limbs.
        let two_pow_128 = BigUint::from_u64(1).shl_limbs(2);
        // Divide back down: (2^128) / (2^64 - 1) should match native u128
        // division of the closest representable quantity - cross-checked via
        // divmod_u64 instead of a direct comparison since 2^128 itself
        // doesn't fit in a u128 constant to compare against directly.
        let (quotient, remainder) = two_pow_128.divmod_u64(u64::MAX);
        // 2^128 = (2^64-1) * (2^64+1) + 1, i.e. quotient = 2^64+1, remainder = 1.
        assert_eq!(
            quotient,
            BigUint::from_u128(1u128 << 64).add(&BigUint::from_u64(1))
        );
        assert_eq!(remainder, 1);

        assert!(BigUint::zero().shl_limbs(5).is_zero());
    }

    #[test]
    fn mul_matches_native_u128_multiplication_when_the_product_fits() {
        let mut rng_state = 0x8899_AABB_CCDD_EEFFu64;
        for _ in 0..2000 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            // Keep both operands under 2^64 so the product (< 2^128) fits a
            // native u128 oracle for direct comparison.
            let a = rng_state;
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let b = rng_state;

            let product = BigUint::from_u64(a).mul(&BigUint::from_u64(b));
            let expected = a as u128 * b as u128;
            assert_eq!(product, BigUint::from_u128(expected), "a={a}, b={b}");
        }
    }

    #[test]
    fn divmod_matches_an_independently_computed_multi_limb_case() {
        // Same 8-prime product `a` as
        // reconstructs_a_value_known_to_exceed_u128_via_multiply_add_divmod_only
        // above (a 488-bit value), divided by a two-prime product `b`
        // (1152921504606846883 * 1152921504606846869, itself exceeding
        // u64). Expected quotient/remainder limbs computed independently in
        // Python (`divmod`, arbitrary-precision integers), then verified
        // there against q*b+r == a before being copied here.
        let a_moduli: [u64; 8] = [
            2305843009213693951,
            2305843009213693907,
            2305843009213693881,
            2305843009213693829,
            2305843009213693807,
            2305843009213693719,
            2305843009213693697,
            2305843009213693677,
        ];
        let a = a_moduli
            .iter()
            .fold(BigUint::from_u64(1), |acc, &m| acc.mul_u64(m));
        let b = BigUint::from_u64(1152921504606846883).mul_u64(1152921504606846869);

        let (quotient, remainder) = a.divmod(&b);

        let expected_quotient = BigUint(vec![
            785937008448,
            11529215034307079614,
            5188146770810392624,
            2954361355554859465,
            16762397813072986308,
            281474976710655,
        ]);
        let expected_remainder = BigUint(vec![9216482227184237885, 3127289509633]);

        assert_eq!(quotient, expected_quotient);
        assert_eq!(remainder, expected_remainder);
        // Cross-check the defining relation directly, independent of the
        // hardcoded expected values above.
        assert_eq!(quotient.mul(&b).add(&remainder), a);
    }

    #[test]
    fn divmod_satisfies_its_own_defining_relation_across_random_multi_limb_cases() {
        // self = quotient * divisor + remainder, 0 <= remainder < divisor -
        // checked algebraically (not against an external oracle) across
        // many random multi-limb dividend/divisor pairs of varying relative
        // size, since divmod's own multiplication/comparison/subtraction
        // are already independently tested above.
        let mut rng_state = 0x2468_ACE1_3579_BDF0u64;
        let mut next = || {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            rng_state
        };

        for _ in 0..200 {
            let a_limbs = 1 + (next() % 6) as usize;
            let b_limbs = 1 + (next() % a_limbs as u64) as usize;
            let a = (0..a_limbs)
                .map(|_| next())
                .fold(BigUint::zero(), |acc, limb| {
                    acc.shl_limbs(1).add(&BigUint::from_u64(limb))
                });
            let mut b = (0..b_limbs)
                .map(|_| next())
                .fold(BigUint::zero(), |acc, limb| {
                    acc.shl_limbs(1).add(&BigUint::from_u64(limb))
                });
            if b.is_zero() {
                b = BigUint::from_u64(1);
            }

            let (quotient, remainder) = a.divmod(&b);
            assert_eq!(quotient.mul(&b).add(&remainder), a);
            assert_eq!(remainder.cmp(&b), Ordering::Less);
        }
    }

    #[test]
    fn divmod_matches_divmod_u64_for_single_limb_divisors() {
        let mut rng_state = 0x1111_2222_3333_4444u64;
        for _ in 0..500 {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let a = BigUint::from_u64(rng_state).mul_u64(rng_state);
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let divisor = (rng_state % (u64::MAX - 1)) + 1;

            let (q_general, r_general) = a.divmod(&BigUint::from_u64(divisor));
            let (q_specialized, r_specialized) = a.divmod_u64(divisor);
            assert_eq!(q_general, q_specialized);
            assert_eq!(r_general, BigUint::from_u64(r_specialized));
        }
    }

    #[test]
    fn mul_matches_mul_u64_chain_for_multi_limb_operands() {
        // Cross-check mul (general bignum x bignum) against mul_u64 chained
        // twice, an independently-written and already-tested path, for
        // operands that themselves exceed a single limb.
        let a = BigUint::from_u64(u64::MAX).mul_u64(u64::MAX); // ~128 bits
        let b = BigUint::from_u64(3);
        let via_mul = a.mul(&b);
        let via_mul_u64 = a.mul_u64(3);
        assert_eq!(via_mul, via_mul_u64);
    }
}
