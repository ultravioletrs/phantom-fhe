//! Embedding small centered integers (RLWE ring coefficients: ternary
//! `{-1,0,1}`, or discrete-Gaussian noise bounded to roughly `±32`) as
//! scalars in Ristretto255's own ~2^252 prime field, and recovering them
//! exactly after Shamir reconstruction.

use curve25519_dalek::scalar::Scalar;

use crate::{MultipartyError, Result};

/// Embeds a small signed integer as a scalar: `value` if non-negative,
/// `L - |value|` (the field's own additive inverse of `|value|`) if
/// negative - the standard centered-to-field-element embedding.
///
/// Errors only for `i128::MIN` (whose absolute value has no `i128`
/// representation) - every other `i128` embeds without loss, since the
/// field is far larger than any magnitude this crate's own callers ever
/// pass (RLWE secret coefficients are always small).
pub fn embed_centered(value: i128) -> Result<Scalar> {
    let magnitude = value
        .checked_abs()
        .ok_or(MultipartyError::InvalidParameters(
            "embed_centered: value is i128::MIN, which has no representable absolute value",
        ))?;
    // `magnitude >= 0` by construction (checked_abs never returns negative
    // except for MIN, already rejected above), so this cast is exact.
    let magnitude = magnitude as u128;
    if value >= 0 {
        Ok(Scalar::from(magnitude))
    } else {
        Ok(-Scalar::from(magnitude))
    }
}

/// Recovers a small signed integer from a scalar known to satisfy `|value|
/// <= magnitude_bound` - sound specifically because every value this crate
/// ever calls this on is a Shamir-reconstructed sum of at most a handful of
/// dealers' own tiny contributions, so its true magnitude is always
/// astronomically smaller than the field's own ~2^252 order: there is no
/// boundary-proximity ambiguity a generic "closest representative"
/// comparison would need to resolve (see this module's own doc comment).
///
/// Determines `k`'s sign and magnitude by direct inspection of `value`'s
/// (and `-value`'s) canonical little-endian byte encoding, rather than a
/// search: [`embed_centered`] embeds a non-negative `k` as the literal
/// integer `k`, so if `value`'s own canonical integer fits in the low 128
/// bits (its top 16 bytes are all zero), that integer *is* `k` directly;
/// symmetrically for a negative `k`, `-value` recovers `|k|` the same way,
/// via `Scalar`'s own (already-implemented, already-tested) negation doing
/// the `L - value` subtraction internally rather than this function
/// hand-rolling wide arithmetic. `L` is a ~252-bit prime, so for any nonzero
/// `value`, `value` and `-value` can never *both* fit in 128 bits (their
/// canonical integers sum to exactly `L`, and `2^129 < L`) - no ambiguity
/// between the two branches. This is `O(1)` (a fixed handful of `Scalar`
/// operations and byte comparisons), not `O(magnitude_bound)`: an earlier
/// version of this function walked `k` up from `0` one `Scalar::ONE` at a
/// time, which is a real denial-of-service hazard for any caller (this
/// crate's own or a downstream one) that passes a large `magnitude_bound` -
/// found and fixed after an external report flagged it.
///
/// Errs, rather than silently wrapping, if neither `value` nor `-value` has
/// a magnitude within `magnitude_bound` - the caller's own `magnitude_bound`
/// was too tight, or `value` is not actually a small centered integer at
/// all (a wiring bug, not a value this function should ever guess at).
pub fn recover_centered(value: Scalar, magnitude_bound: i128) -> Result<i128> {
    let bound: u128 = magnitude_bound.try_into().map_err(|_| {
        MultipartyError::InvalidParameters("recover_centered: magnitude_bound must be non-negative")
    })?;

    if let Some(k) = small_magnitude(&value) {
        if k <= bound {
            return Ok(k as i128);
        }
    }
    if let Some(k) = small_magnitude(&-value) {
        if k <= bound {
            return Ok(-(k as i128));
        }
    }
    Err(MultipartyError::InvalidParameters(
        "recover_centered: value outside magnitude bound",
    ))
}

/// Returns `Some(k)` if `scalar`'s canonical little-endian integer
/// representation fits in 128 bits (its top 16 bytes are all zero, i.e.
/// `scalar < 2^128`), giving that integer directly - `None` otherwise.
fn small_magnitude(scalar: &Scalar) -> Option<u128> {
    let bytes = scalar.as_bytes();
    if bytes[16..].iter().any(|&byte| byte != 0) {
        return None;
    }
    Some(u128::from_le_bytes(
        bytes[..16].try_into().expect("slice is exactly 16 bytes"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_and_recover_round_trip_small_values() {
        for v in -32..=32i128 {
            let embedded = embed_centered(v).unwrap();
            assert_eq!(recover_centered(embedded, 32).unwrap(), v);
        }
    }

    #[test]
    fn negative_one_embeds_as_the_field_order_minus_one_not_a_raw_negative() {
        // Exercises the exact subtlety this module's own doc comment flags:
        // `-1` must embed to a canonical field element (the field's own
        // additive inverse), not "negative one" in some other sense, and
        // `recover_centered` must recognize that field element as `-1`
        // again, not as `field_order - 1` (a huge positive number).
        let embedded = embed_centered(-1).unwrap();
        assert_eq!(embedded, -Scalar::ONE);
        assert_eq!(recover_centered(embedded, 1).unwrap(), -1);
    }

    #[test]
    fn recover_centered_rejects_a_value_outside_the_bound() {
        let embedded = embed_centered(50).unwrap();
        assert!(recover_centered(embedded, 32).is_err());
    }

    #[test]
    fn recover_centered_rejects_a_negative_bound() {
        assert!(recover_centered(Scalar::ZERO, -1).is_err());
    }

    #[test]
    fn recover_centered_handles_a_huge_bound_without_a_linear_scan() {
        // Regression test for a real denial-of-service hazard (found via an
        // external report, verified against this file before fixing): the
        // original implementation walked `k` up from `0` one `Scalar::ONE`
        // at a time, so a caller passing a bound like `i128::MAX / 2` would
        // hang for an astronomical number of iterations. This exercises
        // exactly that shape of call and expects it to return immediately.
        let huge_bound = i128::MAX / 2;
        assert_eq!(
            recover_centered(embed_centered(12345).unwrap(), huge_bound).unwrap(),
            12345
        );
        assert_eq!(
            recover_centered(embed_centered(-12345).unwrap(), huge_bound).unwrap(),
            -12345
        );
        // A value with no small representative at all (e.g. a random-looking
        // scalar, not of the form `embed_centered(k)` for any small `k`)
        // must still fail fast rather than scan up to `huge_bound`.
        assert!(recover_centered(
            Scalar::from(u128::MAX) + Scalar::from(u128::MAX),
            huge_bound
        )
        .is_err());
    }

    #[test]
    fn embed_centered_rejects_i128_min() {
        assert!(embed_centered(i128::MIN).is_err());
    }
}
