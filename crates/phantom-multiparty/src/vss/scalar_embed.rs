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
/// <= magnitude_bound`, via a bounded linear search over `k in
/// 0..=magnitude_bound` testing `k` and `-k` against `value` - sound
/// specifically because every value this crate ever calls this on is a
/// Shamir-reconstructed sum of at most a handful of dealers' own tiny
/// contributions, so its true magnitude is always astronomically smaller
/// than the field's own ~2^252 order: there is no boundary-proximity
/// ambiguity a generic "closest representative" comparison would need to
/// resolve (see this module's own doc comment). Errs, rather than silently
/// wrapping, if no `k` in range matches - the caller's own `magnitude_bound`
/// was too tight, or `value` is not actually a small centered integer at
/// all (a wiring bug, not a value this function should ever guess at).
pub fn recover_centered(value: Scalar, magnitude_bound: i128) -> Result<i128> {
    let bound: u128 = magnitude_bound.try_into().map_err(|_| {
        MultipartyError::InvalidParameters("recover_centered: magnitude_bound must be non-negative")
    })?;
    let mut candidate = Scalar::ZERO;
    let mut k: u128 = 0;
    loop {
        if candidate == value {
            return Ok(k as i128);
        }
        if -candidate == value {
            return Ok(-(k as i128));
        }
        if k == bound {
            return Err(MultipartyError::InvalidParameters(
                "recover_centered: value outside magnitude bound",
            ));
        }
        k += 1;
        candidate += Scalar::ONE;
    }
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
    fn embed_centered_rejects_i128_min() {
        assert!(embed_centered(i128::MIN).is_err());
    }
}
