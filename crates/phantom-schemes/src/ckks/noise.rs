//! Real, parameter-derived precision-degradation formulas for CKKS.
//!
//! Workstream 5 item 4: `ckks::Evaluator`'s [`super::Precision`] tracking
//! used to call [`super::Precision::degrade`] with flat illustrative
//! constants (`0.25`, `1.0`) regardless of the context's actual ring
//! degree, scale, or the operands' own magnitudes - correct in spirit
//! (operations *do* cost precision) but not tied to any real noise
//! analysis. This module derives sound, worst-case bit-loss formulas from
//! the same triangle-inequality style [`phantom_lattice::noise`] already
//! uses for BGV/BFV/RGSW, adapted to CKKS's canonical-embedding setting,
//! and every `Evaluator` method that used a flat constant now calls one of
//! these instead.
//!
//! # From a coefficient-domain noise bound to bits of slot precision
//!
//! A CKKS ciphertext's decryption noise is a ring element `e` - what
//! matters for the *decoded* value isn't `e`'s coefficient magnitudes
//! directly, but its effect after evaluating at the canonical embedding's
//! roots of unity and dividing by the scale `Delta`:
//!
//! ```text
//! decoded_error_j = (1/Delta) * sum_k zeta^((2j+1)k) * e_k
//! ```
//!
//! Since `|zeta^anything| = 1`, the triangle inequality gives
//! `|decoded_error_j| <= (degree/Delta) * max_k |e_k|` - the same
//! "coefficient sup-norm times degree" expansion factor
//! [`phantom_lattice::noise::ring_product_bound`] already uses for ring
//! products, here applied to the embedding evaluation instead. So a
//! coefficient-domain noise bound `noise_bound` corresponds to
//! `precision_bits = log2(Delta / (degree * noise_bound))` bits of slot
//! precision - [`precision_bits_from_noise`] and its inverse
//! [`noise_bound_from_precision`] convert between the two, letting every
//! formula below work purely in coefficient-domain noise bounds (matching
//! [`phantom_lattice::noise`]'s own domain) while [`super::Evaluator`]
//! only ever sees bits.
//!
//! # Per-operation formulas
//!
//! - [`add_degrade_bits`]: noise bounds add (`noise_after = noise_a +
//!   noise_b`, plain triangle inequality) - used for `add`/`sub`/`add_plain`
//!   (and their real-path counterparts) alike, since the formula doesn't
//!   care whether the second operand is a noisy ciphertext or a
//!   near-noiseless plaintext, just its own implied noise bound. For two
//!   equal-precision, equal-scale operands this comes out to *exactly* 1.0
//!   bit (`noise_after = 2*noise` <=> one bit worse), independent of degree
//!   or scale - verified numerically before implementing.
//! - [`mul_degrade_bits`]: the same shape as
//!   [`phantom_lattice::noise::mul_noise_bound`] (`pt_a*e_b + pt_b*e_a +
//!   e_a*e_b`, each term a [`phantom_lattice::noise::ring_product_bound`]),
//!   but computed in `f64` over the *encoded* plaintext bound `Delta *
//!   message_bound` rather than `phantom_lattice::noise`'s integer
//!   plaintext-modulus bound - used for `mul`/`mul_plain` and their
//!   real-path counterparts. In the realistic noise-much-smaller-than-signal
//!   regime this reduces to approximately `log2(2 * degree * message_bound)`
//!   bits, independent of the absolute scale - verified both by direct
//!   computation and against this closed-form approximation before
//!   implementing.
//! - [`rescale_degrade_bits`]: models [`super::Evaluator::rescale_next`]'s
//!   (and `rescale_next_real`'s) division by a modulus close to the current
//!   scale as `noise_after = noise_bound/dropped + 1.0` - the `+1` matching
//!   [`phantom_ring::rns::rescale::mod_down`]'s own documented
//!   off-by-at-most-one floor-division rounding. When the dropped amount is
//!   close to the *current* scale (the standard RNS-CKKS convention, and
//!   what every rescale in this codebase already assumes), this comes out
//!   close to zero - rescale is designed to be precision-*neutral*, trading
//!   absolute ciphertext size for noise, not spending precision - verified
//!   numerically (a well-matched rescale loses a small fraction of a bit; a
//!   badly-matched one, dropped either far above or below the true scale,
//!   loses much more) before implementing.
//! - [`align_degrade_bits`]: [`super::Evaluator::align_levels`] doesn't
//!   change a ciphertext's *tracked* [`super::Scale`] (both inputs are
//!   assumed already at compatible scale despite differing level - see
//!   that method's own doc comment), so each virtual level dropped is
//!   modeled as [`rescale_degrade_bits`] with `scale_after == scale_before`
//!   (an implied `dropped` factor of `1.0`, leaving only the constant `+1`
//!   floor-rounding artifact to pay for) - chained level-by-level so each
//!   step sees the previous step's already-degraded precision. This
//!   replaces the previous flat "1 bit per level" with a per-level cost
//!   that shrinks as the ring's precision headroom grows, verified
//!   numerically to be monotonically increasing with diminishing marginal
//!   cost, always non-negative, and bounded.
//!
//! # What's deliberately not modeled here
//!
//! `mul`/`mul_real` with an evaluation/relinearization key still uses the
//! *raw* [`mul_degrade_bits`] regardless of whether a key is given -
//! relinearization's own key-switching noise contribution isn't included,
//! since `phantom_lattice::rlwe`'s hybrid key-switching doesn't have a
//! formally-derived noise bound of its own yet either (see `SECURITY.md`:
//! "key-switching's own noise contribution doesn't yet have a
//! formally-derived bound"). The same gap means [`super::Evaluator::rotate_slots`]/[`conjugate`](super::Evaluator::conjugate)
//! (each structurally one Galois automorphism - noise-neutral, a pure
//! coefficient permutation with sign flips - plus one key-switch back to
//! the original secret key) are left at a `0.0`-bit degrade rather than an
//! invented number: the automorphism itself costs nothing, and the
//! key-switch's own contribution is the same not-yet-derived gap as
//! relinearization's, so claiming a specific number for it here would be
//! no more principled than the flat constant this module replaces.
//! Real per-ciphertext noise *tracking* (an actual bound carried on
//! [`super::Ciphertext`], checked against a safety threshold) is also out
//! of scope - this module only makes the existing [`super::Precision`]
//! *estimate* real ring/scale parameters can plug into, not a new
//! ciphertext field.

/// Coefficient-domain-to-embedding-domain expansion factor: an embedding
/// evaluation and a ring product both sum `degree` unit-magnitude terms
/// against a coefficient-domain bound, so both use the same `degree`
/// factor - see the module doc comment.
fn expansion_factor(degree: usize) -> f64 {
    degree as f64
}

/// Converts a coefficient-domain noise bound into bits of canonical
/// embedding slot precision, relative to `scale`. Inverse of
/// [`noise_bound_from_precision`]. Clamped to `0.0` (never negative - a
/// negative value would mean the noise already exceeds the scale, i.e. no
/// precision at all).
pub fn precision_bits_from_noise(scale: f64, degree: usize, noise_bound: f64) -> f64 {
    if noise_bound <= 0.0 || scale <= 0.0 {
        return 0.0;
    }
    (scale / (expansion_factor(degree) * noise_bound))
        .log2()
        .max(0.0)
}

/// The coefficient-domain noise bound implied by a tracked
/// [`super::Precision`] value at a given `scale` - inverse of
/// [`precision_bits_from_noise`]. Needed because [`super::Ciphertext`]
/// tracks bits of precision, not an absolute noise bound, but every
/// formula in this module needs to combine actual noise bounds (matching
/// [`phantom_lattice::noise`]'s own domain) before converting back.
pub fn noise_bound_from_precision(precision_bits: f64, scale: f64, degree: usize) -> f64 {
    scale / (expansion_factor(degree) * 2f64.powf(precision_bits))
}

/// Bits of precision lost by adding two operands (ciphertext+ciphertext or
/// ciphertext+plaintext) with the given scales/precisions - see the module
/// doc comment.
pub fn add_degrade_bits(
    degree: usize,
    scale_a: f64,
    precision_a: f64,
    scale_b: f64,
    precision_b: f64,
) -> f64 {
    let noise_a = noise_bound_from_precision(precision_a, scale_a, degree);
    let noise_b = noise_bound_from_precision(precision_b, scale_b, degree);
    let noise_after = noise_a + noise_b;
    let bits_after = precision_bits_from_noise(scale_a, degree, noise_after);
    (precision_a.min(precision_b) - bits_after).max(0.0)
}

/// Bits of precision lost by raw-multiplying two operands
/// (ciphertext*ciphertext or ciphertext*plaintext), each with its own
/// scale, precision, and slot-magnitude bound - see the module doc
/// comment. The output scale is assumed to be `scale_a * scale_b`, matching
/// [`super::Evaluator::mul`]/[`mul_plain`](super::Evaluator::mul_plain)'s
/// own scale bookkeeping.
pub fn mul_degrade_bits(
    degree: usize,
    scale_a: f64,
    precision_a: f64,
    message_bound_a: f64,
    scale_b: f64,
    precision_b: f64,
    message_bound_b: f64,
) -> f64 {
    let noise_a = noise_bound_from_precision(precision_a, scale_a, degree);
    let noise_b = noise_bound_from_precision(precision_b, scale_b, degree);
    let plaintext_bound_a = scale_a * message_bound_a;
    let plaintext_bound_b = scale_b * message_bound_b;
    let n = expansion_factor(degree);
    let cross_a = n * plaintext_bound_a * noise_b;
    let cross_b = n * plaintext_bound_b * noise_a;
    let noise_noise = n * noise_a * noise_b;
    let noise_after = cross_a + cross_b + noise_noise;
    let bits_after = precision_bits_from_noise(scale_a * scale_b, degree, noise_after);
    (precision_a.min(precision_b) - bits_after).max(0.0)
}

/// Bits of precision lost by rescaling from `scale_before` to
/// `scale_after` (dropping a modulus of implied size `scale_before /
/// scale_after`) - see the module doc comment. Close to `0.0` when
/// `scale_after` is close to the current default scale (the standard
/// convention every rescale in this codebase already follows); large when
/// the dropped amount is badly mismatched to the current scale.
pub fn rescale_degrade_bits(
    degree: usize,
    scale_before: f64,
    precision_bits: f64,
    scale_after: f64,
) -> f64 {
    if scale_after <= 0.0 {
        return precision_bits.max(0.0);
    }
    let dropped = scale_before / scale_after;
    let noise = noise_bound_from_precision(precision_bits, scale_before, degree);
    let noise_after = noise / dropped + 1.0;
    let bits_after = precision_bits_from_noise(scale_after, degree, noise_after);
    (precision_bits - bits_after).max(0.0)
}

/// Bits of precision lost aligning a ciphertext down by `levels` virtual
/// rescales without changing its tracked scale - see the module doc
/// comment for why [`super::Evaluator::align_levels`] doesn't change
/// scale, and why this chains [`rescale_degrade_bits`] with
/// `scale_after == scale_before` rather than calling it once.
pub fn align_degrade_bits(degree: usize, scale: f64, precision_bits: f64, levels: usize) -> f64 {
    let mut precision = precision_bits;
    let mut total = 0.0;
    for _ in 0..levels {
        let step = rescale_degrade_bits(degree, scale, precision, scale);
        total += step;
        precision -= step;
    }
    total
}

/// Bits of precision a freshly-encrypted ciphertext starts at, given `scale`
/// and `degree` - used by [`super::Encryptor::encrypt`] (transparent),
/// which previously passed the plaintext's own encode-only precision
/// (`log2(scale)`, no RLWE noise at all) straight through unchanged. That
/// omission wasn't just an isolated gap: every formula in this module
/// works by inverting a tracked `Precision` value back into an implied
/// noise bound ([`noise_bound_from_precision`]) and combining it with
/// *real* noise contributions (each on the order of
/// [`phantom_lattice::security::fresh_error_bound`], tens of units) - fed
/// a `log2(scale)` starting point instead, the implied noise bound comes
/// out to a physically meaningless `1/degree` (a fraction of a single
/// unit), making even a well-matched rescale's small constant rounding
/// artifact look enormous by comparison (caught by
/// [`align_degrade_bits`]'s own test unexpectedly returning several bits
/// for a realistically-scaled ring before this was added). Uses
/// [`phantom_lattice::noise::fresh_public_key_noise_bound`] (the larger of
/// the two fresh-noise bounds, since the transparent scaffold's `Encryptor`
/// doesn't currently distinguish which mode it was constructed with - see
/// that type's own doc comment) as a sound, if not perfectly tight, single
/// starting point.
pub fn fresh_precision_bits(degree: usize, scale: f64) -> f64 {
    let noise_bound = phantom_lattice::noise::fresh_public_key_noise_bound(degree) as f64;
    precision_bits_from_noise(scale, degree, noise_bound)
}

/// Slot-magnitude bound assumed for **real** ciphertexts' precision
/// estimates, where (unlike the transparent scaffold's `slots()`) the
/// actual encrypted magnitude isn't known. `1.0` matches the standard CKKS
/// convention of normalizing inputs to roughly unit magnitude before
/// encoding - if callers encode much larger values, the true precision
/// loss from multiplication will exceed this estimate. The transparent
/// scaffold's own `mul`/`mul_plain` don't need this assumption at all,
/// since they read the real magnitude straight from `slots()`.
pub const ASSUMED_REAL_MESSAGE_BOUND: f64 = 1.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_and_noise_bound_round_trip() {
        for &(scale_bits, degree, noise_log2) in &[
            (10.0, 4usize, -5.0),
            (30.0, 8, 3.0),
            (60.0, 16, 20.0),
            (40.0, 1024, -1.0),
        ] {
            let scale = 2f64.powf(scale_bits);
            let noise_bound = 2f64.powf(noise_log2);
            let bits = precision_bits_from_noise(scale, degree, noise_bound);
            if bits > 0.0 {
                let recovered = noise_bound_from_precision(bits, scale, degree);
                let relative_error = (recovered - noise_bound).abs() / noise_bound;
                assert!(relative_error < 1e-9, "relative_error={relative_error}");
            }
        }
    }

    #[test]
    fn add_degrade_bits_is_exactly_one_bit_for_equal_precision_equal_scale_operands() {
        let degrade = add_degrade_bits(8, 2f64.powi(30), 25.0, 2f64.powi(30), 25.0);
        assert!((degrade - 1.0).abs() < 1e-9, "degrade={degrade}");
    }

    #[test]
    fn add_degrade_bits_is_small_when_one_operand_has_much_less_noise() {
        // A near-noiseless plaintext (very high tracked precision) added to
        // a much noisier ciphertext should cost far less than the full 1
        // bit the symmetric ciphertext+ciphertext case costs.
        let ciphertext_precision = 20.0;
        let plaintext_precision = 45.0;
        let scale = 2f64.powi(30);
        let degrade = add_degrade_bits(8, scale, ciphertext_precision, scale, plaintext_precision);
        assert!(degrade < 0.1, "degrade={degrade}");
    }

    #[test]
    fn mul_degrade_bits_matches_the_dominant_term_approximation_across_scales() {
        // In the noise-much-smaller-than-signal regime, mul_degrade_bits
        // should be close to log2(2*degree*message_bound), independent of
        // the absolute scale - verified numerically in Python before
        // implementing (see the module doc comment).
        let degree = 8;
        let message_bound = 3.0;
        let approx = (2.0 * degree as f64 * message_bound).log2();
        for scale_bits in [20, 30, 40, 50] {
            let scale = 2f64.powi(scale_bits);
            let precision = scale_bits as f64;
            let degrade = mul_degrade_bits(
                degree,
                scale,
                precision,
                message_bound,
                scale,
                precision,
                message_bound,
            );
            assert!(
                (degrade - approx).abs() < 0.01,
                "scale_bits={scale_bits} degrade={degrade} approx={approx}"
            );
        }
    }

    #[test]
    fn mul_degrade_bits_grows_with_message_bound() {
        let degree = 8;
        let scale = 2f64.powi(30);
        let precision = 30.0;
        let small = mul_degrade_bits(degree, scale, precision, 1.0, scale, precision, 1.0);
        let large = mul_degrade_bits(degree, scale, precision, 1000.0, scale, precision, 1000.0);
        assert!(large > small);
    }

    #[test]
    fn rescale_degrade_bits_is_small_when_dropped_amount_matches_the_scale() {
        let degree = 8;
        let scale_before = 2f64.powi(60);
        let precision = 24.4;
        let scale_after = 2f64.powi(30);
        let degrade = rescale_degrade_bits(degree, scale_before, precision, scale_after);
        assert!(degrade < 0.5, "degrade={degrade}");
    }

    #[test]
    fn rescale_degrade_bits_grows_as_the_dropped_amount_overshoots_the_scale() {
        let degree = 8;
        let scale_before = 2f64.powi(60);
        let precision = 24.4;
        let well_matched = rescale_degrade_bits(degree, scale_before, precision, 2f64.powi(30));
        let overshot = rescale_degrade_bits(degree, scale_before, precision, 2f64.powi(10));
        assert!(overshot > well_matched);
    }

    #[test]
    fn fresh_precision_bits_is_well_below_log2_scale() {
        // log2(scale) alone (the old plaintext-precision-passthrough
        // behavior) ignores real RLWE noise entirely - the real formula
        // should be meaningfully smaller.
        let degree = 8;
        let scale = 2f64.powi(30);
        let fresh = fresh_precision_bits(degree, scale);
        assert!(fresh < scale.log2() - 5.0, "fresh={fresh}");
        assert!(fresh > 0.0);
    }

    #[test]
    fn align_degrade_bits_is_monotonic_with_diminishing_marginal_cost_and_never_negative() {
        let degree = 8;
        let scale = 2f64.powi(30);
        let precision = 25.0;
        let mut previous_total = 0.0;
        let mut previous_step = f64::INFINITY;
        for levels in 1..=10 {
            let total = align_degrade_bits(degree, scale, precision, levels);
            assert!(total >= previous_total);
            let step = total - previous_total;
            assert!(
                step <= previous_step + 1e-9,
                "step={step} previous_step={previous_step}"
            );
            previous_total = total;
            previous_step = step;
        }
        assert!(align_degrade_bits(degree, scale, precision, 0) == 0.0);
    }
}
