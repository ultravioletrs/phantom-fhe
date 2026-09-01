//! Noise growth bounds (Workstream 4 item 2 - initial pass).
//!
//! Sound, worst-case upper bounds on how large an RLWE ciphertext's
//! decryption noise can get after fresh encryption or a homomorphic
//! operation - not tight probabilistic estimates. Real noise growth is
//! typically much smaller than these bounds (random sign cancellation
//! across a ring product's terms means the *average* case grows roughly
//! with `sqrt(degree)`, not `degree`), but a sound bound is what
//! correctness depends on: as long as the true noise never exceeds it, and
//! the bound stays under `modulus / 2`, decryption is guaranteed correct
//! regardless of which specific noise samples happened to be drawn.
//! Tightening these into precise average-case bounds - the harder half of
//! item 2 - remains future work; what's here is the sound foundation it
//! would refine.

use crate::security::fresh_error_bound;

/// Worst-case bound on any single coefficient of a negacyclic ring product
/// `a * b`, given bounds on `a`'s and `b`'s own coefficients and the ring's
/// degree.
///
/// Standard triangle-inequality argument: in `R = Z[X]/(X^degree + 1)`, the
/// coefficient of `X^k` in `a * b` is a signed sum of at most `degree`
/// products `a_i * b_j` (the negacyclic wraparound only changes some terms'
/// signs, not how many terms contribute), each bounded by `bound_a *
/// bound_b` in absolute value. Summing `degree` such terms without any
/// assumption about their signs gives `degree * bound_a * bound_b` - sound,
/// but not tight (it assumes the worst case where every term has the same
/// sign, which essentially never happens for real coefficients).
pub fn ring_product_bound(degree: usize, bound_a: u64, bound_b: u64) -> u64 {
    degree as u64 * bound_a * bound_b
}

/// Worst-case decryption noise bound for a **secret-key** fresh encryption:
/// `c0 = pt - a*s + e`, `c1 = a`, so `c0 + c1*s = pt + e` - the noise is
/// exactly the one sampled error term, no ring products involved.
pub fn fresh_secret_key_noise_bound() -> u64 {
    fresh_error_bound()
}

/// Worst-case decryption noise bound for a **public-key** fresh encryption,
/// given the ring's `degree` and the ternary-secret assumption
/// [`crate::security::recommended_secret_distribution`] recommends (`u`,
/// the fresh encryption randomness, and `s`, the secret, both have
/// coefficients in `{-1, 0, 1}`, i.e. bound `1`).
///
/// Public-key encryption combines three noise-like terms: with `pk = (b,
/// a)` where `b = -(a*s + e_pk)`, `c0 = pt + b*u + e1`, `c1 = a*u + e2`, so
/// `c0 + c1*s = pt + u*(b + a*s) + e1 + e2*s = pt - u*e_pk + e1 + e2*s`.
/// `u*e_pk` and `e2*s` are each ring products of a ternary bound-`1`
/// polynomial against a bound-[`fresh_error_bound`] one
/// ([`ring_product_bound`]); `e1` is a bare error term.
pub fn fresh_public_key_noise_bound(degree: usize) -> u64 {
    let error_bound = fresh_error_bound();
    let u_times_e_pk = ring_product_bound(degree, 1, error_bound);
    let e2_times_s = ring_product_bound(degree, 1, error_bound);
    u_times_e_pk + error_bound + e2_times_s
}

/// Worst-case noise bound on the raw (pre-relinearization) product of two
/// ciphertexts, each with plaintext-coefficient bound `plaintext_bound` and
/// decryption-noise bound `noise_bound`.
///
/// Multiplying `ct_a = (c0_a, c1_a)` encrypting `pt_a` with noise `e_a`
/// against `ct_b` similarly: `(c0_a + c1_a*s) * (c0_b + c1_b*s) = (pt_a +
/// e_a) * (pt_b + e_b) = pt_a*pt_b + pt_a*e_b + pt_b*e_a + e_a*e_b`. The
/// noise relative to the true product `pt_a*pt_b` is the last three terms,
/// each a ring product bounded via [`ring_product_bound`].
pub fn mul_noise_bound(degree: usize, plaintext_bound: u64, noise_bound: u64) -> u64 {
    let pt_times_noise = ring_product_bound(degree, plaintext_bound, noise_bound);
    let noise_times_noise = ring_product_bound(degree, noise_bound, noise_bound);
    2 * pt_times_noise + noise_times_noise
}

/// Worst-case noise bound for a real RGSW `external_product(RGSW(m), ct)`,
/// given the **RGSW-encrypted message `m`'s** coefficient bound
/// `message_bound`, the **input ciphertext `ct`'s** own decryption-noise
/// bound `ct_noise_bound`, and the RGSW ciphertext's *total* gadget
/// decomposition digit count `total_levels` (`= moduli.len() *
/// decomposition_params.levels()` - see
/// `phantom_lattice::rgsw::decomposition`'s own module doc comment for why
/// an RNS gadget decomposition needs one digit block per modulus, not just
/// `levels`) and `base_log`.
///
/// Deriving `m * mu` from `ct = (c0, c1)` (`c0 + c1*s = mu + e_ct`) via
/// `sum_i c0_i * RLWE_s(B^i*G_i*m) + sum_i c1_i * RLWE_s(B^i*G_i*m*s)`
/// (`c0_i`/`c1_i` the gadget digits of `c0`/`c1`) gives decryption noise
/// `m*e_ct + sum_i c0_i*e_i + sum_i c1_i*e'_i`, where `e_i`/`e'_i` are each
/// RGSW row's own fresh secret-key-encryption noise. The first term
/// (`m*e_ct`) is one ring product of `m` against `ct`'s noise
/// ([`ring_product_bound`]); the sum is `2 * total_levels` more ring
/// products, each of a gadget digit (bounded by `2^base_log - 1` regardless
/// of the CRT lift factor baked into the *key material* rather than the
/// digit itself) against a fresh noise term (bounded by
/// [`crate::security::fresh_error_bound`]).
pub fn external_product_noise_bound(
    degree: usize,
    message_bound: u64,
    ct_noise_bound: u64,
    total_levels: usize,
    base_log: u32,
) -> u64 {
    let digit_bound = (1u64 << base_log) - 1;
    let message_term = ring_product_bound(degree, message_bound, ct_noise_bound);
    let gadget_term =
        2 * total_levels as u64 * ring_product_bound(degree, digit_bound, fresh_error_bound());
    message_term + gadget_term
}

/// Bits of margin a noise bound leaves against a correctness `threshold`
/// (the largest noise magnitude decryption can still tolerate before
/// wraparound or rounding gives the wrong answer), both given as `log2` of
/// the underlying value - `threshold_bits - noise_bits`, clamped to `0.0`
/// (no margin, never negative). Kept in log space rather than taking the
/// threshold/noise themselves: a scheme's correctness threshold is
/// typically `ciphertext_modulus / (2 * plaintext_modulus)` or similar,
/// and the modulus product for a realistic multi-modulus ring routinely
/// exceeds what a `u64` or even `f64` can represent exactly - but its
/// `log2` (a sum of each modulus's own `log2`) never does. Each scheme
/// derives its own `threshold_bits`/`noise_bits` from its own correctness
/// condition and calls this shared helper - see
/// `phantom_schemes::bgv::noise`/`bfv::noise`/`ckks::noise` (whose own
/// `precision_bits_from_noise` is this same identity specialized to CKKS's
/// canonical-embedding setting, predating this shared extraction).
pub fn noise_budget_bits(threshold_bits: f64, noise_bits: f64) -> f64 {
    (threshold_bits - noise_bits).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_product_bound_matches_hand_worked_small_cases() {
        assert_eq!(ring_product_bound(8, 1, 20), 160);
        assert_eq!(ring_product_bound(4, 3, 5), 60);
        assert_eq!(ring_product_bound(1, 7, 9), 63);
    }

    #[test]
    fn fresh_secret_key_noise_bound_is_exactly_the_error_bound() {
        assert_eq!(fresh_secret_key_noise_bound(), fresh_error_bound());
    }

    #[test]
    fn fresh_public_key_noise_bound_grows_with_degree() {
        let small = fresh_public_key_noise_bound(4);
        let large = fresh_public_key_noise_bound(64);
        assert!(large > small);
        // Exactly 2*degree*error_bound + error_bound by construction.
        let error_bound = fresh_error_bound();
        assert_eq!(
            fresh_public_key_noise_bound(8),
            2 * 8 * error_bound + error_bound
        );
    }

    #[test]
    fn mul_noise_bound_is_much_larger_than_fresh_noise() {
        let degree = 8;
        let fresh = fresh_public_key_noise_bound(degree);
        let after_mul = mul_noise_bound(degree, 4, fresh);
        assert!(after_mul > fresh);
    }

    #[test]
    fn external_product_noise_bound_matches_hand_worked_case() {
        // degree=4, ct_plaintext_bound=3, ct_noise_bound=20, levels=2, base_log=4:
        // digit_bound = 2^4 - 1 = 15
        // message_term = ring_product_bound(4, 3, 20) = 4*3*20 = 240
        // gadget_term = 2*2*ring_product_bound(4, 15, fresh_error_bound()=20) = 4*(4*15*20) = 4*1200 = 4800
        // total = 240 + 4800 = 5040
        assert_eq!(external_product_noise_bound(4, 3, 20, 2, 4), 5040);
    }

    #[test]
    fn noise_budget_bits_is_the_plain_difference_clamped_at_zero() {
        assert_eq!(noise_budget_bits(30.0, 10.0), 20.0);
        assert_eq!(noise_budget_bits(10.0, 30.0), 0.0);
        assert_eq!(noise_budget_bits(10.0, 10.0), 0.0);
    }
}
