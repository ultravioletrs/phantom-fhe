//! Noise/error estimates for real BGV ciphertexts (Workstream 5 item 5).
//!
//! Every function here tracks the same quantity: `e` in a real BGV
//! ciphertext's decryption relation `c0 + c1*s = m + t*e` (`t` = the
//! plaintext modulus) - the *un*-scaled noise term, not the raw ciphertext
//! noise `t*e` itself. [`fresh_secret_key_noise_bound`]/[`fresh_public_key_noise_bound`]
//! are thin re-exports of [`phantom_lattice::noise`]'s own generic RLWE
//! bounds (BGV's real `Encryptor` samples fresh noise identically to plain
//! RLWE - only the `t`-scaling wrapped around it at encryption time is
//! BGV-specific, and these functions track the noise *before* that
//! scaling). [`mul_noise_bound`] and [`relinearize_noise_bound`] are new
//! derivations specific to BGV's own operations; [`noise_budget_bits`]
//! converts an absolute `e` bound into bits of margin against decryption's
//! actual correctness threshold.
//!
//! # `mul_noise_bound`
//!
//! Raw (unrelinearized) multiplication: `(m1+t*e1)*(m2+t*e2) = m1*m2 +
//! t*(m1*e2 + m2*e1 + t*e1*e2)`, so the new `e` term is `m1*e2 + m2*e1 +
//! t*e1*e2` - two [`phantom_lattice::noise::ring_product_bound`]-shaped
//! terms (`m` bounded by `t`, since plaintext residues are `< t`) plus a
//! third scaled by an extra factor of `t` (`t^2*e1*e2` overall, one factor
//! of which is already accounted for by `e_new` itself being an
//! "unscaled-by-`t`" quantity) - genuinely different from
//! [`phantom_lattice::noise::mul_noise_bound`]'s own shape, which has no
//! such extra factor, so this isn't a direct reuse. Verified numerically
//! (Python, 300 randomized trials, direct negacyclic-convolution
//! simulation against the derived bound) before implementing.
//!
//! # `relinearize_noise_bound`
//!
//! `bgv::relinearization`'s classical gadget-decomposition key-switch
//! folds `t`-scaled fresh noise from `levels` key rows into the result:
//! `acc_b + acc_a*s_new = poly*s_old + t*(sum_i digit_i*e_i)` (`digit_i`
//! bounded by the gadget base minus one, `e_i` each row's own fresh
//! [`phantom_lattice::security::fresh_error_bound`]-bounded noise) - the
//! same "digit times fresh row noise, summed over `levels`" shape
//! [`phantom_lattice::noise::external_product_noise_bound`]'s own gadget
//! term uses, but for a *single* gadget block (one decomposition of
//! `poly`, not RGSW's two), so half that formula's factor. This noise adds
//! (triangle inequality) to whatever `e` bound the ciphertext already had
//! before relinearizing. Verified numerically (Python, 200 randomized
//! trials) before implementing.
//!
//! # `noise_budget_bits`
//!
//! Decryption correctness needs `|m + t*e| < q/2` (`q` = the ciphertext
//! modulus product, so decryption's centered-mod-`q` reduction recovers
//! the true integer `m + t*e` without wraparound); bounding `|m| <= t`
//! (plaintext residues are `< t`, a sound if slightly loose choice) gives
//! the sufficient condition `t*(1 + e) < q/2`, i.e. (for any real, useful
//! `e >= 1`) approximately `e < q/(2t)`. In bits: `log2(q) - log2(t) - 1 -
//! log2(e_bound)`, via [`phantom_lattice::noise::noise_budget_bits`] -
//! `q`'s own `log2` is a sum of each modulus's own `log2` rather than
//! `log2` of the literal product, since the product itself routinely
//! doesn't fit in `u64`/`f64` for a realistic multi-modulus ring (see that
//! function's own doc comment).

use phantom_lattice::noise::ring_product_bound;
use phantom_lattice::security::fresh_error_bound;

/// Fresh secret-key encryption noise bound - see the module doc comment.
pub fn fresh_secret_key_noise_bound() -> u64 {
    phantom_lattice::noise::fresh_secret_key_noise_bound()
}

/// Fresh public-key encryption noise bound - see the module doc comment.
pub fn fresh_public_key_noise_bound(degree: usize) -> u64 {
    phantom_lattice::noise::fresh_public_key_noise_bound(degree)
}

/// Noise bound after raw (unrelinearized) multiplication - see the module
/// doc comment for the derivation.
pub fn mul_noise_bound(degree: usize, t: u64, noise_bound: u64) -> u64 {
    2 * ring_product_bound(degree, t, noise_bound)
        + t * ring_product_bound(degree, noise_bound, noise_bound)
}

/// Noise bound after relinearizing with
/// [`super::BgvRelinearizationKey`]/`bgv::relinearization::key_switch`
/// (`levels`/`base_log` from the same [`phantom_lattice::rgsw::GadgetDecompositionParams`]
/// the key was generated with) - see the module doc comment for the
/// derivation.
pub fn relinearize_noise_bound(
    degree: usize,
    levels: usize,
    base_log: u32,
    noise_bound_before: u64,
) -> u64 {
    let digit_bound = (1u64 << base_log) - 1;
    let from_switch = levels as u64 * ring_product_bound(degree, digit_bound, fresh_error_bound());
    noise_bound_before + from_switch
}

/// Bits of margin `noise_bound` leaves before decryption breaks, given
/// `moduli` (the ring's own ciphertext moduli) and the plaintext modulus
/// `t` - see the module doc comment.
pub fn noise_budget_bits(moduli: &[u64], t: u64, noise_bound: u64) -> f64 {
    let q_bits: f64 = moduli.iter().map(|&q| (q as f64).log2()).sum();
    let threshold_bits = q_bits - 1.0 - (t as f64).log2();
    let noise_bits = (noise_bound.max(1) as f64).log2();
    phantom_lattice::noise::noise_budget_bits(threshold_bits, noise_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_bounds_match_the_generic_rlwe_bounds() {
        assert_eq!(
            fresh_secret_key_noise_bound(),
            phantom_lattice::noise::fresh_secret_key_noise_bound()
        );
        assert_eq!(
            fresh_public_key_noise_bound(8),
            phantom_lattice::noise::fresh_public_key_noise_bound(8)
        );
    }

    #[test]
    fn mul_noise_bound_matches_hand_worked_case() {
        // degree=8, t=17, noise_bound=20:
        // 2*ring_product_bound(8,17,20) = 2*8*17*20 = 5440
        // 17*ring_product_bound(8,20,20) = 17*8*400 = 54400
        // total = 59840
        assert_eq!(mul_noise_bound(8, 17, 20), 59840);
    }

    #[test]
    fn mul_noise_bound_grows_with_t_and_noise() {
        let base = mul_noise_bound(8, 17, 20);
        assert!(mul_noise_bound(8, 40, 20) > base);
        assert!(mul_noise_bound(8, 17, 40) > base);
    }

    #[test]
    fn relinearize_noise_bound_matches_hand_worked_case() {
        // degree=8, levels=7, base_log=8, noise_bound_before=59840:
        // digit_bound = 2^8-1 = 255
        // from_switch = 7*ring_product_bound(8,255,20) = 7*8*255*20 = 285600
        // total = 59840 + 285600 = 345440
        assert_eq!(relinearize_noise_bound(8, 7, 8, 59840), 345440);
    }

    #[test]
    fn noise_budget_bits_shrinks_as_noise_grows_and_is_never_negative() {
        let moduli = [1_000_000_000_000_037u64];
        let t = 17;
        let fresh = fresh_secret_key_noise_bound();
        let after_mul = mul_noise_bound(8, t, fresh);
        let fresh_budget = noise_budget_bits(&moduli, t, fresh);
        let mul_budget = noise_budget_bits(&moduli, t, after_mul);
        assert!(mul_budget < fresh_budget);
        assert!(fresh_budget > 0.0);

        // A noise bound comfortably larger than the ciphertext modulus
        // itself leaves no budget at all, not a negative one.
        assert_eq!(noise_budget_bits(&moduli, t, u64::MAX), 0.0);
    }
}
