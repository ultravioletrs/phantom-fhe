//! Noise/error estimates for real BFV ciphertexts (Workstream 5 item 5).
//!
//! Every function here tracks the same quantity: `e` in a real BFV
//! ciphertext's decryption relation `c0 + c1*s = Delta*m + e` (`Delta =
//! floor(Q/t)`) - the raw, unscaled noise term (unlike BGV's, which is
//! itself scaled by `t`). [`fresh_secret_key_noise_bound`]/[`fresh_public_key_noise_bound`]
//! are thin re-exports of [`phantom_lattice::noise`]'s own generic RLWE
//! bounds (BFV's real `Encryptor` samples fresh noise identically to plain
//! RLWE - the `Delta`-scaling is entirely on the *message* side, not the
//! noise). [`mul_noise_bound`] is a new derivation; [`noise_budget_bits`]
//! converts an absolute `e` bound into bits of margin against decryption's
//! actual correctness threshold.
//!
//! # `mul_noise_bound`
//!
//! A naive derivation of [`super::Evaluator::mul_real`]'s noise growth -
//! `(Delta*m1+e1)*(Delta*m2+e2) = Delta^2*m1*m2 + Delta*(m1*e2+m2*e1) +
//! e1*e2`, rescaled by `t/Q` - would suggest reusing
//! [`phantom_lattice::noise::mul_noise_bound`] directly (`Delta*t/Q ≈ 1`
//! cancels the `Delta` factor out of the ratio). That's *unsound*: `Delta =
//! floor(Q/t)`, not `Q/t` exactly, and the gap between them (`r = Q mod t`,
//! `Delta*t = Q - r`) means `rescale_and_round`'s actual `round(true_value *
//! t/Q)` picks up an *additional* noise contribution of its own, roughly
//! `(r/Q) * (m1*m2 convolution)` - proportional to the *message* magnitude,
//! not just the input noise, and *not* captured by
//! [`phantom_lattice::noise::mul_noise_bound`]'s formula at all (caught by
//! numerically verifying against a real `rescale_and_round` simulation
//! before implementing - a first attempt reusing the generic formula
//! directly failed by several orders of magnitude). Bounding each of the
//! rescale identity's terms (`(Delta*r/Q) < 1`, `(1 - r/Q) < 1`, `t/Q <=
//! 1`, plus the round-to-nearest step's own `+1` artifact) gives a sound
//! closed form: `degree*(t + noise_bound)^2 + 1` - verified numerically
//! (Python, 9000 randomized trials across three seeds, against a full
//! `Delta = floor(Q/t)` + real tensor-product + `round(value*t/Q)`
//! simulation) before implementing.
//!
//! # `noise_budget_bits`
//!
//! Decryption correctness needs the raw noise `|e| < Delta/2` (so
//! `round((Delta*m+e)/Delta)` recovers `m` exactly); in bits,
//! `log2(Delta) - 1 - log2(e_bound)`, via
//! [`phantom_lattice::noise::noise_budget_bits`]. `log2(Delta) ≈ log2(Q) -
//! log2(t)` (a sum of each modulus's own `log2`, minus `log2(t)`) avoids
//! ever materializing `Delta` itself, which - like `Q` - routinely doesn't
//! fit in `u64`/`f64` for a realistic multi-modulus ring.
//!
//! # What's deliberately not modeled here
//!
//! No `relinearize_noise_bound`: BFV's real relinearization
//! ([`super::Evaluator::relinearize_real`]) reuses `phantom_lattice::rlwe`'s
//! generic RNS hybrid key-switching unmodified, which doesn't have a
//! formally-derived noise bound of its own yet either (`SECURITY.md`:
//! "key-switching's own noise contribution doesn't yet have a
//! formally-derived bound") - the same gap `ckks::noise`'s own module doc
//! comment documents for CKKS's identical situation, not solved here
//! either.

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
    degree as u64 * (t + noise_bound) * (t + noise_bound) + 1
}

/// Bits of margin `noise_bound` leaves before decryption breaks, given
/// `moduli` (the ring's own ciphertext moduli) and the plaintext modulus
/// `t` - see the module doc comment.
pub fn noise_budget_bits(moduli: &[u64], t: u64, noise_bound: u64) -> f64 {
    let delta_bits: f64 =
        moduli.iter().map(|&q| (q as f64).log2()).sum::<f64>() - (t as f64).log2();
    let threshold_bits = delta_bits - 1.0;
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
        // degree=8, t=17, noise_bound=20: 8*(37^2)+1 = 8*1369+1 = 10953
        assert_eq!(mul_noise_bound(8, 17, 20), 10953);
    }

    #[test]
    fn mul_noise_bound_grows_with_t_and_noise() {
        let base = mul_noise_bound(8, 17, 20);
        assert!(mul_noise_bound(8, 40, 20) > base);
        assert!(mul_noise_bound(8, 17, 40) > base);
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
        assert_eq!(noise_budget_bits(&moduli, t, u64::MAX), 0.0);
    }
}
