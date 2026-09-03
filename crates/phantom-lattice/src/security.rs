//! Literature-grounded security parameter choices (Workstream 4 item 10).
//!
//! Every constant here is the community-standard value used across BFV, BGV,
//! and CKKS implementations and the [homomorphicencryption.org security
//! standard](https://homomorphicencryption.org/standard/) - not a number
//! that happens to make a particular test pass. A parameter set's standard
//! deviation, noise bound, and secret distribution should be traceable back
//! to this module, not chosen ad hoc.

/// Recommended standard deviation for the discrete Gaussian error
/// distribution used in fresh RLWE encryption. `sigma = 3.2` is the value
/// the homomorphicencryption.org standard and the original BFV, BGV, and
/// CKKS papers converge on for a 128-bit-and-above security target; it is
/// also the default `phantom_ring::sampling::sample_discrete_gaussian`'s own
/// doc comment already names as "the homomorphicencryption.org
/// community-standard default error width."
pub const STANDARD_ERROR_STD_DEV: f64 = 3.2;

/// Number of standard deviations the error distribution's support is
/// truncated to. `6` is the same tail cut
/// `phantom_ring::sampling::sample_discrete_gaussian` itself uses
/// internally (its `TAIL_CUT_STD_DEVS`) - the true Gaussian's tail beyond
/// `6*sigma` integrates to about `2e-9`, negligible against any practical
/// number of samples, so no sample from that sampler at
/// [`STANDARD_ERROR_STD_DEV`] ever exceeds [`fresh_error_bound`].
pub const ERROR_TAIL_CUT_STD_DEVS: f64 = 6.0;

/// Recommended secret-key coefficient distribution: ternary, coefficients
/// uniform in `{-1, 0, 1}`. Keeping the secret small bounds how much any
/// single noise term can grow when multiplied against it (see
/// [`crate::noise::ring_product_bound`]), while remaining large enough
/// (`3^N` possibilities for degree `N`) to resist brute-force search - the
/// standard choice across production FHE parameter sets.
pub fn recommended_secret_distribution() -> crate::rlwe::SecretDistribution {
    crate::rlwe::SecretDistribution::Ternary
}

/// Upper bound (absolute value) on any single coefficient of an error term
/// sampled at [`STANDARD_ERROR_STD_DEV`] and truncated to
/// [`ERROR_TAIL_CUT_STD_DEVS`] standard deviations - i.e. this is
/// `ceil(sigma * tail_cut)`, matching exactly how
/// `phantom_ring::sampling::sample_discrete_gaussian` truncates its own
/// support, so a sample from that sampler at this module's recommended
/// sigma is always within this bound.
pub fn fresh_error_bound() -> u64 {
    (STANDARD_ERROR_STD_DEV * ERROR_TAIL_CUT_STD_DEVS).ceil() as u64
}

/// Recommended statistical security parameter (bits) for smudging/noise-
/// flooding error terms in multiparty protocols - see [`smudging_std_dev`].
/// `40` is a standard statistical-security target, deliberately smaller
/// than [`max_secure_total_modulus_bits_128`]'s own 128-bit *computational*
/// target: statistical indistinguishability doesn't need to match RLWE's
/// own hardness margin, and [`smudging_std_dev`]'s exponential noise growth
/// makes a smaller target the practical choice for a usable noise budget.
pub const RECOMMENDED_STATISTICAL_SECURITY_BITS: u32 = 40;

/// Standard deviation for a smudging/noise-flooding error term that
/// statistically hides a signal bounded by `signal_noise_bound`, at
/// `statistical_security_bits` bits of statistical security.
///
/// `sigma_smudge^2 = 2^lambda * sigma_signal^2`, i.e. `sigma_smudge =
/// signal_noise_bound * 2^(statistical_security_bits / 2)` - the same
/// variance-scaling relationship Mouchet, Troncoso-Pastoriza, Bossuat &
/// Hubaux, *"Multiparty Homomorphic Encryption from Ring-Learning-with-
/// Errors"* ([eprint 2020/304](https://eprint.iacr.org/2020/304)), Section
/// IV-E / Appendix A, use for exactly this purpose in a collective
/// key-switching protocol: smudging noise must statistically flood
/// whatever noise a ciphertext already carries, so that a party who can
/// decrypt an individual protocol share learns nothing about the honest
/// contribution beyond negligible advantage. Conservative:
/// `signal_noise_bound` is an already tail-cut *bound*
/// ([`ERROR_TAIL_CUT_STD_DEVS`] wider than a true sigma), used here in
/// place of the signal's own sigma - this only strengthens the hiding,
/// never weakens it.
pub fn smudging_std_dev(signal_noise_bound: u64, statistical_security_bits: u32) -> f64 {
    signal_noise_bound as f64 * 2f64.powf(statistical_security_bits as f64 / 2.0)
}

/// Maximum total ciphertext-modulus bit-length (`sum_i log2(q_i)`) a
/// degree-`degree` ring can use while still meeting the
/// homomorphicencryption.org security standard's 128-bit classical
/// security level for a ternary secret ([`recommended_secret_distribution`]),
/// the same table (indexed by ring degree, in bits) reproduced across
/// production FHE libraries' own parameter defaults (e.g. Microsoft SEAL's
/// `hestdparms.h`). `None` for a degree the table doesn't cover: below its
/// smallest entry (`1024`) or above its largest (`32768`) - every
/// development/test preset this crate's own test suite uses (`degree` `8`
/// to `64`) falls in the "not covered" range below `1024`, which is
/// exactly why `SECURITY.md` describes those presets as not secure -
/// there's no published guidance to check them against, not a table
/// lookup that happens to pass. [`Degree`](phantom_ring::Degree) already
/// enforces power-of-two, so every degree this table *could* apply to is
/// an exact entry - no interpolation needed.
pub fn max_secure_total_modulus_bits_128(degree: usize) -> Option<u32> {
    match degree {
        1024 => Some(27),
        2048 => Some(54),
        4096 => Some(109),
        8192 => Some(218),
        16384 => Some(438),
        32768 => Some(881),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_error_bound_matches_the_documented_sigma_times_tail_cut() {
        assert_eq!(fresh_error_bound(), 20); // ceil(3.2 * 6.0) == ceil(19.2) == 20
    }

    #[test]
    fn max_secure_total_modulus_bits_128_covers_only_the_standard_table_degrees() {
        assert_eq!(max_secure_total_modulus_bits_128(1024), Some(27));
        assert_eq!(max_secure_total_modulus_bits_128(32768), Some(881));
        assert_eq!(max_secure_total_modulus_bits_128(8), None);
        assert_eq!(max_secure_total_modulus_bits_128(512), None);
        assert_eq!(max_secure_total_modulus_bits_128(65536), None);
    }

    #[test]
    fn smudging_std_dev_matches_hand_worked_case() {
        // signal_noise_bound=340 (fresh_public_key_noise_bound(8)),
        // statistical_security_bits=40: 340 * 2^20 = 340 * 1_048_576 =
        // 356_515_840.
        assert_eq!(smudging_std_dev(340, 40), 356_515_840.0);
    }

    #[test]
    fn smudging_std_dev_grows_exponentially_with_the_security_parameter() {
        let low = smudging_std_dev(340, 20);
        let high = smudging_std_dev(340, 40);
        assert_eq!(high / low, 1024.0); // 2^((40-20)/2) = 2^10
    }

    #[test]
    fn max_secure_total_modulus_bits_128_grows_with_degree() {
        let entries = [1024, 2048, 4096, 8192, 16384, 32768];
        let mut previous = 0;
        for degree in entries {
            let bits = max_secure_total_modulus_bits_128(degree).unwrap();
            assert!(bits > previous);
            previous = bits;
        }
    }
}
