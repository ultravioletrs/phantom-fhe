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
