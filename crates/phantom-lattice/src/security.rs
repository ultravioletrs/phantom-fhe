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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_error_bound_matches_the_documented_sigma_times_tail_cut() {
        assert_eq!(fresh_error_bound(), 20); // ceil(3.2 * 6.0) == ceil(19.2) == 20
    }
}
