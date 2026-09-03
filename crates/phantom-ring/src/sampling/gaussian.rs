//! Discrete Gaussian polynomial sampling.
//!
//! Each coefficient is drawn from a discrete Gaussian distribution via a
//! precomputed cumulative distribution table (CDT) over a truncated support,
//! the standard approach reference FHE implementations start from before
//! hardening to constant time.
//!
//! **Not constant-time**: `DiscreteGaussianTable::sample` returns as soon as
//! it finds the cumulative-probability entry the drawn value falls under, so
//! execution time depends on which value gets sampled. A side-channel-hardened
//! deployment needs every table entry touched unconditionally (or a proper
//! Knuth-Yao/Ziggurat construction) - a deliberately scoped, explicitly
//! flagged follow-up, not silently assumed away. This is nonetheless a real
//! discrete Gaussian, replacing the previous placeholder that sampled
//! uniformly over `[-bound, bound]` (not a Gaussian shape at all).

use rand_core::{CryptoRng, RngCore};

use crate::{Poly, Ring};

/// Number of standard deviations the truncated support extends to in each
/// direction. The true Gaussian's tail beyond `6*sigma` integrates to about
/// `2e-9` total probability mass (split across both directions) - negligible
/// against any practical sample count, while keeping the table small.
const TAIL_CUT_STD_DEVS: f64 = 6.0;

/// Precomputed cumulative distribution table for a discrete Gaussian with
/// standard deviation `sigma`, truncated to the integers in `[-tau, tau]`.
struct DiscreteGaussianTable {
    tau: i64,
    /// `cumulative[i]` is the probability of drawing a value `<= -tau + i`.
    /// Monotonically increasing; the last entry is forced to exactly `1.0`
    /// (see `new`), so `sample` always terminates.
    cumulative: Vec<f64>,
}

impl DiscreteGaussianTable {
    fn new(sigma: f64) -> Self {
        debug_assert!(sigma > 0.0 && sigma.is_finite());
        let tau = (TAIL_CUT_STD_DEVS * sigma).ceil() as i64;
        let width = (2 * tau + 1) as usize;

        let weights: Vec<f64> = (0..width)
            .map(|i| {
                let x = (i as i64 - tau) as f64;
                (-x * x / (2.0 * sigma * sigma)).exp()
            })
            .collect();
        let total: f64 = weights.iter().sum();

        let mut cumulative = Vec::with_capacity(width);
        let mut running = 0.0;
        for &w in &weights {
            running += w;
            cumulative.push(running / total);
        }
        // Floating-point summation can land the running total a few ULPs
        // short of 1.0, which would otherwise make the largest support value
        // (`tau`) technically unreachable by any u < 1.0. Force it exact.
        if let Some(last) = cumulative.last_mut() {
            *last = 1.0;
        }

        Self { tau, cumulative }
    }

    fn sample<R: RngCore>(&self, rng: &mut R) -> i64 {
        // next_u64() gives ~2^-64 resolution, far finer than the table's own
        // truncation error at TAIL_CUT_STD_DEVS - not the bottleneck here.
        let u = (rng.next_u64() as f64) / (u64::MAX as f64 + 1.0);
        for (i, &c) in self.cumulative.iter().enumerate() {
            if u < c {
                return i as i64 - self.tau;
            }
        }
        // Unreachable: cumulative's last entry is exactly 1.0 and u < 1.0
        // always holds, so the loop above always returns first. Kept as a
        // safe fallback (matching the table's own bound) rather than an
        // unwrap/panic on a branch that should never run.
        self.tau
    }
}

/// Samples a polynomial with coefficients drawn from a discrete Gaussian
/// distribution of standard deviation `sigma`, represented modulo each RNS
/// modulus (negative values wrap to `modulus - |value|`).
///
/// `sigma` is the actual standard deviation of the sampled distribution, not
/// a uniform-range bound. A typical FHE noise standard deviation is
/// `sigma ~= 3.2`, the homomorphicencryption.org community-standard default
/// error width.
///
/// Each *true* error value is drawn once per coefficient and then reduced
/// into every RNS component identically - not sampled independently per
/// component. See [`crate::sampling::sample_ternary`]'s doc comment for why
/// this matters for any ring with more than one modulus (the same
/// CRT-coherence requirement applies to error terms as to secret keys).
pub fn sample_discrete_gaussian<R>(ring: &Ring, rng: &mut R, sigma: f64) -> Poly
where
    R: RngCore + CryptoRng,
{
    let table = DiscreteGaussianTable::new(sigma);
    let degree = ring.degree();
    let samples: Vec<i64> = (0..degree).map(|_| table.sample(rng)).collect();

    let mut poly = ring.zero();
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value();
        for (i, coeff) in poly.coeffs_mut()[j].iter_mut().enumerate() {
            let sample = samples[i];
            *coeff = if sample < 0 {
                q - ((-sample) as u64 % q)
            } else {
                sample as u64 % q
            };
        }
    }
    poly
}

/// Samples a polynomial with coefficients drawn from a discrete Gaussian of
/// standard deviation `sigma`, for `sigma` far too large for
/// [`sample_discrete_gaussian`]'s own approach to handle: its underlying
/// cumulative-distribution table allocates `O(sigma)` memory, fine at
/// ordinary encryption-noise scale (`sigma ~= 3.2`) but catastrophic at
/// smudging/noise-flooding scale (`sigma` in the hundreds of millions or
/// more, needed to statistically hide a multiparty protocol share - a table
/// that wide would need tens of gigabytes). Uses a Box-Muller transform instead: two
/// independent uniform floats in `(0, 1]` become one standard-normal sample,
/// scaled by `sigma` and rounded to the nearest integer - `O(1)` per
/// coefficient, no table, no truncation (unlike the CDT table's own
/// artificial 6-sigma cutoff, arguably a closer match to a true Gaussian).
/// The rounding-to-nearest-integer discretization error is utterly
/// negligible at this scale, a standard large-sigma discrete-Gaussian
/// approximation.
///
/// Same per-coefficient/RNS-reduction convention as
/// [`sample_discrete_gaussian`] (see that function's own doc comment): one
/// true error value per coefficient, reduced identically into every RNS
/// component.
pub fn sample_smudging_gaussian<R>(ring: &Ring, rng: &mut R, sigma: f64) -> Poly
where
    R: RngCore + CryptoRng,
{
    debug_assert!(sigma > 0.0 && sigma.is_finite());
    let degree = ring.degree();
    let samples: Vec<i64> = (0..degree)
        .map(|_| sample_one_smudging_coefficient(rng, sigma))
        .collect();

    let mut poly = ring.zero();
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value();
        for (i, coeff) in poly.coeffs_mut()[j].iter_mut().enumerate() {
            let sample = samples[i];
            *coeff = if sample < 0 {
                q - ((-sample) as u64 % q)
            } else {
                sample as u64 % q
            };
        }
    }
    poly
}

/// One Box-Muller-transformed, rounded standard-Gaussian sample scaled by
/// `sigma` - see [`sample_smudging_gaussian`]'s own doc comment.
fn sample_one_smudging_coefficient<R>(rng: &mut R, sigma: f64) -> i64
where
    R: RngCore,
{
    // u1 excludes 0 (ln(0) is undefined); u64::MAX+2 as the divisor keeps u1
    // in (0, 1) even at rng output u64::MAX.
    let u1 = (rng.next_u64() as f64 + 1.0) / (u64::MAX as f64 + 2.0);
    let u2 = rng.next_u64() as f64 / (u64::MAX as f64 + 1.0);
    let standard_normal = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    (standard_normal * sigma).round() as i64
}

#[cfg(test)]
mod tests {
    use super::{sample_one_smudging_coefficient, sample_smudging_gaussian, DiscreteGaussianTable};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn cumulative_table_sums_to_exactly_one_and_is_monotonic() {
        for &sigma in &[0.5, 1.0, 3.2, 10.0] {
            let table = DiscreteGaussianTable::new(sigma);
            assert_eq!(*table.cumulative.last().unwrap(), 1.0, "sigma={sigma}");
            let mut prev = 0.0;
            for &c in &table.cumulative {
                assert!(c >= prev, "cumulative table not monotonic at sigma={sigma}");
                prev = c;
            }
        }
    }

    #[test]
    fn table_width_matches_the_documented_tail_cut() {
        let sigma = 3.2;
        let table = DiscreteGaussianTable::new(sigma);
        let expected_tau = (6.0 * sigma).ceil() as i64;
        assert_eq!(table.tau, expected_tau);
        assert_eq!(table.cumulative.len(), (2 * expected_tau + 1) as usize);
    }

    #[test]
    fn samples_stay_within_the_truncated_support() {
        let sigma = 3.2;
        let table = DiscreteGaussianTable::new(sigma);
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        for _ in 0..20_000 {
            let x = table.sample(&mut rng);
            assert!(
                (-table.tau..=table.tau).contains(&x),
                "sample {x} outside [-{}, {}]",
                table.tau,
                table.tau
            );
        }
    }

    #[test]
    fn empirical_mean_and_stddev_match_the_target_distribution() {
        // Independent statistical check: draw many samples and verify the
        // empirical mean is near 0 and the empirical standard deviation is
        // near sigma, both within a tolerance sized from the expected
        // standard error at this sample count (not an arbitrary fudge
        // factor) so the test doesn't flake while still being a real check.
        let sigma = 3.2;
        let table = DiscreteGaussianTable::new(sigma);
        let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
        let n = 200_000;
        let samples: Vec<f64> = (0..n).map(|_| table.sample(&mut rng) as f64).collect();

        let mean: f64 = samples.iter().sum::<f64>() / n as f64;
        let variance: f64 = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let stddev = variance.sqrt();

        // Standard error of the mean is sigma / sqrt(n); allow 6 standard
        // errors of slack for a statistical test that must not flake.
        let mean_tolerance = 6.0 * sigma / (n as f64).sqrt();
        assert!(
            mean.abs() < mean_tolerance,
            "empirical mean {mean} exceeds tolerance {mean_tolerance}"
        );

        // Standard error of the sample standard deviation is roughly
        // sigma / sqrt(2n); allow 6 standard errors of slack here too.
        let stddev_tolerance = 6.0 * sigma / (2.0 * n as f64).sqrt();
        assert!(
            (stddev - sigma).abs() < stddev_tolerance,
            "empirical stddev {stddev} too far from target sigma {sigma} (tolerance {stddev_tolerance})"
        );
    }

    #[test]
    fn smudging_empirical_mean_and_stddev_match_the_target_at_smudging_scale() {
        // sigma ~ 3.57e8 - the same order of magnitude
        // `phantom_lattice::security::smudging_std_dev` produces at its
        // recommended 40-bit statistical security level.
        // `DiscreteGaussianTable::new` at this sigma would need a
        // multi-gigabyte table; this test's own point is that this sampler
        // needs none.
        let sigma = 3.57e8;
        let mut rng = ChaCha20Rng::from_seed([33u8; 32]);
        let n = 200_000;
        let samples: Vec<f64> = (0..n)
            .map(|_| sample_one_smudging_coefficient(&mut rng, sigma) as f64)
            .collect();

        let mean: f64 = samples.iter().sum::<f64>() / n as f64;
        let variance: f64 = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let stddev = variance.sqrt();

        let mean_tolerance = 6.0 * sigma / (n as f64).sqrt();
        assert!(
            mean.abs() < mean_tolerance,
            "empirical mean {mean} exceeds tolerance {mean_tolerance}"
        );
        let stddev_tolerance = 6.0 * sigma / (2.0 * n as f64).sqrt();
        assert!(
            (stddev - sigma).abs() < stddev_tolerance,
            "empirical stddev {stddev} too far from target sigma {sigma} (tolerance {stddev_tolerance})"
        );
    }

    #[test]
    fn sample_smudging_gaussian_reduces_correctly_into_a_real_ring_at_smudging_scale() {
        let ring = crate::Ring::new(
            crate::Degree::new(8).unwrap(),
            vec![crate::Modulus::new(1_000_000_000_000_037).unwrap()],
        )
        .unwrap();
        let mut rng = ChaCha20Rng::from_seed([44u8; 32]);
        let sigma = 3.57e8;
        for _ in 0..20 {
            let poly = sample_smudging_gaussian(&ring, &mut rng, sigma);
            for coeff in &poly.coeffs()[0] {
                assert!(*coeff < 1_000_000_000_000_037);
            }
        }
    }
}
