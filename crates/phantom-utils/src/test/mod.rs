//! Test-only support helpers.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Deterministic RNG for tests and examples that need reproducibility.
pub fn deterministic_rng(seed: [u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed)
}

/// Deterministic RNG seeded with zero bytes.
pub fn zero_seed_rng() -> ChaCha20Rng {
    deterministic_rng([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::deterministic_rng;
    use rand_core::RngCore;

    #[test]
    fn deterministic_rng_repeats_for_same_seed() {
        let seed = [42u8; 32];
        let mut rng_a = deterministic_rng(seed);
        let mut rng_b = deterministic_rng(seed);

        assert_eq!(rng_a.next_u64(), rng_b.next_u64());
        assert_eq!(rng_a.next_u64(), rng_b.next_u64());
    }
}
