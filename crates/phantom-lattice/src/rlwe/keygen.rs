//! RLWE key generation.

use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary, sample_uniform};
use rand_core::{CryptoRng, RngCore};

use crate::rlwe::{GaloisKey, PublicKey, RelinearizationKey, RlweParams, SecretKey};
use crate::Result;

/// Secret key distribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretDistribution {
    /// Ternary coefficients {-1, 0, 1}.
    Ternary,
    /// Narrow Gaussian-like placeholder with the provided bound.
    Gaussian { bound: u64 },
}

/// RLWE key generator.
#[derive(Clone, Debug)]
pub struct KeyGenerator {
    params: RlweParams,
}

impl KeyGenerator {
    /// Creates a key generator.
    pub const fn new(params: RlweParams) -> Self {
        Self { params }
    }

    /// Returns parameters.
    pub const fn params(&self) -> &RlweParams {
        &self.params
    }

    /// Generates a secret key.
    pub fn generate_secret_key<R>(&self, rng: &mut R, distribution: SecretDistribution) -> SecretKey
    where
        R: RngCore + CryptoRng,
    {
        let value = match distribution {
            SecretDistribution::Ternary => sample_ternary(self.params.ring(), rng),
            SecretDistribution::Gaussian { bound } => {
                sample_discrete_gaussian(self.params.ring(), rng, bound)
            }
        };
        SecretKey::new(value)
    }

    /// Generates a public key with zero encryption error (early implementation).
    ///
    /// This is a correctness scaffold, not a production key generation routine.
    pub fn generate_public_key<R>(&self, sk: &SecretKey, rng: &mut R) -> Result<PublicKey>
    where
        R: RngCore + CryptoRng,
    {
        let a = sample_uniform(self.params.ring(), rng);
        let as_prod = self.params.ring().mul(&a, sk.value())?;
        let b = self.params.ring().neg(&as_prod)?;
        Ok(PublicKey::new(b, a))
    }

    /// Generates a placeholder relinearization key.
    pub const fn generate_relinearization_key(&self, _sk: &SecretKey) -> RelinearizationKey {
        RelinearizationKey
    }

    /// Generates placeholder Galois key markers.
    pub fn generate_galois_keys(&self, elements: &[usize], _sk: &SecretKey) -> Vec<GaloisKey> {
        elements.iter().copied().map(GaloisKey::new).collect()
    }
}
