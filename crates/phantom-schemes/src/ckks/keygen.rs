//! CKKS key generation.

use phantom_lattice::rlwe::{
    GaloisKey, PublicKey, RelinearizationKey, SecretDistribution, SecretKey,
};
use rand_core::{CryptoRng, RngCore};

use super::CkksParams;
use crate::Result;

/// Generated CKKS key pair.
#[derive(Clone, Debug)]
pub struct CkksKeyPair {
    /// Secret key.
    pub secret: SecretKey,
    /// Public key.
    pub public: PublicKey,
}

/// Evaluation keys used by CKKS evaluators.
#[derive(Clone, Debug)]
pub struct EvaluationKeys {
    /// Relinearization key.
    pub relinearization: RelinearizationKey,
    /// Rotation/Galois keys.
    pub galois: Vec<GaloisKey>,
}

/// CKKS key generator.
#[derive(Clone, Debug)]
pub struct CkksKeyGenerator {
    inner: phantom_lattice::rlwe::KeyGenerator,
}

impl CkksKeyGenerator {
    /// Creates a key generator.
    pub fn new(params: CkksParams) -> Result<Self> {
        Ok(Self {
            inner: phantom_lattice::rlwe::KeyGenerator::new(params.rlwe_params()?),
        })
    }

    /// Generates a ternary-secret key pair.
    pub fn generate_keypair<R>(&self, rng: &mut R) -> Result<CkksKeyPair>
    where
        R: RngCore + CryptoRng,
    {
        let secret = self
            .inner
            .generate_secret_key(rng, SecretDistribution::Ternary);
        let public = self.inner.generate_public_key(&secret, rng)?;
        Ok(CkksKeyPair { secret, public })
    }

    /// Generates evaluation keys for requested rotation elements.
    pub fn generate_evaluation_keys(
        &self,
        secret: &SecretKey,
        rotation_elements: &[usize],
    ) -> EvaluationKeys {
        EvaluationKeys {
            relinearization: self.inner.generate_relinearization_key(secret),
            galois: self.inner.generate_galois_keys(rotation_elements, secret),
        }
    }
}
