//! BFV key generation.

use crate::{bgv, Result};
use rand_core::{CryptoRng, RngCore};

use super::BfvParams;

/// Generated BFV key pair.
#[derive(Clone, Debug)]
pub struct BfvKeyPair {
    /// Secret key.
    pub secret: phantom_lattice::rlwe::SecretKey,
    /// Public key.
    pub public: phantom_lattice::rlwe::PublicKey,
}

/// Evaluation keys used by BFV evaluators.
#[derive(Clone, Debug)]
pub struct EvaluationKeys {
    pub(crate) inner: bgv::EvaluationKeys,
}

/// BFV key generator.
#[derive(Clone, Debug)]
pub struct BfvKeyGenerator {
    inner: bgv::BgvKeyGenerator,
}

impl BfvKeyGenerator {
    /// Creates a key generator.
    pub fn new(params: BfvParams) -> Result<Self> {
        Ok(Self {
            inner: bgv::BgvKeyGenerator::new(params.inner().clone())?,
        })
    }

    /// Generates a ternary-secret key pair.
    pub fn generate_keypair<R>(&self, rng: &mut R) -> Result<BfvKeyPair>
    where
        R: RngCore + CryptoRng,
    {
        let pair = self.inner.generate_keypair(rng)?;
        Ok(BfvKeyPair {
            secret: pair.secret,
            public: pair.public,
        })
    }

    /// Generates evaluation keys for requested rotation elements.
    pub fn generate_evaluation_keys(
        &self,
        secret: &phantom_lattice::rlwe::SecretKey,
        rotation_elements: &[usize],
    ) -> EvaluationKeys {
        EvaluationKeys {
            inner: self
                .inner
                .generate_evaluation_keys(secret, rotation_elements),
        }
    }
}
