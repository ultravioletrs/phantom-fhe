//! BGV context factory.

use super::{BatchEncoder, BgvKeyGenerator, BgvParams, Decryptor, Encryptor, Evaluator};
use crate::Result;

/// Shared BGV context.
#[derive(Clone, Debug)]
pub struct BgvContext {
    params: BgvParams,
}

impl BgvContext {
    /// Creates a new context from validated parameters.
    pub const fn new(params: BgvParams) -> Self {
        Self { params }
    }

    /// Returns BGV parameters.
    pub const fn params(&self) -> &BgvParams {
        &self.params
    }

    /// Creates a batching encoder.
    pub fn encoder(&self) -> BatchEncoder {
        BatchEncoder::new(self.params.clone())
    }

    /// Creates a key generator.
    pub fn keygen(&self) -> Result<BgvKeyGenerator> {
        BgvKeyGenerator::new(self.params.clone())
    }

    /// Creates a public-key encryptor.
    pub fn encryptor(&self, public_key: phantom_lattice::rlwe::PublicKey) -> Result<Encryptor> {
        Encryptor::with_public_key(self.params.clone(), public_key)
    }

    /// Creates a secret-key encryptor.
    pub fn secret_key_encryptor(
        &self,
        secret_key: phantom_lattice::rlwe::SecretKey,
    ) -> Result<Encryptor> {
        Encryptor::with_secret_key(self.params.clone(), secret_key)
    }

    /// Creates a decryptor.
    pub fn decryptor(&self, secret_key: phantom_lattice::rlwe::SecretKey) -> Result<Decryptor> {
        Decryptor::new(self.params.clone(), secret_key)
    }

    /// Creates an evaluator.
    pub fn evaluator(&self) -> Result<Evaluator> {
        Evaluator::new(self.params.clone())
    }
}
