//! BFV context factory.

use super::{BatchEncoder, BfvKeyGenerator, BfvParams, Decryptor, Encryptor, Evaluator};
use crate::Result;

/// Shared BFV context.
#[derive(Clone, Debug)]
pub struct BfvContext {
    params: BfvParams,
}

impl BfvContext {
    /// Creates a new context from validated parameters.
    pub const fn new(params: BfvParams) -> Self {
        Self { params }
    }

    /// Returns BFV parameters.
    pub const fn params(&self) -> &BfvParams {
        &self.params
    }

    /// Creates a batching encoder.
    pub fn encoder(&self) -> BatchEncoder {
        BatchEncoder::new(self.params.clone())
    }

    /// Creates a key generator.
    pub fn keygen(&self) -> Result<BfvKeyGenerator> {
        BfvKeyGenerator::new(self.params.clone())
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
