//! CKKS context factory.

use super::{CkksKeyGenerator, CkksParams, Decryptor, Encoder, Encryptor, Evaluator};
use crate::Result;

/// Shared CKKS context.
#[derive(Clone, Debug)]
pub struct CkksContext {
    params: CkksParams,
}

impl CkksContext {
    /// Creates a new context from validated parameters.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Returns CKKS parameters.
    pub const fn params(&self) -> &CkksParams {
        &self.params
    }

    /// Creates an encoder.
    pub fn encoder(&self) -> Encoder {
        Encoder::new(self.params.clone())
    }

    /// Creates a key generator.
    pub fn keygen(&self) -> Result<CkksKeyGenerator> {
        CkksKeyGenerator::new(self.params.clone())
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

    /// Creates a real public-key encryptor.
    pub fn real_encryptor(&self, public_key: phantom_lattice::rlwe::PublicKey) -> Encryptor {
        Encryptor::with_public_key_real(self.params.clone(), public_key)
    }

    /// Creates a real secret-key encryptor.
    pub fn real_secret_key_encryptor(
        &self,
        secret_key: phantom_lattice::rlwe::SecretKey,
    ) -> Encryptor {
        Encryptor::with_secret_key_real(self.params.clone(), secret_key)
    }

    /// Creates a real decryptor.
    pub fn real_decryptor(
        &self,
        secret_key: phantom_lattice::rlwe::SecretKey,
    ) -> Result<Decryptor> {
        Decryptor::new_real(self.params.clone(), secret_key)
    }

    /// Creates an evaluator.
    pub fn evaluator(&self) -> Evaluator {
        Evaluator::new(self.params.clone())
    }

    /// Bits of precision a freshly-encrypted ciphertext starts at, at this
    /// context's own ring/default scale - see
    /// [`super::noise::fresh_precision_bits`]. `Ciphertext`/`Plaintext`
    /// already track this as a real, per-value field (unlike BGV/BFV,
    /// which have no per-ciphertext noise field at all - see
    /// `bgv::BgvContext`/`bfv::BfvContext`'s own
    /// `noise_budget_bits`/`fresh_*_noise_budget_bits`), so this exists for
    /// discoverability/API symmetry across the three scheme contexts more
    /// than as a capability CKKS otherwise lacks.
    pub fn fresh_precision_bits(&self) -> f64 {
        super::noise::fresh_precision_bits(
            self.params.ring().degree(),
            self.params.default_scale().value(),
        )
    }
}
