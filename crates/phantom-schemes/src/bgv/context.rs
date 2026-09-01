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

    /// Creates a transparent public-key encryptor (see [`Encryptor`]'s own
    /// doc comment for the transparent-vs-real distinction).
    pub fn encryptor(&self, public_key: phantom_lattice::rlwe::PublicKey) -> Result<Encryptor> {
        Encryptor::with_public_key(self.params.clone(), public_key)
    }

    /// Creates a transparent secret-key encryptor.
    pub fn secret_key_encryptor(
        &self,
        secret_key: phantom_lattice::rlwe::SecretKey,
    ) -> Result<Encryptor> {
        Encryptor::with_secret_key(self.params.clone(), secret_key)
    }

    /// Creates a real public-key encryptor. `public_key` must come from
    /// [`BgvKeyGenerator::generate_keypair_real`].
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

    /// Creates a decryptor.
    pub fn decryptor(&self, secret_key: phantom_lattice::rlwe::SecretKey) -> Result<Decryptor> {
        Decryptor::new(self.params.clone(), secret_key)
    }

    /// Creates an evaluator.
    pub fn evaluator(&self) -> Result<Evaluator> {
        Evaluator::new(self.params.clone())
    }

    /// Bits of noise margin `noise_bound` leaves before decryption breaks,
    /// at this context's own ring/plaintext modulus - see
    /// [`super::noise::noise_budget_bits`].
    pub fn noise_budget_bits(&self, noise_bound: u64) -> f64 {
        let moduli: Vec<u64> = self
            .params
            .ring()
            .moduli()
            .iter()
            .map(|m| m.value())
            .collect();
        super::noise::noise_budget_bits(&moduli, self.params.plaintext_modulus(), noise_bound)
    }

    /// Bits of noise margin left immediately after a fresh secret-key
    /// encryption - see [`Self::noise_budget_bits`] and
    /// [`super::noise::fresh_secret_key_noise_bound`].
    pub fn fresh_secret_key_noise_budget_bits(&self) -> f64 {
        self.noise_budget_bits(super::noise::fresh_secret_key_noise_bound())
    }

    /// Bits of noise margin left immediately after a fresh public-key
    /// encryption - see [`Self::noise_budget_bits`] and
    /// [`super::noise::fresh_public_key_noise_bound`].
    pub fn fresh_public_key_noise_budget_bits(&self) -> f64 {
        self.noise_budget_bits(super::noise::fresh_public_key_noise_bound(
            self.params.ring().degree(),
        ))
    }
}
