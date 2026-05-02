//! BFV encryption.

use rand_core::{CryptoRng, RngCore};

use super::{BfvParams, Ciphertext, Plaintext};
use crate::{bgv, Result};

/// BFV encryptor.
#[derive(Clone, Debug)]
pub struct Encryptor {
    inner: bgv::Encryptor,
}

impl Encryptor {
    /// Creates a public-key encryptor.
    pub fn with_public_key(
        params: BfvParams,
        public_key: phantom_lattice::rlwe::PublicKey,
    ) -> Result<Self> {
        Ok(Self {
            inner: bgv::Encryptor::with_public_key(params.inner().clone(), public_key)?,
        })
    }

    /// Creates a secret-key encryptor.
    pub fn with_secret_key(
        params: BfvParams,
        secret_key: phantom_lattice::rlwe::SecretKey,
    ) -> Result<Self> {
        Ok(Self {
            inner: bgv::Encryptor::with_secret_key(params.inner().clone(), secret_key)?,
        })
    }

    /// Encrypts a BFV plaintext.
    pub fn encrypt<R>(&self, plaintext: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        Ok(Ciphertext::new(self.inner.encrypt(plaintext.inner(), rng)?))
    }
}
