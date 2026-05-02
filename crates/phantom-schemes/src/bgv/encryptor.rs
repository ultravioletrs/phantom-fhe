//! BGV encryption.

use phantom_lattice::rlwe::{PublicKey, SecretKey};
use rand_core::{CryptoRng, RngCore};

use super::{BgvParams, Ciphertext, Plaintext};
use crate::Result;

/// BGV encryptor.
#[derive(Clone, Debug)]
pub struct Encryptor {
    inner: phantom_lattice::rlwe::Encryptor,
}

impl Encryptor {
    /// Creates a public-key encryptor.
    pub fn with_public_key(params: BgvParams, public_key: PublicKey) -> Result<Self> {
        Ok(Self {
            inner: phantom_lattice::rlwe::Encryptor::with_public_key(
                params.rlwe_params()?,
                public_key,
            ),
        })
    }

    /// Creates a secret-key encryptor.
    pub fn with_secret_key(params: BgvParams, secret_key: SecretKey) -> Result<Self> {
        Ok(Self {
            inner: phantom_lattice::rlwe::Encryptor::with_secret_key(
                params.rlwe_params()?,
                secret_key,
            ),
        })
    }

    /// Encrypts a BGV plaintext.
    pub fn encrypt<R>(&self, plaintext: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        let _ = rng;
        match &self.inner {
            phantom_lattice::rlwe::Encryptor::SecretKey { params, .. }
            | phantom_lattice::rlwe::Encryptor::PublicKey { params, .. } => {
                params.ring().check_poly(plaintext.inner().value())?;
            }
        }
        Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
            vec![plaintext.inner().value().clone()],
        )))
    }
}
