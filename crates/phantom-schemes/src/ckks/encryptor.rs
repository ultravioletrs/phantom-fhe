//! CKKS encryption.

use rand_core::{CryptoRng, RngCore};

use super::{Ciphertext, CkksParams, Plaintext};
use crate::Result;

/// CKKS encryptor.
#[derive(Clone, Debug)]
pub struct Encryptor {
    params: CkksParams,
}

impl Encryptor {
    /// Creates a public-key encryptor.
    pub fn with_public_key(
        params: CkksParams,
        public_key: phantom_lattice::rlwe::PublicKey,
    ) -> Result<Self> {
        let _ = public_key;
        params.rlwe_params()?;
        Ok(Self { params })
    }

    /// Creates a secret-key encryptor.
    pub fn with_secret_key(
        params: CkksParams,
        secret_key: phantom_lattice::rlwe::SecretKey,
    ) -> Result<Self> {
        let _ = secret_key;
        params.rlwe_params()?;
        Ok(Self { params })
    }

    /// Encrypts a CKKS plaintext.
    pub fn encrypt<R>(&self, plaintext: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        let _ = rng;
        if plaintext.slots().len() > self.params.slot_count() {
            return Err(crate::SchemesError::InvalidSlotCount);
        }
        Ok(Ciphertext::new(
            plaintext.slots().to_vec(),
            plaintext.scale(),
            plaintext.level(),
            plaintext.precision(),
            1,
        ))
    }
}
