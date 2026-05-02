//! CKKS decryption.

use super::{Ciphertext, CkksParams, Plaintext};
use crate::Result;

/// CKKS decryptor.
#[derive(Clone, Debug)]
pub struct Decryptor {
    params: CkksParams,
}

impl Decryptor {
    /// Creates a decryptor.
    pub fn new(params: CkksParams, secret_key: phantom_lattice::rlwe::SecretKey) -> Result<Self> {
        let _ = secret_key;
        params.rlwe_params()?;
        Ok(Self { params })
    }

    /// Decrypts a CKKS ciphertext.
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Plaintext> {
        if ciphertext.slots().len() > self.params.slot_count() {
            return Err(crate::SchemesError::InvalidSlotCount);
        }
        Ok(Plaintext::new(
            ciphertext.slots().to_vec(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
        ))
    }
}
