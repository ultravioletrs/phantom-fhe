//! BGV decryption.

use phantom_lattice::rlwe::SecretKey;

use super::{BgvParams, Ciphertext, Plaintext};
use crate::Result;

/// BGV decryptor.
#[derive(Clone, Debug)]
pub struct Decryptor {
    inner: phantom_lattice::rlwe::Decryptor,
}

impl Decryptor {
    /// Creates a decryptor.
    pub fn new(params: BgvParams, secret_key: SecretKey) -> Result<Self> {
        Ok(Self {
            inner: phantom_lattice::rlwe::Decryptor::new(params.rlwe_params()?, secret_key),
        })
    }

    /// Decrypts a BGV ciphertext.
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Plaintext> {
        Ok(Plaintext::new(self.inner.decrypt(ciphertext.inner())?))
    }
}
