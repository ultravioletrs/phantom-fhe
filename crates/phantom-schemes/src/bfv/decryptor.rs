//! BFV decryption.

use super::{BfvParams, Ciphertext, Plaintext};
use crate::{bgv, Result};

/// BFV decryptor.
#[derive(Clone, Debug)]
pub struct Decryptor {
    inner: bgv::Decryptor,
}

impl Decryptor {
    /// Creates a decryptor.
    pub fn new(params: BfvParams, secret_key: phantom_lattice::rlwe::SecretKey) -> Result<Self> {
        Ok(Self {
            inner: bgv::Decryptor::new(params.inner().clone(), secret_key)?,
        })
    }

    /// Decrypts a BFV ciphertext.
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Plaintext> {
        Ok(Plaintext::new(self.inner.decrypt(ciphertext.inner())?))
    }
}
