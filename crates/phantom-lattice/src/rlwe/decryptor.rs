//! RLWE decryption.

use crate::rlwe::{Ciphertext, Plaintext, RlweParams, SecretKey};
use crate::{LatticeError, Result};

/// RLWE decryptor.
#[derive(Clone, Debug)]
pub struct Decryptor {
    params: RlweParams,
    sk: SecretKey,
}

impl Decryptor {
    /// Creates a decryptor.
    pub const fn new(params: RlweParams, sk: SecretKey) -> Self {
        Self { params, sk }
    }

    /// Decrypts a ciphertext.
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<Plaintext> {
        if ct.value().is_empty() {
            return Err(LatticeError::DimensionMismatch);
        }
        for component in ct.value() {
            self.params.ring().check_poly(component)?;
        }

        let mut acc = ct.value()[0].clone();
        let mut sk_power = self.sk.value().clone();

        for component in ct.value().iter().skip(1) {
            let term = self.params.ring().mul(component, &sk_power)?;
            self.params.ring().add_assign(&mut acc, &term)?;
            sk_power = self.params.ring().mul(&sk_power, self.sk.value())?;
        }

        Ok(Plaintext::new(acc))
    }
}
