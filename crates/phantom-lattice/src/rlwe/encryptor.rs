//! RLWE encryption.

use phantom_ring::sampling::sample_ternary;
use rand_core::{CryptoRng, RngCore};

use crate::rlwe::{Ciphertext, Plaintext, PublicKey, RlweParams, SecretKey};
use crate::Result;

/// Encryptor for exact RLWE encryption (early implementation, no error term).
#[derive(Clone, Debug)]
pub enum Encryptor {
    /// Secret-key encryptor.
    SecretKey {
        /// Parameters.
        params: RlweParams,
        /// Secret key.
        sk: SecretKey,
    },
    /// Public-key encryptor.
    PublicKey {
        /// Parameters.
        params: RlweParams,
        /// Public key.
        pk: PublicKey,
    },
}

impl Encryptor {
    /// Creates a secret-key encryptor.
    pub const fn with_secret_key(params: RlweParams, sk: SecretKey) -> Self {
        Self::SecretKey { params, sk }
    }

    /// Creates a public-key encryptor.
    pub const fn with_public_key(params: RlweParams, pk: PublicKey) -> Self {
        Self::PublicKey { params, pk }
    }

    /// Encrypts a plaintext.
    pub fn encrypt<R>(&self, pt: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        match self {
            Self::SecretKey { params, sk } => {
                params.ring().check_poly(pt.value())?;
                let a = phantom_ring::sampling::sample_uniform(params.ring(), rng);
                let as_prod = params.ring().schoolbook_mul(&a, sk.value())?;
                let c0 = params.ring().sub(pt.value(), &as_prod)?;
                Ok(Ciphertext::new(vec![c0, a]))
            }
            Self::PublicKey { params, pk } => {
                params.ring().check_poly(pt.value())?;
                let u = sample_ternary(params.ring(), rng);
                let c0_mask = params.ring().schoolbook_mul(&pk.value()[0], &u)?;
                let c1 = params.ring().schoolbook_mul(&pk.value()[1], &u)?;
                let c0 = params.ring().add(pt.value(), &c0_mask)?;
                Ok(Ciphertext::new(vec![c0, c1]))
            }
        }
    }
}
