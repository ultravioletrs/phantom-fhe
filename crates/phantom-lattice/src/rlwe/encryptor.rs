//! RLWE encryption.

use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary};
use rand_core::{CryptoRng, RngCore};

use crate::rlwe::{Ciphertext, Plaintext, PublicKey, RlweParams, SecretKey};
use crate::security::STANDARD_ERROR_STD_DEV;
use crate::Result;

/// Encryptor for real (noisy) RLWE encryption, secret-key or public-key.
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

    /// Encrypts a plaintext with a freshly sampled error term (see
    /// [`crate::security::STANDARD_ERROR_STD_DEV`] and
    /// [`crate::noise::fresh_secret_key_noise_bound`] /
    /// [`crate::noise::fresh_public_key_noise_bound`] for the resulting
    /// noise bound).
    pub fn encrypt<R>(&self, pt: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        match self {
            Self::SecretKey { params, sk } => {
                params.ring().check_poly(pt.value())?;
                let a = phantom_ring::sampling::sample_uniform(params.ring(), rng);
                let e = sample_discrete_gaussian(params.ring(), rng, STANDARD_ERROR_STD_DEV);
                let as_prod = params.ring().mul(&a, sk.value())?;
                let masked = params.ring().sub(pt.value(), &as_prod)?;
                let c0 = params.ring().add(&masked, &e)?;
                Ok(Ciphertext::new(vec![c0, a]))
            }
            Self::PublicKey { params, pk } => {
                params.ring().check_poly(pt.value())?;
                let u = sample_ternary(params.ring(), rng);
                let e1 = sample_discrete_gaussian(params.ring(), rng, STANDARD_ERROR_STD_DEV);
                let e2 = sample_discrete_gaussian(params.ring(), rng, STANDARD_ERROR_STD_DEV);
                let c0_mask = params.ring().mul(&pk.value()[0], &u)?;
                let c0_noisy = params.ring().add(pt.value(), &c0_mask)?;
                let c0 = params.ring().add(&c0_noisy, &e1)?;
                let c1_mask = params.ring().mul(&pk.value()[1], &u)?;
                let c1 = params.ring().add(&c1_mask, &e2)?;
                Ok(Ciphertext::new(vec![c0, c1]))
            }
        }
    }
}
