//! CKKS encryption.
//!
//! Two encryption modes coexist on the same [`Encryptor`] type, mirroring
//! [`crate::bgv::Encryptor`]'s and [`crate::bfv::Encryptor`]'s own designs.
//!
//! **Transparent** ([`Encryptor::with_secret_key`]/[`Encryptor::with_public_key`]/[`Encryptor::encrypt`]):
//! the long-standing scaffold behavior, kept unchanged so every existing
//! caller keeps compiling and behaving identically - the plaintext's
//! `Complex64` slots are carried straight into the ciphertext.
//!
//! **Real** ([`Encryptor::with_secret_key_real`]/[`Encryptor::with_public_key_real`]/[`Encryptor::encrypt_real`]):
//! genuine CKKS encryption of a real plaintext ([`super::Plaintext::poly`]
//! from [`super::Encoder::encode_complex_real`]). Unlike BFV (which scales
//! the message by `Delta` at encryption time), CKKS's message is already
//! Delta-scaled by the encoder, so this is structurally identical to BFV's
//! real path *minus* that scaling step: `c0 = m + e - a*s`, `c1 = a` for
//! secret-key; `c0 = m + b*u + e0`, `c1 = a*u + e1` for public-key - a
//! standard generic RLWE public key works unchanged here, the same as
//! BFV's.

use phantom_lattice::rlwe::{Ciphertext as RlweCiphertext, PublicKey, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary, sample_uniform};
use rand_core::{CryptoRng, RngCore};

use super::{Ciphertext, CkksParams, Plaintext};
use crate::{Result, SchemesError};

#[derive(Clone, Debug)]
enum Mode {
    Transparent,
    RealSecretKey(SecretKey),
    RealPublicKey(PublicKey),
}

/// CKKS encryptor. See the module doc comment for the transparent-vs-real
/// distinction.
#[derive(Clone, Debug)]
pub struct Encryptor {
    params: CkksParams,
    mode: Mode,
}

impl Encryptor {
    /// Creates a transparent public-key encryptor (no real cryptographic
    /// content - see the module doc comment).
    pub fn with_public_key(
        params: CkksParams,
        public_key: phantom_lattice::rlwe::PublicKey,
    ) -> Result<Self> {
        let _ = public_key;
        params.rlwe_params()?;
        Ok(Self {
            params,
            mode: Mode::Transparent,
        })
    }

    /// Creates a transparent secret-key encryptor (no real cryptographic
    /// content - see the module doc comment).
    pub fn with_secret_key(
        params: CkksParams,
        secret_key: phantom_lattice::rlwe::SecretKey,
    ) -> Result<Self> {
        let _ = secret_key;
        params.rlwe_params()?;
        Ok(Self {
            params,
            mode: Mode::Transparent,
        })
    }

    /// Creates a real public-key encryptor. `public_key` can come from
    /// [`super::CkksKeyGenerator::generate_keypair`] unchanged - CKKS's
    /// public key needs no special scaling, the same as BFV's.
    pub fn with_public_key_real(params: CkksParams, public_key: PublicKey) -> Self {
        Self {
            params,
            mode: Mode::RealPublicKey(public_key),
        }
    }

    /// Creates a real secret-key encryptor - see the module doc comment.
    pub fn with_secret_key_real(params: CkksParams, secret_key: SecretKey) -> Self {
        Self {
            params,
            mode: Mode::RealSecretKey(secret_key),
        }
    }

    /// Encrypts a CKKS plaintext.
    pub fn encrypt<R>(&self, plaintext: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        let _ = rng;
        if plaintext.slots().len() > self.params.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        Ok(Ciphertext::new(
            plaintext.slots().to_vec(),
            plaintext.scale(),
            plaintext.level(),
            plaintext.precision(),
            1,
        ))
    }

    /// Encrypts a **real** plaintext ([`Plaintext::poly`] from
    /// [`super::Encoder::encode_complex_real`]) - see the module doc
    /// comment.
    pub fn encrypt_real<R>(&self, plaintext: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        let m = plaintext.poly().ok_or(SchemesError::InvalidParameters(
            "plaintext has no real ring representation - encode with encode_complex_real",
        ))?;
        let ring = self.params.ring();
        ring.check_poly(m)?;

        let (c0, c1) = match &self.mode {
            Mode::Transparent => {
                return Err(SchemesError::InvalidParameters(
                    "encrypt_real requires a real encryptor - use with_secret_key_real/with_public_key_real",
                ))
            }
            Mode::RealSecretKey(sk) => {
                let a = sample_uniform(ring, rng);
                let e = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let a_s = ring.mul(&a, sk.value())?;
                let c0 = ring.sub(&ring.add(m, &e)?, &a_s)?;
                (c0, a)
            }
            Mode::RealPublicKey(pk) => {
                let u = sample_ternary(ring, rng);
                let e0 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let e1 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let b_u = ring.mul(&pk.value()[0], &u)?;
                let a_u = ring.mul(&pk.value()[1], &u)?;
                let c0 = ring.add(&ring.add(m, &b_u)?, &e0)?;
                let c1 = ring.add(&a_u, &e1)?;
                (c0, c1)
            }
        };

        Ok(Ciphertext::new_real(
            RlweCiphertext::new(vec![c0, c1]),
            plaintext.scale(),
            plaintext.level(),
            plaintext.precision(),
            1,
        ))
    }
}
