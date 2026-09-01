//! BGV encryption.
//!
//! Two encryption modes coexist on the same [`Encryptor`] type, chosen by
//! which constructor built it.
//!
//! **Transparent** ([`Encryptor::with_secret_key`]/[`Encryptor::with_public_key`]):
//! the long-standing behavior, kept unchanged so every existing caller
//! across `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`/
//! `phantom-examples` keeps compiling and behaving identically. Wraps the
//! plaintext polynomial directly as a length-1 ciphertext, ignoring the key
//! and RNG entirely. No real cryptographic content.
//!
//! **Real** ([`Encryptor::with_secret_key_real`]/[`Encryptor::with_public_key_real`]):
//! genuine BGV encryption with noise scaled by the plaintext modulus `t`,
//! so it vanishes under decryption's final `mod t` reduction (see
//! [`BgvKeyGenerator::generate_keypair_real`](super::BgvKeyGenerator::generate_keypair_real)'s
//! doc comment for the public-key path's own extra requirement). Secret-key:
//! `c0 = m + t*e - a*s`, `c1 = a`. Public-key: `c0 = m + b*u + t*e0`, `c1 =
//! a*u + t*e1`. Both derived by hand and verified numerically (Python,
//! arbitrary-precision integers) before implementing - round trip,
//! homomorphic add, and raw (pre-relinearization) multiplication all
//! checked to recover exact values `mod t`.
//!
//! [`super::Decryptor`] and [`super::BatchEncoder::decode_u64`] need no
//! matching "real" variant: `decode_u64` already centers each coefficient
//! into `(-q/2, q/2]` before reducing `mod t`, which is exactly the step
//! real BGV noise needs and is a no-op for the already-in-range values
//! transparent encryption produces - so both paths share the same decode
//! code unchanged.

use phantom_lattice::rlwe::{PublicKey, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary, sample_uniform};
use rand_core::{CryptoRng, RngCore};

use super::{BgvParams, Ciphertext, Plaintext};
use crate::Result;

#[derive(Clone, Debug)]
enum Mode {
    Transparent(phantom_lattice::rlwe::Encryptor),
    RealSecretKey { params: BgvParams, sk: SecretKey },
    RealPublicKey { params: BgvParams, pk: PublicKey },
}

/// BGV encryptor. See the module doc comment for the transparent-vs-real
/// distinction.
#[derive(Clone, Debug)]
pub struct Encryptor {
    mode: Mode,
}

impl Encryptor {
    /// Creates a transparent public-key encryptor (no real cryptographic
    /// content - see the module doc comment).
    pub fn with_public_key(params: BgvParams, public_key: PublicKey) -> Result<Self> {
        Ok(Self {
            mode: Mode::Transparent(phantom_lattice::rlwe::Encryptor::with_public_key(
                params.rlwe_params()?,
                public_key,
            )),
        })
    }

    /// Creates a transparent secret-key encryptor (no real cryptographic
    /// content - see the module doc comment).
    pub fn with_secret_key(params: BgvParams, secret_key: SecretKey) -> Result<Self> {
        Ok(Self {
            mode: Mode::Transparent(phantom_lattice::rlwe::Encryptor::with_secret_key(
                params.rlwe_params()?,
                secret_key,
            )),
        })
    }

    /// Creates a real public-key encryptor. `public_key` must come from
    /// [`super::BgvKeyGenerator::generate_keypair_real`], not
    /// [`super::BgvKeyGenerator::generate_keypair`] - see the module doc
    /// comment and that constructor's own doc comment for why.
    pub fn with_public_key_real(params: BgvParams, public_key: PublicKey) -> Self {
        Self {
            mode: Mode::RealPublicKey {
                params,
                pk: public_key,
            },
        }
    }

    /// Creates a real secret-key encryptor - see the module doc comment.
    pub fn with_secret_key_real(params: BgvParams, secret_key: SecretKey) -> Self {
        Self {
            mode: Mode::RealSecretKey {
                params,
                sk: secret_key,
            },
        }
    }

    /// Encrypts a BGV plaintext.
    pub fn encrypt<R>(&self, plaintext: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        match &self.mode {
            Mode::Transparent(inner) => {
                let _ = rng;
                match inner {
                    phantom_lattice::rlwe::Encryptor::SecretKey { params, .. }
                    | phantom_lattice::rlwe::Encryptor::PublicKey { params, .. } => {
                        params.ring().check_poly(plaintext.inner().value())?;
                    }
                }
                Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
                    vec![plaintext.inner().value().clone()],
                )))
            }
            Mode::RealSecretKey { params, sk } => {
                let ring = params.ring();
                let t = params.plaintext_modulus();
                let m = plaintext.inner().value();
                ring.check_poly(m)?;

                let a = sample_uniform(ring, rng);
                let e = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let t_e = ring.scalar_mul(&e, t)?;
                let a_s = ring.mul(&a, sk.value())?;
                let c0 = ring.sub(&ring.add(m, &t_e)?, &a_s)?;

                Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
                    vec![c0, a],
                )))
            }
            Mode::RealPublicKey { params, pk } => {
                let ring = params.ring();
                let t = params.plaintext_modulus();
                let m = plaintext.inner().value();
                ring.check_poly(m)?;

                let u = sample_ternary(ring, rng);
                let e0 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let e1 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let t_e0 = ring.scalar_mul(&e0, t)?;
                let t_e1 = ring.scalar_mul(&e1, t)?;
                let b_u = ring.mul(&pk.value()[0], &u)?;
                let a_u = ring.mul(&pk.value()[1], &u)?;
                let c0 = ring.add(&ring.add(m, &b_u)?, &t_e0)?;
                let c1 = ring.add(&a_u, &t_e1)?;

                Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
                    vec![c0, c1],
                )))
            }
        }
    }
}
