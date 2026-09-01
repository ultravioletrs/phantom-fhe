//! BFV encryption.
//!
//! Two encryption modes coexist on the same [`Encryptor`] type, chosen by
//! which constructor built it, mirroring [`crate::bgv::Encryptor`]'s own
//! design.
//!
//! **Transparent** ([`Encryptor::with_secret_key`]/[`Encryptor::with_public_key`]):
//! the long-standing behavior, kept unchanged so every existing caller
//! keeps compiling and behaving identically. Delegates straight to
//! [`crate::bgv::Encryptor`]'s own transparent path.
//!
//! **Real** ([`Encryptor::with_secret_key_real`]/[`Encryptor::with_public_key_real`]):
//! genuine BFV encryption. Unlike BGV (noise scaled by the plaintext
//! modulus `t`), real BFV scales the *message* by `Delta = floor(Q/t)`
//! (`Q` = the full ciphertext modulus product) and adds *raw*, unscaled
//! noise: `c0 = Delta*m + e - a*s`, `c1 = a` for secret-key; `c0 = Delta*m +
//! b*u + e0`, `c1 = a*u + e1` for public-key - a standard generic RLWE
//! public key works unchanged here (unlike BGV's, which needs its own
//! `t`-scaled noise). Decoding needs a matching real path too - see
//! [`super::BatchEncoder::decode_u64_real`]. Both derived by hand and
//! verified numerically (Python, arbitrary-precision integers) before
//! implementing: round trip and homomorphic add recover exact values `mod
//! t`.

use phantom_lattice::rlwe::{PublicKey, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::reduce::mul_mod;
use phantom_ring::rns::extension::floor_divide_residues;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary, sample_uniform};
use phantom_ring::{Poly, Ring, RnsBasis};
use rand_core::{CryptoRng, RngCore};

use super::{BfvParams, Ciphertext, Plaintext};
use crate::{bgv, Result};

#[derive(Clone, Debug)]
enum Mode {
    Transparent(bgv::Encryptor),
    RealSecretKey { params: BfvParams, sk: SecretKey },
    RealPublicKey { params: BfvParams, pk: PublicKey },
}

/// BFV encryptor. See the module doc comment for the transparent-vs-real
/// distinction.
#[derive(Clone, Debug)]
pub struct Encryptor {
    mode: Mode,
}

impl Encryptor {
    /// Creates a transparent public-key encryptor (no real cryptographic
    /// content - see the module doc comment).
    pub fn with_public_key(params: BfvParams, public_key: PublicKey) -> Result<Self> {
        Ok(Self {
            mode: Mode::Transparent(bgv::Encryptor::with_public_key(
                params.inner().clone(),
                public_key,
            )?),
        })
    }

    /// Creates a transparent secret-key encryptor (no real cryptographic
    /// content - see the module doc comment).
    pub fn with_secret_key(params: BfvParams, secret_key: SecretKey) -> Result<Self> {
        Ok(Self {
            mode: Mode::Transparent(bgv::Encryptor::with_secret_key(
                params.inner().clone(),
                secret_key,
            )?),
        })
    }

    /// Creates a real public-key encryptor. `public_key` can come from the
    /// same [`super::BfvKeyGenerator::generate_keypair`] the transparent
    /// path uses - unlike BGV, BFV's public key needs no special scaling.
    pub fn with_public_key_real(params: BfvParams, public_key: PublicKey) -> Self {
        Self {
            mode: Mode::RealPublicKey {
                params,
                pk: public_key,
            },
        }
    }

    /// Creates a real secret-key encryptor - see the module doc comment.
    pub fn with_secret_key_real(params: BfvParams, secret_key: SecretKey) -> Self {
        Self {
            mode: Mode::RealSecretKey {
                params,
                sk: secret_key,
            },
        }
    }

    /// Encrypts a BFV plaintext.
    pub fn encrypt<R>(&self, plaintext: &Plaintext, rng: &mut R) -> Result<Ciphertext>
    where
        R: RngCore + CryptoRng,
    {
        match &self.mode {
            Mode::Transparent(inner) => Ok(Ciphertext::new(inner.encrypt(plaintext.inner(), rng)?)),
            Mode::RealSecretKey { params, sk } => {
                let ring = params.ring();
                let m = plaintext.inner().inner().value();
                ring.check_poly(m)?;
                let delta_m = scale_by_delta(ring, m, params.plaintext_modulus())?;

                let a = sample_uniform(ring, rng);
                let e = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let a_s = ring.mul(&a, sk.value())?;
                let c0 = ring.sub(&ring.add(&delta_m, &e)?, &a_s)?;

                Ok(Ciphertext::new(bgv::Ciphertext::new(
                    phantom_lattice::rlwe::Ciphertext::new(vec![c0, a]),
                )))
            }
            Mode::RealPublicKey { params, pk } => {
                let ring = params.ring();
                let m = plaintext.inner().inner().value();
                ring.check_poly(m)?;
                let delta_m = scale_by_delta(ring, m, params.plaintext_modulus())?;

                let u = sample_ternary(ring, rng);
                let e0 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let e1 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let b_u = ring.mul(&pk.value()[0], &u)?;
                let a_u = ring.mul(&pk.value()[1], &u)?;
                let c0 = ring.add(&ring.add(&delta_m, &b_u)?, &e0)?;
                let c1 = ring.add(&a_u, &e1)?;

                Ok(Ciphertext::new(bgv::Ciphertext::new(
                    phantom_lattice::rlwe::Ciphertext::new(vec![c0, c1]),
                )))
            }
        }
    }
}

/// Scales `poly` by `Delta = floor(Q/t)` (`Q` = `ring`'s own modulus
/// product), one RNS component at a time - `Delta` itself generally doesn't
/// fit in a `u64` for a multi-modulus ring, so it can't be applied via a
/// single scalar multiply; [`floor_divide_residues`] gives its residues per
/// component instead.
fn scale_by_delta(ring: &Ring, poly: &Poly, t: u64) -> phantom_ring::Result<Poly> {
    let basis = RnsBasis::new(ring.moduli().to_vec())?;
    let delta_residues = floor_divide_residues(&basis, t);

    let mut coeffs = vec![vec![0u64; poly.degree()]; poly.moduli_count()];
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let delta_j = delta_residues[j];
        for (out, &c) in coeffs[j].iter_mut().zip(&poly.coeffs()[j]) {
            *out = mul_mod(c, delta_j, modulus.value());
        }
    }
    Poly::from_coeffs(coeffs)
}
