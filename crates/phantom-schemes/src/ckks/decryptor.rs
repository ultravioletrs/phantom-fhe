//! CKKS decryption.
//!
//! [`Decryptor::decrypt`] is unchanged: a correctness scaffold that returns
//! the transparent ciphertext's own slots directly, kept so every existing
//! caller keeps compiling and behaving identically. [`Decryptor::decrypt_real`]
//! is new: genuine RLWE decryption of a real ciphertext
//! ([`super::Encryptor::encrypt_real`]'s output, or
//! [`super::Evaluator`]'s own real-path operations on one), reusing
//! [`phantom_lattice::rlwe::Decryptor`] directly (the same generic `c0 +
//! c1*s + c2*s^2 + ...` formula BGV/BFV's own real decryption reuses
//! unmodified). Since [`super::Evaluator::rescale_next_real`] can drop RNS
//! components from a ciphertext, `decrypt_real` derives its own working
//! ring/secret key from the ciphertext's own level rather than assuming
//! the context's full-level ring - see [`super::CkksParams::at_level`].

use phantom_lattice::rlwe::SecretKey;
use phantom_ring::rns::rescale::drop_last_modulus;

use super::{Ciphertext, CkksParams, Plaintext};
use crate::{Result, SchemesError};

/// CKKS decryptor.
#[derive(Clone, Debug)]
pub struct Decryptor {
    params: CkksParams,
    sk: Option<SecretKey>,
}

impl Decryptor {
    /// Creates a decryptor (transparent path only - see the module doc
    /// comment).
    pub fn new(params: CkksParams, secret_key: SecretKey) -> Result<Self> {
        let _ = secret_key;
        params.rlwe_params()?;
        Ok(Self { params, sk: None })
    }

    /// Creates a real decryptor. `secret_key` should be the full-level key
    /// (from [`super::CkksKeyGenerator::generate_keypair`]) regardless of
    /// which level ciphertexts passed to [`Self::decrypt_real`] are
    /// actually at - it's truncated to match each ciphertext automatically.
    pub fn new_real(params: CkksParams, secret_key: SecretKey) -> Result<Self> {
        params.rlwe_params()?;
        Ok(Self {
            params,
            sk: Some(secret_key),
        })
    }

    /// Decrypts a CKKS ciphertext.
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Plaintext> {
        if ciphertext.slots().len() > self.params.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        Ok(Plaintext::new(
            ciphertext.slots().to_vec(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
        ))
    }

    /// Decrypts a **real** ciphertext - see the module doc comment. The
    /// result carries no decoded slots ([`Plaintext::slots`] is empty);
    /// decode it with [`super::Encoder::decode_complex_real`].
    pub fn decrypt_real(&self, ciphertext: &Ciphertext) -> Result<Plaintext> {
        let sk = self.sk.as_ref().ok_or(SchemesError::InvalidParameters(
            "decrypt_real requires a real decryptor - use Decryptor::new_real",
        ))?;
        let poly_ct = ciphertext.poly().ok_or(SchemesError::InvalidParameters(
            "ciphertext has no real ring representation - encrypt with Encryptor::encrypt_real",
        ))?;
        let level_params = self.params.at_level(ciphertext.level())?;

        let mut sk_value = sk.value().clone();
        while sk_value.moduli_count() > level_params.ring().moduli().len() {
            sk_value = drop_last_modulus(&sk_value)?;
        }

        let rlwe_decryptor = phantom_lattice::rlwe::Decryptor::new(
            level_params.rlwe_params()?,
            SecretKey::new(sk_value),
        );
        let decrypted = rlwe_decryptor.decrypt(poly_ct)?;

        Ok(Plaintext::new_real(
            Vec::new(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
            decrypted.into_value(),
        ))
    }
}
