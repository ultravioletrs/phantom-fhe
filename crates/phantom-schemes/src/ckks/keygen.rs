//! CKKS key generation.

use phantom_lattice::rlwe::{
    GaloisKey, PublicKey, RelinearizationKey, SecretDistribution, SecretKey,
};
use rand_core::{CryptoRng, RngCore};

use super::CkksParams;
use crate::Result;

/// Generated CKKS key pair.
#[derive(Clone, Debug)]
pub struct CkksKeyPair {
    /// Secret key.
    pub secret: SecretKey,
    /// Public key.
    pub public: PublicKey,
}

/// Evaluation keys used by CKKS evaluators.
#[derive(Clone, Debug)]
pub struct EvaluationKeys {
    /// Relinearization key.
    pub relinearization: RelinearizationKey,
    /// Rotation/Galois keys.
    pub galois: Vec<GaloisKey>,
}

/// CKKS key generator.
#[derive(Clone, Debug)]
pub struct CkksKeyGenerator {
    params: CkksParams,
    inner: phantom_lattice::rlwe::KeyGenerator,
}

impl CkksKeyGenerator {
    /// Creates a key generator.
    pub fn new(params: CkksParams) -> Result<Self> {
        Ok(Self {
            inner: phantom_lattice::rlwe::KeyGenerator::new(params.rlwe_params()?),
            params,
        })
    }

    /// Generates a ternary-secret key pair.
    pub fn generate_keypair<R>(&self, rng: &mut R) -> Result<CkksKeyPair>
    where
        R: RngCore + CryptoRng,
    {
        let secret = self
            .inner
            .generate_secret_key(rng, SecretDistribution::Ternary);
        let public = self.inner.generate_public_key(&secret, rng)?;
        Ok(CkksKeyPair { secret, public })
    }

    /// Generates evaluation keys for requested rotation elements.
    pub fn generate_evaluation_keys(
        &self,
        secret: &SecretKey,
        rotation_elements: &[usize],
    ) -> EvaluationKeys {
        EvaluationKeys {
            relinearization: self.inner.generate_relinearization_key(secret),
            galois: self.inner.generate_galois_keys(rotation_elements, secret),
        }
    }

    /// Generates a real relinearization key for
    /// [`super::Evaluator::relinearize_real`]. A real CKKS ciphertext is
    /// structurally a plain RLWE ciphertext (its message is Delta-scaled by
    /// the encoder, not by any relinearization-key-specific mechanism), so
    /// this is a direct, unmodified pass-through to
    /// [`phantom_lattice::rlwe::KeyGenerator::generate_hybrid_relinearization_key`],
    /// the same reasoning [`crate::bfv::BfvKeyGenerator::generate_hybrid_relinearization_key`]
    /// documents for BFV.
    pub fn generate_hybrid_relinearization_key<R>(
        &self,
        sk: &SecretKey,
        p_moduli: &[phantom_ring::Modulus],
        rng: &mut R,
    ) -> Result<phantom_lattice::rlwe::RelinearizationKey>
    where
        R: RngCore + CryptoRng,
    {
        Ok(self
            .inner
            .generate_hybrid_relinearization_key(sk, p_moduli, rng)?)
    }

    /// Generates a real relinearization key valid at `level` specifically,
    /// rather than at `self`'s own (top) level.
    ///
    /// A [`RelinearizationKey`] from [`Self::generate_hybrid_relinearization_key`]
    /// is *not* usable to relinearize a ciphertext at any level below the
    /// one that key generator was constructed with:
    /// [`phantom_lattice::rlwe::key_switch`] rejects it outright
    /// (`ksk.rows.len()` was fixed to the *original* ring's own modulus
    /// count at key-generation time, which no longer matches a
    /// lower-level ciphertext's own smaller `q_moduli.len()`) - found while
    /// wiring up `phantom-circuits`'s first real multi-level CKKS
    /// evaluator (Workstream 6 item 2/3), which needs to relinearize after
    /// *every* rescale in a Horner-method chain, i.e. at every level from
    /// the input's own down to `0`.
    ///
    /// This builds a fresh key generator and relinearization key entirely
    /// within `self.params.at_level(level)`'s own smaller ring, truncating
    /// `sk` to match first (repeated
    /// [`phantom_ring::rns::rescale::drop_last_modulus`], the same
    /// technique [`super::Decryptor::decrypt_real`] already uses to bring a
    /// full-level secret key down to a real ciphertext's own level) - a
    /// caller building a multi-level circuit needs one such key per level
    /// it will relinearize at, generated once and reused across every
    /// ciphertext that reaches that level.
    pub fn generate_hybrid_relinearization_key_at_level<R>(
        &self,
        sk: &SecretKey,
        level: usize,
        p_moduli: &[phantom_ring::Modulus],
        rng: &mut R,
    ) -> Result<phantom_lattice::rlwe::RelinearizationKey>
    where
        R: RngCore + CryptoRng,
    {
        let level_params = self.params.at_level(level)?;
        let target_moduli = level_params.ring().moduli().len();
        let mut sk_value = sk.value().clone();
        while sk_value.moduli_count() > target_moduli {
            sk_value = phantom_ring::rns::rescale::drop_last_modulus(&sk_value)?;
        }
        let level_sk = SecretKey::new(sk_value);
        let level_keygen = phantom_lattice::rlwe::KeyGenerator::new(level_params.rlwe_params()?);
        Ok(level_keygen.generate_hybrid_relinearization_key(&level_sk, p_moduli, rng)?)
    }

    /// Generates a real Galois (rotation) key for `element`, usable with
    /// [`phantom_lattice::rlwe::Evaluator::apply_galois_automorphism`]. A
    /// real CKKS ciphertext is structurally a plain RLWE ciphertext (see
    /// [`Self::generate_hybrid_relinearization_key`]'s own doc comment), so
    /// this is a direct, unmodified pass-through to
    /// [`phantom_lattice::rlwe::KeyGenerator::generate_hybrid_galois_key`].
    pub fn generate_hybrid_galois_key<R>(
        &self,
        element: usize,
        sk: &SecretKey,
        p_moduli: &[phantom_ring::Modulus],
        rng: &mut R,
    ) -> Result<GaloisKey>
    where
        R: RngCore + CryptoRng,
    {
        Ok(self
            .inner
            .generate_hybrid_galois_key(element, sk, p_moduli, rng)?)
    }

    /// Generates a real Galois key valid at `level` specifically, rather
    /// than at `self`'s own (top) level - the exact same problem
    /// [`Self::generate_hybrid_relinearization_key_at_level`]'s own doc
    /// comment describes and fixes for relinearization keys applies
    /// identically here (`phantom_lattice::rlwe::key_switch` underlies
    /// both `apply_galois_automorphism` and `relinearize`, and rejects a
    /// key generated at the wrong level the same way either time) - found
    /// while wiring up a real, multi-step `phantom_circuits::ckks::LinearTransformEvaluator::apply_real`
    /// chain (coefficients-to-slots followed by slots-to-coefficients),
    /// which rescales (and so drops a level) between the two calls, the
    /// same way a Horner-method circuit's own relinearization needs a
    /// fresh key per level. Builds a fresh key generator and Galois key
    /// entirely within `self.params.at_level(level)`'s own smaller ring,
    /// truncating `sk` to match first, the same way
    /// [`Self::generate_hybrid_relinearization_key_at_level`] does.
    pub fn generate_hybrid_galois_key_at_level<R>(
        &self,
        element: usize,
        sk: &SecretKey,
        level: usize,
        p_moduli: &[phantom_ring::Modulus],
        rng: &mut R,
    ) -> Result<GaloisKey>
    where
        R: RngCore + CryptoRng,
    {
        let level_params = self.params.at_level(level)?;
        let target_moduli = level_params.ring().moduli().len();
        let mut sk_value = sk.value().clone();
        while sk_value.moduli_count() > target_moduli {
            sk_value = phantom_ring::rns::rescale::drop_last_modulus(&sk_value)?;
        }
        let level_sk = SecretKey::new(sk_value);
        let level_keygen = phantom_lattice::rlwe::KeyGenerator::new(level_params.rlwe_params()?);
        Ok(level_keygen.generate_hybrid_galois_key(element, &level_sk, p_moduli, rng)?)
    }
}
