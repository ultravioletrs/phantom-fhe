//! BFV key generation.

use crate::{bgv, Result};
use rand_core::{CryptoRng, RngCore};

use super::BfvParams;

/// Generated BFV key pair.
#[derive(Clone, Debug)]
pub struct BfvKeyPair {
    /// Secret key.
    pub secret: phantom_lattice::rlwe::SecretKey,
    /// Public key.
    pub public: phantom_lattice::rlwe::PublicKey,
}

/// Evaluation keys used by BFV evaluators.
#[derive(Clone, Debug)]
pub struct EvaluationKeys {
    pub(crate) inner: bgv::EvaluationKeys,
}

/// BFV key generator.
#[derive(Clone, Debug)]
pub struct BfvKeyGenerator {
    inner: bgv::BgvKeyGenerator,
}

impl BfvKeyGenerator {
    /// Creates a key generator.
    pub fn new(params: BfvParams) -> Result<Self> {
        Ok(Self {
            inner: bgv::BgvKeyGenerator::new(params.inner().clone())?,
        })
    }

    /// Generates a ternary-secret key pair.
    pub fn generate_keypair<R>(&self, rng: &mut R) -> Result<BfvKeyPair>
    where
        R: RngCore + CryptoRng,
    {
        let pair = self.inner.generate_keypair(rng)?;
        Ok(BfvKeyPair {
            secret: pair.secret,
            public: pair.public,
        })
    }

    /// Generates evaluation keys for requested rotation elements.
    pub fn generate_evaluation_keys(
        &self,
        secret: &phantom_lattice::rlwe::SecretKey,
        rotation_elements: &[usize],
    ) -> EvaluationKeys {
        EvaluationKeys {
            inner: self
                .inner
                .generate_evaluation_keys(secret, rotation_elements),
        }
    }

    /// Generates a real relinearization key for [`super::Evaluator::relinearize_real`].
    /// Unlike BGV (see [`bgv::BgvKeyGenerator::generate_raw_hybrid_relinearization_key`]'s
    /// own doc comment), BFV has no `t`-scaled-noise requirement to
    /// preserve - real BFV's decode only needs the total noise to stay
    /// under `Delta/2`, which the key-switching key's own ordinary
    /// (raw-noise) contribution comfortably satisfies - so this is a
    /// direct, unmodified pass-through.
    pub fn generate_hybrid_relinearization_key<R>(
        &self,
        sk: &phantom_lattice::rlwe::SecretKey,
        p_moduli: &[phantom_ring::Modulus],
        rng: &mut R,
    ) -> Result<phantom_lattice::rlwe::RelinearizationKey>
    where
        R: RngCore + CryptoRng,
    {
        self.inner
            .generate_raw_hybrid_relinearization_key(sk, p_moduli, rng)
    }

    /// Generates a real Galois (rotation) key for `element` (from
    /// [`super::BfvParams::rotation_element`]/[`super::BfvParams::row_swap_element`]),
    /// for [`super::Evaluator::rotate_real`]. Unlike BGV (see
    /// [`bgv::BgvKeyGenerator::generate_raw_hybrid_galois_key`]'s own doc
    /// comment), BFV has no `t`-scaled-noise requirement to preserve - the
    /// same reasoning [`Self::generate_hybrid_relinearization_key`]'s own
    /// doc comment gives - so this is a direct, unmodified pass-through.
    pub fn generate_hybrid_galois_key<R>(
        &self,
        element: usize,
        sk: &phantom_lattice::rlwe::SecretKey,
        p_moduli: &[phantom_ring::Modulus],
        rng: &mut R,
    ) -> Result<phantom_lattice::rlwe::GaloisKey>
    where
        R: RngCore + CryptoRng,
    {
        self.inner
            .generate_raw_hybrid_galois_key(element, sk, p_moduli, rng)
    }
}
