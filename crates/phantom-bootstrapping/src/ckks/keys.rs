//! CKKS bootstrapping keys.

use phantom_lattice::rlwe::{GaloisKey, SecretKey};
use phantom_ring::Modulus;
use phantom_schemes::ckks::CkksKeyGenerator;
use rand_core::{CryptoRng, RngCore};

use super::BootstrapParams;
use crate::Result;

/// CKKS bootstrapping key. Always carries [`Self::rotation_elements`];
/// [`Self::galois_keys`] is empty for a transparent marker built by
/// [`BootstrapKeyGenerator::generate`], or holds one real
/// [`GaloisKey`] per rotation element (same order) when built by
/// [`BootstrapKeyGenerator::generate_real`].
#[derive(Clone, Debug)]
pub struct BootstrapKey {
    params: BootstrapParams,
    rotation_elements: Vec<usize>,
    galois_keys: Vec<GaloisKey>,
}

impl BootstrapKey {
    /// Creates a transparent bootstrap key marker (no key material).
    pub fn new(params: BootstrapParams, rotation_elements: Vec<usize>) -> Self {
        Self {
            params,
            rotation_elements,
            galois_keys: Vec::new(),
        }
    }

    fn with_galois_keys(
        params: BootstrapParams,
        rotation_elements: Vec<usize>,
        galois_keys: Vec<GaloisKey>,
    ) -> Self {
        Self {
            params,
            rotation_elements,
            galois_keys,
        }
    }

    /// Returns bootstrapping parameters.
    pub const fn params(&self) -> &BootstrapParams {
        &self.params
    }

    /// Returns requested rotation elements.
    pub fn rotation_elements(&self) -> &[usize] {
        &self.rotation_elements
    }

    /// Returns real Galois (rotation) key material, one per
    /// [`Self::rotation_elements`] in the same order - empty unless this
    /// key was built by [`BootstrapKeyGenerator::generate_real`]. Not yet
    /// consumed by [`super::Bootstrapper::bootstrap`], whose
    /// `CoeffsToSlots`/`SlotsToCoeffs`/`EvalMod` stages still operate on
    /// transparent slots directly rather than by homomorphically rotating a
    /// real ciphertext - the same "real but not yet wired into a
    /// construction" state `RgswCiphertext` was in before any bootstrapping
    /// construction consumed it.
    pub fn galois_keys(&self) -> &[GaloisKey] {
        &self.galois_keys
    }
}

/// Generates CKKS bootstrapping keys.
#[derive(Clone, Debug)]
pub struct BootstrapKeyGenerator {
    params: BootstrapParams,
}

impl BootstrapKeyGenerator {
    /// Creates a key generator.
    pub const fn new(params: BootstrapParams) -> Self {
        Self { params }
    }

    /// Generates a transparent bootstrap key marker for the requested
    /// rotations - no cryptographic content, for callers with no single
    /// secret key available (e.g. a threshold/multiparty aggregation) or
    /// that don't yet need real key material.
    pub fn generate(&self, rotation_elements: &[usize]) -> BootstrapKey {
        BootstrapKey::new(self.params.clone(), rotation_elements.to_vec())
    }

    /// Generates a bootstrap key with real Galois (rotation) key material,
    /// one [`phantom_schemes::ckks::CkksKeyGenerator::generate_hybrid_galois_key`]
    /// per element of `rotation_elements`, from `secret` and the auxiliary
    /// `p_moduli` real hybrid key-switching needs (see
    /// [`CkksKeyGenerator::generate_hybrid_relinearization_key`]'s own doc
    /// comment for what these are). See [`BootstrapKey::galois_keys`] for
    /// what currently consumes this (nothing yet).
    pub fn generate_real<R>(
        &self,
        secret: &SecretKey,
        rotation_elements: &[usize],
        p_moduli: &[Modulus],
        rng: &mut R,
    ) -> Result<BootstrapKey>
    where
        R: RngCore + CryptoRng,
    {
        let keygen = CkksKeyGenerator::new(self.params.ckks_params().clone())?;
        let galois_keys = rotation_elements
            .iter()
            .map(|&element| keygen.generate_hybrid_galois_key(element, secret, p_moduli, rng))
            .collect::<phantom_schemes::Result<Vec<_>>>()?;
        Ok(BootstrapKey::with_galois_keys(
            self.params.clone(),
            rotation_elements.to_vec(),
            galois_keys,
        ))
    }
}
