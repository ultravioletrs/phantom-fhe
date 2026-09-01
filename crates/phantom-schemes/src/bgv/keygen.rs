//! BGV key generation.

use phantom_lattice::rlwe::{
    GaloisKey, PublicKey, RelinearizationKey, SecretDistribution, SecretKey,
};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_uniform};
use rand_core::{CryptoRng, RngCore};

use super::BgvParams;
use crate::Result;

/// Generated BGV key pair.
#[derive(Clone, Debug)]
pub struct BgvKeyPair {
    /// Secret key.
    pub secret: SecretKey,
    /// Public key.
    pub public: PublicKey,
}

/// Evaluation keys used by BGV evaluators.
#[derive(Clone, Debug)]
pub struct EvaluationKeys {
    /// Relinearization key.
    pub relinearization: RelinearizationKey,
    /// Rotation/Galois keys.
    pub galois: Vec<GaloisKey>,
}

/// BGV key generator.
#[derive(Clone, Debug)]
pub struct BgvKeyGenerator {
    params: BgvParams,
    inner: phantom_lattice::rlwe::KeyGenerator,
}

impl BgvKeyGenerator {
    /// Creates a key generator.
    pub fn new(params: BgvParams) -> Result<Self> {
        let inner = phantom_lattice::rlwe::KeyGenerator::new(params.rlwe_params()?);
        Ok(Self { params, inner })
    }

    /// Generates a ternary-secret key pair with a **transparent** public
    /// key (generic raw-noise RLWE, via
    /// [`phantom_lattice::rlwe::KeyGenerator::generate_public_key`]) - kept
    /// for [`super::Encryptor::with_public_key`]'s still-transparent
    /// callers. Not usable with
    /// [`super::Encryptor::with_public_key_real`], which needs the
    /// `t`-scaled public key [`Self::generate_keypair_real`] produces
    /// instead - see that constructor's own doc comment for why.
    pub fn generate_keypair<R>(&self, rng: &mut R) -> Result<BgvKeyPair>
    where
        R: RngCore + CryptoRng,
    {
        let secret = self
            .inner
            .generate_secret_key(rng, SecretDistribution::Ternary);
        let public = self.inner.generate_public_key(&secret, rng)?;
        Ok(BgvKeyPair { secret, public })
    }

    /// Generates a ternary-secret key pair whose public key carries BGV's
    /// own `t`-scaled noise: `b = -a*s + t*e_pk` (`t` = the plaintext
    /// modulus), rather than the generic RLWE public key's raw `-a*s -
    /// e_pk`. Required by [`super::Encryptor::with_public_key_real`]:
    /// public-key encryption folds the key's own noise into the
    /// ciphertext (`c0 + c1*s = m + u*(b+a*s) + ... = m - u*e_pk + ...`),
    /// so if `e_pk` weren't already a multiple of `t`, that term would
    /// survive decryption's final `mod t` reduction and corrupt the
    /// result - unlike secret-key encryption, which never touches a
    /// public key's noise at all. Verified numerically (Python) before
    /// implementing.
    pub fn generate_keypair_real<R>(&self, rng: &mut R) -> Result<BgvKeyPair>
    where
        R: RngCore + CryptoRng,
    {
        let secret = self
            .inner
            .generate_secret_key(rng, SecretDistribution::Ternary);
        let ring = self.params.ring();
        let t = self.params.plaintext_modulus();

        let a = sample_uniform(ring, rng);
        let e_pk = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
        let t_e_pk = ring.scalar_mul(&e_pk, t)?;
        let a_s = ring.mul(&a, secret.value())?;
        let b = ring.sub(&t_e_pk, &a_s)?;

        Ok(BgvKeyPair {
            secret,
            public: PublicKey::new(b, a),
        })
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

    /// Generates a real RNS hybrid relinearization key with **raw**
    /// (not `t`-scaled) key-switching noise - a thin pass-through to
    /// [`phantom_lattice::rlwe::KeyGenerator::generate_hybrid_relinearization_key`].
    ///
    /// **Not safe to use for relinearizing real BGV ciphertexts**: BGV's
    /// mod-`t` decode invariant requires every noise contribution folded
    /// into a ciphertext to be a multiple of `t` (see [`super::Encryptor`]'s
    /// own module doc comment, and `ModulusSwitcher`'s, for the same
    /// requirement elsewhere), but the generic
    /// key-switching key this produces samples its own fresh noise raw,
    /// the same way [`phantom_lattice::rlwe::generate_key_switch_key`]
    /// always has - relinearizing a real BGV ciphertext with it would
    /// silently corrupt the mod-`t` invariant, not just add noise. Giving
    /// BGV relinearization the `t`-scaled key-switching noise it would
    /// need is out of scope here (it would mean either changing the
    /// shared, scheme-agnostic `phantom_lattice::rlwe` key-switching
    /// primitive, which CKKS/Galois rotation also depend on with no `t`
    /// concept, or duplicating its logic here) - tracked as follow-up.
    ///
    /// Exists on this type (rather than only on
    /// [`BfvKeyGenerator`](crate::bfv::BfvKeyGenerator)) because that's
    /// where the underlying
    /// [`phantom_lattice::rlwe::KeyGenerator`] lives - BFV has no
    /// `t`-scaled-noise requirement of its own, so this raw key is exactly
    /// what its real relinearization needs unmodified.
    pub fn generate_raw_hybrid_relinearization_key<R>(
        &self,
        sk: &SecretKey,
        p_moduli: &[phantom_ring::Modulus],
        rng: &mut R,
    ) -> Result<RelinearizationKey>
    where
        R: RngCore + CryptoRng,
    {
        Ok(self
            .inner
            .generate_hybrid_relinearization_key(sk, p_moduli, rng)?)
    }
}
