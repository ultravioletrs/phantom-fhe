//! RLWE key generation.

use phantom_ring::rns::extension::extend_basis;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary, sample_uniform};
use phantom_ring::{Modulus, RnsBasis};
use rand_core::{CryptoRng, RngCore};

use crate::rlwe::keyswitch::generate_key_switch_key;
use crate::rlwe::{GaloisKey, PublicKey, RelinearizationKey, RlweParams, SecretKey};
use crate::Result;

/// Secret key distribution.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SecretDistribution {
    /// Ternary coefficients {-1, 0, 1}.
    Ternary,
    /// Discrete Gaussian with the given standard deviation.
    Gaussian { sigma: f64 },
}

/// RLWE key generator.
#[derive(Clone, Debug)]
pub struct KeyGenerator {
    params: RlweParams,
}

impl KeyGenerator {
    /// Creates a key generator.
    pub const fn new(params: RlweParams) -> Self {
        Self { params }
    }

    /// Returns parameters.
    pub const fn params(&self) -> &RlweParams {
        &self.params
    }

    /// Generates a secret key.
    pub fn generate_secret_key<R>(&self, rng: &mut R, distribution: SecretDistribution) -> SecretKey
    where
        R: RngCore + CryptoRng,
    {
        let value = match distribution {
            SecretDistribution::Ternary => sample_ternary(self.params.ring(), rng),
            SecretDistribution::Gaussian { sigma } => {
                sample_discrete_gaussian(self.params.ring(), rng, sigma)
            }
        };
        SecretKey::new(value)
    }

    /// Generates a public key: `(b, a) = (-(a*s + e), a)`, a real (noisy)
    /// RLWE-of-zero - `b + a*s = -e`, small but nonzero, per
    /// [`crate::security::STANDARD_ERROR_STD_DEV`].
    pub fn generate_public_key<R>(&self, sk: &SecretKey, rng: &mut R) -> Result<PublicKey>
    where
        R: RngCore + CryptoRng,
    {
        let a = sample_uniform(self.params.ring(), rng);
        let e = sample_discrete_gaussian(
            self.params.ring(),
            rng,
            crate::security::STANDARD_ERROR_STD_DEV,
        );
        let as_prod = self.params.ring().mul(&a, sk.value())?;
        let noisy = self.params.ring().add(&as_prod, &e)?;
        let b = self.params.ring().neg(&noisy)?;
        Ok(PublicKey::new(b, a))
    }

    /// Generates the identity-preserving placeholder relinearization key -
    /// what every scheme crate above this layer still gets, since none of
    /// them yet supply the auxiliary `P` moduli
    /// [`generate_hybrid_relinearization_key`](Self::generate_hybrid_relinearization_key)
    /// needs.
    pub const fn generate_relinearization_key(&self, _sk: &SecretKey) -> RelinearizationKey {
        RelinearizationKey::placeholder()
    }

    /// Generates a real relinearization key: an RNS hybrid key-switching
    /// key from `s²` to `s` (`sk` must be ternary - see
    /// [`crate::rlwe::rebase_ternary_secret`]), using `p_moduli` as the
    /// auxiliary basis. `s²` needs no special centered lift before being
    /// handed to [`generate_key_switch_key`]: for any representative `T`
    /// of `s²`'s true value congruent mod `Q` (in particular the raw `[0,
    /// Q)` CRT reconstruction [`extend_basis`] produces), `P · (Q/q_j) ·
    /// T ≡ P · (Q/q_j) · s² (mod QP)`, because `P · (Q/q_j) · Q` is itself
    /// an exact multiple of `QP` - verified numerically (Python, 100
    /// randomized trials with non-ternary `s_old` values) before relying on
    /// it here.
    pub fn generate_hybrid_relinearization_key<R>(
        &self,
        sk: &SecretKey,
        p_moduli: &[Modulus],
        rng: &mut R,
    ) -> Result<RelinearizationKey>
    where
        R: RngCore + CryptoRng,
    {
        let ring = self.params.ring();
        let s_squared = ring.mul(sk.value(), sk.value())?;

        let q_basis = RnsBasis::new(ring.moduli().to_vec())?;
        let qp_moduli: Vec<Modulus> = ring
            .moduli()
            .iter()
            .chain(p_moduli.iter())
            .copied()
            .collect();
        let qp_basis = RnsBasis::new(qp_moduli)?;
        let s_squared_qp = extend_basis(&s_squared, &q_basis, &qp_basis)?;

        let ksk = generate_key_switch_key(&self.params, p_moduli, &s_squared_qp, sk, rng)?;
        Ok(RelinearizationKey::from_key_switch_key(ksk))
    }

    /// Generates placeholder Galois key markers.
    pub fn generate_galois_keys(&self, elements: &[usize], _sk: &SecretKey) -> Vec<GaloisKey> {
        elements.iter().copied().map(GaloisKey::new).collect()
    }
}
