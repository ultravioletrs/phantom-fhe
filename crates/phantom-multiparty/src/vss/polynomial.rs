//! A dealer's own degree-`(t-1)`, vector-valued random polynomial - the
//! core Pedersen VSS dealing primitive.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand_core::{CryptoRng, RngCore};

use super::generators::PedersenGenerators;
use super::scalar_embed::embed_centered;
use super::share::{VssCommitmentSet, VssShare};
use crate::common::ParticipantId;
use crate::{MultipartyError, Result};

/// One dealer's own local random polynomial: `t` vector-valued coefficients
/// `a_0..a_{t-1}`, each a length-`N` vector of scalars (`N` = the dealer's
/// own secret vector length, i.e. the RLWE ring degree once wired into a
/// scheme's own key generation - not attempted in this crate yet, see this
/// module's own parent doc comment). `a_0` is the dealer's own local secret
/// contribution (embedded from small centered integers via
/// [`embed_centered`]); every other coefficient is a uniformly random
/// full-range scalar, the standard Shamir requirement. A companion,
/// per-degree blinding scalar (`b_0..b_{t-1}`, plain scalars, not vectors)
/// gives the Pedersen commitment its hiding property - see
/// [`Self::commit`]'s own doc comment for why one blinding scalar per
/// degree (not one per coordinate) is still cryptographically sound.
///
/// Never serialized or sent anywhere as a whole - only [`Self::commit`]'s
/// own output (public) and [`Self::create_share`]'s own output (sent to
/// exactly one recipient) ever leave a dealer's own process. Manually
/// zeroed on drop, the same convention
/// [`phantom_lattice::rlwe::SecretKey`] already uses for RLWE secret
/// material.
pub struct VectorPolynomial {
    dealer: ParticipantId,
    /// `coefficient_vectors[k]` is the length-`N` vector for degree `k`.
    coefficient_vectors: Vec<Vec<Scalar>>,
    /// `blinding_coefficients[k]` is the degree-`k` blinding scalar.
    blinding_coefficients: Vec<Scalar>,
}

impl VectorPolynomial {
    /// Samples a fresh random polynomial for `dealer`, whose constant term
    /// is `secret` (the dealer's own small centered-integer contribution)
    /// and whose `threshold - 1` higher-degree coefficient vectors are
    /// uniformly random.
    pub fn sample<R: RngCore + CryptoRng>(
        rng: &mut R,
        dealer: ParticipantId,
        secret: &[i128],
        threshold: usize,
    ) -> Result<Self> {
        if threshold == 0 {
            return Err(MultipartyError::InvalidParameters(
                "VectorPolynomial::sample: threshold must be nonzero",
            ));
        }
        if secret.is_empty() {
            return Err(MultipartyError::InvalidParameters(
                "VectorPolynomial::sample: secret must be nonempty",
            ));
        }
        let vector_len = secret.len();
        let degree_zero = secret
            .iter()
            .map(|&v| embed_centered(v))
            .collect::<Result<Vec<Scalar>>>()?;
        let mut coefficient_vectors = Vec::with_capacity(threshold);
        coefficient_vectors.push(degree_zero);
        for _ in 1..threshold {
            coefficient_vectors.push((0..vector_len).map(|_| Scalar::random(rng)).collect());
        }
        let blinding_coefficients = (0..threshold).map(|_| Scalar::random(rng)).collect();
        Ok(Self {
            dealer,
            coefficient_vectors,
            blinding_coefficients,
        })
    }

    /// Returns the vector length `N`.
    pub fn vector_len(&self) -> usize {
        self.coefficient_vectors[0].len()
    }

    /// Returns the threshold `t` (this polynomial's own degree is `t - 1`).
    pub fn threshold(&self) -> usize {
        self.coefficient_vectors.len()
    }

    /// Evaluates the vector polynomial (and its companion blinding
    /// polynomial) at `x` via Horner's method: `(f(x), rho(x))` where
    /// `f(x)[j] = sum_k coefficient_vectors[k][j] * x^k` and `rho(x) =
    /// sum_k blinding_coefficients[k] * x^k`.
    pub fn evaluate(&self, x: Scalar) -> (Vec<Scalar>, Scalar) {
        let mut f = vec![Scalar::ZERO; self.vector_len()];
        for coefficients in self.coefficient_vectors.iter().rev() {
            for (fj, cj) in f.iter_mut().zip(coefficients) {
                *fj = *fj * x + cj;
            }
        }
        let mut rho = Scalar::ZERO;
        for &r in self.blinding_coefficients.iter().rev() {
            rho = rho * x + r;
        }
        (f, rho)
    }

    /// Creates the share this dealer sends to `recipient`: evaluates at
    /// `recipient`'s own [`ParticipantId`] (used directly as the Shamir
    /// evaluation point - the standard convention, no separate index
    /// mapping needed since [`ParticipantId`]s are already distinct nonzero
    /// integers within a session).
    pub fn create_share(&self, recipient: ParticipantId) -> VssShare {
        let (values, blinding) = self.evaluate(Scalar::from(recipient.get()));
        VssShare::new(self.dealer, recipient, values, blinding)
    }

    /// Commits to this polynomial: `t` Pedersen vector commitments, `C_k =
    /// (sum_j g_j * coefficient_vectors[k][j]) + h * blinding_coefficients[k]`.
    ///
    /// One blinding scalar per degree (not one per coordinate) still gives
    /// perfect hiding of the whole length-`N` vector: `h` generates the
    /// entire (prime-order) group, so as `blinding_coefficients[k]` ranges
    /// uniformly over the field, `C_k` ranges uniformly over the entire
    /// group regardless of `coefficient_vectors[k]` - verified algebraically
    /// (Python) before implementing, see the commit message for this
    /// change's own derivation.
    pub fn commit(&self, generators: &PedersenGenerators) -> Result<VssCommitmentSet> {
        if generators.vector_len() != self.vector_len() {
            return Err(MultipartyError::InvalidParameters(
                "commit: generator/vector length mismatch",
            ));
        }
        let commitments = self
            .coefficient_vectors
            .iter()
            .zip(&self.blinding_coefficients)
            .map(|(coefficients, &blinding)| {
                let mut scalars = coefficients.clone();
                scalars.push(blinding);
                let mut points: Vec<RistrettoPoint> = generators.g().to_vec();
                points.push(generators.h());
                RistrettoPoint::multiscalar_mul(&scalars, &points).compress()
            })
            .collect();
        Ok(VssCommitmentSet::new(self.dealer, commitments))
    }
}

impl Drop for VectorPolynomial {
    fn drop(&mut self) {
        for coefficients in &mut self.coefficient_vectors {
            for scalar in coefficients.iter_mut() {
                *scalar = Scalar::ZERO;
            }
        }
        for scalar in self.blinding_coefficients.iter_mut() {
            *scalar = Scalar::ZERO;
        }
    }
}
