//! BFV evaluator.

use phantom_ring::rns::extension::extend_basis;
use phantom_ring::rns::rescale::rescale_and_round;
use phantom_ring::{Degree, Modulus, Poly, Ring, RnsBasis};

use super::{BfvParams, Ciphertext, EvaluationKeys, Plaintext};
use crate::{bgv, Result};

/// BFV homomorphic evaluator.
#[derive(Clone, Debug)]
pub struct Evaluator {
    params: BfvParams,
    inner: bgv::Evaluator,
}

impl Evaluator {
    /// Creates an evaluator.
    pub fn new(params: BfvParams) -> Result<Self> {
        let inner = bgv::Evaluator::new(params.inner().clone())?;
        Ok(Self { params, inner })
    }

    /// Adds two ciphertexts.
    pub fn add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(self.inner.add(lhs.inner(), rhs.inner())?))
    }

    /// Subtracts two ciphertexts.
    pub fn sub(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(self.inner.sub(lhs.inner(), rhs.inner())?))
    }

    /// Negates a ciphertext.
    pub fn neg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(self.inner.neg(ciphertext.inner())?))
    }

    /// Adds a plaintext to a ciphertext.
    pub fn add_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner
                .add_plain(ciphertext.inner(), plaintext.inner())?,
        ))
    }

    /// Adds a plaintext to a **real** BFV ciphertext. Unlike [`Self::add_plain`]
    /// (adds the raw plaintext directly, correct only for transparent
    /// ciphertexts), this scales the plaintext by `Delta` first, the same
    /// scaling [`super::Encryptor`]'s real path applies at encryption time,
    /// so `c0 + Delta*m2` correctly combines with `c0 + c1*s = Delta*m1 +
    /// noise` to give `Delta*(m1+m2) + noise`. Hand-derived and verified
    /// numerically (Python) before implementing.
    ///
    /// [`Self::mul_plain`] needs no such counterpart: multiplying by a
    /// small, unscaled plaintext doesn't need `Delta`-awareness the way
    /// adding one does - `(c0+c1*s)*m2 = Delta*m1*m2 + noise*m2`, already
    /// exactly the form a real ciphertext needs, verified numerically
    /// alongside this.
    pub fn add_plain_real(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext> {
        let ring = self.params.ring();
        let m = plaintext.inner().inner().value();
        ring.check_poly(m)?;
        let delta_m = super::encryptor::scale_by_delta(ring, m, self.params.plaintext_modulus())?;

        let mut components = ciphertext.inner().inner().value().to_vec();
        let Some(c0) = components.first_mut() else {
            return Err(crate::SchemesError::DimensionMismatch);
        };
        *c0 = ring.add(c0, &delta_m)?;

        Ok(Ciphertext::new(bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(components),
        )))
    }

    /// Multiplies two ciphertexts and optionally relinearizes with evaluation keys.
    pub fn mul(
        &self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        evaluation_keys: Option<&EvaluationKeys>,
    ) -> Result<Ciphertext> {
        let keys = evaluation_keys.map(|keys| &keys.inner);
        Ok(Ciphertext::new(self.inner.mul(
            lhs.inner(),
            rhs.inner(),
            keys,
        )?))
    }

    /// Multiplies two **real** BFV ciphertexts, producing a degree-2
    /// (3-component) result - no relinearization is applied. Unlike
    /// [`Self::mul`] (correct only for transparent ciphertexts, since it's
    /// a raw ring product with no `Delta`-awareness), this performs the
    /// real BFV tensor-and-rescale procedure: the raw tensor product's true
    /// coefficient magnitude can reach roughly `degree * (Q/2)^2` (far
    /// larger than `Q` itself has room for), so both ciphertexts are first
    /// extended into an auxiliary `Q ∪ P` basis (`p_moduli` chosen with
    /// enough headroom - see [`phantom_ring::rns::rescale::rescale_and_round`]'s
    /// own doc comment) where the tensor product can be computed without
    /// wraparound, then [`rescale_and_round`] scales each component by
    /// `t/Q` and reduces it back into `Q`'s own basis. Hand-derived and
    /// verified numerically (Python, both true unbounded-integer arithmetic
    /// and an RNS-mechanized simulation, each cross-checked against real
    /// BFV encrypt/multiply/decrypt round trips) before implementing.
    pub fn mul_real(
        &self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        p_moduli: &[Modulus],
    ) -> Result<Ciphertext> {
        let ring = self.params.ring();
        let q_basis = RnsBasis::new(ring.moduli().to_vec())?;
        let p_basis = RnsBasis::new(p_moduli.to_vec())?;
        let qp_moduli: Vec<Modulus> = ring
            .moduli()
            .iter()
            .chain(p_moduli.iter())
            .copied()
            .collect();
        let qp_ring = Ring::new(Degree::new(ring.degree())?, qp_moduli.clone())?;
        let qp_basis = RnsBasis::new(qp_moduli)?;

        let extend = |poly: &Poly| extend_basis(poly, &q_basis, &qp_basis);
        let lhs_c0 = extend(&lhs.inner().inner().value()[0])?;
        let lhs_c1 = extend(&lhs.inner().inner().value()[1])?;
        let rhs_c0 = extend(&rhs.inner().inner().value()[0])?;
        let rhs_c1 = extend(&rhs.inner().inner().value()[1])?;

        let d0 = qp_ring.mul(&lhs_c0, &rhs_c0)?;
        let d1 = qp_ring.add(
            &qp_ring.mul(&lhs_c0, &rhs_c1)?,
            &qp_ring.mul(&lhs_c1, &rhs_c0)?,
        )?;
        let d2 = qp_ring.mul(&lhs_c1, &rhs_c1)?;

        let t = Modulus::new(self.params.plaintext_modulus())?;
        let new_c0 = rescale_and_round(&d0, &q_basis, &p_basis, t)?;
        let new_c1 = rescale_and_round(&d1, &q_basis, &p_basis, t)?;
        let new_c2 = rescale_and_round(&d2, &q_basis, &p_basis, t)?;

        Ok(Ciphertext::new(bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(vec![new_c0, new_c1, new_c2]),
        )))
    }

    /// Multiplies a ciphertext by a plaintext.
    pub fn mul_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner
                .mul_plain(ciphertext.inner(), plaintext.inner())?,
        ))
    }

    /// Rotates packed coefficient slots.
    pub fn rotate_slots(&self, ciphertext: &Ciphertext, shift: usize) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner.rotate_slots(ciphertext.inner(), shift)?,
        ))
    }

    /// Sums `count` rotations into the first slot interval.
    pub fn sum_slots(&self, ciphertext: &Ciphertext, count: usize) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner.sum_slots(ciphertext.inner(), count)?,
        ))
    }
}
