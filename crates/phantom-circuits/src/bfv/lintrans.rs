//! Exact BFV linear transformations for the current coefficient-slot
//! scaffold, plus a real (encrypted) evaluator
//! ([`LinearTransformEvaluator::apply_real`]) - see
//! `crate::bgv::lintrans`'s own module doc comment for why this is scoped
//! to row-local (block-diagonal) transforms rather than reusing
//! [`DiagonalMatrix`] directly (BFV shares BGV's plaintext ring/slot
//! structure entirely, so the same reasoning and the same
//! `row_local_diagonals` helper apply unchanged).

use phantom_schemes::bfv::{BatchEncoder, BfvParams, Ciphertext, Evaluator};
use phantom_schemes::bgv;

use crate::bgv::lintrans::row_local_diagonals;
use crate::common::{BabyStepGiantStepPlan, DiagonalMatrix, LinearTransform};
use crate::error::{CircuitsError, Result};

/// Evaluates BFV linear transformations over coefficient slots.
#[derive(Clone, Debug)]
pub struct LinearTransformEvaluator {
    params: BfvParams,
}

impl LinearTransformEvaluator {
    /// Creates a BFV linear transform evaluator.
    pub const fn new(params: BfvParams) -> Self {
        Self { params }
    }

    /// Returns the number of slots in the current BFV batching scaffold.
    pub fn slot_count(&self) -> usize {
        self.params.slot_count()
    }

    /// Converts a dense slot matrix into cyclic diagonals.
    pub fn diagonalize(&self, transform: &LinearTransform<u64>) -> Result<DiagonalMatrix<u64>> {
        self.check_transform(transform)?;
        Ok(transform.to_diagonal_matrix())
    }

    /// Plans a baby-step giant-step schedule for a dense transform.
    pub fn bsgs_plan(
        &self,
        transform: &LinearTransform<u64>,
        baby_step_count: usize,
    ) -> Result<BabyStepGiantStepPlan> {
        self.diagonalize(transform)?.bsgs_plan(baby_step_count)
    }

    /// Applies a dense linear transform to a degree-zero BFV ciphertext.
    pub fn apply(
        &self,
        ciphertext: &Ciphertext,
        transform: &LinearTransform<u64>,
    ) -> Result<Ciphertext> {
        self.check_transform(transform)?;
        self.check_degree_zero(ciphertext)?;

        let modulus = self.params.plaintext_modulus();
        let in_component = &ciphertext.inner().inner().value()[0];
        let mut out_component = self.params.ring().zero();

        for rns_index in 0..in_component.moduli_count() {
            let q = self.params.ring().moduli()[rns_index].value();
            for row in 0..self.slot_count() {
                let mut acc = 0u128;
                for col in 0..self.slot_count() {
                    let coeff = (in_component.coeffs()[rns_index][col] % modulus) as u128;
                    let weight = (transform.rows()[row][col] % modulus) as u128;
                    acc = (acc + coeff * weight) % modulus as u128;
                }
                out_component.coeffs_mut()[rns_index][row] = acc as u64 % q;
            }
        }

        Ok(Ciphertext::new(bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(vec![out_component]),
        )))
    }

    /// Applies a diagonalized transform to a degree-zero BFV ciphertext.
    pub fn apply_diagonal(
        &self,
        ciphertext: &Ciphertext,
        diagonals: &DiagonalMatrix<u64>,
    ) -> Result<Ciphertext> {
        if diagonals.slot_count() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }
        let transform = LinearTransform::dense(diagonals.to_dense())?;
        self.apply(ciphertext, &transform)
    }

    fn check_transform(&self, transform: &LinearTransform<u64>) -> Result<()> {
        if transform.slot_count() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }
        Ok(())
    }

    /// Applies a **row-local** dense linear transform to a **real**
    /// (encrypted), [`BatchEncoder::encode_batched`]-encoded BFV
    /// ciphertext, via the rotate-multiply-accumulate diagonal method - see
    /// this module's own doc comment and `crate::bgv::lintrans`'s for why
    /// the row-local restriction and the shared `row_local_diagonals`
    /// helper.
    ///
    /// `rotation_keys` must contain one real
    /// [`phantom_lattice::rlwe::GaloisKey`] (from
    /// [`phantom_schemes::bfv::BfvKeyGenerator::generate_hybrid_galois_key`]
    /// at [`BfvParams::rotation_element`]`(k)`) per nonzero row-local
    /// diagonal offset `k` this transform actually needs, paired with that
    /// same element - offset `0` needs no key.
    pub fn apply_real(
        &self,
        ciphertext: &Ciphertext,
        transform: &LinearTransform<u64>,
        rotation_keys: &[(usize, phantom_lattice::rlwe::GaloisKey)],
    ) -> Result<Ciphertext> {
        self.check_transform(transform)?;
        let half = self.slot_count() / 2;
        let diagonals = row_local_diagonals(transform, half)?;

        let evaluator = Evaluator::new(self.params.clone())
            .map_err(|_| CircuitsError::SchemeOperation("failed to build a BFV evaluator"))?;
        let encoder = BatchEncoder::new(self.params.clone());
        let t = self.params.plaintext_modulus();

        let mut acc: Option<Ciphertext> = None;
        for (k, values) in diagonals {
            let rotated = if k == 0 {
                ciphertext.clone()
            } else {
                let element = self.params.rotation_element(k);
                let key = rotation_keys
                    .iter()
                    .find(|(e, _)| *e == element)
                    .map(|(_, key)| key)
                    .ok_or(CircuitsError::InvalidParameters(
                        "missing a rotation key for a diagonal offset this transform needs",
                    ))?;
                evaluator
                    .rotate_real(ciphertext, key)
                    .map_err(|_| CircuitsError::SchemeOperation("rotate_real failed"))?
            };
            let encoded: Vec<u64> = values.iter().map(|&v| v % t).collect();
            let pt = encoder.encode_batched(&encoded).map_err(|_| {
                CircuitsError::SchemeOperation("failed to encode a transform diagonal")
            })?;
            let term = evaluator
                .mul_plain(&rotated, &pt)
                .map_err(|_| CircuitsError::SchemeOperation("mul_plain failed"))?;
            acc = Some(match acc {
                None => term,
                Some(prev) => evaluator
                    .add(&prev, &term)
                    .map_err(|_| CircuitsError::SchemeOperation("add failed"))?,
            });
        }
        acc.ok_or(CircuitsError::InvalidParameters(
            "transform has no nonzero diagonals",
        ))
    }

    fn check_degree_zero(&self, ciphertext: &Ciphertext) -> Result<()> {
        if ciphertext.degree() != 0 {
            return Err(CircuitsError::InvalidParameters(
                "BFV linear transform scaffold expects degree-zero ciphertexts",
            ));
        }
        self.params
            .ring()
            .check_poly(&ciphertext.inner().inner().value()[0])
            .map_err(|_| CircuitsError::SchemeOperation("invalid BFV ciphertext"))?;
        Ok(())
    }
}
