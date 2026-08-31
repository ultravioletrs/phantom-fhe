//! Exact BGV linear transformations for the current coefficient-slot scaffold.

use phantom_schemes::bgv::{BgvParams, Ciphertext};

use crate::common::{BabyStepGiantStepPlan, DiagonalMatrix, LinearTransform};
use crate::error::{CircuitsError, Result};

/// Evaluates BGV linear transformations over coefficient slots.
#[derive(Clone, Debug)]
pub struct LinearTransformEvaluator {
    params: BgvParams,
}

impl LinearTransformEvaluator {
    /// Creates a BGV linear transform evaluator.
    pub const fn new(params: BgvParams) -> Self {
        Self { params }
    }

    /// Returns the number of slots in the current BGV batching scaffold.
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

    /// Applies a dense linear transform to a degree-zero BGV ciphertext.
    pub fn apply(
        &self,
        ciphertext: &Ciphertext,
        transform: &LinearTransform<u64>,
    ) -> Result<Ciphertext> {
        self.check_transform(transform)?;
        self.check_degree_zero(ciphertext)?;

        let modulus = self.params.plaintext_modulus();
        let in_component = &ciphertext.inner().value()[0];
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

        Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
            vec![out_component],
        )))
    }

    /// Applies a diagonalized transform to a degree-zero BGV ciphertext.
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

    fn check_degree_zero(&self, ciphertext: &Ciphertext) -> Result<()> {
        if ciphertext.degree() != 0 {
            return Err(CircuitsError::InvalidParameters(
                "BGV linear transform scaffold expects degree-zero ciphertexts",
            ));
        }
        self.params
            .ring()
            .check_poly(&ciphertext.inner().value()[0])
            .map_err(|_| CircuitsError::SchemeOperation("invalid BGV ciphertext"))?;
        Ok(())
    }
}
