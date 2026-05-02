//! CKKS linear transformations over transparent approximate slots.

use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64};

use crate::ckks::{c_add, c_mul, check_ciphertext, ckks_ciphertext_like, ensure_finite};
use crate::common::{BabyStepGiantStepPlan, DiagonalMatrix, LinearTransform};
use crate::error::{CircuitsError, Result};

/// Evaluates CKKS linear transformations over packed slots.
#[derive(Clone, Debug)]
pub struct LinearTransformEvaluator {
    params: CkksParams,
}

impl LinearTransformEvaluator {
    /// Creates a CKKS linear transform evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Returns the supported slot count.
    pub fn slot_count(&self) -> usize {
        self.params.slot_count()
    }

    /// Converts a dense slot matrix into cyclic diagonals.
    pub fn diagonalize(
        &self,
        transform: &LinearTransform<Complex64>,
    ) -> Result<DiagonalMatrix<Complex64>> {
        self.check_transform(transform)?;
        Ok(transform.to_diagonal_matrix())
    }

    /// Plans a baby-step giant-step schedule for a dense transform.
    pub fn bsgs_plan(
        &self,
        transform: &LinearTransform<Complex64>,
        baby_step_count: usize,
    ) -> Result<BabyStepGiantStepPlan> {
        self.diagonalize(transform)?.bsgs_plan(baby_step_count)
    }

    /// Applies a dense linear transform to CKKS slots.
    pub fn apply(
        &self,
        ciphertext: &Ciphertext,
        transform: &LinearTransform<Complex64>,
    ) -> Result<Ciphertext> {
        check_ciphertext(&self.params, ciphertext)?;
        self.check_transform(transform)?;
        if ciphertext.slots().len() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }

        let mut out = vec![Complex64::default(); self.slot_count()];
        for (row_index, row) in transform.rows().iter().enumerate() {
            let mut acc = Complex64::default();
            for (weight, value) in row.iter().copied().zip(ciphertext.slots().iter().copied()) {
                acc = c_add(acc, c_mul(weight, value));
            }
            out[row_index] = acc;
        }
        ensure_finite(&out)?;
        Ok(ckks_ciphertext_like(ciphertext, out, 0.5))
    }

    /// Applies a diagonalized transform to CKKS slots.
    pub fn apply_diagonal(
        &self,
        ciphertext: &Ciphertext,
        diagonals: &DiagonalMatrix<Complex64>,
    ) -> Result<Ciphertext> {
        if diagonals.slot_count() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }
        let transform = LinearTransform::dense(diagonals.to_dense())?;
        self.apply(ciphertext, &transform)
    }

    fn check_transform(&self, transform: &LinearTransform<Complex64>) -> Result<()> {
        if transform.slot_count() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }
        Ok(())
    }
}
