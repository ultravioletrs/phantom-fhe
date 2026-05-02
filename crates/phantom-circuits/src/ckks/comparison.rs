//! CKKS comparison-style approximation helpers.

use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64};

use crate::ckks::{check_ciphertext, ckks_ciphertext_like, ensure_finite};
use crate::error::{CircuitsError, Result};

/// Evaluates sign, step, and max approximations over CKKS real slots.
#[derive(Clone, Debug)]
pub struct ComparisonEvaluator {
    params: CkksParams,
}

impl ComparisonEvaluator {
    /// Creates a comparison evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Approximates `sign(x)` as `tanh(alpha*x)` on real parts.
    pub fn sign(&self, input: &Ciphertext, alpha: f64) -> Result<Ciphertext> {
        if !alpha.is_finite() || alpha <= 0.0 {
            return Err(CircuitsError::InvalidParameters(
                "sign sharpness must be finite and positive",
            ));
        }
        check_ciphertext(&self.params, input)?;
        let slots = input
            .slots()
            .iter()
            .map(|slot| Complex64::real((alpha * slot.re).tanh()))
            .collect::<Vec<_>>();
        ensure_finite(&slots)?;
        Ok(ckks_ciphertext_like(input, slots, 1.5))
    }

    /// Approximates the unit step function as `(sign(x)+1)/2`.
    pub fn step(&self, input: &Ciphertext, alpha: f64) -> Result<Ciphertext> {
        let sign = self.sign(input, alpha)?;
        let slots = sign
            .slots()
            .iter()
            .map(|slot| Complex64::real(0.5 * (slot.re + 1.0)))
            .collect::<Vec<_>>();
        ensure_finite(&slots)?;
        Ok(ckks_ciphertext_like(&sign, slots, 0.25))
    }

    /// Approximates `max(lhs, rhs)` on real parts using a smooth absolute value.
    pub fn max(&self, lhs: &Ciphertext, rhs: &Ciphertext, epsilon: f64) -> Result<Ciphertext> {
        if lhs.slots().len() != rhs.slots().len() || lhs.level() != rhs.level() {
            return Err(CircuitsError::DimensionMismatch);
        }
        if !lhs.scale().compatible(rhs.scale()) {
            return Err(CircuitsError::InvalidParameters("scale mismatch"));
        }
        if !epsilon.is_finite() || epsilon <= 0.0 {
            return Err(CircuitsError::InvalidParameters(
                "max epsilon must be finite and positive",
            ));
        }
        check_ciphertext(&self.params, lhs)?;
        check_ciphertext(&self.params, rhs)?;

        let slots = lhs
            .slots()
            .iter()
            .zip(rhs.slots())
            .map(|(lhs, rhs)| {
                let diff = lhs.re - rhs.re;
                Complex64::real(0.5 * (lhs.re + rhs.re + (diff * diff + epsilon).sqrt()))
            })
            .collect::<Vec<_>>();
        ensure_finite(&slots)?;
        Ok(ckks_ciphertext_like(lhs, slots, 1.5))
    }
}
