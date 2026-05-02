//! CKKS inverse approximation helpers.

use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64};

use crate::ckks::{check_ciphertext, ckks_ciphertext_like, ensure_finite};
use crate::error::{CircuitsError, Result};

/// Evaluates reciprocal approximations over CKKS slots.
#[derive(Clone, Debug)]
pub struct InverseEvaluator {
    params: CkksParams,
}

impl InverseEvaluator {
    /// Creates an inverse evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Applies a transparent reciprocal with a minimum denominator magnitude.
    pub fn reciprocal(&self, input: &Ciphertext, min_abs: f64) -> Result<Ciphertext> {
        if !min_abs.is_finite() || min_abs <= 0.0 {
            return Err(CircuitsError::InvalidParameters(
                "minimum reciprocal magnitude must be finite and positive",
            ));
        }
        check_ciphertext(&self.params, input)?;
        let slots = input
            .slots()
            .iter()
            .map(|slot| reciprocal_slot(*slot, min_abs))
            .collect::<Vec<_>>();
        ensure_finite(&slots)?;
        Ok(ckks_ciphertext_like(input, slots, 2.0))
    }
}

fn reciprocal_slot(value: Complex64, min_abs: f64) -> Complex64 {
    let norm = value.re.mul_add(value.re, value.im * value.im);
    if norm < min_abs * min_abs {
        let sign = if value.re < 0.0 { -1.0 } else { 1.0 };
        return Complex64::real(sign / min_abs);
    }
    Complex64::new(value.re / norm, -value.im / norm)
}
