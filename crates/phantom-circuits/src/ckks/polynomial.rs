//! CKKS approximate polynomial evaluation over transparent slots.

use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64, EvaluationKeys};

use crate::ckks::{c_add, c_mul, check_ciphertext, ckks_ciphertext_like, ensure_finite};
use crate::common::PolynomialEvalPlan;
use crate::error::{CircuitsError, Result};

/// Evaluates approximate polynomials over CKKS slots.
#[derive(Clone, Debug)]
pub struct PolynomialEvaluator {
    params: CkksParams,
}

impl PolynomialEvaluator {
    /// Creates a CKKS polynomial evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Builds a scheme-independent evaluation plan for coefficients.
    pub fn plan<T>(&self, coefficients: &[T]) -> Result<PolynomialEvalPlan> {
        PolynomialEvalPlan::for_coefficients(coefficients)
    }

    /// Evaluates a real-coefficient polynomial.
    pub fn evaluate_real(
        &self,
        input: &Ciphertext,
        coefficients: &[f64],
        evaluation_keys: Option<&EvaluationKeys>,
    ) -> Result<Ciphertext> {
        let coefficients = coefficients
            .iter()
            .copied()
            .map(Complex64::real)
            .collect::<Vec<_>>();
        self.evaluate_complex(input, &coefficients, evaluation_keys)
    }

    /// Evaluates `c_0 + c_1*x + ... + c_d*x^d` with complex coefficients.
    pub fn evaluate_complex(
        &self,
        input: &Ciphertext,
        coefficients: &[Complex64],
        evaluation_keys: Option<&EvaluationKeys>,
    ) -> Result<Ciphertext> {
        let _ = evaluation_keys;
        if coefficients.is_empty() {
            return Err(CircuitsError::EmptyPolynomial);
        }
        check_ciphertext(&self.params, input)?;
        let plan = self.plan(coefficients)?;
        let _strategy = plan.strategy();

        let out = input
            .slots()
            .iter()
            .copied()
            .map(|slot| evaluate_complex_polynomial(slot, coefficients))
            .collect::<Vec<_>>();
        ensure_finite(&out)?;
        Ok(ckks_ciphertext_like(
            input,
            out,
            0.75 + coefficients.len() as f64 * 0.05,
        ))
    }
}

pub(crate) fn evaluate_complex_polynomial(x: Complex64, coefficients: &[Complex64]) -> Complex64 {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(Complex64::default(), |acc, coefficient| {
            c_add(c_mul(acc, x), coefficient)
        })
}
