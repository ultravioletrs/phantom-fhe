//! Composite polynomial helpers for CKKS approximation circuits.

use phantom_schemes::ckks::{Ciphertext, CkksParams};

use crate::ckks::polynomial::PolynomialEvaluator;
use crate::error::{CircuitsError, Result};

/// A sequence of real-coefficient polynomials evaluated by composition.
#[derive(Clone, Debug, PartialEq)]
pub struct CompositePolynomial {
    stages: Vec<Vec<f64>>,
}

impl CompositePolynomial {
    /// Creates a composite polynomial approximation.
    pub fn new(stages: Vec<Vec<f64>>) -> Result<Self> {
        if stages.is_empty() || stages.iter().any(Vec::is_empty) {
            return Err(CircuitsError::EmptyPolynomial);
        }
        Ok(Self { stages })
    }

    /// Returns polynomial stages in evaluation order.
    pub fn stages(&self) -> &[Vec<f64>] {
        &self.stages
    }
}

/// Evaluates composite polynomial approximations used by CKKS circuits.
#[derive(Clone, Debug)]
pub struct MinimaxEvaluator {
    polynomial: PolynomialEvaluator,
}

impl MinimaxEvaluator {
    /// Creates a minimax/composite polynomial evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self {
            polynomial: PolynomialEvaluator::new(params),
        }
    }

    /// Evaluates each polynomial stage on the previous stage output.
    pub fn evaluate_composite(
        &self,
        input: &Ciphertext,
        composite: &CompositePolynomial,
    ) -> Result<Ciphertext> {
        let mut acc = input.clone();
        for stage in composite.stages() {
            acc = self.polynomial.evaluate_real(&acc, stage, None)?;
        }
        Ok(acc)
    }
}
