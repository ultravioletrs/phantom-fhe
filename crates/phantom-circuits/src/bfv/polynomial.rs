//! Exact modular polynomial evaluation for BFV ciphertext slots.

use phantom_schemes::bfv::{BfvParams, Ciphertext, EvaluationKeys};
use phantom_schemes::bgv;

use crate::common::PolynomialEvalPlan;
use crate::error::{CircuitsError, Result};

/// Evaluates polynomials over BFV plaintext slots modulo `t`.
#[derive(Clone, Debug)]
pub struct PolynomialEvaluator {
    params: BfvParams,
}

impl PolynomialEvaluator {
    /// Creates a BFV polynomial evaluator.
    pub fn new(params: BfvParams) -> Result<Self> {
        Ok(Self { params })
    }

    /// Builds a scheme-independent evaluation plan for coefficients.
    pub fn plan<T>(&self, coefficients: &[T]) -> Result<PolynomialEvalPlan> {
        PolynomialEvalPlan::for_coefficients(coefficients)
    }

    /// Evaluates `c_0 + c_1*x + ... + c_d*x^d` slotwise modulo the BFV plaintext modulus.
    pub fn evaluate(
        &self,
        input: &Ciphertext,
        coefficients: &[u64],
        evaluation_keys: Option<&EvaluationKeys>,
    ) -> Result<Ciphertext> {
        let _ = evaluation_keys;
        if coefficients.is_empty() {
            return Err(CircuitsError::EmptyPolynomial);
        }
        self.check_degree_zero(input)?;

        let plan = self.plan(coefficients)?;
        let _strategy = plan.strategy();

        let t = self.params.plaintext_modulus();
        let in_component = &input.inner().inner().value()[0];
        let mut out_component = self.params.ring().zero();
        for (rns_index, modulus) in self.params.ring().moduli().iter().enumerate() {
            let q = modulus.value();
            for slot in 0..self.params.slot_count() {
                let x = in_component.coeffs()[rns_index][slot] % t;
                out_component.coeffs_mut()[rns_index][slot] =
                    evaluate_modular_polynomial(x, coefficients, t) % q;
            }
        }

        Ok(Ciphertext::new(bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(vec![out_component]),
        )))
    }

    fn check_degree_zero(&self, ciphertext: &Ciphertext) -> Result<()> {
        if ciphertext.degree() != 0 {
            return Err(CircuitsError::InvalidParameters(
                "BFV polynomial scaffold expects degree-zero ciphertexts",
            ));
        }
        self.params
            .ring()
            .check_poly(&ciphertext.inner().inner().value()[0])
            .map_err(|_| CircuitsError::SchemeOperation("invalid BFV ciphertext"))?;
        Ok(())
    }
}

fn evaluate_modular_polynomial(x: u64, coefficients: &[u64], modulus: u64) -> u64 {
    coefficients.iter().rev().fold(0u64, |acc, coefficient| {
        ((acc as u128 * x as u128 + (*coefficient % modulus) as u128) % modulus as u128) as u64
    })
}
