//! Exact modular polynomial evaluation for BFV ciphertext slots, plus a
//! real (encrypted) evaluator ([`PolynomialEvaluator::evaluate_real`]).

use phantom_ring::Modulus;
use phantom_schemes::bfv::{BatchEncoder, BfvParams, Ciphertext, EvaluationKeys, Evaluator};
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

    /// Evaluates `c_0 + c_1*x + ... + c_d*x^d` against a **real** (encrypted)
    /// BFV ciphertext via Horner's method, using genuine SIMD slots - see
    /// [`phantom_schemes::bgv::BatchEncoder`]'s own module doc comment for
    /// why raw-coefficient `encode_u64` can't support this. Structurally
    /// identical to [`phantom_schemes::bgv`]'s own `PolynomialEvaluator::evaluate_real`
    /// (BFV's mod-`t` arithmetic is exact throughout too, no scale or level
    /// to track), except `mul` needs `relinearize_real` reusing
    /// `phantom_lattice::rlwe`'s generic hybrid key-switching unmodified
    /// (see [`Evaluator::relinearize_real`]'s own doc comment - BFV, unlike
    /// BGV, has no `t`-scaled-noise requirement that would rule that out)
    /// and takes real BFV's own `mul_real(.., p_moduli)`, needing an
    /// auxiliary basis for its extended tensor-and-rescale procedure.
    /// `mul_plain` (unchanged, no `_real` suffix) is already what the real
    /// path needs for the leading `c_d * x` term - see
    /// [`Evaluator::add_plain_real`]'s own doc comment for why only
    /// *addition* needs `Delta`-awareness, not multiplication.
    pub fn evaluate_real(
        &self,
        input: &Ciphertext,
        coefficients: &[u64],
        relin_key: &phantom_lattice::rlwe::RelinearizationKey,
        p_moduli: &[Modulus],
    ) -> Result<Ciphertext> {
        if coefficients.is_empty() {
            return Err(CircuitsError::EmptyPolynomial);
        }
        let degree = coefficients.len() - 1;
        if degree == 0 {
            return Err(CircuitsError::InvalidParameters(
                "evaluate_real needs at least a degree-1 polynomial - a degree-0 constant has no ciphertext to base an encryption on",
            ));
        }
        if input.degree() != 1 {
            return Err(CircuitsError::InvalidParameters(
                "evaluate_real expects a degree-1 real BFV ciphertext",
            ));
        }

        let evaluator = Evaluator::new(self.params.clone())
            .map_err(|_| CircuitsError::SchemeOperation("failed to build a BFV evaluator"))?;
        let encoder = BatchEncoder::new(self.params.clone());
        let t = self.params.plaintext_modulus();
        let slot_count = self.params.slot_count();
        let encode_constant = |value: u64| -> Result<phantom_schemes::bfv::Plaintext> {
            let values = vec![value % t; slot_count];
            encoder
                .encode_batched(&values)
                .map_err(|_| CircuitsError::SchemeOperation("failed to encode a coefficient"))
        };

        let mut acc = evaluator
            .mul_plain(input, &encode_constant(coefficients[degree])?)
            .map_err(|_| CircuitsError::SchemeOperation("mul_plain failed"))?;
        acc = evaluator
            .add_plain_real(&acc, &encode_constant(coefficients[degree - 1])?)
            .map_err(|_| CircuitsError::SchemeOperation("add_plain_real failed"))?;

        for i in (0..degree - 1).rev() {
            acc = evaluator
                .mul_real(&acc, input, p_moduli)
                .map_err(|_| CircuitsError::SchemeOperation("mul_real failed"))?;
            acc = evaluator
                .relinearize_real(&acc, relin_key)
                .map_err(|_| CircuitsError::SchemeOperation("relinearize_real failed"))?;
            acc = evaluator
                .add_plain_real(&acc, &encode_constant(coefficients[i])?)
                .map_err(|_| CircuitsError::SchemeOperation("add_plain_real failed"))?;
        }

        Ok(acc)
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
