//! Exact modular polynomial evaluation for BGV ciphertext slots, plus a
//! real (encrypted) evaluator ([`PolynomialEvaluator::evaluate_real`]).

use phantom_schemes::bgv::{
    BatchEncoder, BgvParams, BgvRelinearizationKey, Ciphertext, EvaluationKeys, Evaluator,
};

use crate::common::PolynomialEvalPlan;
use crate::error::{CircuitsError, Result};

/// Evaluates polynomials over BGV plaintext slots modulo `t`.
#[derive(Clone, Debug)]
pub struct PolynomialEvaluator {
    params: BgvParams,
}

impl PolynomialEvaluator {
    /// Creates a BGV polynomial evaluator.
    pub fn new(params: BgvParams) -> Result<Self> {
        Ok(Self { params })
    }

    /// Builds a scheme-independent evaluation plan for coefficients.
    pub fn plan<T>(&self, coefficients: &[T]) -> Result<PolynomialEvalPlan> {
        PolynomialEvalPlan::for_coefficients(coefficients)
    }

    /// Evaluates `c_0 + c_1*x + ... + c_d*x^d` slotwise modulo the BGV plaintext modulus.
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
        let in_component = &input.inner().value()[0];
        let mut out_component = self.params.ring().zero();
        for (rns_index, modulus) in self.params.ring().moduli().iter().enumerate() {
            let q = modulus.value();
            for slot in 0..self.params.slot_count() {
                let x = in_component.coeffs()[rns_index][slot] % t;
                out_component.coeffs_mut()[rns_index][slot] =
                    evaluate_modular_polynomial(x, coefficients, t) % q;
            }
        }

        Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
            vec![out_component],
        )))
    }

    /// Evaluates `c_0 + c_1*x + ... + c_d*x^d` against a **real** (encrypted)
    /// BGV ciphertext via Horner's method, using genuine SIMD slots (see
    /// [`phantom_schemes::bgv::BatchEncoder`]'s own module doc comment for
    /// why raw-coefficient `encode_u64` can't support this: real BGV
    /// multiplication is negacyclic ring convolution, not elementwise,
    /// unless the plaintext is CRT-batched first). Simpler than CKKS's own
    /// `evaluate_encrypted`: BGV's mod-`t` arithmetic is exact throughout,
    /// with no scale or level to track or rescale between steps, so `x`
    /// needs no `drop_level_real` equivalent and every coefficient encodes
    /// against the same, single `self.params` - just `mul`/`relinearize_real`/
    /// `add_plain` in a loop. `relin_key` (from
    /// [`phantom_schemes::bgv::BgvKeyGenerator::generate_relinearization_key_real`])
    /// is reused unchanged at every step, unlike CKKS's own per-level keys,
    /// since BGV multiplication doesn't change which ring subsequent
    /// operations need.
    pub fn evaluate_real(
        &self,
        input: &Ciphertext,
        coefficients: &[u64],
        relin_key: &BgvRelinearizationKey,
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
                "evaluate_real expects a degree-1 real BGV ciphertext",
            ));
        }

        let evaluator = Evaluator::new(self.params.clone())
            .map_err(|_| CircuitsError::SchemeOperation("failed to build a BGV evaluator"))?;
        let encoder = BatchEncoder::new(self.params.clone());
        let t = self.params.plaintext_modulus();
        let slot_count = self.params.slot_count();
        let encode_constant = |value: u64| -> Result<phantom_schemes::bgv::Plaintext> {
            let values = vec![value % t; slot_count];
            encoder
                .encode_batched(&values)
                .map_err(|_| CircuitsError::SchemeOperation("failed to encode a coefficient"))
        };

        // acc := c_d * x (plaintext multiply, no relinearization needed -
        // mul_plain's generic degree handling treats the plaintext as a
        // degree-0 "ciphertext," so a degree-1 times degree-0 product stays
        // degree-1), then acc := acc + c_{d-1} *before* the loop - Horner's
        // method needs the first ciphertext-ciphertext multiply to happen
        // against `acc + c_{d-1}`, not `acc` alone, or the result comes out
        // as `c_d*x^2 + ...` instead of `c_d*x + c_{d-1}` at the first step.
        let mut acc = evaluator
            .mul_plain(input, &encode_constant(coefficients[degree])?)
            .map_err(|_| CircuitsError::SchemeOperation("mul_plain failed"))?;
        acc = evaluator
            .add_plain(&acc, &encode_constant(coefficients[degree - 1])?)
            .map_err(|_| CircuitsError::SchemeOperation("add_plain failed"))?;

        for i in (0..degree - 1).rev() {
            acc = evaluator
                .mul(&acc, input, None)
                .map_err(|_| CircuitsError::SchemeOperation("mul failed"))?;
            acc = evaluator
                .relinearize_real(&acc, relin_key)
                .map_err(|_| CircuitsError::SchemeOperation("relinearize_real failed"))?;
            acc = evaluator
                .add_plain(&acc, &encode_constant(coefficients[i])?)
                .map_err(|_| CircuitsError::SchemeOperation("add_plain failed"))?;
        }

        Ok(acc)
    }

    fn check_degree_zero(&self, ciphertext: &Ciphertext) -> Result<()> {
        if ciphertext.degree() != 0 {
            return Err(CircuitsError::InvalidParameters(
                "BGV polynomial scaffold expects degree-zero ciphertexts",
            ));
        }
        self.params
            .ring()
            .check_poly(&ciphertext.inner().value()[0])
            .map_err(|_| CircuitsError::SchemeOperation("invalid BGV ciphertext"))?;
        Ok(())
    }
}

fn evaluate_modular_polynomial(x: u64, coefficients: &[u64], modulus: u64) -> u64 {
    coefficients.iter().rev().fold(0u64, |acc, coefficient| {
        ((acc as u128 * x as u128 + (*coefficient % modulus) as u128) % modulus as u128) as u64
    })
}
