//! CKKS approximate polynomial evaluation over transparent slots, plus a
//! real (encrypted) evaluator (`evaluate_encrypted`) - see that method's
//! own doc comment for why it isn't named `evaluate_real` too, unlike every
//! `_real`-suffixed method elsewhere in this codebase.

use phantom_lattice::rlwe::RelinearizationKey;
use phantom_schemes::ckks::{
    Ciphertext, CkksParams, Complex64, Encoder, EvaluationKeys, Evaluator, Plaintext,
};

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

    /// Evaluates `c_0 + c_1*x + ... + c_d*x^d` against a **real** (actually
    /// encrypted) CKKS ciphertext via Horner's method, using
    /// `phantom_schemes::ckks::Evaluator`'s own real arithmetic
    /// (`mul_plain_real`/`mul_real`/`relinearize_real`/`rescale_next_real`/
    /// `drop_level_real`/`add_plain_real`) - unlike [`Self::evaluate_real`]/
    /// [`Self::evaluate_complex`] above (which evaluate directly on the
    /// transparent scaffold's plaintext-equivalent `Complex64` slots), this
    /// performs the actual homomorphic computation. Named `evaluate_encrypted`
    /// rather than `evaluate_real` specifically to avoid colliding with
    /// [`Self::evaluate_real`]'s own, unrelated meaning ("real-valued
    /// coefficients," as opposed to complex ones) - a naming clash already
    /// noted while scoping this work (Workstream 6 item 2/3).
    ///
    /// Horner's method here needs one multiplication - and, critically, one
    /// *rescale* - per coefficient past the leading one: `acc := c_d * x`
    /// (a plaintext multiply, [`Evaluator::mul_plain_real`]), rescale, then
    /// repeatedly `acc := acc*x + c_i` (ciphertext multiply,
    /// [`Evaluator::mul_real`], relinearize, rescale) with `x` itself
    /// brought down to match `acc`'s shrinking level via
    /// [`Evaluator::drop_level_real`] before each multiply (needed because
    /// `mul_real` requires both operands at the same level, but only `acc`
    /// loses a level on each step - see `ckks::Evaluator`'s own module doc
    /// comment and `docs/internal/implementation-plan.md`'s Workstream 6
    /// item 2 entry for the two real-path gaps this uncovered and fixed).
    /// `input.level()` must be at least `coefficients.len() - 1` (one level
    /// per multiplication) - checked explicitly up front rather than
    /// surfacing as an opaque "cannot rescale at level zero" partway
    /// through evaluation.
    ///
    /// `relin_keys[level]` must be a key from
    /// `phantom_schemes::ckks::CkksKeyGenerator::generate_hybrid_relinearization_key_at_level`
    /// generated *for that level specifically* - a single key generated at
    /// `input`'s own top level is **not** reusable at any lower level (see
    /// that method's own doc comment for why: the underlying key-switching
    /// key's row count is fixed to the ring it was generated against).
    /// `relin_keys` must therefore have at least `input.level()` entries
    /// (indices `0..input.level()`, the levels this method will actually
    /// relinearize at - `relin_keys[input.level()]` itself is never used
    /// and may be a placeholder).
    ///
    /// A degree-`0` polynomial (a single coefficient) is rejected: with no
    /// multiplication ever happening, there would be no ciphertext to base
    /// a "constant" encryption on, and an evaluator has no encryption key
    /// to produce one from scratch.
    pub fn evaluate_encrypted(
        &self,
        input: &Ciphertext,
        coefficients: &[f64],
        relin_keys: &[RelinearizationKey],
    ) -> Result<Ciphertext> {
        if coefficients.is_empty() {
            return Err(CircuitsError::EmptyPolynomial);
        }
        let degree = coefficients.len() - 1;
        if degree == 0 {
            return Err(CircuitsError::InvalidParameters(
                "evaluate_encrypted needs at least a degree-1 polynomial - a degree-0 constant has no ciphertext to base an encryption on",
            ));
        }
        if input.level() < degree {
            return Err(CircuitsError::InvalidParameters(
                "not enough remaining levels to evaluate this polynomial",
            ));
        }
        if relin_keys.len() < input.level() {
            return Err(CircuitsError::InvalidParameters(
                "relin_keys must have one entry per level from 0 up to (excluding) input.level()",
            ));
        }

        let evaluator = Evaluator::new(self.params.clone());
        let slot_count = self.params.slot_count();
        let encode_constant_at = |level: usize, value: f64| -> Result<Plaintext> {
            let level_params = self.params.at_level(level).map_err(|_| {
                CircuitsError::SchemeOperation("failed to build a level-specific CKKS encoder")
            })?;
            let values = vec![Complex64::real(value); slot_count];
            Encoder::new(level_params)
                .encode_complex_real(&values)
                .map_err(|_| {
                    CircuitsError::SchemeOperation("failed to encode a polynomial coefficient")
                })
        };

        // acc := c_d * x (plaintext multiply, no relinearization needed).
        let leading = encode_constant_at(input.level(), coefficients[degree])?;
        let mut acc = evaluator
            .mul_plain_real(input, &leading)
            .map_err(|_| CircuitsError::SchemeOperation("mul_plain_real failed"))?;
        acc = evaluator
            .rescale_next_real(&acc)
            .map_err(|_| CircuitsError::SchemeOperation("rescale_next_real failed"))?;
        let mut x = evaluator
            .drop_level_real(input)
            .map_err(|_| CircuitsError::SchemeOperation("drop_level_real failed"))?;
        let next = encode_constant_at(acc.level(), coefficients[degree - 1])?;
        acc = evaluator
            .add_plain_real(&acc, &next)
            .map_err(|_| CircuitsError::SchemeOperation("add_plain_real failed"))?;

        for i in (0..degree - 1).rev() {
            acc = evaluator
                .mul_real(&acc, &x)
                .map_err(|_| CircuitsError::SchemeOperation("mul_real failed"))?;
            let relin_key = &relin_keys[acc.level()];
            acc = evaluator
                .relinearize_real(&acc, relin_key)
                .map_err(|_| CircuitsError::SchemeOperation("relinearize_real failed"))?;
            acc = evaluator
                .rescale_next_real(&acc)
                .map_err(|_| CircuitsError::SchemeOperation("rescale_next_real failed"))?;
            x = evaluator
                .drop_level_real(&x)
                .map_err(|_| CircuitsError::SchemeOperation("drop_level_real failed"))?;
            let c_i = encode_constant_at(acc.level(), coefficients[i])?;
            acc = evaluator
                .add_plain_real(&acc, &c_i)
                .map_err(|_| CircuitsError::SchemeOperation("add_plain_real failed"))?;
        }

        Ok(acc)
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
