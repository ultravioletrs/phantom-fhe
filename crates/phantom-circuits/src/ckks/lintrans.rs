//! CKKS linear transformations over transparent approximate slots, plus a
//! real (encrypted) evaluator ([`LinearTransformEvaluator::apply_real`]).

use phantom_lattice::rlwe::GaloisKey;
use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64, Encoder, Evaluator, Plaintext};

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

    /// Applies a diagonalized transform to a **real** (encrypted) CKKS
    /// ciphertext, via the standard rotate-multiply-accumulate ("diagonal
    /// method"): `(M @ z)[j] = sum_k d_k[j] * rot(z, k)[j]`, where `d_k` is
    /// the transform's own `k`-th cyclic diagonal
    /// ([`Self::diagonalize`]/[`DiagonalMatrix::from_linear_transform`]) -
    /// so `Enc(M @ z) = sum_k pt(d_k) * rotate_real(Enc(z), k)`, using
    /// [`phantom_schemes::ckks::Evaluator::rotate_real`] for the rotation,
    /// `mul_plain_real` for the per-diagonal plaintext multiply, and
    /// `add_real` to accumulate. Direct `O(n)`-rotation evaluation (one
    /// rotation per nonzero diagonal), not the baby-step-giant-step
    /// `O(sqrt n)` schedule [`DiagonalMatrix::bsgs_plan`] can already plan -
    /// matching this crate's established "correctness first" convention
    /// elsewhere (e.g. the encoder's own `O(N^2)` canonical embedding),
    /// tracked as a future optimization, not attempted here.
    ///
    /// `galois_keys` must contain one real
    /// [`phantom_lattice::rlwe::GaloisKey`] (from
    /// [`phantom_schemes::ckks::CkksKeyGenerator::generate_hybrid_galois_key`]
    /// at [`phantom_schemes::ckks::CkksParams::rotation_element`]`(offset)`)
    /// per nonzero diagonal offset `diagonals` actually needs (looked up by
    /// [`GaloisKey::element`]) - the zero offset (the transform's own main
    /// diagonal) needs no key, since it needs no rotation. Deliberately
    /// doesn't call this module's own `check_ciphertext` helper (a real
    /// ciphertext's own `slots()` is always empty - see [`Ciphertext`]'s
    /// own doc comment - so that
    /// check would only ever vacuously pass, the same reason
    /// `PolynomialEvaluator::evaluate_encrypted` skips it too).
    ///
    /// Rescales the accumulated result once before returning (dropping one
    /// level, dividing scale back down by `default_scale`) - every
    /// diagonal's `mul_plain_real` multiplies scale by `default_scale`,
    /// and `add_real` never changes it, so without this a single call
    /// would leave scale multiplied by a full `default_scale` factor, the
    /// same as any other unRescaled real multiplication. Baking the
    /// rescale in here (rather than leaving it to the caller, the way the
    /// lower-level `mul_real`/`mul_plain_real` primitives this is built on
    /// do) matches this method's own "one circuit = one call" shape - the
    /// same convention `PolynomialEvaluator::evaluate_encrypted` already
    /// uses. `ciphertext`'s own level must therefore be at least `1` (not
    /// already at level `0`).
    pub fn apply_real(
        &self,
        ciphertext: &Ciphertext,
        diagonals: &DiagonalMatrix<Complex64>,
        galois_keys: &[GaloisKey],
    ) -> Result<Ciphertext> {
        if diagonals.slot_count() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }
        let evaluator = Evaluator::new(self.params.clone());
        let encode_diagonal_at = |level: usize, values: &[Complex64]| -> Result<Plaintext> {
            let level_params = self.params.at_level(level).map_err(|_| {
                CircuitsError::SchemeOperation("failed to build a level-specific CKKS encoder")
            })?;
            Encoder::new(level_params)
                .encode_complex_real(values)
                .map_err(|_| {
                    CircuitsError::SchemeOperation("failed to encode a transform diagonal")
                })
        };

        let mut acc: Option<Ciphertext> = None;
        for diagonal in diagonals.diagonals() {
            let rotated = if diagonal.offset() == 0 {
                ciphertext.clone()
            } else {
                let element = self.params.rotation_element(diagonal.offset());
                let key = galois_keys
                    .iter()
                    .find(|key| key.element() == element)
                    .ok_or(CircuitsError::InvalidParameters(
                        "missing a Galois key for a diagonal offset this transform needs",
                    ))?;
                evaluator
                    .rotate_real(ciphertext, key)
                    .map_err(|_| CircuitsError::SchemeOperation("rotate_real failed"))?
            };
            let pt = encode_diagonal_at(rotated.level(), diagonal.values())?;
            let term = evaluator
                .mul_plain_real(&rotated, &pt)
                .map_err(|_| CircuitsError::SchemeOperation("mul_plain_real failed"))?;
            acc = Some(match acc {
                None => term,
                Some(prev) => evaluator
                    .add_real(&prev, &term)
                    .map_err(|_| CircuitsError::SchemeOperation("add_real failed"))?,
            });
        }
        let acc = acc.ok_or(CircuitsError::InvalidParameters(
            "transform has no nonzero diagonals",
        ))?;
        // Every diagonal's mul_plain_real multiplies scale by the
        // diagonal's own encoded scale (default_scale), and add_real never
        // changes it - so without this, one apply_real call bumps scale by
        // a full default_scale factor, same as any other real
        // multiplication would. Rescaling here (rather than leaving it to
        // the caller, the way the lower-level mul_real/mul_plain_real
        // primitives this is built on do) matches this method's own
        // "one circuit = one call" shape - the same convention
        // PolynomialEvaluator::evaluate_encrypted already uses, handling
        // its own rescaling internally rather than exposing raw
        // un-rescaled intermediate state. Without it, composing two
        // apply_real calls (e.g. a forward transform followed by an
        // inverse one) compounds scale multiplicatively with nothing
        // dividing it back down, eventually exceeding the ciphertext
        // modulus and wrapping around silently - caught exactly this way
        // while wiring real CKKS bootstrapping's CoeffsToSlots/SlotsToCoeffs
        // on top of this method.
        evaluator
            .rescale_next_real(&acc)
            .map_err(|_| CircuitsError::SchemeOperation("rescale_next_real failed"))
    }
}
