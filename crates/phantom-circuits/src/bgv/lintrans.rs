//! Exact BGV linear transformations for the current coefficient-slot
//! scaffold, plus a real (encrypted) evaluator
//! ([`LinearTransformEvaluator::apply_real`]).
//!
//! [`LinearTransformEvaluator::apply_real`] does **not** reuse
//! [`DiagonalMatrix`]/[`crate::common::Diagonal`] the way
//! [`crate::ckks::LinearTransformEvaluator::apply_real`] does: that type's
//! diagonal offsets assume slots form one flat cyclic group of size `n`
//! (`values[row] = M[row][(row+offset) mod n]`), true for CKKS's own
//! `rotate_real` (a genuine single `N/2`-cyclic shift) but **not** for
//! BGV's - `BatchEncoder`'s own module doc comment derives why BGV's `N`
//! slots are two independent rows of `N/2`, `rotate_real` shifting *both*
//! rows by the same amount in parallel (period `N/2`, not `N`) and
//! `row_swap_element` separately swapping them, with no automorphism
//! reaching between "rotate by k" and "cross into the other row" - the two
//! operations don't compose into anything resembling one `N`-cyclic
//! group. Confirmed numerically (Python, `(N,t)` in `{(8,17),(16,97)}`)
//! before implementing: naively feeding a full `N`-slot transform through
//! [`DiagonalMatrix::from_linear_transform`]'s own offset formula and
//! driving it with [`phantom_schemes::bgv::Evaluator::rotate_real`] computes the *wrong*
//! diagonals for any offset whose `(row+offset) mod n` crosses the
//! row boundary, silently reading from the other row entirely.
//!
//! [`LinearTransformEvaluator::apply_real`] instead only supports
//! **row-local** (block-diagonal in the two rows) transforms - each output
//! row's value depends only on inputs from its own row, never the other -
//! and computes diagonals directly against that structure (`values[row] =
//! M[row][row_base + (local_row+k) mod half]` for `k = 0..half`, `half =
//! N/2`, `row_base`/`local_row` splitting `row` into its own row and
//! position within it), rejecting any transform with a nonzero
//! cross-row entry rather than silently computing something wrong. This
//! mirrors CKKS's own `apply_real` choosing the direct `O(n)`-rotation
//! diagonal method over a BSGS-optimized one - a deliberately scoped,
//! *correct* subset rather than the fully general case (which would also
//! need `rotate_real`'s `row_swap_element` combined with row-local
//! rotation for the two cross-row blocks) - not attempted here.

use phantom_schemes::bgv::{BatchEncoder, BgvParams, BgvRelinearizationKey, Ciphertext, Evaluator};

use crate::common::{BabyStepGiantStepPlan, DiagonalMatrix, LinearTransform};
use crate::error::{CircuitsError, Result};

/// Evaluates BGV linear transformations over coefficient slots.
#[derive(Clone, Debug)]
pub struct LinearTransformEvaluator {
    params: BgvParams,
}

impl LinearTransformEvaluator {
    /// Creates a BGV linear transform evaluator.
    pub const fn new(params: BgvParams) -> Self {
        Self { params }
    }

    /// Returns the number of slots in the current BGV batching scaffold.
    pub fn slot_count(&self) -> usize {
        self.params.slot_count()
    }

    /// Converts a dense slot matrix into cyclic diagonals.
    pub fn diagonalize(&self, transform: &LinearTransform<u64>) -> Result<DiagonalMatrix<u64>> {
        self.check_transform(transform)?;
        Ok(transform.to_diagonal_matrix())
    }

    /// Plans a baby-step giant-step schedule for a dense transform.
    pub fn bsgs_plan(
        &self,
        transform: &LinearTransform<u64>,
        baby_step_count: usize,
    ) -> Result<BabyStepGiantStepPlan> {
        self.diagonalize(transform)?.bsgs_plan(baby_step_count)
    }

    /// Applies a dense linear transform to a degree-zero BGV ciphertext.
    pub fn apply(
        &self,
        ciphertext: &Ciphertext,
        transform: &LinearTransform<u64>,
    ) -> Result<Ciphertext> {
        self.check_transform(transform)?;
        self.check_degree_zero(ciphertext)?;

        let modulus = self.params.plaintext_modulus();
        let in_component = &ciphertext.inner().value()[0];
        let mut out_component = self.params.ring().zero();

        for rns_index in 0..in_component.moduli_count() {
            let q = self.params.ring().moduli()[rns_index].value();
            for row in 0..self.slot_count() {
                let mut acc = 0u128;
                for col in 0..self.slot_count() {
                    let coeff = (in_component.coeffs()[rns_index][col] % modulus) as u128;
                    let weight = (transform.rows()[row][col] % modulus) as u128;
                    acc = (acc + coeff * weight) % modulus as u128;
                }
                out_component.coeffs_mut()[rns_index][row] = acc as u64 % q;
            }
        }

        Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
            vec![out_component],
        )))
    }

    /// Applies a diagonalized transform to a degree-zero BGV ciphertext.
    pub fn apply_diagonal(
        &self,
        ciphertext: &Ciphertext,
        diagonals: &DiagonalMatrix<u64>,
    ) -> Result<Ciphertext> {
        if diagonals.slot_count() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }
        let transform = LinearTransform::dense(diagonals.to_dense())?;
        self.apply(ciphertext, &transform)
    }

    fn check_transform(&self, transform: &LinearTransform<u64>) -> Result<()> {
        if transform.slot_count() != self.slot_count() {
            return Err(CircuitsError::DimensionMismatch);
        }
        Ok(())
    }

    /// Applies a **row-local** dense linear transform to a **real**
    /// (encrypted), [`BatchEncoder::encode_batched`]-encoded BGV
    /// ciphertext, via the rotate-multiply-accumulate diagonal method - see
    /// this module's own doc comment for why the diagonals are computed
    /// against BGV's actual two-row slot structure rather than reusing
    /// [`DiagonalMatrix`], and for the row-local restriction this rejects
    /// outside of.
    ///
    /// `rotation_keys` must contain one real
    /// [`BgvRelinearizationKey`] (from
    /// [`phantom_schemes::bgv::BgvKeyGenerator::generate_rotation_key_real`]
    /// at [`BgvParams::rotation_element`]`(k)`) per nonzero row-local
    /// diagonal offset `k` this transform actually needs, paired with that
    /// same element - offset `0` (the transform's own row-local main
    /// diagonal) needs no key, since it needs no rotation.
    pub fn apply_real(
        &self,
        ciphertext: &Ciphertext,
        transform: &LinearTransform<u64>,
        rotation_keys: &[(usize, BgvRelinearizationKey)],
    ) -> Result<Ciphertext> {
        self.check_transform(transform)?;
        let half = self.slot_count() / 2;
        let diagonals = row_local_diagonals(transform, half)?;

        let evaluator = Evaluator::new(self.params.clone())
            .map_err(|_| CircuitsError::SchemeOperation("failed to build a BGV evaluator"))?;
        let encoder = BatchEncoder::new(self.params.clone());
        let t = self.params.plaintext_modulus();

        let mut acc: Option<Ciphertext> = None;
        for (k, values) in diagonals {
            let rotated = if k == 0 {
                ciphertext.clone()
            } else {
                let element = self.params.rotation_element(k);
                let key = rotation_keys
                    .iter()
                    .find(|(e, _)| *e == element)
                    .map(|(_, key)| key)
                    .ok_or(CircuitsError::InvalidParameters(
                        "missing a rotation key for a diagonal offset this transform needs",
                    ))?;
                evaluator
                    .rotate_real(ciphertext, element, key)
                    .map_err(|_| CircuitsError::SchemeOperation("rotate_real failed"))?
            };
            let encoded: Vec<u64> = values.iter().map(|&v| v % t).collect();
            let pt = encoder.encode_batched(&encoded).map_err(|_| {
                CircuitsError::SchemeOperation("failed to encode a transform diagonal")
            })?;
            let term = evaluator
                .mul_plain(&rotated, &pt)
                .map_err(|_| CircuitsError::SchemeOperation("mul_plain failed"))?;
            acc = Some(match acc {
                None => term,
                Some(prev) => evaluator
                    .add(&prev, &term)
                    .map_err(|_| CircuitsError::SchemeOperation("add failed"))?,
            });
        }
        acc.ok_or(CircuitsError::InvalidParameters(
            "transform has no nonzero diagonals",
        ))
    }

    fn check_degree_zero(&self, ciphertext: &Ciphertext) -> Result<()> {
        if ciphertext.degree() != 0 {
            return Err(CircuitsError::InvalidParameters(
                "BGV linear transform scaffold expects degree-zero ciphertexts",
            ));
        }
        self.params
            .ring()
            .check_poly(&ciphertext.inner().value()[0])
            .map_err(|_| CircuitsError::SchemeOperation("invalid BGV ciphertext"))?;
        Ok(())
    }
}

/// Computes `transform`'s row-local diagonals against BGV's own two-row
/// slot structure (`half = N/2`) - see this module's own doc comment for
/// the derivation. Returns `(k, values)` pairs for `k = 0..half` with at
/// least one nonzero entry; rejects `transform` outright if any entry
/// crosses the row boundary (`row` and `col` in different halves), rather
/// than silently dropping or misreading it.
fn row_local_diagonals(
    transform: &LinearTransform<u64>,
    half: usize,
) -> Result<Vec<(usize, Vec<u64>)>> {
    let n = transform.slot_count();
    for (row, weights) in transform.rows().iter().enumerate() {
        let row_half = row / half;
        for (col, &weight) in weights.iter().enumerate() {
            if weight != 0 && col / half != row_half {
                return Err(CircuitsError::InvalidParameters(
                    "apply_real only supports row-local (block-diagonal) BGV transforms - a nonzero entry crosses the two-row boundary",
                ));
            }
        }
    }

    let mut diagonals = Vec::with_capacity(half);
    for k in 0..half {
        let mut values = vec![0u64; n];
        let mut any_nonzero = false;
        for (row, entry) in values.iter_mut().enumerate() {
            let row_base = (row / half) * half;
            let local_row = row % half;
            let col = row_base + (local_row + k) % half;
            let weight = transform.rows()[row][col];
            *entry = weight;
            any_nonzero |= weight != 0;
        }
        if any_nonzero {
            diagonals.push((k, values));
        }
    }
    Ok(diagonals)
}
