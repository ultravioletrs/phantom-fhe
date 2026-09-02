//! CKKS coefficients-to-slots transform scaffold, plus a real (encrypted)
//! evaluator ([`CoeffsToSlots::apply_real`]).

use std::f64::consts::PI;

use phantom_circuits::ckks::{DftDirection, DftEvaluator, LinearTransformEvaluator};
use phantom_circuits::common::LinearTransform;
use phantom_lattice::rlwe::GaloisKey;
use phantom_schemes::ckks::{Ciphertext, Complex64};

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Coefficients-to-slots transform.
#[derive(Clone, Debug)]
pub struct CoeffsToSlots {
    params: BootstrapParams,
    dft: DftEvaluator,
}

impl CoeffsToSlots {
    /// Creates a coefficients-to-slots transform.
    pub fn new(params: BootstrapParams) -> Self {
        let dft = DftEvaluator::new(params.ckks_params().clone());
        Self { params, dft }
    }

    /// Applies the transparent transform.
    pub fn apply(&self, input: &Ciphertext) -> Result<Ciphertext> {
        check_slots(&self.params, input)?;
        self.dft
            .transform(input, DftDirection::Forward)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))
    }

    /// Applies the **real** (encrypted) forward transform - the same
    /// square `O(n)`-rotation DFT [`Self::apply`]'s transparent scaffold
    /// computes directly, but homomorphically, via
    /// [`phantom_circuits::ckks::LinearTransformEvaluator::apply_real`]'s
    /// diagonal method against the dense DFT matrix (this module's own
    /// `dft_matrix` helper).
    /// `n = self.params.ckks_params().slot_count()` - unlike the
    /// transparent scaffold (which accepts any input length up to that
    /// bound, since [`DftEvaluator::transform`] is generic over vector
    /// length), a real ciphertext's own slot count is fixed by its ring
    /// degree, so this always operates at exactly `n`.
    ///
    /// `galois_keys` must contain one real [`GaloisKey`] (from
    /// [`phantom_schemes::ckks::CkksKeyGenerator::generate_hybrid_galois_key`]
    /// at [`phantom_schemes::ckks::CkksParams::rotation_element`]`(k)`) per
    /// rotation offset `1..n` this transform needs - `apply_real` itself
    /// reports which one is missing if any are absent.
    pub fn apply_real(
        &self,
        ciphertext: &Ciphertext,
        galois_keys: &[GaloisKey],
    ) -> Result<Ciphertext> {
        let n = self.params.ckks_params().slot_count();
        let matrix = dft_matrix(n, DftDirection::Forward);
        let lintrans = LinearTransformEvaluator::new(self.params.ckks_params().clone());
        let diagonals = lintrans
            .diagonalize(&matrix)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        lintrans
            .apply_real(ciphertext, &diagonals, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))
    }
}

pub(crate) fn check_slots(params: &BootstrapParams, input: &Ciphertext) -> Result<()> {
    if input.slots().len() > params.ckks_params().slot_count() {
        return Err(BootstrappingError::DimensionMismatch);
    }
    if params.ckks_params().conjugate_invariant() && input.slots().iter().any(|slot| slot.im != 0.0)
    {
        return Err(BootstrappingError::InvalidParameters(
            "conjugate-invariant CKKS accepts real slots only",
        ));
    }
    Ok(())
}

/// Builds the dense `n x n` DFT matrix [`DftEvaluator::transform`] computes
/// directly (`M[k][j] = scale * exp(i*sign*2*pi*j*k/n)`, `sign = -1`/scale
/// `= 1` for [`DftDirection::Forward`], `sign = 1`/scale `= 1/n` for
/// [`DftDirection::Inverse`]) - shared by [`CoeffsToSlots::apply_real`] and
/// [`super::SlotsToCoeffs::apply_real`].
pub(crate) fn dft_matrix(n: usize, direction: DftDirection) -> LinearTransform<Complex64> {
    let sign = match direction {
        DftDirection::Forward => -1.0,
        DftDirection::Inverse => 1.0,
    };
    let scale = match direction {
        DftDirection::Forward => 1.0,
        DftDirection::Inverse => 1.0 / n as f64,
    };
    let mut rows = vec![vec![Complex64::default(); n]; n];
    for (k, row) in rows.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            let angle = sign * 2.0 * PI * (j * k) as f64 / n as f64;
            *entry = Complex64::new(angle.cos(), angle.sin()) * Complex64::real(scale);
        }
    }
    LinearTransform::dense(rows).expect("n x n rows is always square")
}
