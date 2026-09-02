//! CKKS slots-to-coefficients transform scaffold, plus a real (encrypted)
//! evaluator ([`SlotsToCoeffs::apply_real`]).

use phantom_circuits::ckks::{DftDirection, DftEvaluator, LinearTransformEvaluator};
use phantom_lattice::rlwe::GaloisKey;
use phantom_schemes::ckks::Ciphertext;

use super::coeffs_to_slots::dft_matrix;
use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Slots-to-coefficients transform.
#[derive(Clone, Debug)]
pub struct SlotsToCoeffs {
    params: BootstrapParams,
    dft: DftEvaluator,
}

impl SlotsToCoeffs {
    /// Creates a slots-to-coefficients transform.
    pub fn new(params: BootstrapParams) -> Self {
        let dft = DftEvaluator::new(params.ckks_params().clone());
        Self { params, dft }
    }

    /// Applies the transparent transform.
    pub fn apply(&self, input: &Ciphertext) -> Result<Ciphertext> {
        self.dft
            .transform(input, DftDirection::Inverse)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))
    }

    /// Applies the **real** (encrypted) inverse transform - see
    /// [`super::CoeffsToSlots::apply_real`]'s own doc comment for the
    /// algorithm and the `n = slot_count` constraint; this is the exact
    /// same diagonal method against the inverse DFT matrix instead of the
    /// forward one.
    pub fn apply_real(
        &self,
        ciphertext: &Ciphertext,
        galois_keys: &[GaloisKey],
    ) -> Result<Ciphertext> {
        let n = self.params.ckks_params().slot_count();
        let matrix = dft_matrix(n, DftDirection::Inverse);
        let lintrans = LinearTransformEvaluator::new(self.params.ckks_params().clone());
        let diagonals = lintrans
            .diagonalize(&matrix)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))?;
        lintrans
            .apply_real(ciphertext, &diagonals, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))
    }
}
