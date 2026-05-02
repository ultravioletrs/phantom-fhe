//! CKKS slots-to-coefficients transform scaffold.

use phantom_circuits::ckks::{DftDirection, DftEvaluator};
use phantom_schemes::ckks::Ciphertext;

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Slots-to-coefficients transform.
#[derive(Clone, Debug)]
pub struct SlotsToCoeffs {
    dft: DftEvaluator,
}

impl SlotsToCoeffs {
    /// Creates a slots-to-coefficients transform.
    pub fn new(params: BootstrapParams) -> Self {
        let dft = DftEvaluator::new(params.ckks_params().clone());
        Self { dft }
    }

    /// Applies the transparent transform.
    pub fn apply(&self, input: &Ciphertext) -> Result<Ciphertext> {
        self.dft
            .transform(input, DftDirection::Inverse)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))
    }
}
