//! CKKS coefficients-to-slots transform scaffold.

use phantom_circuits::ckks::{DftDirection, DftEvaluator};
use phantom_schemes::ckks::Ciphertext;

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
