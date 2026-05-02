//! CKKS eval-mod scaffold.

use phantom_circuits::ckks::Mod1Evaluator;
use phantom_schemes::ckks::Ciphertext;

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Eval-mod circuit scaffold.
#[derive(Clone, Debug)]
pub struct EvalMod {
    params: BootstrapParams,
    mod1: Mod1Evaluator,
}

impl EvalMod {
    /// Creates an eval-mod circuit.
    pub fn new(params: BootstrapParams) -> Self {
        let mod1 = Mod1Evaluator::new(params.ckks_params().clone());
        Self { params, mod1 }
    }

    /// Applies centered mod-one when requested by callers.
    pub fn centered_fractional_part(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let _ = &self.params;
        self.mod1
            .centered_fractional_part(input)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))
    }

    /// Transparent eval-mod used by the correctness scaffold to preserve messages.
    pub fn preserve_message(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let _ = &self.params;
        Ok(input.clone())
    }
}
