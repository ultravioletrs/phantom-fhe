//! Reserved BGV bootstrapping evaluator.

use crate::{BootstrappingError, Result};

/// Placeholder evaluator for future BGV centralized bootstrapping.
#[derive(Clone, Debug, Default)]
pub struct Evaluator;

impl Evaluator {
    /// Always reports that BGV centralized bootstrapping is not implemented yet.
    pub fn bootstrap_unimplemented(&self) -> Result<()> {
        Err(BootstrappingError::InvalidParameters(
            "BGV bootstrapping is reserved but not implemented",
        ))
    }
}
