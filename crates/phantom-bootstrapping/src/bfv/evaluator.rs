//! Reserved BFV bootstrapping evaluator.

use crate::{BootstrappingError, Result};

/// Placeholder evaluator for future BFV centralized bootstrapping.
#[derive(Clone, Debug, Default)]
pub struct Evaluator;

impl Evaluator {
    /// Always reports that BFV centralized bootstrapping is not implemented yet.
    pub fn bootstrap_unimplemented(&self) -> Result<()> {
        Err(BootstrappingError::InvalidParameters(
            "BFV bootstrapping is reserved but not implemented",
        ))
    }
}
