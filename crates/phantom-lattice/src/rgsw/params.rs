//! RGSW parameters.

use crate::rlwe::RlweParams;
use crate::{LatticeError, Result};

/// Ring-GSW parameters.
#[derive(Clone, Debug)]
pub struct RgswParams {
    rlwe: RlweParams,
    decomposition_base_log: u32,
    decomposition_levels: usize,
}

impl RgswParams {
    /// Creates RGSW parameters.
    pub fn new(
        rlwe: RlweParams,
        decomposition_base_log: u32,
        decomposition_levels: usize,
    ) -> Result<Self> {
        if decomposition_base_log == 0 || decomposition_base_log >= 63 {
            return Err(LatticeError::InvalidParameters(
                "decomposition_base_log must be in 1..63",
            ));
        }
        if decomposition_levels == 0 {
            return Err(LatticeError::InvalidParameters(
                "decomposition_levels must be non-zero",
            ));
        }
        Ok(Self {
            rlwe,
            decomposition_base_log,
            decomposition_levels,
        })
    }

    /// Returns the underlying RLWE parameters.
    pub const fn rlwe(&self) -> &RlweParams {
        &self.rlwe
    }

    /// Returns the decomposition base bit length.
    pub const fn decomposition_base_log(&self) -> u32 {
        self.decomposition_base_log
    }

    /// Returns the number of decomposition levels.
    pub const fn decomposition_levels(&self) -> usize {
        self.decomposition_levels
    }
}
