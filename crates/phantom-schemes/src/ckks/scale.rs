//! CKKS scale domain type.

use crate::{Result, SchemesError};

/// Positive CKKS scale.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Scale(f64);

impl Scale {
    /// Creates a validated scale.
    pub fn new(value: f64) -> Result<Self> {
        if !value.is_finite() || value <= 0.0 {
            return Err(SchemesError::InvalidParameters(
                "scale must be finite and positive",
            ));
        }
        Ok(Self(value))
    }

    /// Creates a power-of-two scale.
    pub fn from_bits(bits: u32) -> Result<Self> {
        Self::new(2.0_f64.powi(bits as i32))
    }

    /// Returns the raw scale.
    pub const fn value(self) -> f64 {
        self.0
    }

    /// Returns true if scales are close enough for scaffold arithmetic.
    pub fn compatible(self, rhs: Self) -> bool {
        let largest = self.0.abs().max(rhs.0.abs()).max(1.0);
        (self.0 - rhs.0).abs() <= largest * 1e-9
    }
}
