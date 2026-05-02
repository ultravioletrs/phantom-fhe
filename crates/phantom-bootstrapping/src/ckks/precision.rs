//! CKKS bootstrap precision policy.

use phantom_schemes::ckks::Precision;

/// Precision policy used by the transparent bootstrapping scaffold.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PrecisionPolicy {
    target_bits: f64,
}

impl PrecisionPolicy {
    /// Creates a policy.
    pub const fn new(target_bits: f64) -> Self {
        Self { target_bits }
    }

    /// Returns the desired precision estimate.
    pub const fn target_bits(self) -> f64 {
        self.target_bits
    }

    /// Returns the refreshed precision estimate.
    pub fn refreshed(self) -> Precision {
        Precision::new(self.target_bits)
    }
}
