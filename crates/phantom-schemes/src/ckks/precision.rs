//! CKKS precision estimate.

/// Lightweight precision estimate in bits.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Precision {
    bits: f64,
}

impl Precision {
    /// Creates a precision estimate.
    pub const fn new(bits: f64) -> Self {
        Self { bits }
    }

    /// Returns the estimated precision in bits.
    pub const fn bits(self) -> f64 {
        self.bits
    }

    /// Degrades precision by `bits`.
    pub fn degrade(self, bits: f64) -> Self {
        Self::new((self.bits - bits).max(0.0))
    }

    /// Returns the smaller precision estimate.
    pub fn min(self, rhs: Self) -> Self {
        Self::new(self.bits.min(rhs.bits))
    }
}
