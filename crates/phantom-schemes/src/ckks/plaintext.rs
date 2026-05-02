//! CKKS plaintext.

use super::{Complex64, Precision, Scale};

/// CKKS plaintext carrying approximate slots.
#[derive(Clone, Debug, PartialEq)]
pub struct Plaintext {
    slots: Vec<Complex64>,
    scale: Scale,
    level: usize,
    precision: Precision,
}

impl Plaintext {
    /// Creates a plaintext.
    pub fn new(slots: Vec<Complex64>, scale: Scale, level: usize, precision: Precision) -> Self {
        Self {
            slots,
            scale,
            level,
            precision,
        }
    }

    /// Returns encoded slots.
    pub fn slots(&self) -> &[Complex64] {
        &self.slots
    }

    /// Returns the scale.
    pub const fn scale(&self) -> Scale {
        self.scale
    }

    /// Returns the level.
    pub const fn level(&self) -> usize {
        self.level
    }

    /// Returns the precision estimate.
    pub const fn precision(&self) -> Precision {
        self.precision
    }
}
