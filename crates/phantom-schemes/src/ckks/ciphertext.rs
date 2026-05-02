//! CKKS ciphertext.

use super::{Complex64, Precision, Scale};

/// CKKS ciphertext carrying transparent approximate slots for the scaffold.
#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext {
    slots: Vec<Complex64>,
    scale: Scale,
    level: usize,
    precision: Precision,
    degree: usize,
}

impl Ciphertext {
    /// Creates a ciphertext.
    pub fn new(
        slots: Vec<Complex64>,
        scale: Scale,
        level: usize,
        precision: Precision,
        degree: usize,
    ) -> Self {
        Self {
            slots,
            scale,
            level,
            precision,
            degree,
        }
    }

    /// Returns transparent slots.
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

    /// Returns ciphertext degree.
    pub const fn degree(&self) -> usize {
        self.degree
    }
}
