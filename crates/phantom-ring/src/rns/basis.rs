//! RNS basis representation.

use crate::{Modulus, Result, RingError};

/// RNS basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RnsBasis {
    moduli: Vec<Modulus>,
}

impl RnsBasis {
    /// Creates a new basis.
    pub fn new(moduli: Vec<Modulus>) -> Result<Self> {
        if moduli.is_empty() {
            return Err(RingError::DimensionMismatch);
        }
        Ok(Self { moduli })
    }

    /// Returns basis moduli.
    pub fn moduli(&self) -> &[Modulus] {
        &self.moduli
    }
}
