//! Modulus domain type.

use crate::{Result, RingError};

/// Odd machine-word modulus.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Modulus {
    value: u64,
}

impl Modulus {
    /// Creates a validated modulus.
    pub fn new(value: u64) -> Result<Self> {
        if value <= 1 || value % 2 == 0 {
            return Err(RingError::InvalidModulus(value));
        }
        Ok(Self { value })
    }

    /// Returns the raw modulus value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns true if this modulus supports negacyclic NTT of degree `n`.
    pub fn supports_ntt(self, n: usize) -> bool {
        (self.value - 1) % (2 * n) as u64 == 0
    }
}
