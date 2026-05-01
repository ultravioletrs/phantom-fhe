//! Strong domain types used by ring arithmetic.

use crate::{Result, RingError};

/// Ring degree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Degree(usize);

impl Degree {
    /// Creates a validated power-of-two degree.
    pub fn new(value: usize) -> Result<Self> {
        if value == 0 || !value.is_power_of_two() {
            return Err(RingError::InvalidDegree(value));
        }
        Ok(Self(value))
    }

    /// Returns the raw degree.
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Inclusive RNS level.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Level(usize);

impl Level {
    /// Creates a level.
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    /// Returns the raw level.
    pub const fn get(self) -> usize {
        self.0
    }
}
