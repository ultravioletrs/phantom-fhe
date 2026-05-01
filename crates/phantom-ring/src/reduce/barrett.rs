//! Barrett reduction placeholder.
//!
//! The initial implementation uses widened arithmetic. A tuned Barrett reducer
//! can replace this type without changing call sites.

/// Barrett reducer for one modulus.
#[derive(Clone, Copy, Debug)]
pub struct BarrettReducer {
    modulus: u64,
}

impl BarrettReducer {
    /// Creates a reducer.
    pub const fn new(modulus: u64) -> Self {
        Self { modulus }
    }

    /// Reduces `value` modulo this reducer's modulus.
    pub fn reduce(self, value: u128) -> u64 {
        (value % self.modulus as u128) as u64
    }
}
