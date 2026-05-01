//! RLWE ciphertext representation.

use phantom_ring::Poly;

/// Scheme-agnostic RLWE ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    value: Vec<Poly>,
}

impl Ciphertext {
    /// Creates a ciphertext from RLWE components.
    pub fn new(value: Vec<Poly>) -> Self {
        Self { value }
    }

    /// Creates a zero ciphertext of the requested degree.
    pub fn zero(ring: &phantom_ring::Ring, degree: usize) -> Self {
        Self {
            value: (0..=degree).map(|_| ring.zero()).collect(),
        }
    }

    /// Returns the ciphertext degree.
    pub fn degree(&self) -> usize {
        self.value.len().saturating_sub(1)
    }

    /// Returns ciphertext components.
    pub fn value(&self) -> &[Poly] {
        &self.value
    }

    /// Returns mutable ciphertext components.
    pub fn value_mut(&mut self) -> &mut [Poly] {
        &mut self.value
    }

    /// Consumes the ciphertext and returns its components.
    pub fn into_value(self) -> Vec<Poly> {
        self.value
    }
}
