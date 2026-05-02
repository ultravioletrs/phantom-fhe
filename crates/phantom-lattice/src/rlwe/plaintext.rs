//! RLWE plaintext wrapper.

use phantom_ring::Poly;

/// Scheme-agnostic plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plaintext {
    value: Poly,
}

impl Plaintext {
    /// Creates a plaintext from an RNS polynomial.
    pub const fn new(value: Poly) -> Self {
        Self { value }
    }

    /// Returns the underlying polynomial.
    pub const fn value(&self) -> &Poly {
        &self.value
    }

    /// Consumes the plaintext and returns the polynomial.
    pub fn into_value(self) -> Poly {
        self.value
    }
}
