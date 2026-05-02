//! RLWE public key.

use phantom_ring::Poly;

/// Public RLWE key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    value: [Poly; 2],
}

impl PublicKey {
    /// Creates a public key.
    pub const fn new(c0: Poly, c1: Poly) -> Self {
        Self { value: [c0, c1] }
    }

    /// Returns public key components.
    pub const fn value(&self) -> &[Poly; 2] {
        &self.value
    }
}
