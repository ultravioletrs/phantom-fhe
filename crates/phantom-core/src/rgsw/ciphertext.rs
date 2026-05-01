//! RGSW ciphertext representation.

use phantom_ring::Poly;

/// Ring-GSW ciphertext.
///
/// The current scaffold stores a plaintext-backed message polynomial plus a
/// prepared representation hook. Production RGSW encryption will replace this
/// with encrypted gadget rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RgswCiphertext {
    message: Poly,
    rows: Vec<Vec<crate::rlwe::Ciphertext>>,
}

impl RgswCiphertext {
    /// Creates an RGSW ciphertext scaffold.
    pub fn new(message: Poly, rows: Vec<Vec<crate::rlwe::Ciphertext>>) -> Self {
        Self { message, rows }
    }

    /// Creates a plaintext-backed RGSW ciphertext scaffold.
    pub fn from_message(message: Poly) -> Self {
        Self {
            message,
            rows: Vec::new(),
        }
    }

    /// Returns the encoded message polynomial.
    pub const fn message(&self) -> &Poly {
        &self.message
    }

    /// Returns prepared rows.
    pub fn rows(&self) -> &[Vec<crate::rlwe::Ciphertext>] {
        &self.rows
    }
}
