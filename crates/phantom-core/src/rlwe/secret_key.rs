//! RLWE secret key.

use core::fmt;

use phantom_ring::Poly;

/// Secret RLWE key.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretKey {
    value: Poly,
}

impl SecretKey {
    /// Creates a secret key from a polynomial.
    pub const fn new(value: Poly) -> Self {
        Self { value }
    }

    /// Returns the secret polynomial.
    pub const fn value(&self) -> &Poly {
        &self.value
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        for component in self.value.coeffs_mut() {
            for coeff in component {
                *coeff = 0;
            }
        }
    }
}
