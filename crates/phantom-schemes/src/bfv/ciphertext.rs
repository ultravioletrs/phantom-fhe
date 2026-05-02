//! BFV ciphertext wrapper.

use crate::bgv;

/// BFV ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    inner: bgv::Ciphertext,
}

impl Ciphertext {
    /// Creates a BFV ciphertext from the shared exact-arithmetic representation.
    pub(crate) const fn new(inner: bgv::Ciphertext) -> Self {
        Self { inner }
    }

    /// Returns the shared exact-arithmetic ciphertext.
    pub(crate) const fn inner(&self) -> &bgv::Ciphertext {
        &self.inner
    }

    /// Returns the RLWE ciphertext degree.
    pub fn degree(&self) -> usize {
        self.inner.degree()
    }
}
