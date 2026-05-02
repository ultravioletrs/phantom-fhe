//! BGV ciphertext wrapper.

/// BGV ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    inner: phantom_lattice::rlwe::Ciphertext,
}

impl Ciphertext {
    /// Creates a ciphertext from an RLWE ciphertext.
    pub const fn new(inner: phantom_lattice::rlwe::Ciphertext) -> Self {
        Self { inner }
    }

    /// Returns the inner RLWE ciphertext.
    pub const fn inner(&self) -> &phantom_lattice::rlwe::Ciphertext {
        &self.inner
    }

    /// Consumes the wrapper.
    pub fn into_inner(self) -> phantom_lattice::rlwe::Ciphertext {
        self.inner
    }

    /// Returns the RLWE ciphertext degree.
    pub fn degree(&self) -> usize {
        self.inner.degree()
    }
}
