//! BGV plaintext wrapper.

/// BGV plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plaintext {
    inner: phantom_lattice::rlwe::Plaintext,
}

impl Plaintext {
    /// Creates a plaintext from an RLWE plaintext.
    pub const fn new(inner: phantom_lattice::rlwe::Plaintext) -> Self {
        Self { inner }
    }

    /// Returns the inner RLWE plaintext.
    pub const fn inner(&self) -> &phantom_lattice::rlwe::Plaintext {
        &self.inner
    }

    /// Consumes the wrapper.
    pub fn into_inner(self) -> phantom_lattice::rlwe::Plaintext {
        self.inner
    }
}
