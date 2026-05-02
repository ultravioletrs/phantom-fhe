//! BFV plaintext wrapper.

use crate::bgv;

/// BFV plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plaintext {
    inner: bgv::Plaintext,
}

impl Plaintext {
    /// Creates a BFV plaintext from the shared exact-arithmetic representation.
    pub const fn new(inner: bgv::Plaintext) -> Self {
        Self { inner }
    }

    /// Returns the shared exact-arithmetic plaintext.
    pub const fn inner(&self) -> &bgv::Plaintext {
        &self.inner
    }
}
