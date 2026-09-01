//! BFV parameters.

use crate::bgv;
use crate::Result;

/// Parameters for the BFV exact-arithmetic scheme.
#[derive(Clone, Debug)]
pub struct BfvParams {
    inner: bgv::BgvParams,
}

impl BfvParams {
    /// Creates validated BFV parameters.
    pub fn new(ring: phantom_ring::Ring, plaintext_modulus: u64) -> Result<Self> {
        Ok(Self {
            inner: bgv::BgvParams::new(ring, plaintext_modulus)?,
        })
    }

    /// Returns the polynomial ring.
    pub const fn ring(&self) -> &phantom_ring::Ring {
        self.inner.ring()
    }

    /// Returns the plaintext modulus.
    pub const fn plaintext_modulus(&self) -> u64 {
        self.inner.plaintext_modulus()
    }

    /// Returns the number of plaintext slots in the current batching scaffold.
    pub fn slot_count(&self) -> usize {
        self.inner.slot_count()
    }

    /// Converts to scheme-agnostic RLWE parameters.
    pub fn rlwe_params(&self) -> phantom_lattice::Result<phantom_lattice::rlwe::RlweParams> {
        self.inner.rlwe_params()
    }

    /// Returns the shared exact-arithmetic scaffold parameters.
    pub(crate) const fn inner(&self) -> &bgv::BgvParams {
        &self.inner
    }

    /// Returns a builder.
    pub fn builder() -> BfvParamsBuilder {
        BfvParamsBuilder::default()
    }
}

/// Builder for [`BfvParams`].
#[derive(Clone, Debug, Default)]
pub struct BfvParamsBuilder {
    inner: bgv::BgvParamsBuilder,
}

impl BfvParamsBuilder {
    /// Sets the power-of-two polynomial degree.
    pub fn degree(mut self, degree: usize) -> Self {
        self.inner = self.inner.degree(degree);
        self
    }

    /// Sets ciphertext moduli.
    pub fn moduli(mut self, moduli: impl Into<Vec<u64>>) -> Self {
        self.inner = self.inner.moduli(moduli);
        self
    }

    /// Appends one ciphertext modulus.
    pub fn push_modulus(mut self, modulus: u64) -> Self {
        self.inner = self.inner.push_modulus(modulus);
        self
    }

    /// Sets the plaintext modulus.
    pub fn plaintext_modulus(mut self, plaintext_modulus: u64) -> Self {
        self.inner = self.inner.plaintext_modulus(plaintext_modulus);
        self
    }

    /// Requires [`Self::build`] to reject parameters that don't meet the
    /// homomorphicencryption.org 128-bit security standard - see
    /// `crate::security::check_128_bit_security`'s own doc comment.
    pub fn require_128_bit_security(mut self) -> Self {
        self.inner = self.inner.require_128_bit_security();
        self
    }

    /// Builds parameters.
    pub fn build(self) -> Result<BfvParams> {
        Ok(BfvParams {
            inner: self.inner.build()?,
        })
    }
}
