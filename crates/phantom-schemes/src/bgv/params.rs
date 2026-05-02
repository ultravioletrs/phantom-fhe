//! BGV parameters.

use phantom_lattice::rlwe::RlweParams;
use phantom_ring::{Modulus, Ring};

use crate::{Result, SchemesError};

/// Parameters for the BGV exact-arithmetic scheme.
#[derive(Clone, Debug)]
pub struct BgvParams {
    ring: Ring,
    plaintext_modulus: u64,
}

impl BgvParams {
    /// Creates validated BGV parameters.
    pub fn new(ring: Ring, plaintext_modulus: u64) -> Result<Self> {
        if plaintext_modulus <= 1 {
            return Err(SchemesError::InvalidParameters(
                "plaintext modulus must be greater than one",
            ));
        }
        if ring.moduli().is_empty() {
            return Err(SchemesError::InvalidParameters("ring must have moduli"));
        }
        let min_q = ring
            .moduli()
            .iter()
            .map(|q| q.value())
            .min()
            .ok_or(SchemesError::InvalidParameters("ring must have moduli"))?;
        if plaintext_modulus >= min_q {
            return Err(SchemesError::InvalidParameters(
                "plaintext modulus must be smaller than every ciphertext modulus",
            ));
        }
        Ok(Self {
            ring,
            plaintext_modulus,
        })
    }

    /// Returns the polynomial ring.
    pub const fn ring(&self) -> &Ring {
        &self.ring
    }

    /// Returns the plaintext modulus.
    pub const fn plaintext_modulus(&self) -> u64 {
        self.plaintext_modulus
    }

    /// Returns the number of plaintext slots in the current batching scaffold.
    pub fn slot_count(&self) -> usize {
        self.ring.degree()
    }

    /// Converts to scheme-agnostic RLWE parameters.
    pub fn rlwe_params(&self) -> phantom_lattice::Result<RlweParams> {
        RlweParams::new(self.ring.clone())
    }

    /// Returns a builder.
    pub fn builder() -> BgvParamsBuilder {
        BgvParamsBuilder::default()
    }
}

/// Builder for [`BgvParams`].
#[derive(Clone, Debug, Default)]
pub struct BgvParamsBuilder {
    degree: Option<usize>,
    moduli: Vec<u64>,
    plaintext_modulus: Option<u64>,
}

impl BgvParamsBuilder {
    /// Sets the power-of-two polynomial degree.
    pub const fn degree(mut self, degree: usize) -> Self {
        self.degree = Some(degree);
        self
    }

    /// Sets ciphertext moduli.
    pub fn moduli(mut self, moduli: impl Into<Vec<u64>>) -> Self {
        self.moduli = moduli.into();
        self
    }

    /// Appends one ciphertext modulus.
    pub fn push_modulus(mut self, modulus: u64) -> Self {
        self.moduli.push(modulus);
        self
    }

    /// Sets the plaintext modulus.
    pub const fn plaintext_modulus(mut self, plaintext_modulus: u64) -> Self {
        self.plaintext_modulus = Some(plaintext_modulus);
        self
    }

    /// Builds parameters.
    pub fn build(self) -> Result<BgvParams> {
        let degree = phantom_ring::Degree::new(
            self.degree
                .ok_or(SchemesError::InvalidParameters("missing degree"))?,
        )?;
        let plaintext_modulus = self
            .plaintext_modulus
            .ok_or(SchemesError::InvalidParameters("missing plaintext modulus"))?;
        if self.moduli.is_empty() {
            return Err(SchemesError::InvalidParameters("missing ciphertext moduli"));
        }

        let mut moduli = Vec::with_capacity(self.moduli.len());
        for modulus in self.moduli {
            moduli.push(Modulus::new(modulus)?);
        }
        BgvParams::new(Ring::new(degree, moduli)?, plaintext_modulus)
    }
}
