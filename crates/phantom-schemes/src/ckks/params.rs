//! CKKS parameters.

use phantom_lattice::rlwe::RlweParams;
use phantom_ring::{Degree, Modulus, Ring};

use super::Scale;
use crate::{Result, SchemesError};

/// Parameters for the CKKS approximate-arithmetic scheme.
#[derive(Clone, Debug)]
pub struct CkksParams {
    ring: Ring,
    default_scale: Scale,
    conjugate_invariant: bool,
}

impl CkksParams {
    /// Creates validated CKKS parameters.
    pub fn new(ring: Ring, default_scale: Scale, conjugate_invariant: bool) -> Result<Self> {
        if ring.moduli().is_empty() {
            return Err(SchemesError::InvalidParameters("ring must have moduli"));
        }
        Ok(Self {
            ring,
            default_scale,
            conjugate_invariant,
        })
    }

    /// Returns the polynomial ring.
    pub const fn ring(&self) -> &Ring {
        &self.ring
    }

    /// Returns the default scale.
    pub const fn default_scale(&self) -> Scale {
        self.default_scale
    }

    /// Returns whether the context is conjugate-invariant.
    pub const fn conjugate_invariant(&self) -> bool {
        self.conjugate_invariant
    }

    /// Returns the number of supported slots.
    pub fn slot_count(&self) -> usize {
        if self.conjugate_invariant {
            self.ring.degree()
        } else {
            self.ring.degree() / 2
        }
    }

    /// Returns the initial level.
    pub fn initial_level(&self) -> usize {
        self.ring.moduli().len().saturating_sub(1)
    }

    /// Converts to scheme-agnostic RLWE parameters.
    pub fn rlwe_params(&self) -> phantom_lattice::Result<RlweParams> {
        RlweParams::new(self.ring.clone())
    }

    /// Returns a builder.
    pub fn builder() -> CkksParamsBuilder {
        CkksParamsBuilder::default()
    }
}

/// Builder for [`CkksParams`].
#[derive(Clone, Debug, Default)]
pub struct CkksParamsBuilder {
    degree: Option<usize>,
    moduli: Vec<u64>,
    default_scale_bits: Option<u32>,
    conjugate_invariant: bool,
}

impl CkksParamsBuilder {
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

    /// Sets the default scale as `2^bits`.
    pub const fn default_scale_bits(mut self, bits: u32) -> Self {
        self.default_scale_bits = Some(bits);
        self
    }

    /// Enables or disables conjugate-invariant real packing.
    pub const fn conjugate_invariant(mut self, enabled: bool) -> Self {
        self.conjugate_invariant = enabled;
        self
    }

    /// Builds parameters.
    pub fn build(self) -> Result<CkksParams> {
        let degree = Degree::new(
            self.degree
                .ok_or(SchemesError::InvalidParameters("missing degree"))?,
        )?;
        if self.moduli.is_empty() {
            return Err(SchemesError::InvalidParameters("missing ciphertext moduli"));
        }
        let mut moduli = Vec::with_capacity(self.moduli.len());
        for modulus in self.moduli {
            moduli.push(Modulus::new(modulus)?);
        }
        let scale = Scale::from_bits(
            self.default_scale_bits
                .ok_or(SchemesError::InvalidParameters("missing default scale"))?,
        )?;
        CkksParams::new(Ring::new(degree, moduli)?, scale, self.conjugate_invariant)
    }
}
