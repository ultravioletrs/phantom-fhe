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

    /// Returns the ring automorphism element `5^shift mod 2*degree` for
    /// rotating a real CKKS ciphertext's slots left by `shift` positions
    /// (`shift` taken mod [`Self::slot_count`], matching
    /// [`super::Evaluator::rotate_slots`]'s own transparent-scaffold
    /// `shift % len`) - see [`super::Encoder`]'s own module doc comment for
    /// why `5`-power indexing, not sequential, is what makes this a clean
    /// per-slot rotation rather than an arbitrary permutation mixing in
    /// conjugates. Only meaningful for the non-conjugate-invariant real
    /// path (real conjugate-invariant packing isn't supported yet - see
    /// [`super::Encoder::encode_complex_real`]'s own rejection of it).
    /// `element(0) == 1`, the identity automorphism.
    pub fn rotation_element(&self, shift: usize) -> usize {
        let slot_count = self.slot_count();
        let two_n = 2 * self.ring.degree();
        let steps = if slot_count == 0 {
            0
        } else {
            shift % slot_count
        };
        let mut element = 1usize;
        for _ in 0..steps {
            element = (element * 5) % two_n;
        }
        element
    }

    /// Returns the ring automorphism element for conjugating a real CKKS
    /// ciphertext's slots (`2*degree - 1`, i.e. `k = -1 mod 2*degree`) -
    /// the complement to [`Self::rotation_element`], see
    /// [`super::Encoder`]'s own module doc comment.
    pub fn conjugation_element(&self) -> usize {
        2 * self.ring.degree() - 1
    }

    /// Returns params with the ring truncated to its first `level + 1`
    /// moduli - the same convention [`Self::initial_level`] uses. Needed to
    /// decrypt or operate on a real ciphertext after
    /// [`super::Evaluator::rescale_next_real`] has dropped one or more of
    /// its own RNS components, since such a ciphertext's `Poly`s carry
    /// fewer moduli than the context's own full-level ring.
    pub fn at_level(&self, level: usize) -> Result<Self> {
        let moduli = self.ring.moduli();
        if level >= moduli.len() {
            return Err(SchemesError::InvalidParameters(
                "level exceeds the ring's available moduli",
            ));
        }
        let degree = Degree::new(self.ring.degree())?;
        let ring = Ring::new(degree, moduli[..=level].to_vec())?;
        Self::new(ring, self.default_scale, self.conjugate_invariant)
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

/// Builder for [`CkksParams`]. See `crate::security`'s own module doc
/// comment for the split between the consistency check [`Self::build`]
/// always applies and the security check [`Self::require_128_bit_security`]
/// opts into.
#[derive(Clone, Debug, Default)]
pub struct CkksParamsBuilder {
    degree: Option<usize>,
    moduli: Vec<u64>,
    default_scale_bits: Option<u32>,
    conjugate_invariant: bool,
    require_128_bit_security: bool,
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

    /// Requires [`Self::build`] to reject parameters that don't meet the
    /// homomorphicencryption.org 128-bit security standard - see
    /// `crate::security::check_128_bit_security`'s own doc comment.
    pub const fn require_128_bit_security(mut self) -> Self {
        self.require_128_bit_security = true;
        self
    }

    /// Builds parameters.
    pub fn build(self) -> Result<CkksParams> {
        let degree_value = self
            .degree
            .ok_or(SchemesError::InvalidParameters("missing degree"))?;
        let degree = Degree::new(degree_value)?;
        if self.moduli.is_empty() {
            return Err(SchemesError::InvalidParameters("missing ciphertext moduli"));
        }
        let mut moduli = Vec::with_capacity(self.moduli.len());
        for modulus in self.moduli {
            moduli.push(Modulus::new(modulus)?);
        }
        crate::security::check_distinct_moduli(&moduli)?;
        if self.require_128_bit_security {
            crate::security::check_128_bit_security(degree_value, &moduli)?;
        }
        let scale = Scale::from_bits(
            self.default_scale_bits
                .ok_or(SchemesError::InvalidParameters("missing default scale"))?,
        )?;
        CkksParams::new(Ring::new(degree, moduli)?, scale, self.conjugate_invariant)
    }
}
