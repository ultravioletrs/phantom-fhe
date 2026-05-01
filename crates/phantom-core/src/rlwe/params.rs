//! RLWE parameter wrapper.

use phantom_ring::Ring;

use crate::{CoreError, Result};

/// Scheme-agnostic RLWE parameters.
#[derive(Clone, Debug)]
pub struct RlweParams {
    ring: Ring,
}

impl RlweParams {
    /// Creates parameters from a ring context.
    pub fn new(ring: Ring) -> Result<Self> {
        if ring.moduli().is_empty() {
            return Err(CoreError::InvalidParameters("ring must have moduli"));
        }
        Ok(Self { ring })
    }

    /// Returns the ring context.
    pub const fn ring(&self) -> &Ring {
        &self.ring
    }

    /// Returns a builder.
    pub fn builder() -> RlweParamsBuilder {
        RlweParamsBuilder { ring: None }
    }
}

/// Builder for [`RlweParams`].
#[derive(Clone, Debug, Default)]
pub struct RlweParamsBuilder {
    ring: Option<Ring>,
}

impl RlweParamsBuilder {
    /// Sets the ring context.
    pub fn ring(mut self, ring: Ring) -> Self {
        self.ring = Some(ring);
        self
    }

    /// Builds parameters.
    pub fn build(self) -> Result<RlweParams> {
        let ring = self
            .ring
            .ok_or(CoreError::InvalidParameters("missing ring"))?;
        RlweParams::new(ring)
    }
}
