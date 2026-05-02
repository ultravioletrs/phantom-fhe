//! CKKS bootstrapping parameters.

use phantom_schemes::ckks::CkksParams;

use crate::{BootstrappingError, Result};

/// Parameters controlling CKKS bootstrapping scaffolds.
#[derive(Clone, Debug)]
pub struct BootstrapParams {
    ckks_params: CkksParams,
    target_level: usize,
    target_precision_bits: f64,
    sparse_slot_count: usize,
    batch_size: usize,
}

impl BootstrapParams {
    /// Creates validated bootstrapping parameters.
    pub fn new(
        ckks_params: CkksParams,
        target_level: usize,
        target_precision_bits: f64,
        sparse_slot_count: usize,
        batch_size: usize,
    ) -> Result<Self> {
        if target_level > ckks_params.initial_level() {
            return Err(BootstrappingError::InvalidParameters(
                "target level exceeds CKKS initial level",
            ));
        }
        if !target_precision_bits.is_finite() || target_precision_bits <= 0.0 {
            return Err(BootstrappingError::InvalidParameters(
                "target precision must be finite and positive",
            ));
        }
        if sparse_slot_count == 0 || sparse_slot_count > ckks_params.slot_count() {
            return Err(BootstrappingError::InvalidParameters(
                "sparse slot count must be in 1..=slot_count",
            ));
        }
        if batch_size == 0 {
            return Err(BootstrappingError::InvalidParameters(
                "batch size must be nonzero",
            ));
        }

        Ok(Self {
            ckks_params,
            target_level,
            target_precision_bits,
            sparse_slot_count,
            batch_size,
        })
    }

    /// Returns the underlying CKKS parameters.
    pub const fn ckks_params(&self) -> &CkksParams {
        &self.ckks_params
    }

    /// Returns the post-bootstrap target level.
    pub const fn target_level(&self) -> usize {
        self.target_level
    }

    /// Returns the post-bootstrap target precision in bits.
    pub const fn target_precision_bits(&self) -> f64 {
        self.target_precision_bits
    }

    /// Returns the sparse slot count used by packing helpers.
    pub const fn sparse_slot_count(&self) -> usize {
        self.sparse_slot_count
    }

    /// Returns the preferred batch size.
    pub const fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Returns a builder.
    pub fn builder(ckks_params: CkksParams) -> BootstrapParamsBuilder {
        BootstrapParamsBuilder::new(ckks_params)
    }
}

/// Builder for [`BootstrapParams`].
#[derive(Clone, Debug)]
pub struct BootstrapParamsBuilder {
    ckks_params: CkksParams,
    target_level: Option<usize>,
    target_precision_bits: Option<f64>,
    sparse_slot_count: Option<usize>,
    batch_size: Option<usize>,
}

impl BootstrapParamsBuilder {
    /// Creates a builder from CKKS parameters.
    pub const fn new(ckks_params: CkksParams) -> Self {
        Self {
            ckks_params,
            target_level: None,
            target_precision_bits: None,
            sparse_slot_count: None,
            batch_size: None,
        }
    }

    /// Sets the post-bootstrap level.
    pub const fn target_level(mut self, target_level: usize) -> Self {
        self.target_level = Some(target_level);
        self
    }

    /// Sets the post-bootstrap precision.
    pub const fn target_precision_bits(mut self, bits: f64) -> Self {
        self.target_precision_bits = Some(bits);
        self
    }

    /// Sets the sparse packing slot count.
    pub const fn sparse_slot_count(mut self, count: usize) -> Self {
        self.sparse_slot_count = Some(count);
        self
    }

    /// Sets the preferred batch size.
    pub const fn batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = Some(batch_size);
        self
    }

    /// Builds validated parameters.
    pub fn build(self) -> Result<BootstrapParams> {
        let target_level = self
            .target_level
            .unwrap_or_else(|| self.ckks_params.initial_level());
        let sparse_slot_count = self
            .sparse_slot_count
            .unwrap_or_else(|| self.ckks_params.slot_count());
        BootstrapParams::new(
            self.ckks_params,
            target_level,
            self.target_precision_bits.unwrap_or(20.0),
            sparse_slot_count,
            self.batch_size.unwrap_or(1),
        )
    }
}
