//! CKKS sparse packing helpers.

use phantom_schemes::ckks::{Ciphertext, Complex64};

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Packs sparse CKKS ciphertexts into a dense transparent batch.
#[derive(Clone, Debug)]
pub struct Packer {
    params: BootstrapParams,
}

impl Packer {
    /// Creates a packer.
    pub const fn new(params: BootstrapParams) -> Self {
        Self { params }
    }

    /// Packs ciphertext slots by concatenation and zero-padding to the full slot count.
    pub fn pack(&self, inputs: &[Ciphertext]) -> Result<Ciphertext> {
        if inputs.is_empty() {
            return Err(BootstrappingError::InvalidParameters(
                "cannot pack an empty ciphertext batch",
            ));
        }

        let mut slots = Vec::new();
        for input in inputs {
            if input.slots().len() > self.params.sparse_slot_count() {
                return Err(BootstrappingError::DimensionMismatch);
            }
            slots.extend_from_slice(input.slots());
        }
        if slots.len() > self.params.ckks_params().slot_count() {
            return Err(BootstrappingError::DimensionMismatch);
        }
        slots.resize(self.params.ckks_params().slot_count(), Complex64::default());

        let first = &inputs[0];
        Ok(Ciphertext::new(
            slots,
            first.scale(),
            first.level(),
            first.precision(),
            first.degree(),
        ))
    }
}
