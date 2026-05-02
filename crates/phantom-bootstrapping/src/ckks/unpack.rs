//! CKKS sparse unpacking helpers.

use phantom_schemes::ckks::Ciphertext;

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Unpacks dense transparent batches into sparse CKKS ciphertexts.
#[derive(Clone, Debug)]
pub struct Unpacker {
    params: BootstrapParams,
}

impl Unpacker {
    /// Creates an unpacker.
    pub const fn new(params: BootstrapParams) -> Self {
        Self { params }
    }

    /// Splits a ciphertext into `count` sparse ciphertexts.
    pub fn unpack(&self, input: &Ciphertext, count: usize) -> Result<Vec<Ciphertext>> {
        if count == 0 {
            return Err(BootstrappingError::InvalidParameters(
                "unpack count must be nonzero",
            ));
        }
        let needed = count * self.params.sparse_slot_count();
        if needed > input.slots().len() {
            return Err(BootstrappingError::DimensionMismatch);
        }

        let mut out = Vec::with_capacity(count);
        for index in 0..count {
            let start = index * self.params.sparse_slot_count();
            let end = start + self.params.sparse_slot_count();
            out.push(Ciphertext::new(
                input.slots()[start..end].to_vec(),
                input.scale(),
                input.level(),
                input.precision(),
                input.degree(),
            ));
        }
        Ok(out)
    }
}
