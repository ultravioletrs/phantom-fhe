//! Ergonomic CKKS bootstrapping evaluator.

use phantom_schemes::ckks::Ciphertext;

use super::{BootstrapKey, BootstrapParams, Bootstrapper};
use crate::Result;

/// Evaluator facade for CKKS bootstrapping operations.
#[derive(Clone, Debug)]
pub struct Evaluator {
    bootstrapper: Bootstrapper,
}

impl Evaluator {
    /// Creates an evaluator from bootstrapping parameters and key material.
    pub fn new(params: BootstrapParams, key: BootstrapKey) -> Self {
        Self {
            bootstrapper: Bootstrapper::new(params, key),
        }
    }

    /// Bootstraps one ciphertext.
    pub fn bootstrap(&self, input: &Ciphertext) -> Result<Ciphertext> {
        self.bootstrapper.bootstrap(input)
    }

    /// Bootstraps a batch of ciphertexts.
    pub fn bootstrap_batch(&self, inputs: &[Ciphertext]) -> Result<Vec<Ciphertext>> {
        self.bootstrapper.bootstrap_batch(inputs)
    }
}
