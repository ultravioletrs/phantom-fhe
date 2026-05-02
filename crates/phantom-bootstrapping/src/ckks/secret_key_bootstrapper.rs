//! Secret-key CKKS bootstrapping scaffold for tests and examples.

use phantom_schemes::ckks::Ciphertext;

use super::{BootstrapKeyGenerator, BootstrapParams, Bootstrapper};
use crate::Result;

/// Test-oriented secret-key bootstrapper that creates transparent key markers internally.
#[derive(Clone, Debug)]
pub struct SecretKeyBootstrapper {
    inner: Bootstrapper,
}

impl SecretKeyBootstrapper {
    /// Creates a secret-key bootstrapper scaffold.
    pub fn new(params: BootstrapParams, rotation_elements: &[usize]) -> Self {
        let key = BootstrapKeyGenerator::new(params.clone()).generate(rotation_elements);
        Self {
            inner: Bootstrapper::new(params, key),
        }
    }

    /// Bootstraps one ciphertext.
    pub fn bootstrap(&self, input: &Ciphertext) -> Result<Ciphertext> {
        self.inner.bootstrap(input)
    }
}
