//! CKKS bootstrapping keys.

use super::BootstrapParams;

/// Transparent CKKS bootstrapping key marker.
#[derive(Clone, Debug)]
pub struct BootstrapKey {
    params: BootstrapParams,
    rotation_elements: Vec<usize>,
}

impl BootstrapKey {
    /// Creates a bootstrap key marker.
    pub fn new(params: BootstrapParams, rotation_elements: Vec<usize>) -> Self {
        Self {
            params,
            rotation_elements,
        }
    }

    /// Returns bootstrapping parameters.
    pub const fn params(&self) -> &BootstrapParams {
        &self.params
    }

    /// Returns requested rotation elements.
    pub fn rotation_elements(&self) -> &[usize] {
        &self.rotation_elements
    }
}

/// Generates transparent CKKS bootstrapping key markers.
#[derive(Clone, Debug)]
pub struct BootstrapKeyGenerator {
    params: BootstrapParams,
}

impl BootstrapKeyGenerator {
    /// Creates a key generator.
    pub const fn new(params: BootstrapParams) -> Self {
        Self { params }
    }

    /// Generates a bootstrap key marker for the requested rotations.
    pub fn generate(&self, rotation_elements: &[usize]) -> BootstrapKey {
        BootstrapKey::new(self.params.clone(), rotation_elements.to_vec())
    }
}
