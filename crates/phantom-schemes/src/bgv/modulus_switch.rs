//! BGV modulus-switching surface.

use super::{BgvParams, Ciphertext};
use crate::Result;

/// Modulus-switching facade.
#[derive(Clone, Debug)]
pub struct ModulusSwitcher {
    params: BgvParams,
}

impl ModulusSwitcher {
    /// Creates a switcher.
    pub const fn new(params: BgvParams) -> Self {
        Self { params }
    }

    /// Switches to the next modulus level.
    ///
    /// This correctness scaffold preserves the ciphertext unchanged. A later
    /// production pass will replace it with level-aware RNS modulus switching.
    pub fn switch_next(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        for component in ciphertext.inner().value() {
            self.params.ring().check_poly(component)?;
        }
        Ok(ciphertext.clone())
    }
}
