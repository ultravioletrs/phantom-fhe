//! CKKS bootstrapper scaffold.

use phantom_schemes::ckks::{Ciphertext, Precision};

use super::{BootstrapKey, BootstrapParams, CoeffsToSlots, EvalMod, SlotsToCoeffs};
use crate::ckks::coeffs_to_slots::check_slots;
use crate::Result;

/// Centralized CKKS bootstrapper.
#[derive(Clone, Debug)]
pub struct Bootstrapper {
    params: BootstrapParams,
    key: BootstrapKey,
    coeffs_to_slots: CoeffsToSlots,
    slots_to_coeffs: SlotsToCoeffs,
    eval_mod: EvalMod,
}

impl Bootstrapper {
    /// Creates a bootstrapper from parameters and a bootstrap key marker.
    pub fn new(params: BootstrapParams, key: BootstrapKey) -> Self {
        Self {
            coeffs_to_slots: CoeffsToSlots::new(params.clone()),
            slots_to_coeffs: SlotsToCoeffs::new(params.clone()),
            eval_mod: EvalMod::new(params.clone()),
            params,
            key,
        }
    }

    /// Returns bootstrapping parameters.
    pub const fn params(&self) -> &BootstrapParams {
        &self.params
    }

    /// Returns the bootstrap key marker.
    pub const fn key(&self) -> &BootstrapKey {
        &self.key
    }

    /// Bootstraps one ciphertext, preserving transparent messages and refreshing metadata.
    pub fn bootstrap(&self, input: &Ciphertext) -> Result<Ciphertext> {
        check_slots(&self.params, input)?;
        if self.params.ckks_params().conjugate_invariant() {
            return Ok(self.refresh_metadata(input));
        }
        let slots = self.coeffs_to_slots.apply(input)?;
        let slots = self.eval_mod.preserve_message(&slots)?;
        let coeffs = self.slots_to_coeffs.apply(&slots)?;
        Ok(self.refresh_metadata(&coeffs))
    }

    /// Bootstraps a batch of ciphertexts.
    pub fn bootstrap_batch(&self, inputs: &[Ciphertext]) -> Result<Vec<Ciphertext>> {
        inputs
            .iter()
            .map(|ciphertext| self.bootstrap(ciphertext))
            .collect()
    }

    fn refresh_metadata(&self, ciphertext: &Ciphertext) -> Ciphertext {
        Ciphertext::new(
            ciphertext.slots().to_vec(),
            self.params.ckks_params().default_scale(),
            self.params.target_level(),
            Precision::new(self.params.target_precision_bits()),
            ciphertext.degree(),
        )
    }
}
