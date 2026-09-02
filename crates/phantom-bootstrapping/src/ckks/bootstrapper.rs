//! CKKS bootstrapper scaffold, plus a real (encrypted) pipeline
//! ([`Bootstrapper::bootstrap_real`]).

use phantom_lattice::rlwe::{GaloisKey, RelinearizationKey};
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

    /// Bootstraps one ciphertext: runs the real coefficients-to-slots /
    /// eval-mod / slots-to-coefficients pipeline (see [`EvalMod::reduce_mod_q`]'s
    /// own doc comment for what the middle stage actually removes) and
    /// refreshes metadata. `input`'s raw field is coefficient-domain (it is
    /// transformed by [`CoeffsToSlots::apply`] *first*), so a modulus-raised
    /// ciphertext's own wraparound shows up only after that first step:
    /// `coeffs_to_slots.apply(input)`'s slots may hold `m_j +
    /// raise_modulus*I_j` for the true message `m_j` and any bounded
    /// integer `I_j`, not just `m_j` itself. Producing that raised state
    /// from a *real* (encrypted) ciphertext is a separate, not-yet-built
    /// concern (Workstream 6 item 2's own real-path gap for BGV/BFV-style
    /// modulus mechanics, not attempted here) - on this transparent
    /// scaffold it's simply whatever `input` already contains.
    pub fn bootstrap(&self, input: &Ciphertext) -> Result<Ciphertext> {
        check_slots(&self.params, input)?;
        if self.params.ckks_params().conjugate_invariant() {
            return Ok(self.refresh_metadata(input));
        }
        let slots = self.coeffs_to_slots.apply(input)?;
        let slots = self.eval_mod.reduce_mod_q(&slots)?;
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

    /// Runs the real (encrypted) coefficients-to-slots / eval-mod /
    /// slots-to-coefficients pipeline on `input` - the same three stages
    /// [`Self::bootstrap`] composes transparently, but via
    /// [`CoeffsToSlots::apply_real`], [`EvalMod::reduce_mod_q_real`] and
    /// [`SlotsToCoeffs::apply_real`], each requiring its own real key
    /// material rather than operating on cleartext slots directly.
    ///
    /// Unlike [`Self::bootstrap`], this does **not** refresh `output`'s
    /// level/scale to [`BootstrapParams::target_level`] -
    /// [`Ciphertext::new`]'s transparent metadata relabeling has no real
    /// counterpart (a real ciphertext's level/scale describe its actual RNS
    /// representation, not a claim that can be overwritten without doing
    /// the work); `output` simply carries whatever level and scale fall out
    /// of the three real stages actually run.
    ///
    /// This is also *not* the full bootstrapping circuit: real
    /// bootstrapping starts by raising a nearly-exhausted ciphertext's
    /// modulus back up to a full top-level chain before this pipeline can
    /// run on it (the same modulus-raise gap [`Self::bootstrap`]'s own doc
    /// comment already documents as separate, not-yet-built - `input` here
    /// must already be at whatever raised level/modulus the three stages
    /// below expect, exactly as [`EvalMod::reduce_mod_q_real`]'s own tests
    /// construct it).
    ///
    /// Each stage's own key material is generated at a different level (the
    /// two `apply_real` calls each consume one level via their own internal
    /// rescale, and `reduce_mod_q_real` consumes more on top of that) - see
    /// [`CoeffsToSlots::apply_real`] and [`EvalMod::reduce_mod_q_real`]'s
    /// own doc comments for why a key generated at one level can't be
    /// reused at another.
    pub fn bootstrap_real(
        &self,
        input: &Ciphertext,
        c2s_galois_keys: &[GaloisKey],
        eval_mod_relin_keys: &[RelinearizationKey],
        s2c_galois_keys: &[GaloisKey],
    ) -> Result<Ciphertext> {
        if self.params.ckks_params().conjugate_invariant() {
            return Ok(input.clone());
        }
        let slots = self.coeffs_to_slots.apply_real(input, c2s_galois_keys)?;
        let slots = self
            .eval_mod
            .reduce_mod_q_real(&slots, eval_mod_relin_keys)?;
        self.slots_to_coeffs.apply_real(&slots, s2c_galois_keys)
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
