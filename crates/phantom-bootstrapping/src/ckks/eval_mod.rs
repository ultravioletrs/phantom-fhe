//! CKKS eval-mod scaffold.
//!
//! Real CKKS bootstrapping's "eval-mod" stage removes an unknown multiple
//! of the ciphertext's own lowest modulus `q_0` that "raising" the
//! ciphertext into a bigger working modulus introduces: after
//! [`super::CoeffsToSlots::apply`], each slot holds (approximately) `m_j +
//! q_0*I_j` for the true message `m_j` (assumed bounded, `|m_j| <<
//! q_0/2`) and some unknown but *bounded* integer `I_j`. Reducing each
//! slot mod `q_0`, centered, recovers `m_j` - the standard technique
//! (Cheon-Han-Kim-Kim-Song and follow-ups) approximates this centered
//! mod-`q_0` reduction with a low-degree polynomial (often built from
//! `sin`/`cos`), but the *exact* operation it approximates is precisely
//! `phantom_circuits::ckks::Mod1Evaluator::centered_fractional_part`'s
//! own `x - round(x)` ("mod 1", centered) - scaled by `q_0`:
//! `q_0 * centered_fractional_part(x / q_0)`.
//!
//! [`Mod1Evaluator::centered_fractional_part`] itself only ever computes
//! the *unscaled* `x - round(x)` (correct for its own direct callers,
//! which operate on already-bounded-by-one inputs) - calling it directly
//! on [`super::CoeffsToSlots::apply`]'s own output, whose magnitude has no
//! relationship to `1`, would silently corrupt any message not already in
//! `(-0.5, 0.5)` (confirmed directly: this crate's own pre-existing test,
//! `eval_mod_exposes_centered_fractional_part_without_forcing_bootstrap_to_change_messages`,
//! is named specifically to document that exposing it wasn't the same as
//! wiring it in unscaled). [`EvalMod::reduce_mod_q`] is the scaled
//! version [`super::Bootstrapper::bootstrap`] actually needs, verified
//! numerically (Python, 20000 randomized trials, `|m| < 0.4*q`, real and
//! complex) before implementing - real and imaginary parts reduced
//! independently, since a genuine complex slot's own real/imaginary
//! "wraparound" integers are themselves independent.

use phantom_circuits::ckks::Mod1Evaluator;
use phantom_schemes::ckks::{Ciphertext, Complex64};

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Eval-mod circuit scaffold.
#[derive(Clone, Debug)]
pub struct EvalMod {
    params: BootstrapParams,
    mod1: Mod1Evaluator,
}

impl EvalMod {
    /// Creates an eval-mod circuit.
    pub fn new(params: BootstrapParams) -> Self {
        let mod1 = Mod1Evaluator::new(params.ckks_params().clone());
        Self { params, mod1 }
    }

    /// Applies centered mod-one directly (`x - round(x)`, **not** scaled
    /// by [`BootstrapParams::raise_modulus`]) - exposed standalone for
    /// direct callers that already have a bounded-by-one input, but *not*
    /// what [`super::Bootstrapper::bootstrap`] itself uses (see
    /// [`Self::reduce_mod_q`] and this module's own doc comment for why).
    pub fn centered_fractional_part(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let _ = &self.params;
        self.mod1
            .centered_fractional_part(input)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))
    }

    /// Transparent eval-mod used by the correctness scaffold to preserve messages.
    pub fn preserve_message(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let _ = &self.params;
        Ok(input.clone())
    }

    /// Removes an unknown multiple of [`BootstrapParams::raise_modulus`]
    /// (`q`) from every slot, real and imaginary parts independently:
    /// `q * centered_fractional_part(x / q)` - see this module's own doc
    /// comment for the derivation and why this, not
    /// [`Self::centered_fractional_part`] directly, is the real-CKKS-style
    /// eval-mod operation [`super::Bootstrapper::bootstrap`] uses.
    pub fn reduce_mod_q(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let q = self.params.raise_modulus();
        let slots = input
            .slots()
            .iter()
            .map(|slot| Complex64::new(reduce_mod(slot.re, q), reduce_mod(slot.im, q)))
            .collect();
        Ok(Ciphertext::new(
            slots,
            input.scale(),
            input.level(),
            input.precision(),
            input.degree(),
        ))
    }
}

fn reduce_mod(x: f64, q: f64) -> f64 {
    let scaled = x / q;
    q * (scaled - scaled.round())
}
