//! CKKS slots-to-coefficients transform scaffold, plus a real (encrypted)
//! evaluator ([`SlotsToCoeffs::apply_real`]).

use phantom_circuits::ckks::{DftDirection, DftEvaluator, LinearTransformEvaluator};
use phantom_lattice::rlwe::GaloisKey;
use phantom_schemes::ckks::{Ciphertext, Evaluator};

use super::coeffs_to_slots::u0_u1_matrices;
use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Slots-to-coefficients transform.
#[derive(Clone, Debug)]
pub struct SlotsToCoeffs {
    params: BootstrapParams,
    dft: DftEvaluator,
}

impl SlotsToCoeffs {
    /// Creates a slots-to-coefficients transform.
    pub fn new(params: BootstrapParams) -> Self {
        let dft = DftEvaluator::new(params.ckks_params().clone());
        Self { params, dft }
    }

    /// Applies the transparent transform.
    pub fn apply(&self, input: &Ciphertext) -> Result<Ciphertext> {
        self.dft
            .transform(input, DftDirection::Inverse)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))
    }

    /// Applies the **real** (encrypted) inverse of
    /// [`super::CoeffsToSlots::apply_real`] - see that method's own doc
    /// comment for the derivation. Given the two ciphertexts it produced
    /// (or, after `EvalMod` has reduced each independently, their
    /// corrected replacements), reconstructs the single ciphertext whose
    /// own canonical-embedding slots are `z' = U_0 . z0 + U_1 . z1` (the
    /// paper's own inverse identity, verified alongside the forward one) -
    /// no conjugation needed this direction, just two
    /// [`LinearTransformEvaluator::apply_real`] calls (against `U_0`,
    /// `U_1` directly, not their conjugate-transposes) plus an `add_real`.
    ///
    /// `z0`/`z1` must be at the same level; `galois_keys` must contain one
    /// real [`GaloisKey`] per rotation offset `1..n` (`n = slot_count`),
    /// generated at that level. Costs one rescale (both underlying
    /// `apply_real` calls are parallel branches from `z0`'s/`z1`'s own
    /// starting level).
    pub fn apply_real(
        &self,
        z0: &Ciphertext,
        z1: &Ciphertext,
        galois_keys: &[GaloisKey],
    ) -> Result<Ciphertext> {
        let n = self.params.ckks_params().slot_count();
        let (u0, u1) = u0_u1_matrices(n);
        let lintrans = LinearTransformEvaluator::new(self.params.ckks_params().clone());
        let evaluator = Evaluator::new(self.params.ckks_params().clone());

        let diag_u0 = lintrans
            .diagonalize(&u0)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))?;
        let diag_u1 = lintrans
            .diagonalize(&u1)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))?;

        let term0 = lintrans
            .apply_real(z0, &diag_u0, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))?;
        let term1 = lintrans
            .apply_real(z1, &diag_u1, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))?;
        evaluator
            .add_real(&term0, &term1)
            .map_err(|_| BootstrappingError::CircuitOperation("slots-to-coefficients"))
    }
}
