//! CKKS mod-one approximation helpers.

use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64};

use crate::ckks::{check_ciphertext, ckks_ciphertext_like, ensure_finite};
use crate::error::Result;

/// Evaluates the fractional `x mod 1` centered around zero.
#[derive(Clone, Debug)]
pub struct Mod1Evaluator {
    params: CkksParams,
}

impl Mod1Evaluator {
    /// Creates a mod-one evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Maps real slot values to `x - round(x)`.
    pub fn centered_fractional_part(&self, input: &Ciphertext) -> Result<Ciphertext> {
        check_ciphertext(&self.params, input)?;
        let slots = input
            .slots()
            .iter()
            .map(|slot| Complex64::real(slot.re - slot.re.round()))
            .collect::<Vec<_>>();
        ensure_finite(&slots)?;
        Ok(ckks_ciphertext_like(input, slots, 1.25))
    }
}
