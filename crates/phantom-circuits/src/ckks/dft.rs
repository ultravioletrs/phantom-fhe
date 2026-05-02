//! CKKS DFT helpers over transparent slots.

use std::f64::consts::PI;

use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64};

use crate::ckks::{c_add, c_mul, c_scale, check_ciphertext, ckks_ciphertext_like, ensure_finite};
use crate::error::Result;

/// Direction for a discrete Fourier transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DftDirection {
    /// Forward DFT with negative exponent.
    Forward,
    /// Inverse DFT with positive exponent and `1/n` normalization.
    Inverse,
}

/// Evaluates homomorphic-DFT scaffolds over CKKS slots.
#[derive(Clone, Debug)]
pub struct DftEvaluator {
    params: CkksParams,
}

impl DftEvaluator {
    /// Creates a DFT evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Applies a direct O(n^2) DFT to transparent CKKS slots.
    pub fn transform(&self, input: &Ciphertext, direction: DftDirection) -> Result<Ciphertext> {
        check_ciphertext(&self.params, input)?;
        let n = input.slots().len();
        if n == 0 {
            return Ok(input.clone());
        }
        let sign = match direction {
            DftDirection::Forward => -1.0,
            DftDirection::Inverse => 1.0,
        };
        let scale = match direction {
            DftDirection::Forward => 1.0,
            DftDirection::Inverse => 1.0 / n as f64,
        };

        let mut out = vec![Complex64::default(); n];
        for (k, out_slot) in out.iter_mut().enumerate() {
            let mut acc = Complex64::default();
            for (j, value) in input.slots().iter().copied().enumerate() {
                let angle = sign * 2.0 * PI * (j * k) as f64 / n as f64;
                let twiddle = Complex64::new(angle.cos(), angle.sin());
                acc = c_add(acc, c_mul(value, twiddle));
            }
            *out_slot = c_scale(acc, scale);
        }
        ensure_finite(&out)?;
        Ok(ckks_ciphertext_like(input, out, 1.0))
    }
}
