//! CKKS approximate encoders.

use super::{CkksParams, Complex64, Plaintext, Precision, Scale};
use crate::{Result, SchemesError};

/// CKKS encoder for complex and real vectors.
#[derive(Clone, Debug)]
pub struct Encoder {
    params: CkksParams,
}

impl Encoder {
    /// Creates an encoder.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Returns the number of supported slots.
    pub fn slot_count(&self) -> usize {
        self.params.slot_count()
    }

    /// Encodes complex slots with the default scale.
    pub fn encode_complex(&self, values: &[Complex64]) -> Result<Plaintext> {
        if self.params.conjugate_invariant() && values.iter().any(|v| v.im != 0.0) {
            return Err(SchemesError::InvalidParameters(
                "conjugate-invariant CKKS accepts real slots only",
            ));
        }
        self.encode_complex_with_scale(values, self.params.default_scale())
    }

    /// Encodes real slots with the default scale.
    pub fn encode_real(&self, values: &[f64]) -> Result<Plaintext> {
        let values = values
            .iter()
            .copied()
            .map(Complex64::real)
            .collect::<Vec<_>>();
        self.encode_complex(&values)
    }

    /// Encodes complex slots with an explicit scale.
    pub fn encode_complex_with_scale(
        &self,
        values: &[Complex64],
        scale: Scale,
    ) -> Result<Plaintext> {
        if values.len() > self.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        if values
            .iter()
            .any(|v| !v.re.is_finite() || !v.im.is_finite())
        {
            return Err(SchemesError::InvalidParameters("CKKS slots must be finite"));
        }
        let precision = Precision::new(scale.value().log2().max(0.0));
        Ok(Plaintext::new(
            values.to_vec(),
            scale,
            self.params.initial_level(),
            precision,
        ))
    }

    /// Decodes complex slots.
    pub fn decode_complex(&self, plaintext: &Plaintext) -> Result<Vec<Complex64>> {
        if plaintext.slots().len() > self.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        Ok(plaintext.slots().to_vec())
    }

    /// Decodes real slots.
    pub fn decode_real(&self, plaintext: &Plaintext) -> Result<Vec<f64>> {
        Ok(self
            .decode_complex(plaintext)?
            .into_iter()
            .map(|value| value.re)
            .collect())
    }
}
