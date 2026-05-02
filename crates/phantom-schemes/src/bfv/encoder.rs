//! BFV batching encoder.

use super::{BfvParams, Plaintext};
use crate::{bgv, Result};

/// Coefficient-batching encoder for exact integers modulo `t`.
#[derive(Clone, Debug)]
pub struct BatchEncoder {
    params: BfvParams,
    inner: bgv::BatchEncoder,
}

impl BatchEncoder {
    /// Creates an encoder.
    pub fn new(params: BfvParams) -> Self {
        Self {
            inner: bgv::BatchEncoder::new(params.inner().clone()),
            params,
        }
    }

    /// Returns the number of supported slots.
    pub fn slot_count(&self) -> usize {
        self.inner.slot_count()
    }

    /// Encodes unsigned integers modulo the plaintext modulus.
    pub fn encode_u64(&self, values: &[u64]) -> Result<Plaintext> {
        Ok(Plaintext::new(self.inner.encode_u64(values)?))
    }

    /// Decodes all slots as unsigned integers modulo the plaintext modulus.
    pub fn decode_u64(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        self.inner.decode_u64(plaintext.inner())
    }

    /// Encodes signed integers modulo the plaintext modulus.
    pub fn encode_i64(&self, values: &[i64]) -> Result<Plaintext> {
        let t = self.params.plaintext_modulus();
        let encoded = values
            .iter()
            .map(|value| encode_signed(*value, t))
            .collect::<Vec<_>>();
        self.encode_u64(&encoded)
    }

    /// Decodes all slots as centered signed integers modulo the plaintext modulus.
    pub fn decode_i64(&self, plaintext: &Plaintext) -> Result<Vec<i64>> {
        let t = self.params.plaintext_modulus();
        Ok(self
            .decode_u64(plaintext)?
            .into_iter()
            .map(|value| decode_signed(value, t))
            .collect())
    }
}

fn encode_signed(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        value as u64 % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

fn decode_signed(value: u64, modulus: u64) -> i64 {
    let value = value % modulus;
    if value > modulus / 2 {
        -((modulus - value) as i64)
    } else {
        value as i64
    }
}
