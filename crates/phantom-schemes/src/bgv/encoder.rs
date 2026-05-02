//! BGV batching encoder.

use phantom_lattice::rlwe;

use super::{BgvParams, Plaintext};
use crate::{Result, SchemesError};

/// Coefficient-batching encoder for exact integers modulo `t`.
#[derive(Clone, Debug)]
pub struct BatchEncoder {
    params: BgvParams,
}

impl BatchEncoder {
    /// Creates an encoder.
    pub const fn new(params: BgvParams) -> Self {
        Self { params }
    }

    /// Returns the number of supported slots.
    pub fn slot_count(&self) -> usize {
        self.params.slot_count()
    }

    /// Encodes unsigned integers modulo the plaintext modulus.
    pub fn encode_u64(&self, values: &[u64]) -> Result<Plaintext> {
        if values.len() > self.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }

        let ring = self.params.ring();
        let t = self.params.plaintext_modulus();
        let mut poly = ring.zero();
        for component_index in 0..poly.moduli_count() {
            let q = ring.moduli()[component_index].value();
            for (slot, value) in values.iter().copied().enumerate() {
                poly.coeffs_mut()[component_index][slot] = (value % t) % q;
            }
        }
        Ok(Plaintext::new(rlwe::Plaintext::new(poly)))
    }

    /// Decodes all slots as unsigned integers modulo the plaintext modulus.
    pub fn decode_u64(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        self.params.ring().check_poly(plaintext.inner().value())?;
        let first_component = plaintext
            .inner()
            .value()
            .component(0)
            .ok_or(SchemesError::DimensionMismatch)?;
        let q = self.params.ring().moduli()[0].value();
        let t = self.params.plaintext_modulus();
        Ok(first_component
            .iter()
            .map(|coeff| decode_signed_residue(*coeff, q, t))
            .collect())
    }
}

fn decode_signed_residue(coeff: u64, modulus: u64, plaintext_modulus: u64) -> u64 {
    if coeff <= modulus / 2 {
        coeff % plaintext_modulus
    } else {
        let magnitude = (modulus - coeff) % plaintext_modulus;
        if magnitude == 0 {
            0
        } else {
            plaintext_modulus - magnitude
        }
    }
}
