//! BFV batching encoder.

use super::{BfvParams, Plaintext};
use crate::{bgv, Result, SchemesError};

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

    /// Encodes unsigned integers `Delta`-scaled - the encrypt-side
    /// counterpart [`Self::decode_u64_real`] needs on the way back: embeds
    /// a value directly as if it had gone through the real encryption
    /// path's own `Delta = floor(q/t)` scaling, without any encryption
    /// (e.g. to build a trivial, `c1 = 0` ciphertext row from an already-
    /// known plaintext value - `phantom_multiparty`'s own collective
    /// bootstrapping needs exactly this, re-embedding a value revealed
    /// through a masked collective decryption).
    pub fn encode_u64_real(&self, values: &[u64]) -> Result<Plaintext> {
        let unscaled = self.inner.encode_u64(values)?;
        let scaled = super::encryptor::scale_by_delta(
            self.params.ring(),
            unscaled.inner().value(),
            self.params.plaintext_modulus(),
        )?;
        Ok(Plaintext::new(bgv::Plaintext::new(
            phantom_lattice::rlwe::Plaintext::new(scaled),
        )))
    }

    /// Encodes `values` via genuine CRT-based SIMD batching - a direct
    /// pass-through to [`bgv::BatchEncoder::encode_batched`] (BFV shares
    /// BGV's plaintext ring/slot structure entirely; see that method's own
    /// module doc comment for the algorithm and slot layout).
    pub fn encode_batched(&self, values: &[u64]) -> Result<Plaintext> {
        Ok(Plaintext::new(self.inner.encode_batched(values)?))
    }

    /// Decodes all slots from a CRT-batched plaintext - the exact inverse
    /// of [`Self::encode_batched`].
    pub fn decode_batched(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        self.inner.decode_batched(plaintext.inner())
    }

    /// Decodes a raw decrypted real-BFV ciphertext's slots via CRT-based
    /// SIMD batching - the [`Self::encode_batched`]/[`Self::decode_batched`]
    /// counterpart [`Self::decode_u64_real`] is for raw-coefficient
    /// packing. First recovers each raw coefficient's true mod-`t` value
    /// the same way [`Self::decode_u64_real`] does (`decode_bfv_residue`:
    /// center, `round(|centered|*t/q)`, reapply sign), then re-embeds those
    /// values as a fresh mod-`t` plaintext and runs
    /// [`bgv::BatchEncoder::decode_batched`]'s own NTT-based slot decode on
    /// it - safe because `decode_bfv_residue`'s output is always `< t`,
    /// well inside the "positive half" `bgv`'s own residue interpretation
    /// expects, so re-embedding it as a plain nonnegative coefficient and
    /// decoding it again is a no-op round trip.
    pub fn decode_batched_real(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        let ring = self.params.ring();
        ring.check_poly(plaintext.inner().inner().value())?;
        let component = plaintext
            .inner()
            .inner()
            .value()
            .component(0)
            .ok_or(SchemesError::DimensionMismatch)?;
        let q = ring.moduli()[0].value();
        let t = self.params.plaintext_modulus();
        let descaled: Vec<u64> = component
            .iter()
            .map(|&coeff| decode_bfv_residue(coeff, q, t))
            .collect();

        let mut embedded = ring.zero();
        for component_index in 0..embedded.moduli_count() {
            let qc = ring.moduli()[component_index].value();
            for (i, &v) in descaled.iter().enumerate() {
                embedded.coeffs_mut()[component_index][i] = v % qc;
            }
        }
        let embedded_plaintext =
            bgv::Plaintext::new(phantom_lattice::rlwe::Plaintext::new(embedded));
        self.inner.decode_batched(&embedded_plaintext)
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

    /// Decodes a raw decrypted real-BFV ciphertext's first component (`c0 +
    /// c1*s + ... = Delta*m + E (mod q)`, not yet unscaled) as unsigned
    /// integers modulo the plaintext modulus - the counterpart
    /// [`crate::bfv::Encryptor`]'s real path needs, since it scales the
    /// message by `Delta = floor(q/t)` at encryption time instead of `t`
    /// dividing the noise the way BGV's real path does. `plaintext` here is
    /// the still-scaled-by-`Delta` value straight out of
    /// [`crate::bfv::Decryptor::decrypt`] (itself unchanged - it's
    /// scheme-agnostic and doesn't know about `Delta`), not something
    /// [`Self::decode_u64`] can consume directly.
    pub fn decode_u64_real(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        self.params
            .ring()
            .check_poly(plaintext.inner().inner().value())?;
        let component = plaintext
            .inner()
            .inner()
            .value()
            .component(0)
            .ok_or(SchemesError::DimensionMismatch)?;
        let q = self.params.ring().moduli()[0].value();
        let t = self.params.plaintext_modulus();
        Ok(component
            .iter()
            .map(|&coeff| decode_bfv_residue(coeff, q, t))
            .collect())
    }

    /// Decodes a raw decrypted real-BFV ciphertext as centered signed
    /// integers - see [`Self::decode_u64_real`].
    pub fn decode_i64_real(&self, plaintext: &Plaintext) -> Result<Vec<i64>> {
        let t = self.params.plaintext_modulus();
        Ok(self
            .decode_u64_real(plaintext)?
            .into_iter()
            .map(|value| decode_signed(value, t))
            .collect())
    }
}

/// Recovers a `mod t` message value from one raw decrypted-and-`Delta`-scaled
/// coefficient `Delta*m + E (mod q)`: centers `coeff` into `(-q/2, q/2]`,
/// then computes `round(|centered| * t / q)` (the standard BFV decode
/// rounding step - `Delta = floor(q/t)`, so `Delta*m*t/q ≈ m` up to the
/// rounding this corrects for), reapplying `centered`'s sign before
/// reducing `mod t`.
fn decode_bfv_residue(coeff: u64, modulus: u64, plaintext_modulus: u64) -> u64 {
    let (negative, magnitude) = if coeff <= modulus / 2 {
        (false, coeff)
    } else {
        (true, modulus - coeff)
    };
    let numerator = u128::from(magnitude) * u128::from(plaintext_modulus);
    let rounded = ((numerator + u128::from(modulus) / 2) / u128::from(modulus)) as u64;
    if negative {
        (plaintext_modulus - rounded % plaintext_modulus) % plaintext_modulus
    } else {
        rounded % plaintext_modulus
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
