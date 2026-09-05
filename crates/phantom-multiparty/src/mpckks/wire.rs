//! Internal CKKS multiparty wire helpers.

use phantom_ring::{Poly, Ring};
use phantom_schemes::ckks::{Ciphertext, Complex64, Precision, Scale};

use crate::{MultipartyError, Result};

pub(crate) fn encode_poly(poly: &Poly) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(poly.moduli_count() as u64).to_le_bytes());
    out.extend_from_slice(&(poly.degree() as u64).to_le_bytes());
    for component in poly.coeffs() {
        for coeff in component {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    out
}

pub(crate) fn decode_poly(payload: &[u8], ring: &Ring) -> Result<Poly> {
    let mut reader = Reader::new(payload);
    let moduli_count = reader.u64()? as usize;
    let degree = reader.u64()? as usize;
    if moduli_count != ring.moduli().len() || degree != ring.degree() {
        return Err(MultipartyError::MalformedMessage);
    }

    let mut coeffs = vec![vec![0u64; degree]; moduli_count];
    for component in &mut coeffs {
        for coeff in component {
            *coeff = reader.u64()?;
        }
    }
    if !reader.is_finished() {
        return Err(MultipartyError::MalformedMessage);
    }
    let poly = Poly::from_coeffs(coeffs).map_err(|_| MultipartyError::MalformedMessage)?;
    ring.check_poly(&poly)
        .map_err(|_| MultipartyError::MalformedMessage)?;
    Ok(poly)
}

/// Encodes a pair of polynomials (e.g. a PCKS share's own `(h0, h1)`) as one
/// payload: each poly's own [`encode_poly`] output, length-prefixed.
pub(crate) fn encode_poly_pair(first: &Poly, second: &Poly) -> Vec<u8> {
    let mut out = Vec::new();
    let first_bytes = encode_poly(first);
    out.extend_from_slice(&(first_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&first_bytes);
    out.extend_from_slice(&encode_poly(second));
    out
}

pub(crate) fn decode_poly_pair(payload: &[u8], ring: &Ring) -> Result<(Poly, Poly)> {
    let mut reader = Reader::new(payload);
    let first_len = reader.u64()? as usize;
    let first_bytes = reader.take(first_len)?;
    let first = decode_poly(first_bytes, ring)?;
    let second_bytes = &payload[reader.offset..];
    let second = decode_poly(second_bytes, ring)?;
    Ok((first, second))
}

pub(crate) fn encode_ciphertext(ciphertext: &Ciphertext) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(ciphertext.slots().len() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext.scale().value().to_le_bytes());
    out.extend_from_slice(&(ciphertext.level() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext.precision().bits().to_le_bytes());
    out.extend_from_slice(&(ciphertext.degree() as u64).to_le_bytes());
    for slot in ciphertext.slots() {
        out.extend_from_slice(&slot.re.to_le_bytes());
        out.extend_from_slice(&slot.im.to_le_bytes());
    }
    out
}

pub(crate) fn decode_ciphertext(payload: &[u8], max_slots: usize) -> Result<Ciphertext> {
    let mut reader = Reader::new(payload);
    let slot_count = reader.u64()? as usize;
    if slot_count > max_slots {
        return Err(MultipartyError::MalformedMessage);
    }
    let scale = Scale::new(reader.f64()?).map_err(|_| MultipartyError::MalformedMessage)?;
    let level = reader.u64()? as usize;
    let precision = Precision::new(reader.f64()?);
    let degree = reader.u64()? as usize;
    let mut slots = Vec::with_capacity(slot_count);
    for _ in 0..slot_count {
        let re = reader.f64()?;
        let im = reader.f64()?;
        if !re.is_finite() || !im.is_finite() {
            return Err(MultipartyError::MalformedMessage);
        }
        slots.push(Complex64::new(re, im));
    }
    if !reader.is_finished() {
        return Err(MultipartyError::MalformedMessage);
    }
    Ok(Ciphertext::new(slots, scale, level, precision, degree))
}

pub(crate) fn ensure_equal_payloads<'a>(
    shares: impl IntoIterator<Item = &'a crate::common::Share>,
) -> Result<&'a [u8]> {
    let mut iter = shares.into_iter();
    let first = iter.next().ok_or(MultipartyError::MissingShare)?;
    for share in iter {
        if share.payload() != first.payload() {
            return Err(MultipartyError::MalformedMessage);
        }
    }
    Ok(first.payload())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn f64(&mut self) -> Result<f64> {
        let bytes = self.take(8)?;
        Ok(f64::from_le_bytes(bytes.try_into().unwrap()))
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(MultipartyError::MalformedMessage)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(MultipartyError::MalformedMessage)?;
        self.offset = end;
        Ok(bytes)
    }
}
