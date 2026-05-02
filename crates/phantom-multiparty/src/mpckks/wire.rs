//! Internal CKKS multiparty wire helpers.

use phantom_schemes::ckks::{Ciphertext, Complex64, Precision, Scale};

use crate::{MultipartyError, Result};

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
