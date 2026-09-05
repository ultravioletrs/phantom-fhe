//! Internal BGV multiparty wire helpers.

use phantom_ring::{Poly, Ring};

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

/// Encodes a sequence of `(b, a)` polynomial-pair rows (e.g. a collective
/// Galois-key share's own per-`(modulus_index, level)` contributions) as one
/// payload: a row count, one shared `moduli_count`/`degree` header (every
/// row lives in the same ring), then each row's own coefficients
/// back-to-back - deliberately not `N` repetitions of [`encode_poly_pair`]'s
/// own self-contained format, which would repeat that header per row for no
/// reason and (more importantly) [`decode_poly_pair`] assumes it owns the
/// *entire* remaining payload, incompatible with being one of several
/// entries in a longer sequence.
pub(crate) fn encode_poly_rows(rows: &[(Poly, Poly)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    let (moduli_count, degree) = rows
        .first()
        .map_or((0, 0), |(first, _)| (first.moduli_count(), first.degree()));
    out.extend_from_slice(&(moduli_count as u64).to_le_bytes());
    out.extend_from_slice(&(degree as u64).to_le_bytes());
    for (b, a) in rows {
        for poly in [b, a] {
            for component in poly.coeffs() {
                for coeff in component {
                    out.extend_from_slice(&coeff.to_le_bytes());
                }
            }
        }
    }
    out
}

pub(crate) fn decode_poly_rows(payload: &[u8], ring: &Ring) -> Result<Vec<(Poly, Poly)>> {
    let mut reader = Reader::new(payload);
    let row_count = reader.u64()? as usize;
    let moduli_count = reader.u64()? as usize;
    let degree = reader.u64()? as usize;
    if row_count > 0 && (moduli_count != ring.moduli().len() || degree != ring.degree()) {
        return Err(MultipartyError::MalformedMessage);
    }
    let poly_len = moduli_count
        .checked_mul(degree)
        .and_then(|n| n.checked_mul(8))
        .ok_or(MultipartyError::MalformedMessage)?;

    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let b = decode_poly_body(reader.take(poly_len)?, moduli_count, degree, ring)?;
        let a = decode_poly_body(reader.take(poly_len)?, moduli_count, degree, ring)?;
        rows.push((b, a));
    }
    if !reader.is_finished() {
        return Err(MultipartyError::MalformedMessage);
    }
    Ok(rows)
}

fn decode_poly_body(bytes: &[u8], moduli_count: usize, degree: usize, ring: &Ring) -> Result<Poly> {
    let mut reader = Reader::new(bytes);
    let mut coeffs = vec![vec![0u64; degree]; moduli_count];
    for component in &mut coeffs {
        for coeff in component {
            *coeff = reader.u64()?;
        }
    }
    let poly = Poly::from_coeffs(coeffs).map_err(|_| MultipartyError::MalformedMessage)?;
    ring.check_poly(&poly)
        .map_err(|_| MultipartyError::MalformedMessage)?;
    Ok(poly)
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

    const fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }
}
