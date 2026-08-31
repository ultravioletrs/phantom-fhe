//! Canonical binary encodings for public lattice objects.

use std::io::Cursor;

use phantom_ring::Poly;
use phantom_utils::buffer::{BufferReader, BufferWriter};
use phantom_utils::serialization::{DomainTag, SerializationHeader, Version};

use crate::rlwe::{EvaluationKey, GaloisKey, PublicKey, RelinearizationKey};
use crate::{LatticeError, Result};

const VERSION: Version = Version::new(1);
const RLWE_PUBLIC_KEY: DomainTag = DomainTag::from_array(*b"RLWEPK01");
const RLWE_EVALUATION_KEY: DomainTag = DomainTag::from_array(*b"RLWEEK01");

/// Encodes an RLWE public key.
pub fn encode_public_key(public_key: &PublicKey) -> Result<Vec<u8>> {
    let mut writer = writer(RLWE_PUBLIC_KEY)?;
    for component in public_key.value() {
        write_poly(&mut writer, component)?;
    }
    Ok(writer.into_inner())
}

/// Decodes an RLWE public key.
pub fn decode_public_key(bytes: &[u8]) -> Result<PublicKey> {
    let mut reader = reader(bytes, RLWE_PUBLIC_KEY)?;
    Ok(PublicKey::new(
        read_poly(&mut reader)?,
        read_poly(&mut reader)?,
    ))
}

/// Encodes public RLWE evaluation-key markers.
///
/// Only records *whether* a relinearization key was present, not its
/// content - true even for a real key-switching-based one
/// ([`RelinearizationKey::from_key_switch_key`]), whose actual
/// cryptographic material (a full [`crate::rlwe::KeySwitchKey`]) this
/// function does not serialize. See [`decode_evaluation_key`].
pub fn encode_evaluation_key(evaluation_key: &EvaluationKey) -> Result<Vec<u8>> {
    let mut writer = writer(RLWE_EVALUATION_KEY)?;
    writer.write_u8(u8::from(evaluation_key.relinearization_key().is_some()))?;
    writer.write_u64_le(evaluation_key.galois_keys().len() as u64)?;
    for key in evaluation_key.galois_keys() {
        writer.write_u64_le(key.element() as u64)?;
    }
    Ok(writer.into_inner())
}

/// Decodes public RLWE evaluation-key markers.
///
/// Always reconstructs a *placeholder* relinearization key
/// ([`RelinearizationKey::placeholder`]) when the marker says one was
/// present - this format has never carried real relinearization-key
/// content (there was none to carry until real key-switching-based
/// relinearization keys existed), so round-tripping a real key through
/// this function silently downgrades it to the placeholder. Real
/// key-switching key serialization is real follow-up work, not attempted
/// here.
pub fn decode_evaluation_key(bytes: &[u8]) -> Result<EvaluationKey> {
    let mut reader = reader(bytes, RLWE_EVALUATION_KEY)?;
    let relin = match reader.read_u8()? {
        0 => None,
        1 => Some(RelinearizationKey::placeholder()),
        _ => {
            return Err(LatticeError::InvalidParameters(
                "invalid relinearization marker",
            ))
        }
    };
    let galois_count = read_usize(&mut reader)?;
    let mut galois = Vec::with_capacity(galois_count);
    for _ in 0..galois_count {
        galois.push(GaloisKey::new(read_usize(&mut reader)?));
    }
    Ok(EvaluationKey::new(relin, galois))
}

fn writer(domain: DomainTag) -> Result<BufferWriter<Vec<u8>>> {
    let mut writer = BufferWriter::new(Vec::new());
    SerializationHeader::new(domain, VERSION).write_to(&mut writer)?;
    Ok(writer)
}

fn reader(bytes: &[u8], domain: DomainTag) -> Result<BufferReader<Cursor<&[u8]>>> {
    let mut reader = BufferReader::new(Cursor::new(bytes));
    SerializationHeader::read_expected(&mut reader, domain, VERSION)?;
    Ok(reader)
}

fn write_poly(writer: &mut BufferWriter<Vec<u8>>, poly: &Poly) -> Result<()> {
    writer.write_u64_le(poly.moduli_count() as u64)?;
    writer.write_u64_le(poly.degree() as u64)?;
    for component in poly.coeffs() {
        for coeff in component {
            writer.write_u64_le(*coeff)?;
        }
    }
    Ok(())
}

fn read_poly(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<Poly> {
    let moduli_count = read_usize(reader)?;
    let degree = read_usize(reader)?;
    if moduli_count == 0 || degree == 0 {
        return Err(LatticeError::InvalidParameters("invalid polynomial shape"));
    }
    let mut coeffs = vec![vec![0u64; degree]; moduli_count];
    for component in &mut coeffs {
        for coeff in component {
            *coeff = reader.read_u64_le()?;
        }
    }
    Ok(Poly::from_coeffs(coeffs)?)
}

fn read_usize(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<usize> {
    let value = reader.read_u64_le()?;
    usize::try_from(value).map_err(|_| LatticeError::InvalidParameters("length overflow"))
}
