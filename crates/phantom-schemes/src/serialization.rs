//! Canonical binary encodings for public scheme objects.

use std::io::Cursor;

use phantom_lattice::rlwe;
use phantom_ring::{Degree, Modulus, Poly, Ring};
use phantom_utils::buffer::{BufferReader, BufferWriter};
use phantom_utils::serialization::{DomainTag, SerializationHeader, Version};

use crate::{bfv, bgv, ckks, Result, SchemesError};

const VERSION: Version = Version::new(1);
const BGV_PARAMS: DomainTag = DomainTag::from_array(*b"BGVPRM01");
const BFV_PARAMS: DomainTag = DomainTag::from_array(*b"BFVPRM01");
const CKKS_PARAMS: DomainTag = DomainTag::from_array(*b"CKKSPR01");
const BGV_PT: DomainTag = DomainTag::from_array(*b"BGVPLT01");
const BFV_PT: DomainTag = DomainTag::from_array(*b"BFVPLT01");
const CKKS_PT: DomainTag = DomainTag::from_array(*b"CKKSPL01");
const BGV_CT: DomainTag = DomainTag::from_array(*b"BGVCTXT1");
const BFV_CT: DomainTag = DomainTag::from_array(*b"BFVCTXT1");
const CKKS_CT: DomainTag = DomainTag::from_array(*b"CKKSCT01");
const CKKS_PT_REAL: DomainTag = DomainTag::from_array(*b"CKKPLR01");
const CKKS_CT_REAL: DomainTag = DomainTag::from_array(*b"CKKCTR01");

/// Encodes BGV parameters.
pub fn encode_bgv_params(params: &bgv::BgvParams) -> Result<Vec<u8>> {
    let mut writer = writer(BGV_PARAMS)?;
    write_ring(&mut writer, params.ring())?;
    writer.write_u64_le(params.plaintext_modulus())?;
    Ok(writer.into_inner())
}

/// Decodes BGV parameters.
pub fn decode_bgv_params(bytes: &[u8]) -> Result<bgv::BgvParams> {
    let mut reader = reader(bytes, BGV_PARAMS)?;
    let ring = read_ring(&mut reader)?;
    let plaintext_modulus = reader.read_u64_le()?;
    bgv::BgvParams::new(ring, plaintext_modulus)
}

/// Encodes BFV parameters.
pub fn encode_bfv_params(params: &bfv::BfvParams) -> Result<Vec<u8>> {
    let mut writer = writer(BFV_PARAMS)?;
    write_ring(&mut writer, params.ring())?;
    writer.write_u64_le(params.plaintext_modulus())?;
    Ok(writer.into_inner())
}

/// Decodes BFV parameters.
pub fn decode_bfv_params(bytes: &[u8]) -> Result<bfv::BfvParams> {
    let mut reader = reader(bytes, BFV_PARAMS)?;
    let ring = read_ring(&mut reader)?;
    let plaintext_modulus = reader.read_u64_le()?;
    bfv::BfvParams::new(ring, plaintext_modulus)
}

/// Encodes CKKS parameters.
pub fn encode_ckks_params(params: &ckks::CkksParams) -> Result<Vec<u8>> {
    let mut writer = writer(CKKS_PARAMS)?;
    write_ring(&mut writer, params.ring())?;
    write_f64(&mut writer, params.default_scale().value())?;
    writer.write_u8(u8::from(params.conjugate_invariant()))?;
    Ok(writer.into_inner())
}

/// Decodes CKKS parameters.
pub fn decode_ckks_params(bytes: &[u8]) -> Result<ckks::CkksParams> {
    let mut reader = reader(bytes, CKKS_PARAMS)?;
    let ring = read_ring(&mut reader)?;
    let scale = ckks::Scale::new(read_f64(&mut reader)?)?;
    let conjugate_invariant = match reader.read_u8()? {
        0 => false,
        1 => true,
        _ => return Err(SchemesError::InvalidParameters("invalid CKKS boolean")),
    };
    ckks::CkksParams::new(ring, scale, conjugate_invariant)
}

/// Encodes a BGV plaintext.
pub fn encode_bgv_plaintext(plaintext: &bgv::Plaintext) -> Result<Vec<u8>> {
    let mut writer = writer(BGV_PT)?;
    write_poly(&mut writer, plaintext.inner().value())?;
    Ok(writer.into_inner())
}

/// Decodes a BGV plaintext.
pub fn decode_bgv_plaintext(bytes: &[u8]) -> Result<bgv::Plaintext> {
    let mut reader = reader(bytes, BGV_PT)?;
    Ok(bgv::Plaintext::new(rlwe::Plaintext::new(read_poly(
        &mut reader,
    )?)))
}

/// Encodes a BFV plaintext.
pub fn encode_bfv_plaintext(plaintext: &bfv::Plaintext) -> Result<Vec<u8>> {
    let mut writer = writer(BFV_PT)?;
    write_poly(&mut writer, plaintext.inner().inner().value())?;
    Ok(writer.into_inner())
}

/// Decodes a BFV plaintext.
pub fn decode_bfv_plaintext(bytes: &[u8]) -> Result<bfv::Plaintext> {
    let mut reader = reader(bytes, BFV_PT)?;
    Ok(bfv::Plaintext::new(bgv::Plaintext::new(
        rlwe::Plaintext::new(read_poly(&mut reader)?),
    )))
}

/// Encodes a BGV ciphertext.
pub fn encode_bgv_ciphertext(ciphertext: &bgv::Ciphertext) -> Result<Vec<u8>> {
    let mut writer = writer(BGV_CT)?;
    write_ciphertext(&mut writer, ciphertext.inner())?;
    Ok(writer.into_inner())
}

/// Decodes a BGV ciphertext.
pub fn decode_bgv_ciphertext(bytes: &[u8]) -> Result<bgv::Ciphertext> {
    let mut reader = reader(bytes, BGV_CT)?;
    Ok(bgv::Ciphertext::new(read_ciphertext(&mut reader)?))
}

/// Encodes a BFV ciphertext.
pub fn encode_bfv_ciphertext(ciphertext: &bfv::Ciphertext) -> Result<Vec<u8>> {
    let mut writer = writer(BFV_CT)?;
    write_ciphertext(&mut writer, ciphertext.inner().inner())?;
    Ok(writer.into_inner())
}

/// Decodes a BFV ciphertext.
pub fn decode_bfv_ciphertext(bytes: &[u8]) -> Result<bfv::Ciphertext> {
    let mut reader = reader(bytes, BFV_CT)?;
    Ok(bfv::Ciphertext::new(bgv::Ciphertext::new(read_ciphertext(
        &mut reader,
    )?)))
}

/// Encodes a CKKS plaintext.
pub fn encode_ckks_plaintext(plaintext: &ckks::Plaintext) -> Result<Vec<u8>> {
    let mut writer = writer(CKKS_PT)?;
    write_ckks_slots(&mut writer, plaintext.slots())?;
    write_f64(&mut writer, plaintext.scale().value())?;
    writer.write_u64_le(plaintext.level() as u64)?;
    write_f64(&mut writer, plaintext.precision().bits())?;
    Ok(writer.into_inner())
}

/// Decodes a CKKS plaintext.
pub fn decode_ckks_plaintext(bytes: &[u8]) -> Result<ckks::Plaintext> {
    let mut reader = reader(bytes, CKKS_PT)?;
    let slots = read_ckks_slots(&mut reader)?;
    let scale = ckks::Scale::new(read_f64(&mut reader)?)?;
    let level = read_usize(&mut reader)?;
    let precision = ckks::Precision::new(read_f64(&mut reader)?);
    Ok(ckks::Plaintext::new(slots, scale, level, precision))
}

/// Encodes a **real** CKKS plaintext ([`ckks::Plaintext::poly`] from
/// [`ckks::Encoder::encode_complex_real`] or [`ckks::Decryptor::decrypt_real`]) -
/// unlike [`encode_ckks_plaintext`] (the transparent path, which only ever
/// carries `slots`), a real `ckks::Plaintext`'s actual content lives in its
/// `poly`, not `slots()` (empty for one produced by `decrypt_real` - see
/// that type's own doc comment), so it needs its own wire format rather
/// than silently losing the `poly` the way reusing `encode_ckks_plaintext`
/// on a real plaintext would.
pub fn encode_ckks_plaintext_real(plaintext: &ckks::Plaintext) -> Result<Vec<u8>> {
    let poly = plaintext.poly().ok_or(SchemesError::InvalidParameters(
        "plaintext has no real ring representation - encode with encode_complex_real",
    ))?;
    let mut writer = writer(CKKS_PT_REAL)?;
    write_poly(&mut writer, poly)?;
    write_f64(&mut writer, plaintext.scale().value())?;
    writer.write_u64_le(plaintext.level() as u64)?;
    write_f64(&mut writer, plaintext.precision().bits())?;
    Ok(writer.into_inner())
}

/// Decodes a **real** CKKS plaintext - see [`encode_ckks_plaintext_real`].
/// The result's `slots()` is empty, matching `ckks::Plaintext::new_real`'s
/// own convention for a plaintext not produced by encoding; decode it with
/// [`ckks::Encoder::decode_complex_real`].
pub fn decode_ckks_plaintext_real(bytes: &[u8]) -> Result<ckks::Plaintext> {
    let mut reader = reader(bytes, CKKS_PT_REAL)?;
    let poly = read_poly(&mut reader)?;
    let scale = ckks::Scale::new(read_f64(&mut reader)?)?;
    let level = read_usize(&mut reader)?;
    let precision = ckks::Precision::new(read_f64(&mut reader)?);
    Ok(ckks::Plaintext::new_real(
        Vec::new(),
        scale,
        level,
        precision,
        poly,
    ))
}

/// Encodes a CKKS ciphertext.
pub fn encode_ckks_ciphertext(ciphertext: &ckks::Ciphertext) -> Result<Vec<u8>> {
    let mut writer = writer(CKKS_CT)?;
    write_ckks_slots(&mut writer, ciphertext.slots())?;
    write_f64(&mut writer, ciphertext.scale().value())?;
    writer.write_u64_le(ciphertext.level() as u64)?;
    write_f64(&mut writer, ciphertext.precision().bits())?;
    writer.write_u64_le(ciphertext.degree() as u64)?;
    Ok(writer.into_inner())
}

/// Decodes a CKKS ciphertext.
pub fn decode_ckks_ciphertext(bytes: &[u8]) -> Result<ckks::Ciphertext> {
    let mut reader = reader(bytes, CKKS_CT)?;
    let slots = read_ckks_slots(&mut reader)?;
    let scale = ckks::Scale::new(read_f64(&mut reader)?)?;
    let level = read_usize(&mut reader)?;
    let precision = ckks::Precision::new(read_f64(&mut reader)?);
    let degree = read_usize(&mut reader)?;
    Ok(ckks::Ciphertext::new(
        slots, scale, level, precision, degree,
    ))
}

/// Encodes a **real** CKKS ciphertext ([`ckks::Ciphertext::poly`] from
/// [`ckks::Encryptor::encrypt_real`] or [`ckks::Evaluator`]'s own
/// real-path operations) - see [`encode_ckks_plaintext_real`]'s own doc
/// comment for why this needs a separate wire format from
/// [`encode_ckks_ciphertext`] rather than reusing it (a real
/// `ckks::Ciphertext::slots()` is deliberately empty, so reusing the
/// transparent encoding would silently discard the actual encrypted
/// content).
pub fn encode_ckks_ciphertext_real(ciphertext: &ckks::Ciphertext) -> Result<Vec<u8>> {
    let poly = ciphertext.poly().ok_or(SchemesError::InvalidParameters(
        "ciphertext has no real ring representation - encrypt with Encryptor::encrypt_real",
    ))?;
    let mut writer = writer(CKKS_CT_REAL)?;
    write_ciphertext(&mut writer, poly)?;
    write_f64(&mut writer, ciphertext.scale().value())?;
    writer.write_u64_le(ciphertext.level() as u64)?;
    write_f64(&mut writer, ciphertext.precision().bits())?;
    writer.write_u64_le(ciphertext.degree() as u64)?;
    Ok(writer.into_inner())
}

/// Decodes a **real** CKKS ciphertext - see [`encode_ckks_ciphertext_real`].
pub fn decode_ckks_ciphertext_real(bytes: &[u8]) -> Result<ckks::Ciphertext> {
    let mut reader = reader(bytes, CKKS_CT_REAL)?;
    let poly = read_ciphertext(&mut reader)?;
    let scale = ckks::Scale::new(read_f64(&mut reader)?)?;
    let level = read_usize(&mut reader)?;
    let precision = ckks::Precision::new(read_f64(&mut reader)?);
    let degree = read_usize(&mut reader)?;
    Ok(ckks::Ciphertext::new_real(
        poly, scale, level, precision, degree,
    ))
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

fn write_ring(writer: &mut BufferWriter<Vec<u8>>, ring: &Ring) -> Result<()> {
    writer.write_u64_le(ring.degree() as u64)?;
    writer.write_u64_le(ring.moduli().len() as u64)?;
    for modulus in ring.moduli() {
        writer.write_u64_le(modulus.value())?;
    }
    Ok(())
}

fn read_ring(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<Ring> {
    let degree = Degree::new(read_usize(reader)?)?;
    let moduli_count = read_usize(reader)?;
    let mut moduli = Vec::with_capacity(moduli_count);
    for _ in 0..moduli_count {
        moduli.push(Modulus::new(reader.read_u64_le()?)?);
    }
    Ok(Ring::new(degree, moduli)?)
}

fn write_ciphertext(
    writer: &mut BufferWriter<Vec<u8>>,
    ciphertext: &rlwe::Ciphertext,
) -> Result<()> {
    writer.write_u64_le(ciphertext.value().len() as u64)?;
    for poly in ciphertext.value() {
        write_poly(writer, poly)?;
    }
    Ok(())
}

fn read_ciphertext(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<rlwe::Ciphertext> {
    let count = read_usize(reader)?;
    let mut value = Vec::with_capacity(count);
    for _ in 0..count {
        value.push(read_poly(reader)?);
    }
    Ok(rlwe::Ciphertext::new(value))
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
        return Err(SchemesError::InvalidParameters("invalid polynomial shape"));
    }
    let mut coeffs = vec![vec![0u64; degree]; moduli_count];
    for component in &mut coeffs {
        for coeff in component {
            *coeff = reader.read_u64_le()?;
        }
    }
    Ok(Poly::from_coeffs(coeffs)?)
}

fn write_ckks_slots(writer: &mut BufferWriter<Vec<u8>>, slots: &[ckks::Complex64]) -> Result<()> {
    writer.write_u64_le(slots.len() as u64)?;
    for slot in slots {
        write_f64(writer, slot.re)?;
        write_f64(writer, slot.im)?;
    }
    Ok(())
}

fn read_ckks_slots(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<Vec<ckks::Complex64>> {
    let count = read_usize(reader)?;
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        let re = read_f64(reader)?;
        let im = read_f64(reader)?;
        if !re.is_finite() || !im.is_finite() {
            return Err(SchemesError::InvalidParameters("non-finite CKKS slot"));
        }
        slots.push(ckks::Complex64::new(re, im));
    }
    Ok(slots)
}

fn write_f64(writer: &mut BufferWriter<Vec<u8>>, value: f64) -> Result<()> {
    if !value.is_finite() {
        return Err(SchemesError::InvalidParameters("non-finite float"));
    }
    writer.write_u64_le(value.to_bits())?;
    Ok(())
}

fn read_f64(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<f64> {
    let value = f64::from_bits(reader.read_u64_le()?);
    if value.is_finite() {
        Ok(value)
    } else {
        Err(SchemesError::InvalidParameters("non-finite float"))
    }
}

fn read_usize(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<usize> {
    let value = reader.read_u64_le()?;
    usize::try_from(value).map_err(|_| SchemesError::InvalidParameters("length overflow"))
}
