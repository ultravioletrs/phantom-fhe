//! Canonical binary encodings for bootstrapping public configuration.

use std::io::Cursor;

use phantom_utils::buffer::{BufferReader, BufferWriter};
use phantom_utils::serialization::{DomainTag, SerializationHeader, Version};

use crate::ckks::BootstrapParams;
use crate::{BootstrappingError, Result};

const VERSION: Version = Version::new(1);
const CKKS_BOOTSTRAP_PARAMS: DomainTag = DomainTag::from_array(*b"CKKSBTP1");

/// Encodes CKKS bootstrapping parameters.
pub fn encode_ckks_bootstrap_params(params: &BootstrapParams) -> Result<Vec<u8>> {
    let mut writer = writer(CKKS_BOOTSTRAP_PARAMS)?;
    let ckks_params = phantom_schemes::serialization::encode_ckks_params(params.ckks_params())?;
    writer.write_bytes(&ckks_params)?;
    writer.write_u64_le(params.target_level() as u64)?;
    write_f64(&mut writer, params.target_precision_bits())?;
    writer.write_u64_le(params.sparse_slot_count() as u64)?;
    writer.write_u64_le(params.batch_size() as u64)?;
    write_f64(&mut writer, params.raise_modulus())?;
    Ok(writer.into_inner())
}

/// Decodes CKKS bootstrapping parameters.
pub fn decode_ckks_bootstrap_params(bytes: &[u8]) -> Result<BootstrapParams> {
    let mut reader = reader(bytes, CKKS_BOOTSTRAP_PARAMS)?;
    let ckks_params = phantom_schemes::serialization::decode_ckks_params(&reader.read_bytes()?)?;
    let target_level = read_usize(&mut reader)?;
    let target_precision_bits = read_f64(&mut reader)?;
    let sparse_slot_count = read_usize(&mut reader)?;
    let batch_size = read_usize(&mut reader)?;
    let raise_modulus = read_f64(&mut reader)?;
    BootstrapParams::new(
        ckks_params,
        target_level,
        target_precision_bits,
        sparse_slot_count,
        batch_size,
        raise_modulus,
    )
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

fn write_f64(writer: &mut BufferWriter<Vec<u8>>, value: f64) -> Result<()> {
    if !value.is_finite() {
        return Err(BootstrappingError::InvalidParameters("non-finite float"));
    }
    writer.write_u64_le(value.to_bits())?;
    Ok(())
}

fn read_f64(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<f64> {
    let value = f64::from_bits(reader.read_u64_le()?);
    if value.is_finite() {
        Ok(value)
    } else {
        Err(BootstrappingError::InvalidParameters("non-finite float"))
    }
}

fn read_usize(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<usize> {
    let value = reader.read_u64_le()?;
    usize::try_from(value).map_err(|_| BootstrappingError::InvalidParameters("length overflow"))
}
