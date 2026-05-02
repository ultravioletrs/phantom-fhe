//! Canonical binary encodings for scheme-independent circuit plans.

use std::io::Cursor;

use phantom_utils::buffer::{BufferReader, BufferWriter};
use phantom_utils::serialization::{DomainTag, SerializationHeader, Version};

use crate::common::{BabyStepGiantStepPlan, PolynomialEvalPlan, PolynomialEvalStrategy};
use crate::{CircuitsError, Result};

const VERSION: Version = Version::new(1);
const POLYNOMIAL_PLAN: DomainTag = DomainTag::from_array(*b"CIRPOLY1");
const BSGS_PLAN: DomainTag = DomainTag::from_array(*b"CIRBSGS1");

/// Encodes a polynomial evaluation plan.
pub fn encode_polynomial_eval_plan(plan: &PolynomialEvalPlan) -> Result<Vec<u8>> {
    let mut writer = writer(POLYNOMIAL_PLAN)?;
    writer.write_u64_le(plan.degree() as u64)?;
    writer.write_u8(strategy_tag(plan.strategy()))?;
    Ok(writer.into_inner())
}

/// Decodes a polynomial evaluation plan.
pub fn decode_polynomial_eval_plan(bytes: &[u8]) -> Result<PolynomialEvalPlan> {
    let mut reader = reader(bytes, POLYNOMIAL_PLAN)?;
    let degree = read_usize(&mut reader)?;
    let strategy = read_strategy(reader.read_u8()?)?;
    PolynomialEvalPlan::with_strategy(degree, strategy)
}

/// Encodes a baby-step giant-step rotation plan.
pub fn encode_bsgs_plan(plan: &BabyStepGiantStepPlan) -> Result<Vec<u8>> {
    let mut writer = writer(BSGS_PLAN)?;
    writer.write_u64_le(plan.slot_count() as u64)?;
    writer.write_u64_le(plan.baby_step_count() as u64)?;
    writer.write_u64_le(plan.diagonal_offsets().len() as u64)?;
    for offset in plan.diagonal_offsets() {
        writer.write_u64_le(*offset as u64)?;
    }
    Ok(writer.into_inner())
}

/// Decodes a baby-step giant-step rotation plan.
pub fn decode_bsgs_plan(bytes: &[u8]) -> Result<BabyStepGiantStepPlan> {
    let mut reader = reader(bytes, BSGS_PLAN)?;
    let slot_count = read_usize(&mut reader)?;
    let baby_step_count = read_usize(&mut reader)?;
    let offset_count = read_usize(&mut reader)?;
    let mut offsets = Vec::with_capacity(offset_count);
    for _ in 0..offset_count {
        offsets.push(read_usize(&mut reader)?);
    }
    BabyStepGiantStepPlan::new(slot_count, offsets, baby_step_count)
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

fn strategy_tag(strategy: PolynomialEvalStrategy) -> u8 {
    match strategy {
        PolynomialEvalStrategy::Constant => 0,
        PolynomialEvalStrategy::Horner => 1,
        PolynomialEvalStrategy::PowerBasis => 2,
        PolynomialEvalStrategy::PatersonStockmeyer => 3,
    }
}

fn read_strategy(tag: u8) -> Result<PolynomialEvalStrategy> {
    match tag {
        0 => Ok(PolynomialEvalStrategy::Constant),
        1 => Ok(PolynomialEvalStrategy::Horner),
        2 => Ok(PolynomialEvalStrategy::PowerBasis),
        3 => Ok(PolynomialEvalStrategy::PatersonStockmeyer),
        _ => Err(CircuitsError::InvalidParameters(
            "invalid polynomial evaluation strategy",
        )),
    }
}

fn read_usize(reader: &mut BufferReader<Cursor<&[u8]>>) -> Result<usize> {
    let value = reader.read_u64_le()?;
    usize::try_from(value).map_err(|_| CircuitsError::InvalidParameters("length overflow"))
}
