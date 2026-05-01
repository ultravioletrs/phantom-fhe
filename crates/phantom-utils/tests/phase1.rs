use std::io::Cursor;

use phantom_utils::buffer::{BufferReader, BufferWriter};
use phantom_utils::sampling::{fill_bytes, random_bytes};
use phantom_utils::serialization::{DomainTag, SerializationHeader, Version};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn buffer_round_trips_primitives_and_bytes() {
    let mut writer = BufferWriter::new(Vec::new());
    writer.write_u8(7).unwrap();
    writer.write_u16_le(0x1234).unwrap();
    writer.write_u32_le(0x89ab_cdef).unwrap();
    writer.write_u64_le(0x0123_4567_89ab_cdef).unwrap();
    writer.write_bytes(b"phantom").unwrap();

    let encoded = writer.into_inner();
    let mut reader = BufferReader::new(Cursor::new(encoded));

    assert_eq!(reader.read_u8().unwrap(), 7);
    assert_eq!(reader.read_u16_le().unwrap(), 0x1234);
    assert_eq!(reader.read_u32_le().unwrap(), 0x89ab_cdef);
    assert_eq!(reader.read_u64_le().unwrap(), 0x0123_4567_89ab_cdef);
    assert_eq!(reader.read_bytes().unwrap(), b"phantom");
}

#[test]
fn serialization_header_round_trips_and_validates() {
    let domain = DomainTag::from_array(*b"PHUTL001");
    let version = Version::new(1);
    let header = SerializationHeader::new(domain, version);

    let mut writer = BufferWriter::new(Vec::new());
    header.write_to(&mut writer).unwrap();

    let mut reader = BufferReader::new(Cursor::new(writer.into_inner()));
    let decoded = SerializationHeader::read_expected(&mut reader, domain, version).unwrap();

    assert_eq!(decoded, header);
}

#[test]
fn serialization_header_rejects_bad_domain() {
    let header = SerializationHeader::new(DomainTag::from_array(*b"PHUTL001"), Version::new(1));
    let mut writer = BufferWriter::new(Vec::new());
    header.write_to(&mut writer).unwrap();

    let mut reader = BufferReader::new(Cursor::new(writer.into_inner()));
    let err = SerializationHeader::read_expected(
        &mut reader,
        DomainTag::from_array(*b"PHUTL002"),
        Version::new(1),
    )
    .unwrap_err();

    assert!(err.to_string().contains("invalid domain"));
}

#[test]
fn serialization_header_rejects_bad_version() {
    let header = SerializationHeader::new(DomainTag::from_array(*b"PHUTL001"), Version::new(1));
    let mut writer = BufferWriter::new(Vec::new());
    header.write_to(&mut writer).unwrap();

    let mut reader = BufferReader::new(Cursor::new(writer.into_inner()));
    let err = SerializationHeader::read_expected(
        &mut reader,
        DomainTag::from_array(*b"PHUTL001"),
        Version::new(2),
    )
    .unwrap_err();

    assert!(err.to_string().contains("unsupported version"));
}

#[test]
fn secure_sampling_accepts_crypto_rngs() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut out = [0u8; 32];
    fill_bytes(&mut rng, &mut out);

    assert_ne!(out, [0u8; 32]);

    let bytes = random_bytes(&mut rng, 16);
    assert_eq!(bytes.len(), 16);
}
