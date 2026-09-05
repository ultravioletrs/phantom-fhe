use phantom_lattice::rlwe::{EvaluationKey, GaloisKey, PublicKey, RelinearizationKey};
use phantom_lattice::serialization;
use phantom_ring::Poly;
use proptest::prelude::*;

fn poly(offset: u64) -> Poly {
    Poly::from_coeffs(vec![
        vec![offset, offset + 1, offset + 2, offset + 3],
        vec![offset + 4, offset + 5, offset + 6, offset + 7],
    ])
    .unwrap()
}

#[test]
fn public_keys_round_trip() {
    let public_key = PublicKey::new(poly(1), poly(9));
    let decoded =
        serialization::decode_public_key(&serialization::encode_public_key(&public_key).unwrap())
            .unwrap();

    assert_eq!(decoded, public_key);
}

#[test]
fn evaluation_key_markers_round_trip() {
    // EvaluationKey/RelinearizationKey don't derive PartialEq (a real
    // RelinearizationKey can hold a KeySwitchKey, which doesn't either -
    // see evaluation_key.rs), so this checks the fields the markers
    // actually round-trip (see serialization.rs's own doc comments: only
    // "was a relinearization key present", never its content) instead of
    // whole-struct equality.
    let evaluation_key = EvaluationKey::new(
        Some(RelinearizationKey::placeholder()),
        vec![GaloisKey::new(3), GaloisKey::new(5)],
    );
    let decoded = serialization::decode_evaluation_key(
        &serialization::encode_evaluation_key(&evaluation_key).unwrap(),
    )
    .unwrap();

    assert_eq!(
        decoded.relinearization_key().is_some(),
        evaluation_key.relinearization_key().is_some()
    );
    assert_eq!(
        decoded
            .galois_keys()
            .iter()
            .map(GaloisKey::element)
            .collect::<Vec<_>>(),
        evaluation_key
            .galois_keys()
            .iter()
            .map(GaloisKey::element)
            .collect::<Vec<_>>()
    );
}

#[test]
fn rejects_wrong_domain_and_truncated_payloads() {
    let public_key = PublicKey::new(poly(1), poly(9));
    let encoded = serialization::encode_public_key(&public_key).unwrap();
    assert!(serialization::decode_evaluation_key(&encoded).is_err());

    let mut truncated =
        serialization::encode_evaluation_key(&EvaluationKey::new(None, vec![GaloisKey::new(7)]))
            .unwrap();
    truncated.pop();
    assert!(serialization::decode_evaluation_key(&truncated).is_err());
}

// Golden-byte fixtures (Workstream 8 item 1): a fixed, previously-generated
// encoding for each type pair, asserted in both directions - `encode` still
// produces exactly this, and `decode` still accepts it. This is what a pure
// round-trip test (encode then immediately decode) *can't* catch: a
// round-trip only proves this build's own encoder and decoder still agree
// with *each other*, not that the wire shape itself hasn't silently drifted
// from what an already-serialized value out in the world looks like.
const GOLDEN_PUBLIC_KEY: &[u8] = &[
    82, 76, 87, 69, 80, 75, 48, 49, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0,
    0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0,
    0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 11, 0,
    0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0,
    15, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0,
];

const GOLDEN_EVALUATION_KEY: &[u8] = &[
    82, 76, 87, 69, 69, 75, 48, 49, 1, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 5, 0,
    0, 0, 0, 0, 0, 0,
];

#[test]
fn golden_public_key_bytes_are_stable() {
    let public_key = PublicKey::new(poly(1), poly(9));
    assert_eq!(
        serialization::encode_public_key(&public_key).unwrap(),
        GOLDEN_PUBLIC_KEY
    );
    assert_eq!(
        serialization::decode_public_key(GOLDEN_PUBLIC_KEY).unwrap(),
        public_key
    );
}

#[test]
fn golden_evaluation_key_bytes_are_stable() {
    let evaluation_key = EvaluationKey::new(
        Some(RelinearizationKey::placeholder()),
        vec![GaloisKey::new(3), GaloisKey::new(5)],
    );
    assert_eq!(
        serialization::encode_evaluation_key(&evaluation_key).unwrap(),
        GOLDEN_EVALUATION_KEY
    );
    let decoded = serialization::decode_evaluation_key(GOLDEN_EVALUATION_KEY).unwrap();
    assert_eq!(
        decoded.relinearization_key().is_some(),
        evaluation_key.relinearization_key().is_some()
    );
    assert_eq!(
        decoded
            .galois_keys()
            .iter()
            .map(GaloisKey::element)
            .collect::<Vec<_>>(),
        evaluation_key
            .galois_keys()
            .iter()
            .map(GaloisKey::element)
            .collect::<Vec<_>>()
    );
}

// Exhaustive domain/version-mismatch rejection (Workstream 8 item 2): every
// type pair, both a wrong-domain payload and a wrong-version payload (same
// domain, corrupted version bytes) - not just the one representative pair
// `rejects_wrong_domain_and_truncated_payloads` above already checked.
// Header layout is `domain (8 bytes) || version (u16 LE)` - see
// `serialization.rs`'s own `writer`/`SerializationHeader::write_to`.
fn flip_version_byte(mut encoded: Vec<u8>) -> Vec<u8> {
    encoded[8] = encoded[8].wrapping_add(1);
    encoded
}

#[test]
fn every_type_rejects_a_wrong_domain_and_a_wrong_version() {
    let public_key_bytes =
        serialization::encode_public_key(&PublicKey::new(poly(1), poly(9))).unwrap();
    let evaluation_key_bytes =
        serialization::encode_evaluation_key(&EvaluationKey::new(None, vec![GaloisKey::new(7)]))
            .unwrap();

    // Wrong domain: each type's own bytes fed to the other's decoder.
    assert!(matches!(
        serialization::decode_evaluation_key(&public_key_bytes).unwrap_err(),
        phantom_lattice::LatticeError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_public_key(&evaluation_key_bytes).unwrap_err(),
        phantom_lattice::LatticeError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));

    // Wrong version: same domain, corrupted version field.
    assert!(matches!(
        serialization::decode_public_key(&flip_version_byte(public_key_bytes)).unwrap_err(),
        phantom_lattice::LatticeError::Utils(phantom_utils::UtilsError::UnsupportedVersion { .. })
    ));
    assert!(matches!(
        serialization::decode_evaluation_key(&flip_version_byte(evaluation_key_bytes)).unwrap_err(),
        phantom_lattice::LatticeError::Utils(phantom_utils::UtilsError::UnsupportedVersion { .. })
    ));
}

// Fuzz/property tests for decode rejection (Workstream 8 item 3): decoders
// must fail gracefully (a typed `Err`) on arbitrary bytes, never panic -
// `proptest` itself treats any panic inside a test body as a failure, so
// the property is simply "call decode and don't unwrap."
proptest! {
    #[test]
    fn decode_public_key_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_public_key(&bytes);
    }

    #[test]
    fn decode_evaluation_key_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_evaluation_key(&bytes);
    }
}
