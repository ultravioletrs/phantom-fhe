use phantom_bootstrapping::ckks::BootstrapParams;
use phantom_bootstrapping::serialization;
use phantom_ring::Ring;
use phantom_schemes::ckks::CkksParams;
use proptest::prelude::*;

fn ckks_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

#[test]
fn ckks_bootstrap_params_round_trip() {
    let params = BootstrapParams::builder(ckks_params())
        .target_level(1)
        .target_precision_bits(18.5)
        .sparse_slot_count(2)
        .batch_size(4)
        .build()
        .unwrap();

    let decoded = serialization::decode_ckks_bootstrap_params(
        &serialization::encode_ckks_bootstrap_params(&params).unwrap(),
    )
    .unwrap();

    assert_same_ring(decoded.ckks_params().ring(), params.ckks_params().ring());
    assert_eq!(
        decoded.ckks_params().default_scale(),
        params.ckks_params().default_scale()
    );
    assert_eq!(decoded.target_level(), params.target_level());
    assert_eq!(
        decoded.target_precision_bits(),
        params.target_precision_bits()
    );
    assert_eq!(decoded.sparse_slot_count(), params.sparse_slot_count());
    assert_eq!(decoded.batch_size(), params.batch_size());
}

fn assert_same_ring(actual: &Ring, expected: &Ring) {
    assert_eq!(actual.degree(), expected.degree());
    assert_eq!(
        actual
            .moduli()
            .iter()
            .map(|modulus| modulus.value())
            .collect::<Vec<_>>(),
        expected
            .moduli()
            .iter()
            .map(|modulus| modulus.value())
            .collect::<Vec<_>>()
    );
}

#[test]
fn rejects_truncated_payloads() {
    let params = BootstrapParams::builder(ckks_params()).build().unwrap();
    let mut encoded = serialization::encode_ckks_bootstrap_params(&params).unwrap();
    encoded.pop();
    assert!(serialization::decode_ckks_bootstrap_params(&encoded).is_err());
}

// Golden-byte fixture (Workstream 8 item 1) - see
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent
// comment for why this catches something round-trip tests can't.
const GOLDEN_CKKS_BOOTSTRAP_PARAMS: &[u8] = &[
    67, 75, 75, 83, 66, 84, 80, 49, 1, 0, 59, 0, 0, 0, 0, 0, 0, 0, 67, 75, 75, 83, 80, 82, 48, 49,
    1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0,
    0, 0, 1, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 64, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 128, 50, 64, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 132, 46,
    65,
];

#[test]
fn golden_ckks_bootstrap_params_bytes_are_stable() {
    let params = BootstrapParams::builder(ckks_params())
        .target_level(1)
        .target_precision_bits(18.5)
        .sparse_slot_count(2)
        .batch_size(4)
        .build()
        .unwrap();
    assert_eq!(
        serialization::encode_ckks_bootstrap_params(&params).unwrap(),
        GOLDEN_CKKS_BOOTSTRAP_PARAMS
    );
    let decoded =
        serialization::decode_ckks_bootstrap_params(GOLDEN_CKKS_BOOTSTRAP_PARAMS).unwrap();
    assert_same_ring(decoded.ckks_params().ring(), params.ckks_params().ring());
    assert_eq!(decoded.target_level(), params.target_level());
    assert_eq!(decoded.batch_size(), params.batch_size());
}

// Wrong-version rejection (Workstream 8 item 2) - the domain-mismatch case
// doesn't apply here (this crate has only one serialized type), but a
// corrupted version field is still an untested rejection path. Header
// layout is `domain (8 bytes) || version (u16 LE)`.
#[test]
fn rejects_a_wrong_version() {
    let params = BootstrapParams::builder(ckks_params()).build().unwrap();
    let mut encoded = serialization::encode_ckks_bootstrap_params(&params).unwrap();
    encoded[8] = encoded[8].wrapping_add(1);
    assert!(matches!(
        serialization::decode_ckks_bootstrap_params(&encoded).unwrap_err(),
        phantom_bootstrapping::BootstrappingError::Utils(
            phantom_utils::UtilsError::UnsupportedVersion { .. }
        )
    ));
}

// Fuzz/property test for decode rejection (Workstream 8 item 3) - see
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent
// comment: the property is "never panics," proptest catches panics itself.
proptest! {
    #[test]
    fn decode_ckks_bootstrap_params_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_ckks_bootstrap_params(&bytes);
    }
}
