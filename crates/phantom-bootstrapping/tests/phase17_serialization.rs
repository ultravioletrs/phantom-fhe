use phantom_bootstrapping::ckks::BootstrapParams;
use phantom_bootstrapping::serialization;
use phantom_ring::Ring;
use phantom_schemes::ckks::CkksParams;

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
