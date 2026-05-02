use phantom_lattice::rlwe::{EvaluationKey, GaloisKey, PublicKey, RelinearizationKey};
use phantom_lattice::serialization;
use phantom_ring::Poly;

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
    let evaluation_key = EvaluationKey::new(
        Some(RelinearizationKey),
        vec![GaloisKey::new(3), GaloisKey::new(5)],
    );
    let decoded = serialization::decode_evaluation_key(
        &serialization::encode_evaluation_key(&evaluation_key).unwrap(),
    )
    .unwrap();

    assert_eq!(decoded, evaluation_key);
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
