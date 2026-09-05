use phantom_circuits::common::{
    serialization, BabyStepGiantStepPlan, PolynomialEvalPlan, PolynomialEvalStrategy,
};
use proptest::prelude::*;

#[test]
fn polynomial_eval_plans_round_trip() {
    let plan =
        PolynomialEvalPlan::with_strategy(12, PolynomialEvalStrategy::PatersonStockmeyer).unwrap();
    let decoded = serialization::decode_polynomial_eval_plan(
        &serialization::encode_polynomial_eval_plan(&plan).unwrap(),
    )
    .unwrap();

    assert_eq!(decoded.degree(), plan.degree());
    assert_eq!(decoded.coefficient_count(), plan.coefficient_count());
    assert_eq!(decoded.strategy(), plan.strategy());
    assert_eq!(
        decoded.paterson_stockmeyer().unwrap().blocks(),
        plan.paterson_stockmeyer().unwrap().blocks()
    );
}

#[test]
fn baby_step_giant_step_plans_round_trip() {
    let plan = BabyStepGiantStepPlan::new(16, vec![0, 3, 7, 9, 20], 4).unwrap();
    let decoded =
        serialization::decode_bsgs_plan(&serialization::encode_bsgs_plan(&plan).unwrap()).unwrap();

    assert_eq!(decoded.slot_count(), plan.slot_count());
    assert_eq!(decoded.baby_step_count(), plan.baby_step_count());
    assert_eq!(decoded.diagonal_offsets(), plan.diagonal_offsets());
    assert_eq!(decoded.baby_steps(), plan.baby_steps());
    assert_eq!(decoded.giant_steps(), plan.giant_steps());
}

#[test]
fn rejects_wrong_domain_and_truncated_payloads() {
    let plan = PolynomialEvalPlan::for_degree(3).unwrap();
    let encoded = serialization::encode_polynomial_eval_plan(&plan).unwrap();
    assert!(serialization::decode_bsgs_plan(&encoded).is_err());

    let mut truncated =
        serialization::encode_bsgs_plan(&BabyStepGiantStepPlan::new(8, vec![1, 3], 2).unwrap())
            .unwrap();
    truncated.pop();
    assert!(serialization::decode_bsgs_plan(&truncated).is_err());
}

// Golden-byte fixtures (Workstream 8 item 1) - see
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent
// comment for why this catches something round-trip tests can't.
const GOLDEN_POLYNOMIAL_EVAL_PLAN: &[u8] = &[
    67, 73, 82, 80, 79, 76, 89, 49, 1, 0, 12, 0, 0, 0, 0, 0, 0, 0, 3,
];
const GOLDEN_BSGS_PLAN: &[u8] = &[
    67, 73, 82, 66, 83, 71, 83, 49, 1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0,
    0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0,
];

#[test]
fn golden_polynomial_eval_plan_bytes_are_stable() {
    let plan =
        PolynomialEvalPlan::with_strategy(12, PolynomialEvalStrategy::PatersonStockmeyer).unwrap();
    assert_eq!(
        serialization::encode_polynomial_eval_plan(&plan).unwrap(),
        GOLDEN_POLYNOMIAL_EVAL_PLAN
    );
    let decoded = serialization::decode_polynomial_eval_plan(GOLDEN_POLYNOMIAL_EVAL_PLAN).unwrap();
    assert_eq!(decoded.degree(), plan.degree());
    assert_eq!(decoded.strategy(), plan.strategy());
}

#[test]
fn golden_bsgs_plan_bytes_are_stable() {
    let plan = BabyStepGiantStepPlan::new(16, vec![0, 3, 7, 9, 20], 4).unwrap();
    assert_eq!(
        serialization::encode_bsgs_plan(&plan).unwrap(),
        GOLDEN_BSGS_PLAN
    );
    let decoded = serialization::decode_bsgs_plan(GOLDEN_BSGS_PLAN).unwrap();
    assert_eq!(decoded.slot_count(), plan.slot_count());
    assert_eq!(decoded.diagonal_offsets(), plan.diagonal_offsets());
}

// Exhaustive domain/version-mismatch rejection (Workstream 8 item 2) -
// every type pair, both directions of domain confusion, plus the
// previously-untested wrong-version case (same domain, corrupted version
// field). Header layout is `domain (8 bytes) || version (u16 LE)`.
fn flip_version_byte(mut encoded: Vec<u8>) -> Vec<u8> {
    encoded[8] = encoded[8].wrapping_add(1);
    encoded
}

#[test]
fn every_type_rejects_a_wrong_domain_and_a_wrong_version() {
    let poly_bytes =
        serialization::encode_polynomial_eval_plan(&PolynomialEvalPlan::for_degree(3).unwrap())
            .unwrap();
    let bsgs_bytes =
        serialization::encode_bsgs_plan(&BabyStepGiantStepPlan::new(8, vec![1, 3], 2).unwrap())
            .unwrap();

    assert!(matches!(
        serialization::decode_bsgs_plan(&poly_bytes).unwrap_err(),
        phantom_circuits::CircuitsError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_polynomial_eval_plan(&bsgs_bytes).unwrap_err(),
        phantom_circuits::CircuitsError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));

    assert!(matches!(
        serialization::decode_polynomial_eval_plan(&flip_version_byte(poly_bytes)).unwrap_err(),
        phantom_circuits::CircuitsError::Utils(
            phantom_utils::UtilsError::UnsupportedVersion { .. }
        )
    ));
    assert!(matches!(
        serialization::decode_bsgs_plan(&flip_version_byte(bsgs_bytes)).unwrap_err(),
        phantom_circuits::CircuitsError::Utils(
            phantom_utils::UtilsError::UnsupportedVersion { .. }
        )
    ));
}

// Fuzz/property tests for decode rejection (Workstream 8 item 3) - see
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent
// comment: the property is "never panics," proptest catches panics itself.
proptest! {
    #[test]
    fn decode_polynomial_eval_plan_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_polynomial_eval_plan(&bytes);
    }

    #[test]
    fn decode_bsgs_plan_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_bsgs_plan(&bytes);
    }
}
