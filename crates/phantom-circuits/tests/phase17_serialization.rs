use phantom_circuits::common::{
    serialization, BabyStepGiantStepPlan, PolynomialEvalPlan, PolynomialEvalStrategy,
};

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
