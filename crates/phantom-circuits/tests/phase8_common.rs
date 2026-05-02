use phantom_circuits::common::{
    BabyStepGiantStepPlan, DiagonalMatrix, LinearTransform, PatersonStockmeyerPlan,
    PolynomialEvalPlan, PolynomialEvalStrategy,
};
use phantom_circuits::CircuitsError;

#[test]
fn dense_matrix_round_trips_through_diagonals() {
    let matrix = vec![vec![1, 2, 7], vec![8, 3, 4], vec![5, 9, 6]];
    let transform = LinearTransform::dense(matrix.clone()).unwrap();

    let diagonals = transform.to_diagonal_matrix();

    assert_eq!(diagonals.slot_count(), 3);
    assert_eq!(diagonals.to_dense(), matrix);
    assert_eq!(
        diagonals
            .diagonals()
            .iter()
            .map(|diagonal| diagonal.offset())
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
}

#[test]
fn zero_diagonals_are_omitted() {
    let transform = LinearTransform::dense(vec![
        vec![1, 0, 0, 0],
        vec![0, 2, 0, 0],
        vec![0, 0, 3, 0],
        vec![0, 0, 0, 4],
    ])
    .unwrap();

    let diagonals = transform.to_diagonal_matrix();

    assert_eq!(diagonals.diagonals().len(), 1);
    assert_eq!(diagonals.diagonals()[0].offset(), 0);
    assert_eq!(diagonals.to_dense()[2][2], 3);
}

#[test]
fn slot_permutation_descriptor_uses_cyclic_offsets() {
    let transform = LinearTransform::slot_permutation(4, 1, 0u64, 1u64).unwrap();
    assert_eq!(
        transform.rows(),
        &[
            vec![0, 1, 0, 0],
            vec![0, 0, 1, 0],
            vec![0, 0, 0, 1],
            vec![1, 0, 0, 0]
        ]
    );

    let diagonals = transform.to_diagonal_matrix();
    assert_eq!(diagonals.diagonals().len(), 1);
    assert_eq!(diagonals.diagonals()[0].offset(), 1);
}

#[test]
fn bsgs_plan_decomposes_diagonal_offsets() {
    let plan = BabyStepGiantStepPlan::new(16, vec![0, 1, 5, 6, 10, 21], 4).unwrap();

    assert_eq!(plan.diagonal_offsets(), &[0, 1, 5, 6, 10]);
    assert_eq!(plan.baby_steps(), &[0, 1, 2]);
    assert_eq!(plan.giant_steps(), &[0, 4, 8]);
    assert_eq!(plan.decompose_offset(10), Some((8, 2)));
    assert_eq!(plan.decompose_offset(21), Some((4, 1)));
    assert_eq!(plan.decompose_offset(3), None);
}

#[test]
fn diagonal_matrix_can_create_bsgs_plan() {
    let transform = LinearTransform::dense(vec![
        vec![1, 0, 2, 0],
        vec![0, 1, 0, 2],
        vec![2, 0, 1, 0],
        vec![0, 2, 0, 1],
    ])
    .unwrap();
    let diagonals = transform.to_diagonal_matrix();
    let plan = diagonals.bsgs_plan(2).unwrap();

    assert_eq!(plan.diagonal_offsets(), &[0, 2]);
    assert_eq!(plan.baby_steps(), &[0]);
    assert_eq!(plan.giant_steps(), &[0, 2]);
}

#[test]
fn polynomial_planner_selects_expected_default_strategies() {
    assert_eq!(
        PolynomialEvalPlan::for_degree(0).unwrap().strategy(),
        PolynomialEvalStrategy::Constant
    );
    assert_eq!(
        PolynomialEvalPlan::for_degree(3).unwrap().strategy(),
        PolynomialEvalStrategy::Horner
    );
    assert_eq!(
        PolynomialEvalPlan::for_degree(7).unwrap().strategy(),
        PolynomialEvalStrategy::PowerBasis
    );
    assert_eq!(
        PolynomialEvalPlan::for_degree(8).unwrap().strategy(),
        PolynomialEvalStrategy::PatersonStockmeyer
    );
}

#[test]
fn power_basis_plan_lists_nonconstant_powers() {
    let plan = PolynomialEvalPlan::with_strategy(5, PolynomialEvalStrategy::PowerBasis).unwrap();

    assert_eq!(plan.coefficient_count(), 6);
    assert_eq!(plan.power_basis().powers(), &[1, 2, 3, 4, 5]);
    assert!(plan.paterson_stockmeyer().is_none());
}

#[test]
fn paterson_stockmeyer_plan_covers_all_coefficients() {
    let plan = PatersonStockmeyerPlan::new(10, Some(3)).unwrap();

    assert_eq!(plan.baby_powers(), &[1, 2, 3]);
    assert_eq!(plan.giant_powers(), &[3, 6, 9]);
    assert_eq!(
        plan.blocks()
            .iter()
            .map(|block| (
                block.start_degree(),
                block.end_degree(),
                block.giant_index()
            ))
            .collect::<Vec<_>>(),
        vec![(0, 2, 0), (3, 5, 1), (6, 8, 2), (9, 10, 3)]
    );

    let selected =
        PolynomialEvalPlan::with_strategy(10, PolynomialEvalStrategy::PatersonStockmeyer).unwrap();
    assert!(selected.paterson_stockmeyer().is_some());
}

#[test]
fn invalid_inputs_are_rejected() {
    assert_eq!(
        LinearTransform::<u64>::dense(vec![vec![1, 2], vec![3]]).unwrap_err(),
        CircuitsError::DimensionMismatch
    );
    assert_eq!(
        DiagonalMatrix::new(0, Vec::<phantom_circuits::common::Diagonal<u64>>::new()).unwrap_err(),
        CircuitsError::InvalidParameters("slot count must be nonzero")
    );
    assert_eq!(
        PolynomialEvalPlan::for_coefficients::<u64>(&[]).unwrap_err(),
        CircuitsError::EmptyPolynomial
    );
    assert!(PatersonStockmeyerPlan::new(0, None).is_err());
}
