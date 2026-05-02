use phantom_circuits::ckks::{
    ComparisonEvaluator, CompositePolynomial, DftDirection, DftEvaluator, InverseEvaluator,
    LinearTransformEvaluator, MinimaxEvaluator, Mod1Evaluator, PolynomialEvaluator,
};
use phantom_circuits::common::{LinearTransform, PolynomialEvalStrategy};
use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64, Precision, Scale};

fn params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

fn real_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .conjugate_invariant(true)
        .build()
        .unwrap()
}

fn ciphertext(slots: &[Complex64]) -> Ciphertext {
    Ciphertext::new(
        slots.to_vec(),
        Scale::from_bits(10).unwrap(),
        2,
        Precision::new(10.0),
        1,
    )
}

fn assert_close(actual: Complex64, expected: Complex64) {
    assert!(
        (actual.re - expected.re).abs() < 1e-9 && (actual.im - expected.im).abs() < 1e-9,
        "{actual:?} != {expected:?}"
    );
}

#[test]
fn ckks_linear_transform_applies_complex_matrix_and_plans_diagonals() {
    let evaluator = LinearTransformEvaluator::new(params());
    let input = ciphertext(&[
        Complex64::new(1.0, 1.0),
        Complex64::new(2.0, -1.0),
        Complex64::real(3.0),
        Complex64::real(4.0),
    ]);
    let transform = LinearTransform::dense(vec![
        vec![
            Complex64::real(1.0),
            Complex64::real(1.0),
            Complex64::default(),
            Complex64::default(),
        ],
        vec![
            Complex64::default(),
            Complex64::real(1.0),
            Complex64::real(-1.0),
            Complex64::default(),
        ],
        vec![
            Complex64::default(),
            Complex64::default(),
            Complex64::real(2.0),
            Complex64::default(),
        ],
        vec![
            Complex64::real(1.0),
            Complex64::default(),
            Complex64::default(),
            Complex64::real(1.0),
        ],
    ])
    .unwrap();

    let output = evaluator.apply(&input, &transform).unwrap();
    assert_close(output.slots()[0], Complex64::new(3.0, 0.0));
    assert_close(output.slots()[1], Complex64::new(-1.0, -1.0));
    assert_close(output.slots()[2], Complex64::real(6.0));
    assert_close(output.slots()[3], Complex64::new(5.0, 1.0));
    assert!(output.precision().bits() < input.precision().bits());

    let diagonals = evaluator.diagonalize(&transform).unwrap();
    let plan = evaluator.bsgs_plan(&transform, 2).unwrap();
    assert_eq!(diagonals.slot_count(), 4);
    assert!(plan.diagonal_offsets().contains(&0));
}

#[test]
fn ckks_polynomial_and_minimax_evaluators_work() {
    let polynomial = PolynomialEvaluator::new(params());
    let input = ciphertext(&[
        Complex64::real(0.0),
        Complex64::real(1.0),
        Complex64::real(2.0),
    ]);

    let output = polynomial
        .evaluate_real(&input, &[1.0, 2.0, 3.0], None)
        .unwrap();
    assert_close(output.slots()[0], Complex64::real(1.0));
    assert_close(output.slots()[1], Complex64::real(6.0));
    assert_close(output.slots()[2], Complex64::real(17.0));

    let plan = polynomial
        .plan(&[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0])
        .unwrap();
    assert_eq!(plan.strategy(), PolynomialEvalStrategy::PatersonStockmeyer);

    let minimax = MinimaxEvaluator::new(params());
    let composite = CompositePolynomial::new(vec![vec![1.0, 2.0], vec![0.0, 0.0, 1.0]]).unwrap();
    let output = minimax.evaluate_composite(&input, &composite).unwrap();
    assert_close(output.slots()[0], Complex64::real(1.0));
    assert_close(output.slots()[1], Complex64::real(9.0));
    assert_close(output.slots()[2], Complex64::real(25.0));
}

#[test]
fn ckks_comparison_inverse_and_mod1_helpers_work_on_real_slots() {
    let input = ciphertext(&[
        Complex64::real(-2.0),
        Complex64::real(-0.25),
        Complex64::real(0.25),
        Complex64::real(2.0),
    ]);

    let comparison = ComparisonEvaluator::new(params());
    let sign = comparison.sign(&input, 8.0).unwrap();
    assert!(sign.slots()[0].re < -0.99);
    assert!(sign.slots()[3].re > 0.99);

    let step = comparison.step(&input, 8.0).unwrap();
    assert!(step.slots()[0].re < 0.01);
    assert!(step.slots()[3].re > 0.99);

    let rhs = ciphertext(&[
        Complex64::real(-1.0),
        Complex64::real(-1.0),
        Complex64::real(1.0),
        Complex64::real(1.0),
    ]);
    let max = comparison.max(&input, &rhs, 1e-12).unwrap();
    assert_close(max.slots()[0], Complex64::real(-1.0));
    assert_close(max.slots()[1], Complex64::real(-0.25));
    assert_close(max.slots()[2], Complex64::real(1.0));
    assert_close(max.slots()[3], Complex64::real(2.0));

    let inverse = InverseEvaluator::new(params())
        .reciprocal(&input, 0.1)
        .unwrap();
    assert_close(inverse.slots()[0], Complex64::real(-0.5));
    assert_close(inverse.slots()[3], Complex64::real(0.5));

    let mod1 = Mod1Evaluator::new(params())
        .centered_fractional_part(&ciphertext(&[
            Complex64::real(1.25),
            Complex64::real(-1.25),
            Complex64::real(2.75),
        ]))
        .unwrap();
    assert_close(mod1.slots()[0], Complex64::real(0.25));
    assert_close(mod1.slots()[1], Complex64::real(-0.25));
    assert_close(mod1.slots()[2], Complex64::real(-0.25));
}

#[test]
fn ckks_dft_round_trips() {
    let input = ciphertext(&[
        Complex64::real(1.0),
        Complex64::new(0.0, 1.0),
        Complex64::real(-1.0),
        Complex64::new(0.0, -1.0),
    ]);
    let dft = DftEvaluator::new(params());

    let transformed = dft.transform(&input, DftDirection::Forward).unwrap();
    let roundtrip = dft.transform(&transformed, DftDirection::Inverse).unwrap();

    for (actual, expected) in roundtrip.slots().iter().zip(input.slots()) {
        assert_close(*actual, *expected);
    }
}

#[test]
fn ckks_conjugate_invariant_circuits_reject_complex_slots() {
    let input = ciphertext(&[Complex64::new(1.0, 1.0)]);
    let comparison = ComparisonEvaluator::new(real_params());

    assert!(comparison.sign(&input, 4.0).is_err());
}
