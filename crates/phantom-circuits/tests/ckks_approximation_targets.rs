//! Approximation-quality tests for CKKS circuit evaluators against known
//! mathematical targets, complementing `phase11_ckks.rs`'s machinery smoke
//! tests with derived error bounds checked against exact reference values.
//!
//! Every bound below was verified numerically in Python (grid/random sweeps,
//! tens to hundreds of thousands of samples) before being encoded here:
//! - `sign`/`step`: `tanh(alpha*x)` vs. exact `sign(x)`, bounded by
//!   `2*exp(-2*alpha*|x|)` (from `1 - tanh(z) = 2/(e^{2z}+1) < 2*e^{-2z}`).
//! - `max`: the smooth-abs formula vs. exact `max`, bounded by
//!   `0.5*sqrt(epsilon)` (tight at `lhs == rhs`).
//! - `reciprocal`: exact `1/z` outside the clamp radius.
//! - `centered_fractional_part`: exact `x - round(x)`.
//! - the composite sign approximation (`MinimaxEvaluator`/
//!   `CompositePolynomial`, iterating `f(x) = 1.5*x - 0.5*x^3`) converging
//!   to `sign(x)` for `|x|` bounded away from zero, a standard CKKS
//!   bootstrapping technique (`x=1`/`x=-1` are attracting fixed points with
//!   `f'(+-1)=0`, `x=0` is repelling) - 6 iterations bring the worst-case
//!   error on `|x| in [0.3, 1.0]` under `1e-4`.

use phantom_circuits::ckks::{
    ComparisonEvaluator, CompositePolynomial, InverseEvaluator, MinimaxEvaluator, Mod1Evaluator,
};
use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64, Precision, Scale};

// Large enough slot count (degree/2 = 64) to hold every grid used below in
// one ciphertext; the evaluators here are all transparent-scaffold Complex64
// arithmetic, so the degree has no bearing on real ring/NTT constraints.
fn params() -> CkksParams {
    CkksParams::builder()
        .degree(128)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
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

fn grid(lo: f64, hi: f64, steps: usize) -> Vec<f64> {
    (0..=steps)
        .map(|i| lo + (hi - lo) * (i as f64) / (steps as f64))
        .collect()
}

#[test]
fn comparison_sign_error_matches_derived_tanh_bound() {
    let comparison = ComparisonEvaluator::new(params());
    for &alpha in &[0.5, 1.0, 4.0, 8.0, 16.0] {
        let xs = grid(-3.0, 3.0, 40)
            .into_iter()
            .filter(|x| x.abs() > 1e-6)
            .collect::<Vec<_>>();
        let input = ciphertext(&xs.iter().map(|&x| Complex64::real(x)).collect::<Vec<_>>());
        let sign = comparison.sign(&input, alpha).unwrap();
        for (&x, slot) in xs.iter().zip(sign.slots()) {
            let target = if x > 0.0 { 1.0 } else { -1.0 };
            let bound = 2.0 * (-2.0 * alpha * x.abs()).exp();
            assert!(
                (slot.re - target).abs() <= bound + 1e-12,
                "alpha={alpha} x={x}: |{} - {target}| > {bound}",
                slot.re
            );
        }
    }
}

#[test]
fn comparison_step_error_matches_derived_bound() {
    let comparison = ComparisonEvaluator::new(params());
    let alpha = 6.0;
    let xs = grid(-3.0, 3.0, 40)
        .into_iter()
        .filter(|x| x.abs() > 1e-6)
        .collect::<Vec<_>>();
    let input = ciphertext(&xs.iter().map(|&x| Complex64::real(x)).collect::<Vec<_>>());
    let step = comparison.step(&input, alpha).unwrap();
    for (&x, slot) in xs.iter().zip(step.slots()) {
        let target = if x > 0.0 { 1.0 } else { 0.0 };
        let bound = (-2.0 * alpha * x.abs()).exp();
        assert!(
            (slot.re - target).abs() <= bound + 1e-12,
            "x={x}: |{} - {target}| > {bound}",
            slot.re
        );
    }
}

#[test]
fn comparison_max_error_matches_derived_closed_form_bound() {
    let comparison = ComparisonEvaluator::new(params());
    let lhs_vals = grid(-5.0, 5.0, 10);
    let rhs_vals = grid(-5.0, 5.0, 10);
    for &epsilon in &[1e-6, 1e-3, 1.0] {
        let lhs = ciphertext(
            &lhs_vals
                .iter()
                .map(|&v| Complex64::real(v))
                .collect::<Vec<_>>(),
        );
        let rhs = ciphertext(
            &rhs_vals
                .iter()
                .map(|&v| Complex64::real(v))
                .collect::<Vec<_>>(),
        );
        let max = comparison.max(&lhs, &rhs, epsilon).unwrap();
        let bound = 0.5 * epsilon.sqrt();
        for ((&l, &r), slot) in lhs_vals.iter().zip(&rhs_vals).zip(max.slots()) {
            let target = l.max(r);
            assert!(
                (slot.re - target).abs() <= bound + 1e-12,
                "l={l} r={r} eps={epsilon}: |{} - {target}| > {bound}",
                slot.re
            );
        }
    }
}

#[test]
fn inverse_reciprocal_matches_exact_reciprocal_outside_clamp() {
    let min_abs = 0.1;
    let inverse = InverseEvaluator::new(params());
    let values = [
        Complex64::real(-3.0),
        Complex64::real(-1.0),
        Complex64::real(0.5),
        Complex64::real(2.0),
        Complex64::new(1.0, 1.0),
        Complex64::new(-2.0, 3.0),
    ];
    for &z in &values {
        let norm = z.re * z.re + z.im * z.im;
        assert!(
            norm >= min_abs * min_abs,
            "test value must be outside clamp"
        );
        let input = ciphertext(&[z]);
        let output = inverse.reciprocal(&input, min_abs).unwrap();
        let expected = Complex64::new(z.re / norm, -z.im / norm);
        assert!((output.slots()[0].re - expected.re).abs() < 1e-12);
        assert!((output.slots()[0].im - expected.im).abs() < 1e-12);
    }
}

#[test]
fn inverse_reciprocal_clamps_inside_the_minimum_magnitude() {
    let min_abs = 0.5;
    let inverse = InverseEvaluator::new(params());
    let input = ciphertext(&[
        Complex64::real(0.01),
        Complex64::real(-0.01),
        Complex64::real(0.0),
    ]);
    let output = inverse.reciprocal(&input, min_abs).unwrap();
    assert!((output.slots()[0].re - 1.0 / min_abs).abs() < 1e-12);
    assert!((output.slots()[1].re - (-1.0 / min_abs)).abs() < 1e-12);
    assert!((output.slots()[2].re - 1.0 / min_abs).abs() < 1e-12);
}

#[test]
fn mod1_matches_exact_centered_fractional_part() {
    let mod1 = Mod1Evaluator::new(params());
    let xs = [
        0.0, 0.25, -0.25, 0.5, -0.5, 1.25, -1.25, 2.75, -2.75, 3.5, -3.5,
    ];
    let input = ciphertext(&xs.iter().map(|&x| Complex64::real(x)).collect::<Vec<_>>());
    let output = mod1.centered_fractional_part(&input).unwrap();
    for (&x, slot) in xs.iter().zip(output.slots()) {
        let expected = x - x.round();
        assert!(
            (slot.re - expected).abs() < 1e-12,
            "x={x}: {} != {expected}",
            slot.re
        );
    }
}

/// The classic CKKS bootstrapping sign approximation: iterating
/// `f(x) = 1.5*x - 0.5*x^3` converges to `sign(x)` for `x` bounded away
/// from the repelling fixed point at `0`, since `f'(+-1) = 0` (attracting)
/// while `f'(0) = 1.5` (repelling). Verified numerically in Python: with
/// `|x| >= 0.3`, 6 iterations bring the worst-case error to `~2.7e-5` on a
/// fine deterministic grid, well clear of the `1e-4` tolerance used here.
#[test]
fn minimax_composite_sign_approximation_converges_to_true_sign() {
    let stage = vec![0.0, 1.5, 0.0, -0.5];
    let composite = CompositePolynomial::new(vec![stage; 6]).unwrap();
    let minimax = MinimaxEvaluator::new(params());

    let xs = grid(0.3, 1.0, 20)
        .into_iter()
        .flat_map(|x| [x, -x])
        .collect::<Vec<_>>();
    let input = ciphertext(&xs.iter().map(|&x| Complex64::real(x)).collect::<Vec<_>>());
    let output = minimax.evaluate_composite(&input, &composite).unwrap();

    for (&x, slot) in xs.iter().zip(output.slots()) {
        let target = if x > 0.0 { 1.0 } else { -1.0 };
        assert!(
            (slot.re - target).abs() < 1e-4,
            "x={x}: composite sign approximation {} too far from {target}",
            slot.re
        );
    }
}

#[test]
fn minimax_composite_sign_approximation_is_exact_at_the_stable_fixed_points() {
    let stage = vec![0.0, 1.5, 0.0, -0.5];
    let composite = CompositePolynomial::new(vec![stage; 6]).unwrap();
    let minimax = MinimaxEvaluator::new(params());

    let input = ciphertext(&[
        Complex64::real(1.0),
        Complex64::real(-1.0),
        Complex64::real(0.0),
    ]);
    let output = minimax.evaluate_composite(&input, &composite).unwrap();
    assert!((output.slots()[0].re - 1.0).abs() < 1e-12);
    assert!((output.slots()[1].re - (-1.0)).abs() < 1e-12);
    assert!((output.slots()[2].re - 0.0).abs() < 1e-12);
}
