//! Tests for the RNS primitives real hybrid key-switching needs
//! (Workstream 4 item 3): `crt_basis_constant` (the per-row CRT scaling
//! constant key-switching key generation needs) and `mod_down` (dividing a
//! result computed in an extended `Q ∪ P` basis back down to `Q`, the
//! "shrink the noise back down" half of the hybrid technique). Expected
//! values below are computed independently in Python (arbitrary-precision
//! integers, not this crate's own logic).

use phantom_ring::rns::extension::crt_basis_constant;
use phantom_ring::rns::rescale::mod_down;
use phantom_ring::{Modulus, Poly, RnsBasis};

fn basis(values: &[u64]) -> RnsBasis {
    RnsBasis::new(values.iter().map(|&v| Modulus::new(v).unwrap()).collect()).unwrap()
}

#[test]
fn crt_basis_constant_matches_independently_computed_values() {
    // source_moduli = [1000000007, 1000000009, 1000000021]; targets =
    // [1000000033, 1000000087, 1000000021] (the last target intentionally
    // equals one of the source moduli itself, to exercise M_i mod q_i == 0).
    let source = basis(&[1000000007, 1000000009, 1000000021]);
    let targets = [
        Modulus::new(1000000033).unwrap(),
        Modulus::new(1000000087).unwrap(),
        Modulus::new(1000000021).unwrap(),
    ];

    assert_eq!(
        crt_basis_constant(&source, 0, &targets).unwrap(),
        vec![288, 5148, 0]
    );
    assert_eq!(
        crt_basis_constant(&source, 1, &targets).unwrap(),
        vec![312, 5280, 0]
    );
    assert_eq!(
        crt_basis_constant(&source, 2, &targets).unwrap(),
        vec![624, 6240, 168]
    );
}

#[test]
fn crt_basis_constant_rejects_an_out_of_range_index() {
    let source = basis(&[1000000007, 1000000009]);
    let targets = [Modulus::new(1000000021).unwrap()];
    assert!(crt_basis_constant(&source, 2, &targets).is_err());
}

#[test]
fn mod_down_matches_independently_computed_values() {
    let q_basis = basis(&[1000000007, 1000000009, 1000000021]);
    let p_basis = basis(&[1000000033, 1000000087]);

    // Each case: (q_residues, p_residues, expected floor(X/P) mod q_i),
    // X and the expected values computed independently in Python.
    let cases: [([u64; 3], [u64; 2], [u64; 3]); 5] = [
        (
            [766660236, 739668678, 181159463],
            [631635913, 787782386],
            [662316164, 408867339, 760978972],
        ),
        (
            [924458172, 546328330, 31847771],
            [393706958, 172472376],
            [441158376, 717740311, 136826714],
        ),
        (
            [453300889, 740061663, 664211032],
            [971487349, 334463978],
            [36444581, 496994845, 342166178],
        ),
        (
            [972391161, 199897803, 812967025],
            [760078575, 506215414],
            [493508411, 571340396, 640287368],
        ),
        (
            [767960181, 193274140, 377824791],
            [760491788, 413077980],
            [667640411, 856214714, 23128671],
        ),
    ];

    for (i, (q_res, p_res, expected)) in cases.iter().enumerate() {
        let coeffs: Vec<Vec<u64>> = q_res.iter().chain(p_res.iter()).map(|&r| vec![r]).collect();
        let poly = Poly::from_coeffs(coeffs).unwrap();

        let result = mod_down(&poly, &q_basis, &p_basis).unwrap();

        for (j, &expected_j) in expected.iter().enumerate() {
            assert_eq!(
                result.coeffs()[j][0],
                expected_j,
                "case {i}: mismatch at Q-component {j}"
            );
        }
    }
}

#[test]
fn mod_down_rejects_a_component_count_mismatch() {
    let q_basis = basis(&[1000000007, 1000000009]);
    let p_basis = basis(&[1000000033]);
    // Only 2 components total, but q_basis+p_basis needs 3.
    let poly = Poly::from_coeffs(vec![vec![1], vec![2]]).unwrap();
    assert!(mod_down(&poly, &q_basis, &p_basis).is_err());
}
