//! Tests for the RNS primitives real hybrid key-switching needs
//! (Workstream 4 item 3): `crt_basis_constant` (the per-row CRT scaling
//! constant key-switching key generation needs) and `mod_down` (dividing a
//! result computed in an extended `Q ∪ P` basis back down to `Q`, the
//! "shrink the noise back down" half of the hybrid technique). Expected
//! values below are computed independently in Python (arbitrary-precision
//! integers, not this crate's own logic).

use phantom_ring::rns::extension::{crt_basis_constant, crt_lift_constant};
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
fn crt_lift_constant_matches_independently_computed_values() {
    // Same source/targets as `crt_basis_constant_matches_independently_computed_values`
    // - `crt_lift_constant` differs by the extra `(Q/q_i)^{-1} mod q_i`
    // factor, so its own expected values (independently computed in
    // Python) are different from that test's.
    let source = basis(&[1000000007, 1000000009, 1000000021]);
    let targets = [
        Modulus::new(1000000033).unwrap(),
        Modulus::new(1000000087).unwrap(),
        Modulus::new(1000000021).unwrap(),
    ];

    assert_eq!(
        crt_lift_constant(&source, 0, &targets).unwrap(),
        vec![285714038, 857128407, 0]
    );
    assert_eq!(
        crt_lift_constant(&source, 1, &targets).unwrap(),
        vec![999999708, 999982707, 0]
    );
    assert_eq!(
        crt_lift_constant(&source, 2, &targets).unwrap(),
        vec![714278833, 142477221, 1]
    );
}

#[test]
fn crt_lift_constant_reconstructs_the_true_value_via_crt() {
    // The defining identity: sum_i G_i * (x mod q_i) == x (mod Q), for any
    // x - verified directly here (not just against independently computed
    // constants) since this identity is exactly what a CRT-coherent RNS
    // gadget decomposition's key material relies on.
    let moduli = [1000000007u64, 1000000009, 1000000021];
    let source = basis(&moduli);
    let targets: Vec<Modulus> = moduli.iter().map(|&m| Modulus::new(m).unwrap()).collect();
    let big_q: u128 = moduli.iter().map(|&m| m as u128).product();

    for &x in &[0u128, 1, 12345, 999999999999u128, big_q - 1] {
        let x = x % big_q;
        let residues: Vec<u64> = moduli.iter().map(|&q| (x % q as u128) as u64).collect();

        // sum_i G_i * (x mod q_i), reduced mod each modulus in the source
        // basis itself (targets == moduli here) - should equal x mod q_j
        // for every j, the defining CRT reconstruction identity.
        let mut per_modulus_sum = vec![0u128; moduli.len()];
        for (i, &residue) in residues.iter().enumerate() {
            let gi = crt_lift_constant(&source, i, &targets).unwrap();
            for (j, &qj) in moduli.iter().enumerate() {
                per_modulus_sum[j] =
                    (per_modulus_sum[j] + u128::from(gi[j]) * u128::from(residue)) % u128::from(qj);
            }
        }
        for (j, &qj) in moduli.iter().enumerate() {
            assert_eq!(
                per_modulus_sum[j],
                x % u128::from(qj),
                "modulus index {j}, x={x}"
            );
        }
    }
}

#[test]
fn crt_lift_constant_rejects_an_out_of_range_index() {
    let source = basis(&[1000000007, 1000000009]);
    let targets = [Modulus::new(1000000021).unwrap()];
    assert!(crt_lift_constant(&source, 2, &targets).is_err());
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
