//! Tests for `rescale_and_round` (BFV multiplication's rescale-and-round
//! step - Workstream 5 item 1, BFV multiplication). Expected values
//! computed independently in Python (arbitrary-precision integers, not
//! this crate's own logic).

use phantom_ring::rns::rescale::rescale_and_round;
use phantom_ring::{Modulus, Poly, RnsBasis};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

const Q: u64 = 1_000_000_000_000_037;
const P1: u64 = 1_000_000_000_000_091;
const P2: u64 = 1_000_000_000_000_159;
const T: u64 = 17;

fn basis(values: &[u64]) -> RnsBasis {
    RnsBasis::new(values.iter().map(|&v| Modulus::new(v).unwrap()).collect()).unwrap()
}

#[test]
fn rescale_and_round_matches_independently_computed_values() {
    let q_basis = basis(&[Q]);
    let p_basis = basis(&[P1, P2]);
    let t = Modulus::new(T).unwrap();

    // Each case: (residue mod Q, residue mod P1, residue mod P2, expected
    // residue mod Q after rescale_and_round) - a random true signed value X
    // in (-QP/2, QP/2] reduced into (Q, P1, P2), and round(X*t/Q) mod Q.
    let cases: [(u64, u64, u64, u64); 6] = [
        (
            449332939131162,
            117232600352498,
            658372176483081,
            231805550178489,
        ),
        (
            471742717741405,
            675103610420589,
            999268166787009,
            860330930568387,
        ),
        (
            291452378467606,
            969014282688180,
            455186530857017,
            309525554264040,
        ),
        (
            939654132633003,
            49764569480084,
            66478919005866,
            722637269844681,
        ),
        (
            259771279219915,
            832353273983470,
            472259477167400,
            833990026379478,
        ),
        (
            404453303867632,
            162138581636677,
            33106315876234,
            516080923985715,
        ),
    ];

    for (i, &(rq, rp1, rp2, expected)) in cases.iter().enumerate() {
        let poly = Poly::from_coeffs(vec![vec![rq], vec![rp1], vec![rp2]]).unwrap();
        let result = rescale_and_round(&poly, &q_basis, &p_basis, t).unwrap();
        assert_eq!(result.moduli_count(), 1);
        assert_eq!(result.coeffs()[0][0], expected, "case {i}");
    }
}

#[test]
fn rescale_and_round_matches_true_arithmetic_across_many_random_values() {
    // Property check: build a random true signed value X (small enough that
    // both X and X*t fit in i128 for an independent oracle computation),
    // reduce it into (Q, P1, P2) residues, and confirm rescale_and_round's
    // result matches round(X*t/Q) computed directly via i128 arithmetic.
    let q_basis = basis(&[Q]);
    let p_basis = basis(&[P1, P2]);
    let t = Modulus::new(T).unwrap();

    let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
    for _ in 0..200 {
        // Keep |X| comfortably inside i128 range (Q*P1*P2 ~ 2^150 would
        // overflow i128, so sample a smaller X directly rather than the
        // full (-QP/2, QP/2] range - still exercises the same code path,
        // just not the full magnitude rescale_and_round must support in
        // production use, which the fixed cases above already cover).
        let magnitude =
            i128::from(rng.next_u64() % (1 << 60)) * i128::from(rng.next_u64() % (1 << 60));
        let sign = if rng.next_u32() % 2 == 0 { 1 } else { -1 };
        let x = sign * magnitude;

        let rq = x.rem_euclid(Q as i128) as u64;
        let rp1 = x.rem_euclid(P1 as i128) as u64;
        let rp2 = x.rem_euclid(P2 as i128) as u64;
        let poly = Poly::from_coeffs(vec![vec![rq], vec![rp1], vec![rp2]]).unwrap();

        let result = rescale_and_round(&poly, &q_basis, &p_basis, t).unwrap();

        let scaled = x * i128::from(T);
        let expected = if scaled >= 0 {
            (scaled + i128::from(Q) / 2) / i128::from(Q)
        } else {
            -((-scaled + i128::from(Q) / 2) / i128::from(Q))
        };
        let expected_residue = expected.rem_euclid(Q as i128) as u64;

        assert_eq!(result.coeffs()[0][0], expected_residue, "x={x}");
    }
}

#[test]
fn rescale_and_round_rejects_a_component_count_mismatch() {
    let q_basis = basis(&[Q]);
    let p_basis = basis(&[P1, P2]);
    let t = Modulus::new(T).unwrap();
    // Only 2 components total, but q_basis+p_basis needs 3.
    let poly = Poly::from_coeffs(vec![vec![1], vec![2]]).unwrap();
    assert!(rescale_and_round(&poly, &q_basis, &p_basis, t).is_err());
}
