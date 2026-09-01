//! Tests for `reconstruct_centered_values` (the RNS primitive CKKS's real
//! decoder is built on - Workstream 5 item 3). Expected values computed
//! independently in Python (arbitrary-precision integers, not this crate's
//! own logic).

use phantom_ring::rns::extension::reconstruct_centered_values;
use phantom_ring::{Modulus, Poly, RnsBasis};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn basis(values: &[u64]) -> RnsBasis {
    RnsBasis::new(values.iter().map(|&v| Modulus::new(v).unwrap()).collect()).unwrap()
}

#[test]
fn reconstruct_centered_values_matches_independently_computed_values() {
    let moduli = [1000000007u64, 1000000009, 1000000021];
    let source = basis(&moduli);

    // Each case: (residues mod each modulus, expected centered true value).
    let cases: [([u64; 3], i128); 5] = [
        (
            [698977656, 655745311, 597935216],
            -469038207982995064199115768,
        ),
        (
            [470560859, 906157031, 450853085],
            -196838584367215395454856346,
        ),
        (
            [88862025, 863398856, 677423100],
            411707177700046351815534921,
        ),
        ([81059594, 498045808, 39535695], 416902233461942549886448146),
        (
            [339474990, 794298173, 604247750],
            -392374952005410745472027717,
        ),
    ];

    for (i, &(residues, expected)) in cases.iter().enumerate() {
        let poly = Poly::from_coeffs(residues.iter().map(|&r| vec![r]).collect()).unwrap();
        let values = reconstruct_centered_values(&poly, &source).unwrap();
        assert_eq!(values, vec![expected], "case {i}");
    }
}

#[test]
fn reconstruct_centered_values_round_trips_across_many_random_signed_values() {
    // Property check: pick a random signed value small enough to fit
    // comfortably (i64 range), reduce into (q0, q1) residues, and confirm
    // reconstruction recovers it exactly.
    let q0 = 1_000_000_000_000_037u64;
    let q1 = 1_000_000_000_000_091u64;
    let source = basis(&[q0, q1]);

    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    for _ in 0..200 {
        let magnitude = i128::from(rng.next_u64() % (1 << 40));
        let sign = if rng.next_u32() % 2 == 0 { 1 } else { -1 };
        let x = sign * magnitude;

        let r0 = x.rem_euclid(i128::from(q0)) as u64;
        let r1 = x.rem_euclid(i128::from(q1)) as u64;
        let poly = Poly::from_coeffs(vec![vec![r0], vec![r1]]).unwrap();

        let values = reconstruct_centered_values(&poly, &source).unwrap();
        assert_eq!(values, vec![x], "x={x}");
    }
}

#[test]
fn reconstruct_centered_values_rejects_a_component_count_mismatch() {
    let source = basis(&[1000000007, 1000000009]);
    let poly = Poly::from_coeffs(vec![vec![5]]).unwrap();
    assert!(reconstruct_centered_values(&poly, &source).is_err());
}
