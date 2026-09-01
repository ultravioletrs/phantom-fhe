//! Tests for `modulus_switch_down` (BGV/BFV-style exact modulus switching -
//! Workstream 5 item 2). Expected values below are computed independently
//! in Python (arbitrary-precision integers, not this crate's own logic),
//! matching the style `key_switch_primitives.rs` established.

use phantom_ring::rns::rescale::modulus_switch_down;
use phantom_ring::{Modulus, Poly, RnsBasis};

fn basis(values: &[u64]) -> RnsBasis {
    RnsBasis::new(values.iter().map(|&v| Modulus::new(v).unwrap()).collect()).unwrap()
}

#[test]
fn modulus_switch_down_matches_independently_computed_values() {
    // q_moduli = [1000000007, 1000000009, 1000000021] (last one dropped),
    // t = 17. Each case: (residues in the full 3-modulus basis, expected
    // residues in the remaining 2-modulus basis after switching).
    let q_basis = basis(&[1000000007, 1000000009, 1000000021]);
    let t = Modulus::new(17).unwrap();

    let cases: [([u64; 3], [u64; 2]); 6] = [
        ([134395791, 83055555, 385487134], [53493480, 558130711]),
        ([759025028, 793051145, 885850019], [62369653, 492266774]),
        ([119808076, 143870386, 322931336], [699776931, 818411611]),
        ([546794409, 221269741, 887558996], [332802546, 527809248]),
        ([531427252, 501803285, 642409321], [349215572, 654949506]),
        ([129088772, 644433380, 420106822], [407784432, 185360552]),
    ];

    for (i, (residues, expected)) in cases.iter().enumerate() {
        let poly = Poly::from_coeffs(residues.iter().map(|&r| vec![r]).collect()).unwrap();
        let switched = modulus_switch_down(&poly, &q_basis, t).unwrap();

        assert_eq!(switched.moduli_count(), 2);
        for (j, &expected_j) in expected.iter().enumerate() {
            assert_eq!(
                switched.coeffs()[j][0],
                expected_j,
                "case {i}: mismatch at component {j}"
            );
        }
    }
}

#[test]
fn modulus_switch_down_preserves_congruence_mod_t_across_many_random_values() {
    // Property check (not against a fixed oracle): for many random true
    // values, reconstruct the true value in both the original and switched
    // bases via u128 CRT (small enough moduli here to fit), and confirm the
    // switched value is congruent to the original mod t.
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    let q0 = 1_000_003u64;
    let q1 = 1_000_033u64;
    let q_basis = basis(&[q0, q1]);
    let t_value = 17u64;
    let t = Modulus::new(t_value).unwrap();

    let q0_128 = u128::from(q0);
    let big_q = q0_128 * u128::from(q1);

    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    for _ in 0..200 {
        let true_value = u128::from(rng.next_u64()) % big_q;
        let r0 = (true_value % q0_128) as u64;
        let r1 = (true_value % u128::from(q1)) as u64;
        let poly = Poly::from_coeffs(vec![vec![r0], vec![r1]]).unwrap();

        let switched = modulus_switch_down(&poly, &q_basis, t).unwrap();
        assert_eq!(switched.moduli_count(), 1);
        let switched_r0 = switched.coeffs()[0][0];

        let original_mod_t = (true_value % u128::from(t_value)) as u64;
        assert_eq!(
            switched_r0 % t_value,
            original_mod_t,
            "congruence mod t broken for true_value={true_value}"
        );
    }
}

#[test]
fn modulus_switch_down_rejects_a_single_modulus_basis() {
    let q_basis = basis(&[1000000007]);
    let t = Modulus::new(17).unwrap();
    let poly = Poly::from_coeffs(vec![vec![5]]).unwrap();
    assert!(modulus_switch_down(&poly, &q_basis, t).is_err());
}
