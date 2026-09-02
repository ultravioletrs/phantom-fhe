//! Tests for `extend_basis_centered` (the RNS primitive CKKS real
//! bootstrapping's modulus-raise step is built on - Workstream 11 item 1).

use phantom_ring::rns::extension::{extend_basis_centered, reconstruct_centered_values};
use phantom_ring::{Modulus, Poly, RnsBasis};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn basis(values: &[u64]) -> RnsBasis {
    RnsBasis::new(values.iter().map(|&v| Modulus::new(v).unwrap()).collect()).unwrap()
}

#[test]
fn extend_basis_centered_embeds_a_negative_value_correctly() {
    // A single-modulus source (mirroring a real ciphertext's own lowest,
    // "level 0" modulus) holding one coefficient whose centered value is
    // negative - the exact case `extend_basis`'s own non-negative
    // convention would get wrong (it would reconstruct `q0 - 5`, not
    // `-5`, and carry that huge offset into the target basis instead).
    let q0 = 1_000_003u64;
    let source = basis(&[q0]);
    let target = basis(&[1_000_000_007, 1_000_000_009]);

    let value = -5i128;
    let residue = value.rem_euclid(i128::from(q0)) as u64;
    let poly = Poly::from_coeffs(vec![vec![residue]]).unwrap();

    let extended = extend_basis_centered(&poly, &source, &target).unwrap();
    assert_eq!(extended.component(0).unwrap()[0], (1_000_000_007 - 5));
    assert_eq!(extended.component(1).unwrap()[0], (1_000_000_009 - 5));

    // Reconstructing back out of the target basis recovers the same
    // signed value, not the non-negative `q0 - 5`.
    let recovered = reconstruct_centered_values(&extended, &target).unwrap();
    assert_eq!(recovered, vec![value]);
}

#[test]
fn extend_basis_centered_round_trips_across_many_random_signed_values() {
    // Property check: a random signed value small enough to fit
    // comfortably within the single-modulus source basis, extended into a
    // much bigger target basis, reconstructs back to the exact same
    // value - the modulus-raise property real bootstrapping relies on
    // (the *value* a raised ciphertext carries doesn't change, only the
    // basis it's represented in).
    let q0 = 1_073_741_827u64;
    let source = basis(&[q0]);
    let target = basis(&[
        4_611_686_018_427_400_249,
        1_073_741_717,
        1_073_741_719,
        1_073_741_723,
    ]);

    let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
    for _ in 0..200 {
        let magnitude = i128::from(rng.next_u64() % (q0 / 2));
        let sign = if rng.next_u32() % 2 == 0 { 1 } else { -1 };
        let x = sign * magnitude;

        let residue = x.rem_euclid(i128::from(q0)) as u64;
        let poly = Poly::from_coeffs(vec![vec![residue]]).unwrap();

        let extended = extend_basis_centered(&poly, &source, &target).unwrap();
        let recovered = reconstruct_centered_values(&extended, &target).unwrap();
        assert_eq!(recovered, vec![x], "x={x}");
    }
}

#[test]
fn extend_basis_centered_rejects_a_component_count_mismatch() {
    let source = basis(&[1_000_000_007, 1_000_000_009]);
    let target = basis(&[1_000_000_021]);
    let poly = Poly::from_coeffs(vec![vec![5]]).unwrap();
    assert!(extend_basis_centered(&poly, &source, &target).is_err());
}
