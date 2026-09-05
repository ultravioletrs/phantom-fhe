//! Tests for `decode_scaled_value` (undoing BFV-style `Delta` scaling
//! directly to a `mod t` result - the primitive
//! `phantom-schemes::bfv::BatchEncoder::decode_u64_real` needed but didn't
//! have, previously only reading the ring's first modulus as if it were
//! the whole `Q`). Expected values computed independently via `i128`
//! arithmetic, not this crate's own logic.

use phantom_ring::rns::decode_scaled_value;
use phantom_ring::{Modulus, Poly, RnsBasis};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn basis(values: &[u64]) -> RnsBasis {
    RnsBasis::new(values.iter().map(|&v| Modulus::new(v).unwrap()).collect()).unwrap()
}

#[test]
fn decode_scaled_value_matches_true_arithmetic_across_many_random_values_multi_modulus() {
    // The exact shape that exposed the original bug: a basis with more
    // than one modulus, where none of them alone is anywhere close to the
    // true value's own magnitude (unlike a single-modulus basis, where
    // "read the one modulus" and "reconstruct across the basis" happen to
    // coincide).
    let q1 = 1_000_003u64;
    let q2 = 1_000_033u64;
    let q3 = 1_000_037u64;
    let basis3 = basis(&[q1, q2, q3]);
    let t = Modulus::new(65_537u64).unwrap();
    let q_total: i128 = q1 as i128 * q2 as i128 * q3 as i128;

    let mut rng = ChaCha20Rng::from_seed([53u8; 32]);
    for _ in 0..200 {
        // A true signed value spanning most of (-Q/2, Q/2], not just a
        // small fraction of it - BFV's own Delta*m+noise is comparable in
        // size to the whole Q, which is exactly what this needs to cover.
        let magnitude = ((rng.next_u64() % (1 << 40)) as i128)
            * ((rng.next_u64() % (1 << 40)) as i128)
            % (q_total / 2);
        let sign = if rng.next_u32() % 2 == 0 { 1 } else { -1 };
        let x = sign * magnitude;

        let rq1 = x.rem_euclid(q1 as i128) as u64;
        let rq2 = x.rem_euclid(q2 as i128) as u64;
        let rq3 = x.rem_euclid(q3 as i128) as u64;
        let poly = Poly::from_coeffs(vec![vec![rq1], vec![rq2], vec![rq3]]).unwrap();

        let result = decode_scaled_value(&poly, &basis3, t).unwrap();

        let t_value = 65_537i128;
        let scaled = x * t_value;
        let expected = if scaled >= 0 {
            (scaled + q_total / 2) / q_total
        } else {
            -((-scaled + q_total / 2) / q_total)
        };
        let expected_mod_t = expected.rem_euclid(t_value) as u64;

        assert_eq!(result[0], expected_mod_t, "x={x}");
    }
}

#[test]
fn decode_scaled_value_matches_a_single_modulus_basis_directly() {
    // Sanity check against the trivial (pre-existing, always-worked) case:
    // a single-modulus basis, where this must agree with a direct
    // centered-residue computation.
    let q = Modulus::new(1_000_000_000_000_037u64).unwrap();
    let single = basis(&[q.value()]);
    let t = Modulus::new(17u64).unwrap();

    let x: i128 = 300_000_000_000_011; // positive, comparable to q
    let rq = x.rem_euclid(q.value() as i128) as u64;
    let poly = Poly::from_coeffs(vec![vec![rq]]).unwrap();

    let result = decode_scaled_value(&poly, &single, t).unwrap();

    let expected = ((x * 17 + q.value() as i128 / 2) / q.value() as i128).rem_euclid(17);
    assert_eq!(result[0], expected as u64);
}

#[test]
fn decode_scaled_value_rejects_a_component_count_mismatch() {
    let basis2 = basis(&[1_000_003u64, 1_000_033]);
    let t = Modulus::new(17u64).unwrap();
    let poly = Poly::from_coeffs(vec![vec![1]]).unwrap();
    assert!(decode_scaled_value(&poly, &basis2, t).is_err());
}
