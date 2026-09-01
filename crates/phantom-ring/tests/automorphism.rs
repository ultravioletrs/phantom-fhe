//! Tests for `Ring::apply_automorphism` (the `σ_k: X -> X^k` Galois
//! automorphism Workstream 4 item 5's real ciphertext rotation is built on).
//! The hand-derived coefficient-permutation-with-sign-flip formula was
//! checked against direct polynomial substitution `p(X^k) mod (X^N+1)` in
//! Python before any Rust was written; the cases below re-run that same
//! cross-check in Rust, plus randomized checks of the algebraic properties
//! any ring automorphism must satisfy.

use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn ring(degree: usize, modulus: u64) -> Ring {
    Ring::new(
        Degree::new(degree).unwrap(),
        vec![Modulus::new(modulus).unwrap()],
    )
    .unwrap()
}

fn poly(coeffs: &[u64]) -> Poly {
    Poly::from_coeffs(vec![coeffs.to_vec()]).unwrap()
}

#[test]
fn matches_direct_polynomial_substitution_on_a_hand_checked_example() {
    // p(X) = 1 + 2X + 3X^2 + 4X^3, N=4, k=3, q=17. p(X^3) reduced mod
    // (X^4+1): X^6 = -X^2, X^9 = X, giving 1 + 4X - 3X^2 + 2X^3, i.e.
    // [1, 4, 14, 2] mod 17 - independently verified in Python before this
    // test was written (two different reduction methods agreed).
    let r = ring(4, 17);
    let p = poly(&[1, 2, 3, 4]);
    let sigma = r.apply_automorphism(&p, 3).unwrap();
    assert_eq!(sigma.coeffs()[0], vec![1, 4, 14, 2]);
}

#[test]
fn identity_element_is_a_no_op() {
    let r = ring(8, 4_000_081);
    let p = poly(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let sigma = r.apply_automorphism(&p, 1).unwrap();
    assert_eq!(sigma.coeffs()[0], p.coeffs()[0]);
}

#[test]
fn rejects_elements_not_coprime_to_two_n() {
    let r = ring(8, 4_000_081);
    let p = poly(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(r.apply_automorphism(&p, 2).is_err()); // even
    assert!(r.apply_automorphism(&p, 4).is_err()); // even
    assert!(r.apply_automorphism(&p, 8).is_err()); // shares factor 8 with 2N=16
}

#[test]
fn is_a_ring_homomorphism_under_multiplication_across_random_trials() {
    // sigma_k(a * b) == sigma_k(a) * sigma_k(b) is guaranteed by construction
    // for any genuine ring automorphism - this checks the *implementation*
    // respects that property, across random polynomials and every valid
    // Galois element for this ring's degree.
    let degree = 8;
    let modulus = 4_000_081u64;
    let r = ring(degree, modulus);
    let two_n = 2 * degree;
    let valid_elements: Vec<usize> = (1..two_n).filter(|k| gcd(*k, two_n) == 1).collect();
    assert_eq!(valid_elements.len(), 8); // phi(16) = 8 (all odd values in 1..16, since 2N=16=2^4)

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    for _ in 0..50 {
        let a = poly(
            &(0..degree)
                .map(|_| rng.next_u64() % modulus)
                .collect::<Vec<_>>(),
        );
        let b = poly(
            &(0..degree)
                .map(|_| rng.next_u64() % modulus)
                .collect::<Vec<_>>(),
        );
        let ab = r.mul(&a, &b).unwrap();
        for &k in &valid_elements {
            let sigma_ab = r.apply_automorphism(&ab, k).unwrap();
            let sigma_a = r.apply_automorphism(&a, k).unwrap();
            let sigma_b = r.apply_automorphism(&b, k).unwrap();
            let sigma_a_sigma_b = r.mul(&sigma_a, &sigma_b).unwrap();
            assert_eq!(
                sigma_ab.coeffs()[0],
                sigma_a_sigma_b.coeffs()[0],
                "homomorphism property failed for k={k}"
            );
        }
    }
}

#[test]
fn composing_two_automorphisms_matches_the_single_combined_element() {
    // sigma_k1(sigma_k2(p)) == sigma_{k1*k2 mod 2N}(p), another property any
    // genuine automorphism group action must satisfy.
    let degree = 8;
    let modulus = 4_000_081u64;
    let r = ring(degree, modulus);
    let two_n = 2 * degree;

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let p = poly(
        &(0..degree)
            .map(|_| rng.next_u64() % modulus)
            .collect::<Vec<_>>(),
    );

    for k1 in (1..two_n).filter(|k| gcd(*k, two_n) == 1) {
        for k2 in (1..two_n).filter(|k| gcd(*k, two_n) == 1) {
            let composed_k = (k1 * k2) % two_n;
            let composed_k = if composed_k == 0 { two_n } else { composed_k };
            let lhs = r
                .apply_automorphism(&r.apply_automorphism(&p, k2).unwrap(), k1)
                .unwrap();
            let rhs = r.apply_automorphism(&p, composed_k).unwrap();
            assert_eq!(lhs.coeffs()[0], rhs.coeffs()[0], "k1={k1} k2={k2}");
        }
    }
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}
