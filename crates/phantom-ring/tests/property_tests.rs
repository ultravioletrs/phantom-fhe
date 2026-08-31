//! Property-based tests (Workstream 3 item 1), using `proptest` - pre-approved
//! as a dev-dependency for exactly this purpose in
//! `docs/internal/dependency-policy.md`. These complement, rather than
//! replace, `tests/phase2.rs`'s hand-seeded randomized tests: proptest brings
//! its own RNG/shrinking and lets each property range over a much wider,
//! generator-driven input space (e.g. the full `u64` modulus range for
//! modular arithmetic) instead of a fixed number of hand-rolled iterations.

use phantom_ring::ntt::{CpuNttBackend, NttBackend};
use phantom_ring::reduce::{
    add_mod, inv_mod, mul_mod, neg_mod, pow_mod, sub_mod, BarrettReducer, MontgomeryReducer,
    MONTGOMERY_MAX_MODULUS,
};
use phantom_ring::rns::crt::{decompose_value, reconstruct_residue};
use phantom_ring::rns::extension::extend_basis;
use phantom_ring::rns::rescale::drop_last_modulus;
use phantom_ring::{Degree, Modulus, Poly, Ring, RnsBasis};
use proptest::prelude::*;

fn modulus_and_two_residues() -> impl Strategy<Value = (u64, u64, u64)> {
    (2u64..=u64::MAX).prop_flat_map(|m| (Just(m), 0..m, 0..m))
}

fn modulus_and_three_residues() -> impl Strategy<Value = (u64, u64, u64, u64)> {
    (2u64..=u64::MAX).prop_flat_map(|m| (Just(m), 0..m, 0..m, 0..m))
}

fn odd_modulus_and_two_residues() -> impl Strategy<Value = (u64, u64, u64)> {
    // m = 2*half + 5: always odd, always >= 5, stays under MONTGOMERY_MAX_MODULUS.
    (0u64..(MONTGOMERY_MAX_MODULUS - 5) / 2).prop_flat_map(|half| {
        let m = 2 * half + 5;
        (Just(m), 0..m, 0..m)
    })
}

fn prime_modulus_and_nonzero_residue() -> impl Strategy<Value = (u64, u64)> {
    // Fixed small set of known primes (inv_mod uses Fermat's little theorem,
    // which requires a prime modulus) spanning small, NTT-sized, and
    // realistic ~61-bit RNS-CKKS/BGV ranges.
    let primes: Vec<u64> = vec![3, 5, 97, 193, 12289, 2305843009213693951];
    prop::sample::select(primes).prop_flat_map(|m| (Just(m), 1..m))
}

proptest! {
    // ---- Modular arithmetic (crate::reduce free functions) ----

    #[test]
    fn add_mod_is_commutative((m, a, b) in modulus_and_two_residues()) {
        prop_assert_eq!(add_mod(a, b, m), add_mod(b, a, m));
    }

    #[test]
    fn add_mod_is_associative((m, a, b, c) in modulus_and_three_residues()) {
        prop_assert_eq!(add_mod(add_mod(a, b, m), c, m), add_mod(a, add_mod(b, c, m), m));
    }

    #[test]
    fn sub_mod_undoes_add_mod((m, a, b) in modulus_and_two_residues()) {
        prop_assert_eq!(sub_mod(add_mod(a, b, m), b, m), a);
    }

    #[test]
    fn neg_mod_is_the_additive_inverse((m, a, _b) in modulus_and_two_residues()) {
        prop_assert_eq!(add_mod(a, neg_mod(a, m), m), 0);
    }

    #[test]
    fn mul_mod_matches_widened_u128_reference((m, a, b) in modulus_and_two_residues()) {
        let expected = ((a as u128 * b as u128) % m as u128) as u64;
        prop_assert_eq!(mul_mod(a, b, m), expected);
    }

    #[test]
    fn mul_mod_is_commutative((m, a, b) in modulus_and_two_residues()) {
        prop_assert_eq!(mul_mod(a, b, m), mul_mod(b, a, m));
    }

    #[test]
    fn mul_mod_distributes_over_add_mod((m, a, b, c) in modulus_and_three_residues()) {
        let lhs = mul_mod(a, add_mod(b, c, m), m);
        let rhs = add_mod(mul_mod(a, b, m), mul_mod(a, c, m), m);
        prop_assert_eq!(lhs, rhs);
    }

    #[test]
    fn pow_mod_and_inv_mod_recover_the_multiplicative_identity(
        (m, a) in prime_modulus_and_nonzero_residue()
    ) {
        prop_assert_eq!(mul_mod(a, inv_mod(a, m), m), 1);
        // pow_mod(a, m-1, m) == 1 is Fermat's little theorem itself, and
        // inv_mod is literally pow_mod(a, m-2, m) - check both hold together
        // rather than trusting inv_mod's definition in isolation.
        prop_assert_eq!(pow_mod(a, m - 1, m), 1);
    }

    #[test]
    fn barrett_reducer_matches_mul_mod_for_in_range_residues((m, a, b) in modulus_and_two_residues()) {
        let reducer = BarrettReducer::new(m).unwrap();
        prop_assert_eq!(reducer.reduce(a as u128 * b as u128), mul_mod(a, b, m));
    }

    #[test]
    fn montgomery_reducer_matches_mul_mod_for_in_range_residues(
        (m, a, b) in odd_modulus_and_two_residues()
    ) {
        let reducer = MontgomeryReducer::new(m).unwrap();
        prop_assert_eq!(reducer.mul(a, b), mul_mod(a, b, m));
    }
}

// ---- Polynomial arithmetic (Ring ring axioms) ----

const POLY_DEGREE: usize = 8;
const POLY_MODULUS: u64 = 97;

fn property_test_ring() -> Ring {
    Ring::new_ntt(
        Degree::new(POLY_DEGREE).unwrap(),
        vec![Modulus::new(POLY_MODULUS).unwrap()],
    )
    .unwrap()
}

fn poly_strategy() -> impl Strategy<Value = Poly> {
    proptest::collection::vec(0..POLY_MODULUS, POLY_DEGREE)
        .prop_map(|coeffs| Poly::from_coeffs(vec![coeffs]).unwrap())
}

proptest! {
    #[test]
    fn ring_add_is_commutative(a in poly_strategy(), b in poly_strategy()) {
        let ring = property_test_ring();
        prop_assert_eq!(ring.add(&a, &b).unwrap(), ring.add(&b, &a).unwrap());
    }

    #[test]
    fn ring_add_is_associative(a in poly_strategy(), b in poly_strategy(), c in poly_strategy()) {
        let ring = property_test_ring();
        let lhs = ring.add(&ring.add(&a, &b).unwrap(), &c).unwrap();
        let rhs = ring.add(&a, &ring.add(&b, &c).unwrap()).unwrap();
        prop_assert_eq!(lhs, rhs);
    }

    #[test]
    fn ring_sub_undoes_add(a in poly_strategy(), b in poly_strategy()) {
        let ring = property_test_ring();
        let sum = ring.add(&a, &b).unwrap();
        prop_assert_eq!(ring.sub(&sum, &b).unwrap(), a);
    }

    #[test]
    fn ring_neg_is_the_additive_inverse(a in poly_strategy()) {
        let ring = property_test_ring();
        let sum = ring.add(&a, &ring.neg(&a).unwrap()).unwrap();
        prop_assert_eq!(sum, ring.zero());
    }

    #[test]
    fn ring_mul_is_commutative(a in poly_strategy(), b in poly_strategy()) {
        let ring = property_test_ring();
        prop_assert_eq!(ring.mul(&a, &b).unwrap(), ring.mul(&b, &a).unwrap());
    }

    #[test]
    fn ring_mul_distributes_over_add(a in poly_strategy(), b in poly_strategy(), c in poly_strategy()) {
        let ring = property_test_ring();
        let lhs = ring.mul(&a, &ring.add(&b, &c).unwrap()).unwrap();
        let rhs = ring
            .add(&ring.mul(&a, &b).unwrap(), &ring.mul(&a, &c).unwrap())
            .unwrap();
        prop_assert_eq!(lhs, rhs);
    }

    // ---- NTT round trip ----

    #[test]
    fn ntt_forward_inverse_round_trip_recovers_the_original(poly in poly_strategy()) {
        let ring = property_test_ring();
        let backend = CpuNttBackend;
        let mut transformed = poly.clone();
        backend.forward(&ring, &mut transformed).unwrap();
        backend.inverse(&ring, &mut transformed).unwrap();
        prop_assert_eq!(transformed, poly);
    }
}

// ---- RNS reconstruction ----

const RNS_MODULI: [u64; 3] = [17, 97, 193];

fn rns_basis() -> RnsBasis {
    RnsBasis::new(
        RNS_MODULI
            .iter()
            .map(|&q| Modulus::new(q).unwrap())
            .collect(),
    )
    .unwrap()
}

proptest! {
    #[test]
    fn decompose_then_reconstruct_residue_is_identity(
        value in 0u128..(RNS_MODULI[0] as u128 * RNS_MODULI[1] as u128 * RNS_MODULI[2] as u128)
    ) {
        let basis = rns_basis();
        let residues = decompose_value(value, &basis);
        prop_assert_eq!(reconstruct_residue(&residues, &basis).unwrap(), value);
    }

    #[test]
    fn extend_basis_target_residues_match_direct_reduction_of_the_true_value(
        value in 0u128..(RNS_MODULI[0] as u128 * RNS_MODULI[1] as u128)
    ) {
        let source = RnsBasis::new(vec![
            Modulus::new(RNS_MODULI[0]).unwrap(),
            Modulus::new(RNS_MODULI[1]).unwrap(),
        ])
        .unwrap();
        let target = RnsBasis::new(vec![
            Modulus::new(RNS_MODULI[2]).unwrap(),
            Modulus::new(257).unwrap(),
        ])
        .unwrap();
        let residues = decompose_value(value, &source);
        let poly = Poly::from_coeffs(vec![vec![residues[0]], vec![residues[1]]]).unwrap();
        let extended = extend_basis(&poly, &source, &target).unwrap();
        prop_assert_eq!(extended.coeffs()[0][0], (value % RNS_MODULI[2] as u128) as u64);
        prop_assert_eq!(extended.coeffs()[1][0], (value % 257) as u64);
    }

    #[test]
    fn drop_last_modulus_removes_exactly_the_last_component(
        c0 in proptest::collection::vec(0..RNS_MODULI[0], 4),
        c1 in proptest::collection::vec(0..RNS_MODULI[1], 4),
        c2 in proptest::collection::vec(0..RNS_MODULI[2], 4),
    ) {
        let poly = Poly::from_coeffs(vec![c0.clone(), c1.clone(), c2]).unwrap();
        let dropped = drop_last_modulus(&poly).unwrap();
        prop_assert_eq!(dropped.coeffs(), &[c0, c1][..]);
    }
}
