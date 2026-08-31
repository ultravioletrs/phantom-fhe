use phantom_ring::ntt::{CpuNttBackend, NttBackend};
use phantom_ring::reduce::{add_mod, mul_mod, neg_mod, sub_mod, MONTGOMERY_MAX_MODULUS};
use phantom_ring::reduce::{BarrettReducer, MontgomeryReducer};
use phantom_ring::rns::crt::{decompose_value, reconstruct_poly, reconstruct_residue};
use phantom_ring::rns::extension::extend_basis;
use phantom_ring::rns::rescale::drop_last_modulus;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary, sample_uniform};
use phantom_ring::{Degree, Modulus, Poly, Ring, RnsBasis};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn test_ring() -> Ring {
    Ring::new_ntt(
        Degree::new(4).unwrap(),
        vec![Modulus::new(17).unwrap(), Modulus::new(97).unwrap()],
    )
    .unwrap()
}

#[test]
fn modular_arithmetic_is_correct() {
    assert_eq!(add_mod(15, 5, 17), 3);
    assert_eq!(sub_mod(3, 5, 17), 15);
    assert_eq!(neg_mod(5, 17), 12);
    assert_eq!(mul_mod(9, 4, 17), 2);
}

#[test]
fn ring_rejects_invalid_parameters() {
    assert!(Degree::new(0).is_err());
    assert!(Degree::new(6).is_err());
    assert!(Modulus::new(2).is_err());

    let err = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(19).unwrap()]).unwrap_err();
    assert!(err.to_string().contains("not congruent"));
}

#[test]
fn polynomial_arithmetic_works_componentwise() {
    let ring = test_ring();
    let a = Poly::from_coeffs(vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]).unwrap();
    let b = Poly::from_coeffs(vec![vec![16, 1, 2, 3], vec![96, 1, 2, 3]]).unwrap();

    let sum = ring.add(&a, &b).unwrap();
    assert_eq!(sum.coeffs()[0], vec![0, 3, 5, 7]);
    assert_eq!(sum.coeffs()[1], vec![4, 7, 9, 11]);

    let diff = ring.sub(&a, &b).unwrap();
    assert_eq!(diff.coeffs()[0], vec![2, 1, 1, 1]);
    assert_eq!(diff.coeffs()[1], vec![6, 5, 5, 5]);

    let neg = ring.neg(&a).unwrap();
    assert_eq!(neg.coeffs()[0], vec![16, 15, 14, 13]);

    let scaled = ring.scalar_mul(&a, 3).unwrap();
    assert_eq!(scaled.coeffs()[0], vec![3, 6, 9, 12]);
    assert_eq!(scaled.coeffs()[1], vec![15, 18, 21, 24]);
}

#[test]
fn schoolbook_negacyclic_multiplication_matches_manual_case() {
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    let x3 = Poly::from_coeffs(vec![vec![0, 0, 0, 1]]).unwrap();
    let x = Poly::from_coeffs(vec![vec![0, 1, 0, 0]]).unwrap();

    let product = ring.schoolbook_mul(&x3, &x).unwrap();

    // x^3 * x = x^4 = -1 in Z_q[X] / (X^4 + 1).
    assert_eq!(product.coeffs()[0], vec![16, 0, 0, 0]);
}

#[test]
fn ntt_round_trip_returns_original() {
    let ring = test_ring();
    let mut poly = Poly::from_coeffs(vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]).unwrap();
    let original = poly.clone();
    let backend = CpuNttBackend;

    backend.forward(&ring, &mut poly).unwrap();
    backend.inverse(&ring, &mut poly).unwrap();

    assert_eq!(poly, original);
}

#[test]
fn ntt_multiplication_matches_schoolbook() {
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    let a = Poly::from_coeffs(vec![vec![1, 2, 3, 4]]).unwrap();
    let b = Poly::from_coeffs(vec![vec![4, 1, 2, 3]]).unwrap();
    let expected = ring.schoolbook_mul(&a, &b).unwrap();

    let backend = CpuNttBackend;
    let mut a_ntt = a.clone();
    let mut b_ntt = b.clone();
    backend.forward(&ring, &mut a_ntt).unwrap();
    backend.forward(&ring, &mut b_ntt).unwrap();

    let mut product = ring.coeffwise_mul(&a_ntt, &b_ntt).unwrap();
    backend.inverse(&ring, &mut product).unwrap();

    assert_eq!(product, expected);
}

#[test]
fn ntt_round_trip_and_multiplication_hold_across_degrees_and_moduli() {
    // The degree-4 cases above are hand-traceable but too small to catch
    // indexing bugs that only surface with more than one radix-2 butterfly
    // stage. Every (degree, modulus) pair here needs modulus = 1 (mod 2*degree).
    let cases: [(usize, u64); 6] = [
        (4, 17),
        (8, 97),
        (16, 193),
        (32, 257),
        (64, 769),
        (128, 3329),
    ];

    let backend = CpuNttBackend;
    let mut rng = ChaCha20Rng::from_seed([23u8; 32]);

    for (degree, modulus) in cases {
        let ring = Ring::new_ntt(
            Degree::new(degree).unwrap(),
            vec![Modulus::new(modulus).unwrap()],
        )
        .unwrap();

        for _ in 0..10 {
            let coeffs: Vec<u64> = (0..degree).map(|_| rng.next_u64() % modulus).collect();
            let poly = Poly::from_coeffs(vec![coeffs]).unwrap();

            // Round trip.
            let mut transformed = poly.clone();
            backend.forward(&ring, &mut transformed).unwrap();
            backend.inverse(&ring, &mut transformed).unwrap();
            assert_eq!(
                transformed, poly,
                "round trip failed at degree={degree}, modulus={modulus}"
            );

            // NTT-based multiplication vs. independent schoolbook multiplication.
            let other_coeffs: Vec<u64> = (0..degree).map(|_| rng.next_u64() % modulus).collect();
            let other = Poly::from_coeffs(vec![other_coeffs]).unwrap();
            let expected = ring.schoolbook_mul(&poly, &other).unwrap();

            let mut a_ntt = poly.clone();
            let mut b_ntt = other.clone();
            backend.forward(&ring, &mut a_ntt).unwrap();
            backend.forward(&ring, &mut b_ntt).unwrap();
            let mut product = ring.coeffwise_mul(&a_ntt, &b_ntt).unwrap();
            backend.inverse(&ring, &mut product).unwrap();

            assert_eq!(
                product, expected,
                "NTT multiplication != schoolbook at degree={degree}, modulus={modulus}"
            );
        }
    }
}

#[test]
fn ring_mul_matches_schoolbook_when_ntt_is_supported() {
    let cases: [(usize, u64); 6] = [
        (4, 17),
        (8, 97),
        (16, 193),
        (32, 257),
        (64, 769),
        (128, 3329),
    ];
    let mut rng = ChaCha20Rng::from_seed([29u8; 32]);

    for (degree, modulus) in cases {
        let ring = Ring::new_ntt(
            Degree::new(degree).unwrap(),
            vec![Modulus::new(modulus).unwrap()],
        )
        .unwrap();

        for _ in 0..10 {
            let a_coeffs: Vec<u64> = (0..degree).map(|_| rng.next_u64() % modulus).collect();
            let b_coeffs: Vec<u64> = (0..degree).map(|_| rng.next_u64() % modulus).collect();
            let a = Poly::from_coeffs(vec![a_coeffs]).unwrap();
            let b = Poly::from_coeffs(vec![b_coeffs]).unwrap();

            let expected = ring.schoolbook_mul(&a, &b).unwrap();
            let actual = ring.mul(&a, &b).unwrap();
            assert_eq!(
                actual, expected,
                "mul != schoolbook_mul at degree={degree}, modulus={modulus}"
            );
        }
    }
}

#[test]
fn ring_mul_falls_back_to_schoolbook_when_ntt_is_unsupported() {
    // modulus=23 does not satisfy (q-1) % (2*degree) == 0 for degree=4
    // ((23-1)=22, 22 % 8 = 6 != 0), so Ring::new (not new_ntt) accepts it
    // but mul has no NTT table to use for this modulus.
    let degree = Degree::new(4).unwrap();
    let modulus = Modulus::new(23).unwrap();
    assert!(!modulus.supports_ntt(degree.get()));
    let ring = Ring::new(degree, vec![modulus]).unwrap();

    let a = Poly::from_coeffs(vec![vec![1, 2, 3, 4]]).unwrap();
    let b = Poly::from_coeffs(vec![vec![5, 6, 7, 8]]).unwrap();

    let expected = ring.schoolbook_mul(&a, &b).unwrap();
    let actual = ring.mul(&a, &b).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn ring_mul_is_correct_even_for_unreduced_coefficients() {
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    let huge = u64::MAX - 1;
    let a = Poly::from_coeffs(vec![vec![huge, 5, huge, 2]]).unwrap();
    let b = Poly::from_coeffs(vec![vec![3, huge, 1, huge]]).unwrap();

    let expected = ring.schoolbook_mul(&a, &b).unwrap();
    let actual = ring.mul(&a, &b).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn ring_multiplication_is_correct_even_for_unreduced_coefficients() {
    // Poly's type does not enforce coefficients < modulus; Ring's multiplication
    // hot paths (which now route through BarrettReducer, valid only for already-
    // reduced operands) must stay correct regardless, falling back for anything
    // out of range rather than silently producing a wrong result.
    let ring = Ring::new(Degree::new(2).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    let huge = u64::MAX - 1; // far outside [0, 17), and (huge as u128)^2 >> 17^2
    let a = Poly::from_coeffs(vec![vec![huge, 5]]).unwrap();
    let b = Poly::from_coeffs(vec![vec![3, huge]]).unwrap();

    let product = ring.coeffwise_mul(&a, &b).unwrap();
    assert_eq!(product.coeffs()[0][0], mul_mod(huge, 3, 17));
    assert_eq!(product.coeffs()[0][1], mul_mod(5, huge, 17));

    // schoolbook_mul routes through the same mul_residue helper via a different path;
    // check it against the negacyclic formula computed with the unconditionally-correct
    // free functions: (a0+a1X)(b0+b1X) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)X, mod X^2=-1.
    let school = ring.schoolbook_mul(&a, &b).unwrap();
    let expected_c0 = sub_mod(mul_mod(huge, 3, 17), mul_mod(5, huge, 17), 17);
    let expected_c1 = add_mod(mul_mod(huge, huge, 17), mul_mod(5, 3, 17), 17);
    assert_eq!(school.coeffs()[0][0], expected_c0);
    assert_eq!(school.coeffs()[0][1], expected_c1);

    let scaled = ring.scalar_mul(&a, huge).unwrap();
    assert_eq!(scaled.coeffs()[0][0], mul_mod(huge, huge % 17, 17));
    assert_eq!(scaled.coeffs()[0][1], mul_mod(5, huge % 17, 17));
}

#[test]
fn crt_reconstructs_and_extends_basis() {
    let source = RnsBasis::new(vec![Modulus::new(17).unwrap(), Modulus::new(97).unwrap()]).unwrap();
    let target = RnsBasis::new(vec![
        Modulus::new(17).unwrap(),
        Modulus::new(97).unwrap(),
        Modulus::new(193).unwrap(),
    ])
    .unwrap();
    let value = 1234u128;
    let residues = decompose_value(value, &source);

    assert_eq!(reconstruct_residue(&residues, &source).unwrap(), value);

    let poly = Poly::from_coeffs(vec![vec![1, residues[0]], vec![1, residues[1]]]).unwrap();
    let reconstructed = reconstruct_poly(&poly, &source).unwrap();
    assert_eq!(reconstructed, vec![1, value]);

    let extended = extend_basis(&poly, &source, &target).unwrap();
    assert_eq!(extended.coeffs()[2], vec![1, (value % 193) as u64]);
}

#[test]
fn extend_basis_is_exact_for_a_realistic_multi_prime_basis_that_overflows_u128() {
    // 8 distinct ~61-bit primes: a realistic RNS-CKKS/BGV source basis size.
    // Their product is ~489 bits, far beyond u128 (128 bits) - this is
    // exactly the scenario the old u128-based reconstruction silently
    // overflowed on. All expected values below were computed independently
    // in Python (arbitrary-precision integers, hand-rolled Miller-Rabin for
    // primality - no dependency on this crate or its BigUint), not derived
    // from this crate's own output.
    let source_moduli = [
        2305843009213693967u64,
        2305843009213693973,
        2305843009213694009,
        2305843009213694017,
        2305843009213694087,
        2305843009213694149,
        2305843009213694173,
        2305843009213694207,
    ];
    let source = RnsBasis::new(
        source_moduli
            .iter()
            .map(|&q| Modulus::new(q).unwrap())
            .collect(),
    )
    .unwrap();
    let target = RnsBasis::new(vec![
        Modulus::new(1_048_583).unwrap(),     // target_modulus
        Modulus::new(1_073_741_827).unwrap(), // target_modulus2
    ])
    .unwrap();

    // v0 = 123456789012345678901234567890123456789012345 (147 bits, > u128::MAX)
    let r0 = [
        342893574864583285u64,
        959742221355242309,
        49148116979906131,
        1640227331347129390,
        1150651776253986770,
        1375840191547803060,
        1537391981174416543,
        1958410646369059455,
    ];
    // v1 = 42 (small value, sanity check the same machinery on a trivial case)
    let r1 = [42u64; 8];

    let poly = Poly::from_coeffs(vec![
        vec![r0[0], r1[0]],
        vec![r0[1], r1[1]],
        vec![r0[2], r1[2]],
        vec![r0[3], r1[3]],
        vec![r0[4], r1[4]],
        vec![r0[5], r1[5]],
        vec![r0[6], r1[6]],
        vec![r0[7], r1[7]],
    ])
    .unwrap();

    let extended = extend_basis(&poly, &source, &target).unwrap();

    assert_eq!(extended.coeffs()[0], vec![844_573, 42]);
    assert_eq!(extended.coeffs()[1], vec![1_010_884_516, 42]);
}

#[test]
fn modulus_drop_removes_last_component() {
    let poly = Poly::from_coeffs(vec![vec![1, 2], vec![3, 4], vec![5, 6]]).unwrap();
    let dropped = drop_last_modulus(&poly).unwrap();

    assert_eq!(dropped.coeffs(), &[vec![1, 2], vec![3, 4]]);
}

#[test]
fn samplers_return_valid_dimensions_and_ranges() {
    let ring = test_ring();
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    let uniform = sample_uniform(&ring, &mut rng);
    let ternary = sample_ternary(&ring, &mut rng);
    let gaussian = sample_discrete_gaussian(&ring, &mut rng, 3.0);

    for poly in [&uniform, &ternary, &gaussian] {
        assert_eq!(poly.degree(), ring.degree());
        assert_eq!(poly.moduli_count(), ring.moduli().len());
        for (component, modulus) in poly.coeffs().iter().zip(ring.moduli()) {
            assert!(component.iter().all(|&x| x < modulus.value()));
        }
    }

    for (component, modulus) in ternary.coeffs().iter().zip(ring.moduli()) {
        let q = modulus.value();
        assert!(component.iter().all(|&x| x == 0 || x == 1 || x == q - 1));
    }
}

#[test]
fn ternary_and_gaussian_samples_are_crt_coherent_across_rns_components() {
    // Regression test for a real bug: sample_ternary/sample_discrete_gaussian
    // used to draw an independent random choice per (RNS component,
    // coefficient) pair rather than one true value per coefficient reduced
    // consistently into every component. That's invisible on a
    // single-modulus ring (nothing to be inconsistent with), but on this
    // ring's two moduli, a coefficient's true CRT-reconstructed value must
    // land in {0, 1, product-1} for ternary (not some unrelated residue that
    // happens to satisfy each component's own range check independently),
    // and within the Gaussian's tail cut for the error sampler.
    let ring = test_ring();
    let basis = RnsBasis::new(ring.moduli().to_vec()).unwrap();
    let product: u128 = ring.moduli().iter().map(|m| m.value() as u128).product();
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);

    let ternary = sample_ternary(&ring, &mut rng);
    let reconstructed = reconstruct_poly(&ternary, &basis).unwrap();
    for &value in &reconstructed {
        assert!(
            value == 0 || value == 1 || value == product - 1,
            "ternary coefficient reconstructed to {value}, not in {{0, 1, {}}} - components are not CRT-coherent",
            product - 1
        );
    }

    let sigma = 3.2;
    let tail_cut = 6.0f64;
    let bound = (sigma * tail_cut).ceil() as u128;
    let gaussian = sample_discrete_gaussian(&ring, &mut rng, sigma);
    let reconstructed = reconstruct_poly(&gaussian, &basis).unwrap();
    for &value in &reconstructed {
        let centered = value.min(product - value);
        assert!(
            centered <= bound,
            "gaussian coefficient reconstructed to {value} (centered {centered}), outside the tail-cut bound {bound} - components are not CRT-coherent"
        );
    }
}

#[test]
fn barrett_matches_naive_reduction_exhaustively_for_small_moduli() {
    for modulus in (3u64..200).step_by(2) {
        let reducer = BarrettReducer::new(modulus).unwrap();
        let mut x = 0u128;
        let bound = modulus as u128 * modulus as u128;
        while x < bound {
            assert_eq!(
                reducer.reduce(x),
                (x % modulus as u128) as u64,
                "mismatch for modulus={modulus}, x={x}"
            );
            x += 1;
        }
    }
}

#[test]
fn barrett_matches_naive_reduction_for_random_large_moduli() {
    // Covers the full 64-bit modulus range, not just the old <2^32
    // restriction - this is exactly what changed: BarrettReducer now handles
    // realistic RNS-CKKS/BGV moduli (~40-60 bits), not just small ones.
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    for _ in 0..2000 {
        let modulus = rng.next_u64().max(2);
        let reducer = BarrettReducer::new(modulus).unwrap();
        let bound = modulus as u128 * modulus as u128;
        let x = (((rng.next_u64() as u128) << 64) | rng.next_u64() as u128) % bound;
        assert_eq!(
            reducer.reduce(x),
            (x % modulus as u128) as u64,
            "mismatch for modulus={modulus}, x={x}"
        );
    }
}

#[test]
fn barrett_matches_naive_reduction_for_realistic_ntt_friendly_primes() {
    // The ~61-bit primes also used in the large-basis extend_basis
    // regression test (crates/phantom-ring/tests/phase2.rs's own
    // extend_basis_is_exact_for_a_realistic_multi_prime_basis_that_overflows_u128) -
    // a realistic RNS-CKKS/BGV modulus size, previously far outside
    // BarrettReducer's <2^32 range.
    let primes: [u64; 4] = [
        2305843009213693951,
        2305843009213693907,
        2305843009213693881,
        2305843009213693829,
    ];
    let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
    for modulus in primes {
        let reducer = BarrettReducer::new(modulus).unwrap();
        for _ in 0..500 {
            let a = rng.next_u64() % modulus;
            let b = rng.next_u64() % modulus;
            let x = a as u128 * b as u128;
            assert_eq!(
                reducer.reduce(x),
                mul_mod(a, b, modulus),
                "mismatch for modulus={modulus}, a={a}, b={b}"
            );
        }
    }
}

#[test]
fn barrett_reduce_holds_up_to_modulus_times_2_pow_64_not_just_below_modulus_squared() {
    // BarrettReducer's doc comment proves reduce is correct up to the wider
    // bound `value < modulus * 2^64` (not just `value < modulus^2`), since
    // that's exactly the bound under which the estimated quotient still fits
    // a u64. Exercise the gap between the two bounds directly - values here
    // are deliberately >= modulus^2 (the crate's normal precondition) but
    // still < modulus * 2^64. This does not call `reduce` outside its
    // documented precondition; it uses the wider one the doc comment proves.
    let mut rng = ChaCha20Rng::from_seed([29u8; 32]);
    for _ in 0..2000 {
        let modulus = rng.next_u64().max(2);
        let reducer = BarrettReducer::new(modulus).unwrap();
        let wide_bound = modulus as u128 * (1u128 << 64);
        let squared_bound = modulus as u128 * modulus as u128;
        // A value in [modulus^2, modulus*2^64) - always nonempty since
        // modulus < 2^64 implies modulus^2 < modulus*2^64.
        let span = wide_bound - squared_bound;
        let x = squared_bound + (((rng.next_u64() as u128) << 64) | rng.next_u64() as u128) % span;
        assert_eq!(
            reducer.reduce(x),
            (x % modulus as u128) as u64,
            "mismatch for modulus={modulus}, x={x} (x is in [modulus^2, modulus*2^64))"
        );
    }
}

#[test]
fn barrett_covers_boundary_values() {
    let modulus = 97u64;
    let reducer = BarrettReducer::new(modulus).unwrap();
    let m = modulus as u128;
    assert_eq!(reducer.reduce(0), 0);
    assert_eq!(reducer.reduce(m - 1), (m - 1) as u64 % modulus);
    assert_eq!(
        reducer.reduce((modulus - 1) as u128 * (modulus - 1) as u128),
        1
    ); // (m-1)^2 mod m == 1
    assert_eq!(reducer.reduce(m * m - 1), (m * m - 1) as u64 % modulus);
}

#[test]
fn barrett_rejects_modulus_too_small_but_accepts_the_full_64_bit_range() {
    assert!(BarrettReducer::new(0).is_err());
    assert!(BarrettReducer::new(1).is_err());
    assert!(BarrettReducer::new(2).is_ok());
    assert!(BarrettReducer::new(u64::MAX).is_ok());
}

#[test]
fn montgomery_mul_matches_naive_reduction_exhaustively_for_small_moduli() {
    for modulus in (3u64..200).step_by(2) {
        let reducer = MontgomeryReducer::new(modulus).unwrap();
        for a in 0..modulus {
            for b in 0..modulus {
                assert_eq!(
                    reducer.mul(a, b),
                    ((a as u128 * b as u128) % modulus as u128) as u64,
                    "mismatch for modulus={modulus}, a={a}, b={b}"
                );
            }
        }
    }
}

#[test]
fn montgomery_mul_matches_naive_reduction_for_random_large_moduli() {
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    for _ in 0..5000 {
        let modulus = (rng.next_u64() % (MONTGOMERY_MAX_MODULUS - 3)) | 1;
        let modulus = modulus.max(3);
        let reducer = MontgomeryReducer::new(modulus).unwrap();
        let a = rng.next_u64() % modulus;
        let b = rng.next_u64() % modulus;
        assert_eq!(
            reducer.mul(a, b),
            ((a as u128 * b as u128) % modulus as u128) as u64,
            "mismatch for modulus={modulus}, a={a}, b={b}"
        );
    }
}

#[test]
fn montgomery_round_trip_preserves_value() {
    let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
    for _ in 0..2000 {
        let modulus = (rng.next_u64() % (MONTGOMERY_MAX_MODULUS - 3)) | 1;
        let modulus = modulus.max(3);
        let reducer = MontgomeryReducer::new(modulus).unwrap();
        let a = rng.next_u64() % modulus;
        let mont = reducer.to_montgomery(a);
        assert_eq!(
            reducer.from_montgomery(mont),
            a,
            "round trip failed for modulus={modulus}, a={a}"
        );
    }
}

#[test]
fn montgomery_rejects_invalid_moduli() {
    assert!(MontgomeryReducer::new(0).is_err());
    assert!(MontgomeryReducer::new(4).is_err()); // even
    assert!(MontgomeryReducer::new(MONTGOMERY_MAX_MODULUS).is_err());
    assert!(MontgomeryReducer::new(MONTGOMERY_MAX_MODULUS - 1).is_ok());
}
