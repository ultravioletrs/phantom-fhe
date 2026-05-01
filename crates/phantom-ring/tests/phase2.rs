use phantom_ring::ntt::{CpuNttBackend, NttBackend};
use phantom_ring::reduce::{add_mod, mul_mod, neg_mod, sub_mod};
use phantom_ring::rns::crt::{decompose_value, reconstruct_poly, reconstruct_residue};
use phantom_ring::rns::extension::extend_basis;
use phantom_ring::rns::rescale::drop_last_modulus;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary, sample_uniform};
use phantom_ring::{Degree, Modulus, Poly, Ring, RnsBasis};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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
    let gaussian = sample_discrete_gaussian(&ring, &mut rng, 3);

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
