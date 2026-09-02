//! Real (encrypted) BFV polynomial evaluation:
//! `PolynomialEvaluator::evaluate_real`, mirroring
//! `bgv_real_polynomial.rs`'s own coverage - see that method's own doc
//! comment for the algorithm and the differences from BGV's version.

use phantom_circuits::bfv::PolynomialEvaluator;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bfv::{BfvContext, BfvParams};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DEGREE: usize = 8;
const MODULUS: u64 = 1_000_000_000_000_037;
const T: u64 = 17;
const P1: u64 = 1_000_000_000_000_091;
const P2: u64 = 1_000_000_000_000_159;

fn params() -> BfvParams {
    BfvParams::new(
        Ring::new(
            Degree::new(DEGREE).unwrap(),
            vec![Modulus::new(MODULUS).unwrap()],
        )
        .unwrap(),
        T,
    )
    .unwrap()
}

fn p_moduli() -> Vec<Modulus> {
    vec![Modulus::new(P1).unwrap(), Modulus::new(P2).unwrap()]
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn eval_poly_mod_t(coefficients: &[u64], x: u64, t: u64) -> u64 {
    coefficients
        .iter()
        .rev()
        .fold(0u64, |acc, &c| (acc * x + c % t) % t)
}

#[test]
fn evaluate_real_computes_a_quadratic_polynomial_on_a_real_ciphertext() {
    let ctx = BfvContext::new(params());
    let mut rng = seeded_rng(91);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let p_moduli = p_moduli();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();

    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = PolynomialEvaluator::new(params()).unwrap();

    // p(x) = 5 - 2x + 3x^2 mod 17 (-2 mod 17 = 15)
    let coefficients = [5u64, 15, 3];
    let x_values: Vec<u64> = (0..DEGREE as u64).map(|i| (i * 3 + 1) % T).collect();
    let x_pt = encoder.encode_batched(&x_values).unwrap();
    let x_ct = encryptor.encrypt(&x_pt, &mut rng).unwrap();

    let result = evaluator
        .evaluate_real(&x_ct, &coefficients, &relin_key, &p_moduli)
        .unwrap();
    assert_eq!(result.degree(), 1);

    let decoded = encoder
        .decode_batched_real(&decryptor.decrypt(&result).unwrap())
        .unwrap();
    let expected: Vec<u64> = x_values
        .iter()
        .map(|&x| eval_poly_mod_t(&coefficients, x, T))
        .collect();
    assert_eq!(decoded, expected);
}

#[test]
fn evaluate_real_computes_a_linear_polynomial_with_one_multiplication() {
    let ctx = BfvContext::new(params());
    let mut rng = seeded_rng(93);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let p_moduli = p_moduli();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();

    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = PolynomialEvaluator::new(params()).unwrap();

    let coefficients = [4u64, 6]; // p(x) = 4 + 6x
    let x_values: Vec<u64> = (0..DEGREE as u64).map(|i| (2 * i + 1) % T).collect();
    let x_pt = encoder.encode_batched(&x_values).unwrap();
    let x_ct = encryptor.encrypt(&x_pt, &mut rng).unwrap();

    let result = evaluator
        .evaluate_real(&x_ct, &coefficients, &relin_key, &p_moduli)
        .unwrap();
    let decoded = encoder
        .decode_batched_real(&decryptor.decrypt(&result).unwrap())
        .unwrap();
    let expected: Vec<u64> = x_values
        .iter()
        .map(|&x| eval_poly_mod_t(&coefficients, x, T))
        .collect();
    assert_eq!(decoded, expected);
}

#[test]
fn evaluate_real_rejects_a_degree_zero_polynomial() {
    let ctx = BfvContext::new(params());
    let mut rng = seeded_rng(97);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let p_moduli = p_moduli();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();

    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret);
    let evaluator = PolynomialEvaluator::new(params()).unwrap();

    let x_pt = encoder.encode_batched(&[1]).unwrap();
    let x_ct = encryptor.encrypt(&x_pt, &mut rng).unwrap();

    assert!(evaluator
        .evaluate_real(&x_ct, &[3], &relin_key, &p_moduli)
        .is_err());
}
