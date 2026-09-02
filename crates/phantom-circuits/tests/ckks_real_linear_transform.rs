//! Real (encrypted) CKKS linear transforms:
//! `LinearTransformEvaluator::apply_real` - the diagonal-method
//! rotate/multiply/accumulate evaluator built on `phantom-schemes`'s real
//! `rotate_real`/`mul_plain_real`/`add_real` primitives. See that method's
//! own doc comment for the algorithm.

use phantom_circuits::ckks::LinearTransformEvaluator;
use phantom_circuits::common::{Diagonal, DiagonalMatrix, LinearTransform};
use phantom_ring::Modulus;
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DEGREE: usize = 8;
const Q0: u64 = 1_000_000_000_000_037;
const Q1: u64 = 1_073_741_827;
const SCALE_BITS: u32 = 30;

const P1: u64 = 1_000_000_000_000_091;
const P2: u64 = 1_000_000_000_000_159;

fn params() -> CkksParams {
    CkksParams::builder()
        .degree(DEGREE)
        .moduli(vec![Q0, Q1])
        .default_scale_bits(SCALE_BITS)
        .build()
        .unwrap()
}

fn p_moduli() -> Vec<Modulus> {
    vec![Modulus::new(P1).unwrap(), Modulus::new(P2).unwrap()]
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn assert_close(actual: &[Complex64], expected: &[Complex64], tol: f64) {
    assert_eq!(actual.len(), expected.len());
    for (a, e) in actual.iter().zip(expected) {
        assert!(
            (a.re - e.re).abs() < tol && (a.im - e.im).abs() < tol,
            "actual={a:?} expected={e:?} tol={tol}"
        );
    }
}

/// Galois keys for every offset a `DiagonalMatrix` actually needs (skipping
/// offset `0`, which `apply_real` never rotates for).
fn galois_keys_for(
    keygen: &phantom_schemes::ckks::CkksKeyGenerator,
    sk: &phantom_lattice::rlwe::SecretKey,
    params: &CkksParams,
    diagonals: &DiagonalMatrix<Complex64>,
    rng: &mut ChaCha20Rng,
) -> Vec<phantom_lattice::rlwe::GaloisKey> {
    diagonals
        .diagonals()
        .iter()
        .filter(|d| d.offset() != 0)
        .map(|d| {
            let element = params.rotation_element(d.offset());
            keygen
                .generate_hybrid_galois_key(element, sk, &p_moduli(), rng)
                .unwrap()
        })
        .collect()
}

fn dense_matrix_vector(rows: &[Vec<Complex64>], x: &[Complex64]) -> Vec<Complex64> {
    rows.iter()
        .map(|row| {
            row.iter()
                .zip(x)
                .fold(Complex64::default(), |acc, (&w, &v)| acc + w * v)
        })
        .collect()
}

#[test]
fn apply_real_computes_a_dense_random_matrix_vector_product() {
    let ctx = CkksContext::new(params());
    let mut rng = seeded_rng(51);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = LinearTransformEvaluator::new(params());

    let n = encoder.slot_count();
    // A dense, not diagonal-sparse, matrix - exercises every rotation
    // offset from 0 to n-1 in one test.
    let rows: Vec<Vec<Complex64>> = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| Complex64::new((i + 1) as f64, -((j + 1) as f64) * 0.5))
                .collect()
        })
        .collect();
    let transform = LinearTransform::dense(rows.clone()).unwrap();
    let diagonals = evaluator.diagonalize(&transform).unwrap();
    assert_eq!(diagonals.diagonals().len(), n);

    let x_values: Vec<Complex64> = (0..n)
        .map(|i| Complex64::new(i as f64 - 1.5, 0.25 * i as f64))
        .collect();
    let x_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&x_values).unwrap(), &mut rng)
        .unwrap();

    let galois_keys = galois_keys_for(&keygen, &keys.secret, &params(), &diagonals, &mut rng);

    let result = evaluator
        .apply_real(&x_ct, &diagonals, &galois_keys)
        .unwrap();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&result).unwrap())
        .unwrap();

    let expected = dense_matrix_vector(&rows, &x_values);
    assert_close(&decoded, &expected, 1e-2);
}

#[test]
fn apply_real_matches_rotate_real_for_a_pure_permutation() {
    let ctx = CkksContext::new(params());
    let mut rng = seeded_rng(53);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = LinearTransformEvaluator::new(params());

    let n = encoder.slot_count();
    let shift = 2usize;
    let transform = LinearTransform::slot_permutation(
        n,
        shift as isize,
        Complex64::default(),
        Complex64::real(1.0),
    )
    .unwrap();
    let diagonals = evaluator.diagonalize(&transform).unwrap();
    // A pure cyclic rotation has exactly one nonzero diagonal.
    assert_eq!(diagonals.diagonals().len(), 1);
    assert_eq!(diagonals.diagonals()[0].offset(), shift);

    let x_values: Vec<Complex64> = (0..n).map(|i| Complex64::real((i + 1) as f64)).collect();
    let x_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&x_values).unwrap(), &mut rng)
        .unwrap();

    let galois_keys = galois_keys_for(&keygen, &keys.secret, &params(), &diagonals, &mut rng);
    let result = evaluator
        .apply_real(&x_ct, &diagonals, &galois_keys)
        .unwrap();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&result).unwrap())
        .unwrap();

    let mut expected = x_values.clone();
    expected.rotate_left(shift);
    assert_close(&decoded, &expected, 1e-4);
}

#[test]
fn apply_real_rejects_a_missing_galois_key() {
    let ctx = CkksContext::new(params());
    let mut rng = seeded_rng(55);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let evaluator = LinearTransformEvaluator::new(params());

    let n = encoder.slot_count();
    let transform =
        LinearTransform::slot_permutation(n, 1, Complex64::default(), Complex64::real(1.0))
            .unwrap();
    let diagonals = evaluator.diagonalize(&transform).unwrap();

    let x_values: Vec<Complex64> = vec![Complex64::real(1.0); n];
    let x_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&x_values).unwrap(), &mut rng)
        .unwrap();

    assert!(evaluator.apply_real(&x_ct, &diagonals, &[]).is_err());
}

#[test]
fn apply_real_rejects_mismatched_slot_counts() {
    let evaluator = LinearTransformEvaluator::new(params());
    let bad = DiagonalMatrix::new(
        1,
        vec![Diagonal::new(0, vec![Complex64::real(1.0)]).unwrap()],
    )
    .unwrap();

    let ctx = CkksContext::new(params());
    let mut rng = seeded_rng(57);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret);
    let x_ct = encryptor
        .encrypt_real(
            &encoder
                .encode_complex_real(&vec![Complex64::real(1.0); encoder.slot_count()])
                .unwrap(),
            &mut rng,
        )
        .unwrap();

    assert!(evaluator.apply_real(&x_ct, &bad, &[]).is_err());
}
