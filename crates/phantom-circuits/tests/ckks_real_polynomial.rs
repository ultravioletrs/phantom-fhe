//! Real (encrypted) CKKS polynomial evaluation (Workstream 6 item 2/3):
//! `PolynomialEvaluator::evaluate_encrypted`, the first `phantom-circuits`
//! evaluator wired to CKKS's real arithmetic path rather than the
//! transparent scaffold - see that method's own doc comment for the
//! Horner-method algorithm and the real-path gaps
//! (`Evaluator::drop_level_real`, `Scale::compatible`'s tolerance,
//! `mul_plain_real`, and finally `CkksKeyGenerator::
//! generate_hybrid_relinearization_key_at_level`) this codebase's own
//! earlier scoping work - and building this evaluator itself - found and
//! fixed to make it possible.

use phantom_circuits::ckks::PolynomialEvaluator;
use phantom_ring::Modulus;
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

// One large "headroom" modulus (survives every rescale, providing enough
// room for the raw tensor product at each multiplication step) plus three
// moduli each close to 2^SCALE_BITS (dropped one per Horner step, in
// order) - a degree-3 polynomial needs 3 multiplicative levels, i.e. 4
// moduli total. All four Miller-Rabin verified distinct primes in Python
// before use.
const DEGREE: usize = 8;
const Q0: u64 = 4_611_686_018_427_400_249;
const RESCALE_A: u64 = 1_073_741_827;
const RESCALE_B: u64 = 1_073_741_831;
const RESCALE_C: u64 = 1_073_741_833;
const SCALE_BITS: u32 = 30;

const P1: u64 = 4_611_686_018_428_388_057;
const P2: u64 = 4_611_686_018_428_388_089;

fn params() -> CkksParams {
    CkksParams::builder()
        .degree(DEGREE)
        .moduli(vec![Q0, RESCALE_A, RESCALE_B, RESCALE_C])
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

fn eval_poly(coefficients: &[f64], x: f64) -> f64 {
    coefficients.iter().rev().fold(0.0, |acc, &c| acc * x + c)
}

/// Pads `values` up to `slot_count` with zeros, matching exactly what
/// `Encoder::encode_complex_real` does internally - `decode_complex_real`
/// always returns `slot_count` values, so a real round trip's "expected"
/// vector needs the same padding (evaluated through the polynomial, not
/// left as zero, since `p(0)` is generally `coefficients[0]`, not `0`).
fn padded_expected(
    coefficients: &[f64],
    x_values: &[Complex64],
    slot_count: usize,
) -> Vec<Complex64> {
    let mut out: Vec<Complex64> = x_values
        .iter()
        .map(|x| Complex64::real(eval_poly(coefficients, x.re)))
        .collect();
    out.resize(slot_count, Complex64::real(eval_poly(coefficients, 0.0)));
    out
}

/// Generates one relinearization key per level from `0` to `top_level`
/// (inclusive), indexed by level - `relin_keys[level]` is only valid for
/// relinearizing a ciphertext at that exact level (see
/// `CkksKeyGenerator::generate_hybrid_relinearization_key_at_level`'s own
/// doc comment for why a single top-level key isn't reusable at lower
/// levels).
fn relin_keys_per_level(
    keygen: &phantom_schemes::ckks::CkksKeyGenerator,
    sk: &phantom_lattice::rlwe::SecretKey,
    top_level: usize,
    rng: &mut ChaCha20Rng,
) -> Vec<phantom_lattice::rlwe::RelinearizationKey> {
    (0..=top_level)
        .map(|level| {
            keygen
                .generate_hybrid_relinearization_key_at_level(sk, level, &p_moduli(), rng)
                .unwrap()
        })
        .collect()
}

#[test]
fn evaluate_encrypted_computes_a_cubic_polynomial_on_a_real_ciphertext() {
    let ctx = CkksContext::new(params());
    let mut rng = seeded_rng(41);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();

    let evaluator = PolynomialEvaluator::new(params());

    // p(x) = 2 - x + 3x^2 - 0.5x^3 - a real cubic, not a trivial monomial,
    // exercising every add_plain_real step with a genuinely different
    // coefficient each time.
    let coefficients = [2.0, -1.0, 3.0, -0.5];

    let x_values: Vec<Complex64> = vec![
        Complex64::real(1.5),
        Complex64::real(-2.0),
        Complex64::real(0.25),
        Complex64::real(3.0),
    ];
    let x_pt = encoder.encode_complex_real(&x_values).unwrap();
    let x_ct = encryptor.encrypt_real(&x_pt, &mut rng).unwrap();
    assert_eq!(x_ct.level(), 3);

    let relin_keys = relin_keys_per_level(&keygen, &keys.secret, x_ct.level(), &mut rng);

    let result = evaluator
        .evaluate_encrypted(&x_ct, &coefficients, &relin_keys)
        .unwrap();
    assert_eq!(result.level(), 0);

    let decrypted = decryptor.decrypt_real(&result).unwrap();
    let decoded = encoder.decode_complex_real(&decrypted).unwrap();

    let expected = padded_expected(&coefficients, &x_values, encoder.slot_count());
    assert_close(&decoded, &expected, 1e-2);
}

#[test]
fn evaluate_encrypted_computes_a_linear_polynomial_with_one_level() {
    let ctx = CkksContext::new(params());
    let mut rng = seeded_rng(43);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();

    let evaluator = PolynomialEvaluator::new(params());
    let coefficients = [5.0, -3.0]; // p(x) = 5 - 3x, degree 1

    let x_values: Vec<Complex64> = vec![Complex64::real(2.0), Complex64::real(-1.0)];
    let x_pt = encoder.encode_complex_real(&x_values).unwrap();
    let x_ct = encryptor.encrypt_real(&x_pt, &mut rng).unwrap();

    // A linear polynomial never actually calls relinearize_real (see
    // evaluate_encrypted's own doc comment: the loop is empty for
    // degree==1), but every level from 0 to x_ct.level() is still
    // required by the signature's own contract - generate them anyway,
    // matching what any real caller would do without special-casing.
    let relin_keys = relin_keys_per_level(&keygen, &keys.secret, x_ct.level(), &mut rng);

    let result = evaluator
        .evaluate_encrypted(&x_ct, &coefficients, &relin_keys)
        .unwrap();
    assert_eq!(result.level(), x_ct.level() - 1);

    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&result).unwrap())
        .unwrap();
    let expected = padded_expected(&coefficients, &x_values, encoder.slot_count());
    assert_close(&decoded, &expected, 1e-4);
}

#[test]
fn evaluate_encrypted_rejects_a_degree_zero_polynomial_and_too_few_levels() {
    let ctx = CkksContext::new(params());
    let mut rng = seeded_rng(47);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());

    let evaluator = PolynomialEvaluator::new(params());
    let x_pt = encoder
        .encode_complex_real(&[Complex64::real(1.0)])
        .unwrap();
    let x_ct = encryptor.encrypt_real(&x_pt, &mut rng).unwrap();

    let relin_keys = relin_keys_per_level(&keygen, &keys.secret, x_ct.level(), &mut rng);

    assert!(evaluator
        .evaluate_encrypted(&x_ct, &[3.0], &relin_keys)
        .is_err());

    // 5 coefficients need degree=4 levels, but x_ct only has level()==3.
    assert!(evaluator
        .evaluate_encrypted(&x_ct, &[1.0, 1.0, 1.0, 1.0, 1.0], &relin_keys)
        .is_err());
}
