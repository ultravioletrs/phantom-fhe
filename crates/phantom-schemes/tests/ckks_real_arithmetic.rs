//! Tests for CKKS's real ciphertext/encryption/arithmetic path
//! (`Ciphertext::poly`, `Encryptor::encrypt_real`, `Decryptor::decrypt_real`,
//! `Evaluator::{add,sub,neg,add_plain,mul,relinearize,rescale_next}_real` -
//! the rest of Workstream 5 item 3/4, on top of the real canonical-embedding
//! encoder `ckks_real_encoding.rs` already covers). Complements
//! `phase7_ckks.rs`'s coverage of the still-transparent scaffold, which
//! this doesn't touch.

use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Two-modulus ring: `REAL_MODULUS` (large, stays after rescale) and
// `RESCALE_MODULUS` (the dropped modulus, chosen close to `2^SCALE_BITS` -
// the standard RNS-CKKS convention that keeps the tracked scale close to
// `default_scale` across a rescale, matching how `Evaluator::rescale_next`'s
// own transparent scaffold already assumes this - see its own doc comment).
// Both primes Miller-Rabin verified in Python before use.
const REAL_DEGREE: usize = 8;
const REAL_MODULUS: u64 = 1_000_000_000_000_037;
const RESCALE_MODULUS: u64 = 1_073_741_827;
const SCALE_BITS: u32 = 30;

fn real_arith_params() -> CkksParams {
    CkksParams::builder()
        .degree(REAL_DEGREE)
        .moduli(vec![REAL_MODULUS, RESCALE_MODULUS])
        .default_scale_bits(SCALE_BITS)
        .build()
        .unwrap()
}

// Auxiliary "P" moduli for the real hybrid relinearization key - same
// role/sizing as BFV's own `p_moduli()` (`phase6_bfv.rs`), reusing the same
// verified-prime pair for consistency.
const P1: u64 = 1_000_000_000_000_091;
const P2: u64 = 1_000_000_000_000_159;

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

fn sample_values(encoder: &phantom_schemes::ckks::Encoder, seed: u8) -> Vec<Complex64> {
    let mut rng = seeded_rng(seed);
    (0..encoder.slot_count())
        .map(|_| {
            Complex64::new(
                random_range(&mut rng, -5.0, 5.0),
                random_range(&mut rng, -5.0, 5.0),
            )
        })
        .collect()
}

fn random_range(rng: &mut ChaCha20Rng, low: f64, high: f64) -> f64 {
    use rand_core::RngCore;
    let unit = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
    low + unit * (high - low)
}

#[test]
fn real_secret_key_round_trip_recovers_approximate_values() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(1);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret).unwrap();

    let values = sample_values(&encoder, 2);
    let pt = encoder.encode_complex_real(&values).unwrap();
    let ct = encryptor.encrypt_real(&pt, &mut rng).unwrap();
    assert!(ct.poly().is_some());
    assert!(ct.slots().is_empty());

    let decrypted = decryptor.decrypt_real(&ct).unwrap();
    let decoded = encoder.decode_complex_real(&decrypted).unwrap();
    assert_close(&decoded, &values, 1e-6);
}

#[test]
fn real_public_key_round_trip_recovers_approximate_values() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(3);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(keys.public);
    let decryptor = ctx.real_decryptor(keys.secret).unwrap();

    let values = sample_values(&encoder, 4);
    let pt = encoder.encode_complex_real(&values).unwrap();
    let ct = encryptor.encrypt_real(&pt, &mut rng).unwrap();
    let decrypted = decryptor.decrypt_real(&ct).unwrap();
    let decoded = encoder.decode_complex_real(&decrypted).unwrap();
    assert_close(&decoded, &values, 1e-6);
}

#[test]
fn real_homomorphic_add_sub_neg_and_add_plain_are_approximate() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(5);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator();

    let a_values = sample_values(&encoder, 6);
    let b_values = sample_values(&encoder, 7);
    let a_pt = encoder.encode_complex_real(&a_values).unwrap();
    let b_pt = encoder.encode_complex_real(&b_values).unwrap();
    let a_ct = encryptor.encrypt_real(&a_pt, &mut rng).unwrap();
    let b_ct = encryptor.encrypt_real(&b_pt, &mut rng).unwrap();

    let sum = evaluator.add_real(&a_ct, &b_ct).unwrap();
    let expected_sum: Vec<Complex64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| *a + *b)
        .collect();
    let decoded_sum = encoder
        .decode_complex_real(&decryptor.decrypt_real(&sum).unwrap())
        .unwrap();
    assert_close(&decoded_sum, &expected_sum, 1e-6);

    let diff = evaluator.sub_real(&a_ct, &b_ct).unwrap();
    let expected_diff: Vec<Complex64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| *a - *b)
        .collect();
    let decoded_diff = encoder
        .decode_complex_real(&decryptor.decrypt_real(&diff).unwrap())
        .unwrap();
    assert_close(&decoded_diff, &expected_diff, 1e-6);

    let negated = evaluator.neg_real(&a_ct).unwrap();
    let expected_neg: Vec<Complex64> = a_values.iter().map(|a| -*a).collect();
    let decoded_neg = encoder
        .decode_complex_real(&decryptor.decrypt_real(&negated).unwrap())
        .unwrap();
    assert_close(&decoded_neg, &expected_neg, 1e-6);

    let added_plain = evaluator.add_plain_real(&a_ct, &b_pt).unwrap();
    let decoded_added_plain = encoder
        .decode_complex_real(&decryptor.decrypt_real(&added_plain).unwrap())
        .unwrap();
    assert_close(&decoded_added_plain, &expected_sum, 1e-6);
}

#[test]
fn real_raw_multiplication_without_relinearization_is_approximate() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(8);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator();

    let a_values = sample_values(&encoder, 9);
    let b_values = sample_values(&encoder, 10);
    let a_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&b_values).unwrap(), &mut rng)
        .unwrap();

    let product = evaluator.mul_real(&a_ct, &b_ct).unwrap();
    assert_eq!(product.degree(), 2);
    let expected: Vec<Complex64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| *a * *b)
        .collect();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&product).unwrap())
        .unwrap();
    assert_close(&decoded, &expected, 1e-4);
}

#[test]
fn real_relinearization_reduces_degree_and_preserves_the_product() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(11);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator();
    let keygen = ctx.keygen().unwrap();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli(), &mut rng)
        .unwrap();

    let a_values = sample_values(&encoder, 12);
    let b_values = sample_values(&encoder, 13);
    let a_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&b_values).unwrap(), &mut rng)
        .unwrap();

    let product = evaluator.mul_real(&a_ct, &b_ct).unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
    assert_eq!(relinearized.degree(), 1);

    let expected: Vec<Complex64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| *a * *b)
        .collect();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&relinearized).unwrap())
        .unwrap();
    assert_close(&decoded, &expected, 1e-4);
}

#[test]
fn real_rescale_after_multiplication_tracks_level_and_scale_and_preserves_the_product() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(14);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator();
    let keygen = ctx.keygen().unwrap();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli(), &mut rng)
        .unwrap();

    let a_values = sample_values(&encoder, 15);
    let b_values = sample_values(&encoder, 16);
    let a_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&b_values).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(a_ct.level(), 1);

    let product = evaluator.mul_real(&a_ct, &b_ct).unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
    let rescaled = evaluator.rescale_next_real(&relinearized).unwrap();
    assert_eq!(rescaled.level(), 0);
    // A multiplication squares the scale (Delta^2); rescaling by a modulus
    // close to Delta should bring it back close to the default scale again
    // - the whole point of choosing `RESCALE_MODULUS` close to `2^SCALE_BITS`
    // (see the module doc comment).
    let default_scale = ctx.params().default_scale().value();
    assert!((rescaled.scale().value() - default_scale).abs() < default_scale * 0.1);

    let expected: Vec<Complex64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| *a * *b)
        .collect();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&rescaled).unwrap())
        .unwrap();
    assert_close(&decoded, &expected, 1e-6);
}

#[test]
fn rescale_next_real_rejects_level_zero() {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(REAL_MODULUS).unwrap()],
    )
    .unwrap();
    let params = CkksParams::new(
        ring,
        phantom_schemes::ckks::Scale::from_bits(SCALE_BITS).unwrap(),
        false,
    )
    .unwrap();
    let ctx = CkksContext::new(params);
    let mut rng = seeded_rng(17);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret);
    let evaluator = ctx.evaluator();

    let values = sample_values(&encoder, 18);
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(ct.level(), 0);
    assert!(evaluator.rescale_next_real(&ct).is_err());
}

#[test]
fn real_path_methods_reject_a_transparent_ciphertext() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(19);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let evaluator = ctx.evaluator();
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();

    let values = sample_values(&encoder, 20);
    let transparent_pt = encoder.encode_complex(&values).unwrap();
    let transparent_encryptor = ctx.encryptor(keys.public).unwrap();
    let transparent_ct = transparent_encryptor
        .encrypt(&transparent_pt, &mut rng)
        .unwrap();

    assert!(decryptor.decrypt_real(&transparent_ct).is_err());
    assert!(evaluator.neg_real(&transparent_ct).is_err());
    assert!(evaluator.rescale_next_real(&transparent_ct).is_err());
}
