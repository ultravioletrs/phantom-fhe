//! Tests for CKKS's real ciphertext/encryption/arithmetic path
//! (`Ciphertext::poly`, `Encryptor::encrypt_real`, `Decryptor::decrypt_real`,
//! `Evaluator::{add,sub,neg,add_plain,mul,relinearize,rescale_next}_real` -
//! the rest of Workstream 5 item 3/4, on top of the real canonical-embedding
//! encoder `ckks_real_encoding.rs` already covers). Complements
//! `phase7_ckks.rs`'s coverage of the still-transparent scaffold, which
//! this doesn't touch.

use phantom_lattice::noise::fresh_secret_key_noise_bound;
use phantom_lattice::rlwe::{
    Decryptor as RlweDecryptor, Encryptor as RlweEncryptor, Evaluator as RlweEvaluator,
    KeyGenerator as RlweKeyGenerator, Plaintext as RlwePlaintext, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use phantom_schemes::ckks::{CkksContext, CkksKeyGenerator, CkksParams, Complex64};
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

// Three-modulus ring for the Horner-style regression test below: two large
// primes that both survive a raw (unrelinearized) tensor product's
// magnitude (`~default_scale^2 * message_bound`, comfortably under
// `Q0*Q1 ~ 2^112`) at level 1, plus the same `RESCALE_MODULUS` as the
// third (dropped first) modulus - unlike `real_arith_params`'s two-modulus
// ring, whose level 0 (a single ~2^50 modulus) is too small to hold a
// second raw tensor product at all, an unrelated sizing constraint, not a
// property of the scale/mul fix under test. Both new primes Miller-Rabin
// verified in Python before use.
const HORNER_Q0: u64 = 36_028_797_018_976_327;
const HORNER_Q1: u64 = 36_028_797_018_976_331;

fn horner_params() -> CkksParams {
    CkksParams::builder()
        .degree(REAL_DEGREE)
        .moduli(vec![HORNER_Q0, HORNER_Q1, RESCALE_MODULUS])
        .default_scale_bits(SCALE_BITS)
        .build()
        .unwrap()
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

    let mul_plain = evaluator.mul_plain_real(&a_ct, &b_pt).unwrap();
    let expected_mul: Vec<Complex64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| *a * *b)
        .collect();
    let decoded_mul_plain = encoder
        .decode_complex_real(&decryptor.decrypt_real(&mul_plain).unwrap())
        .unwrap();
    assert_close(&decoded_mul_plain, &expected_mul, 1e-4);
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

#[test]
fn drop_level_real_reduces_level_without_changing_scale_or_the_decrypted_value() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(21);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator();

    let values = sample_values(&encoder, 22);
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(ct.level(), 1);

    let dropped = evaluator.drop_level_real(&ct).unwrap();
    assert_eq!(dropped.level(), 0);
    // Unlike rescale_next_real, scale is untouched - exactly the value
    // multi-level circuits need to bring one ciphertext's level down to
    // match another's without also changing its scale.
    assert_eq!(dropped.scale(), ct.scale());

    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&dropped).unwrap())
        .unwrap();
    assert_close(&decoded, &values, 1e-6);
}

#[test]
fn drop_level_real_rejects_level_zero_and_a_transparent_ciphertext() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(23);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let evaluator = ctx.evaluator();

    let values = sample_values(&encoder, 24);
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();
    let at_level_zero = evaluator.rescale_next_real(&ct).unwrap();
    assert!(evaluator.drop_level_real(&at_level_zero).is_err());

    let transparent_encryptor = ctx.encryptor(keys.public).unwrap();
    let transparent_ct = transparent_encryptor
        .encrypt(&encoder.encode_complex(&values).unwrap(), &mut rng)
        .unwrap();
    assert!(evaluator.drop_level_real(&transparent_ct).is_err());
}

// Modulus-raise fixture (Workstream 11 item 3): `RAISE_Q0` plays the role of
// a real bootstrapping "q0" (a ciphertext's own lowest, level-zero
// modulus), and the other three are the much bigger "target" chain a
// modulus-raise lifts it into - `RAISE_TARGET_1` matches the headroom-sized
// modulus `phantom-bootstrapping`'s own real `EvalMod` fixture uses, so
// `Q_target >> RAISE_Q0 * degree * ||s||_1` comfortably holds for any
// ternary secret at this small a ring degree. All four Miller-Rabin
// verified distinct primes in Python before use.
const RAISE_Q0: u64 = 1_073_741_827;
const RAISE_TARGET_1: u64 = 4_611_686_018_427_400_249;
const RAISE_TARGET_2: u64 = 1_073_741_717;
const RAISE_TARGET_3: u64 = 1_073_741_719;

fn raise_params() -> CkksParams {
    CkksParams::builder()
        .degree(REAL_DEGREE)
        .moduli(vec![
            RAISE_Q0,
            RAISE_TARGET_1,
            RAISE_TARGET_2,
            RAISE_TARGET_3,
        ])
        .default_scale_bits(SCALE_BITS)
        .build()
        .unwrap()
}

#[test]
fn raise_level_real_recovers_the_value_plus_a_bounded_multiple_of_q0() {
    // `Evaluator::raise_level_real`'s own doc comment derives the bound
    // `|I| <= (h+2)/2` (`h` = the secret's own Hamming weight) on the
    // wraparound integer a raise introduces - this test builds a real
    // level-zero ciphertext, raises it, and confirms both that the mod-`q0`
    // congruence survives (the raise didn't corrupt the encrypted value)
    // and that the actual wraparound stays within that derived bound.
    let ckks = raise_params();
    let target_level = ckks.initial_level();
    let ctx = CkksContext::new(ckks.clone());
    let mut rng = seeded_rng(51);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();

    // A ternary secret's residue is nonzero mod every modulus exactly when
    // the underlying integer coefficient is nonzero (0 stays 0 everywhere;
    // +-1 embeds as a nonzero residue everywhere) - so counting against
    // the first RNS component alone gives the exact Hamming weight.
    let h = keys
        .secret
        .value()
        .component(0)
        .unwrap()
        .iter()
        .filter(|&&r| r != 0)
        .count() as i128;

    // Truncate the full-level secret down to level 0's own single-modulus
    // ring - the same technique `Decryptor::decrypt_real` already uses
    // internally, needed here explicitly since encryption at level 0 must
    // happen against a level-0-sized ring.
    let mut sk0_value = keys.secret.value().clone();
    while sk0_value.moduli_count() > 1 {
        sk0_value = phantom_ring::rns::rescale::drop_last_modulus(&sk0_value).unwrap();
    }
    let sk0 = phantom_lattice::rlwe::SecretKey::new(sk0_value);

    let level0_params = ckks.at_level(0).unwrap();
    let level0_ctx = CkksContext::new(level0_params.clone());
    let encoder0 = level0_ctx.encoder();
    let encryptor0 = level0_ctx.real_secret_key_encryptor(sk0.clone());

    // Message zero, so the level-0 decrypted value is just the small
    // encryption noise directly - isolating the wraparound the raise
    // itself introduces from the (already well-understood) encryption
    // noise/encoding-rounding contributions the rest of the real-path
    // suite already covers.
    let zero_message = vec![Complex64::real(0.0); encoder0.slot_count()];
    let ct0 = encryptor0
        .encrypt_real(
            &encoder0.encode_complex_real(&zero_message).unwrap(),
            &mut rng,
        )
        .unwrap();
    assert_eq!(ct0.level(), 0);

    let decryptor0 = level0_ctx.real_decryptor(sk0).unwrap();
    let before = decryptor0.decrypt_real(&ct0).unwrap();
    let source_basis = phantom_ring::RnsBasis::new(level0_params.ring().moduli().to_vec()).unwrap();
    let before_centered = phantom_ring::rns::extension::reconstruct_centered_values(
        before.poly().unwrap(),
        &source_basis,
    )
    .unwrap();
    for &v in &before_centered {
        assert!(
            v.unsigned_abs() < u128::from(RAISE_Q0 / 2),
            "fresh encryption noise already exceeds q0/2: v={v}"
        );
    }

    let evaluator = ctx.evaluator();
    let raised = evaluator.raise_level_real(&ct0, target_level).unwrap();
    assert_eq!(raised.level(), target_level);

    let decryptor_full = ctx.real_decryptor(keys.secret).unwrap();
    let after = decryptor_full.decrypt_real(&raised).unwrap();
    let target_basis = phantom_ring::RnsBasis::new(
        ckks.at_level(target_level)
            .unwrap()
            .ring()
            .moduli()
            .to_vec(),
    )
    .unwrap();
    let after_centered = phantom_ring::rns::extension::reconstruct_centered_values(
        after.poly().unwrap(),
        &target_basis,
    )
    .unwrap();

    let q0 = i128::from(RAISE_Q0);
    let bound = (h + 2) / 2 + 1; // +1 slack for integer-division rounding
    for (b, a) in before_centered.iter().zip(&after_centered) {
        let diff = a - b;
        assert_eq!(
            diff.rem_euclid(q0),
            0,
            "raise broke the mod-q0 congruence: before={b} after={a}"
        );
        let wraparound = diff / q0;
        assert!(
            wraparound.abs() <= bound,
            "wraparound {wraparound} exceeds derived bound {bound} (h={h})"
        );
    }
}

#[test]
fn raise_level_real_rejects_a_ciphertext_above_level_zero() {
    let ckks = raise_params();
    let ctx = CkksContext::new(ckks.clone());
    let mut rng = seeded_rng(52);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret);
    let evaluator = ctx.evaluator();

    let values = sample_values(&encoder, 53);
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();
    assert!(ct.level() > 0);
    assert!(evaluator
        .raise_level_real(&ct, ckks.initial_level())
        .is_err());
}

// Regression coverage for two findings from Workstream 6 item 2's scoping
// (see `docs/internal/implementation-plan.md`): a genuine Horner-style
// circuit (`x^3` computed as `x^2 * x`, not `x*x*x` directly) needs both
// `mul_real` to accept operands whose scales don't match (real CKKS
// multiplication never required this - only addition does, since the
// result's scale is just the product of the inputs either way) and
// `Scale::compatible` to tolerate the small, expected drift a real
// `rescale_next_real` call introduces (dividing by the *actual* dropped
// modulus, never exactly a power of two).

#[test]
fn mul_real_accepts_mismatched_scales_enabling_a_horner_style_cube() {
    let ctx = CkksContext::new(horner_params());
    let mut rng = seeded_rng(25);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator();
    let relin_key = ctx
        .keygen()
        .unwrap()
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli(), &mut rng)
        .unwrap();

    let x_values = sample_values(&encoder, 26);
    let x_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&x_values).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(x_ct.level(), 2);

    // x^2, rescaled down to level 1 - its tracked scale is now
    // `default_scale^2 / RESCALE_MODULUS`, not exactly `default_scale`.
    let x_squared = evaluator
        .relinearize_real(&evaluator.mul_real(&x_ct, &x_ct).unwrap(), &relin_key)
        .unwrap();
    let x_squared_rescaled = evaluator.rescale_next_real(&x_squared).unwrap();
    assert_eq!(x_squared_rescaled.level(), 1);

    // x itself, brought down to the same level via `drop_level_real` -
    // scale untouched, so it's still exactly `default_scale`, deliberately
    // *not* matching `x_squared_rescaled`'s own (slightly drifted) scale.
    let x_dropped = evaluator.drop_level_real(&x_ct).unwrap();
    assert_eq!(x_dropped.level(), 1);
    assert_ne!(
        x_dropped.scale().value(),
        x_squared_rescaled.scale().value()
    );

    // The regression itself: before this fix, `mul_real` rejected this
    // call outright (`check_binary`'s scale-compatibility check), even
    // though real CKKS multiplication never required matching scales -
    // the raw product decrypts correctly either way (verified below via
    // `phantom_lattice::rlwe::Decryptor::decrypt`'s own degree-2 support,
    // sidestepping the unrelated fact that `relin_key` was generated for
    // the full-level ring and so isn't itself usable below level 2).
    let cubed_raw = evaluator.mul_real(&x_squared_rescaled, &x_dropped).unwrap();
    assert_eq!(cubed_raw.degree(), 2);
    assert_eq!(cubed_raw.level(), 1);

    let expected: Vec<Complex64> = x_values.iter().map(|x| *x * *x * *x).collect();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&cubed_raw).unwrap())
        .unwrap();
    assert_close(&decoded, &expected, 1e-3);
}

#[test]
fn add_plain_real_tolerates_the_scale_drift_a_real_rescale_introduces() {
    let ctx = CkksContext::new(real_arith_params());
    let mut rng = seeded_rng(27);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let relin_key = ctx
        .keygen()
        .unwrap()
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli(), &mut rng)
        .unwrap();
    let decryptor = ctx.real_decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator();

    let x_values = sample_values(&encoder, 28);
    let x_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&x_values).unwrap(), &mut rng)
        .unwrap();
    let x_squared = evaluator
        .relinearize_real(&evaluator.mul_real(&x_ct, &x_ct).unwrap(), &relin_key)
        .unwrap();
    let x_squared_rescaled = evaluator.rescale_next_real(&x_squared).unwrap();

    // A freshly-encoded plaintext at level 0's *nominal* default scale -
    // not derived from any rescale, so it's exactly `2^SCALE_BITS`, while
    // `x_squared_rescaled`'s own scale is `default_scale^2 / RESCALE_MODULUS`
    // (close, but never bit-for-bit equal, since `RESCALE_MODULUS` is odd
    // and so can never equal `2^SCALE_BITS` exactly).
    let level_zero_encoder =
        phantom_schemes::ckks::Encoder::new(real_arith_params().at_level(0).unwrap());
    let c_values = sample_values(&level_zero_encoder, 29);
    let c_pt = level_zero_encoder.encode_complex_real(&c_values).unwrap();
    assert_ne!(c_pt.scale().value(), x_squared_rescaled.scale().value());

    let sum = evaluator
        .add_plain_real(&x_squared_rescaled, &c_pt)
        .unwrap();

    let expected: Vec<Complex64> = x_values
        .iter()
        .zip(&c_values)
        .map(|(x, c)| *x * *x + *c)
        .collect();
    let decoded = level_zero_encoder
        .decode_complex_real(&decryptor.decrypt_real(&sum).unwrap())
        .unwrap();
    assert_close(&decoded, &expected, 1e-3);
}

// Asserts every RNS limb's centered residue (mapping `[0, modulus)` to
// `(-modulus/2, modulus/2]`) is within `bound` - the RNS generalization of
// phantom-lattice's own single-modulus `assert_noise_bounded` helper
// (`phase3_rlwe.rs`), applied one modulus at a time since each row of
// `Poly::coeffs()` is an independent residue.
fn assert_noise_bounded_rns(actual: &Poly, expected: &Poly, bound: u64, moduli: &[Modulus]) {
    for (row_idx, modulus) in moduli.iter().enumerate() {
        let m = modulus.value();
        for (&a, &e) in actual.coeffs()[row_idx]
            .iter()
            .zip(expected.coeffs()[row_idx].iter())
        {
            let diff = (a + m - e) % m;
            let centered = diff.min(m - diff);
            assert!(
                centered <= bound,
                "noise {centered} exceeds bound {bound} (limb {row_idx}, actual={a}, expected={e}, modulus={m})"
            );
        }
    }
}

#[test]
fn generate_hybrid_galois_key_produces_a_working_real_rotation_key() {
    // Proves CkksKeyGenerator::generate_hybrid_galois_key (Workstream 6
    // item 5's prerequisite - phantom_bootstrapping::ckks::BootstrapKey
    // needs a source of real Galois keys) is a correct pass-through to
    // phantom_lattice::rlwe::KeyGenerator::generate_hybrid_galois_key, for
    // the exact ring a real CKKS ciphertext at these params uses. Since a
    // real CKKS ciphertext is structurally a plain RLWE ciphertext (see
    // CkksKeyGenerator::generate_hybrid_relinearization_key's own doc
    // comment), this drives the RLWE layer directly rather than through
    // ckks::Ciphertext/Plaintext, whose real constructors are pub(crate).
    let params = real_arith_params();
    let rlwe_params = params.rlwe_params().unwrap();
    let mut rng = seeded_rng(31);
    let sk = RlweKeyGenerator::new(rlwe_params.clone())
        .generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let keygen = CkksKeyGenerator::new(params).unwrap();

    // element=3 is coprime to 2*REAL_DEGREE=16 - the same choice
    // phantom-lattice's own galois-automorphism test uses.
    let element = 3;
    let galois_key = keygen
        .generate_hybrid_galois_key(element, &sk, &p_moduli(), &mut rng)
        .unwrap();
    assert!(galois_key.key_switch_key().is_some());

    let plaintext_coeffs = vec![1, 2, 3, 4, 0, 0, 0, 0];
    let plaintext_poly =
        Poly::from_coeffs(vec![plaintext_coeffs.clone(), plaintext_coeffs]).unwrap();
    let pt = RlwePlaintext::new(plaintext_poly.clone());

    let encryptor = RlweEncryptor::with_secret_key(rlwe_params.clone(), sk.clone());
    let decryptor = RlweDecryptor::new(rlwe_params.clone(), sk);
    let evaluator = RlweEvaluator::new(rlwe_params.clone());

    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
    let rotated = evaluator
        .apply_galois_automorphism(&ct, &galois_key)
        .unwrap();
    let decrypted = decryptor.decrypt(&rotated).unwrap();

    let expected_poly = rlwe_params
        .ring()
        .apply_automorphism(&plaintext_poly, element)
        .unwrap();

    // Fresh encryption noise plus real key-switching's own modest
    // contribution - same margin phantom-lattice's own
    // real_galois_automorphism_matches_plaintext_sigma_and_preserves_decryptability
    // test uses.
    let bound = fresh_secret_key_noise_bound() + 4 * fresh_secret_key_noise_bound();
    assert_noise_bounded_rns(
        decrypted.value(),
        &expected_poly,
        bound,
        rlwe_params.ring().moduli(),
    );
}

#[test]
fn rotate_real_shifts_slots_left_for_every_amount() {
    let params = real_arith_params();
    let ctx = CkksContext::new(params.clone());
    let mut rng = seeded_rng(37);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator();
    let keygen = ctx.keygen().unwrap();

    let values = sample_values(&encoder, 38);
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();

    for shift in 1..params.slot_count() {
        let element = params.rotation_element(shift);
        let key = keygen
            .generate_hybrid_galois_key(element, &keys.secret, &p_moduli(), &mut rng)
            .unwrap();
        let rotated = evaluator.rotate_real(&ct, &key).unwrap();
        let decoded = encoder
            .decode_complex_real(&decryptor.decrypt_real(&rotated).unwrap())
            .unwrap();
        let mut expected = values.clone();
        expected.rotate_left(shift);
        assert_close(&decoded, &expected, 1e-4);
    }
}

#[test]
fn conjugate_real_conjugates_every_slot() {
    let params = real_arith_params();
    let ctx = CkksContext::new(params.clone());
    let mut rng = seeded_rng(39);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator();
    let keygen = ctx.keygen().unwrap();

    let values = sample_values(&encoder, 40);
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();

    let element = params.conjugation_element();
    let key = keygen
        .generate_hybrid_galois_key(element, &keys.secret, &p_moduli(), &mut rng)
        .unwrap();
    let conjugated = evaluator.conjugate_real(&ct, &key).unwrap();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&conjugated).unwrap())
        .unwrap();
    let expected: Vec<Complex64> = values.iter().map(|v| v.conj()).collect();
    assert_close(&decoded, &expected, 1e-4);
}

#[test]
fn rotate_real_rejects_a_degree_two_ciphertext() {
    let params = real_arith_params();
    let ctx = CkksContext::new(params.clone());
    let mut rng = seeded_rng(41);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let evaluator = ctx.evaluator();
    let keygen = ctx.keygen().unwrap();

    let values = sample_values(&encoder, 42);
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();
    let product = evaluator.mul_real(&ct, &ct).unwrap();
    assert_eq!(product.degree(), 2);

    let element = params.rotation_element(1);
    let key = keygen
        .generate_hybrid_galois_key(element, &keys.secret, &p_moduli(), &mut rng)
        .unwrap();
    assert!(evaluator.rotate_real(&product, &key).is_err());
}
