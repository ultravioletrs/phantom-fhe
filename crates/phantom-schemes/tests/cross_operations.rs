//! Cross-operation tests (Workstream 5 item 7): each test chains several
//! operations together in one pipeline - encrypt, add, multiply,
//! relinearize, rescale/modswitch, rotate, and serialize/deserialize - and
//! checks the final decrypted value, rather than exercising one operation
//! in isolation the way every other test file in this crate does. This is
//! deliberately about *composition*: a bug that only shows up when
//! operations are chained (stale level/scale bookkeeping surviving a
//! serialize/deserialize round trip, a real ciphertext's `poly` silently
//! dropped by a serializer that only knew the transparent shape - the
//! latter a real bug this file's own CKKS pipeline caught, see
//! `crate::serialization::encode_ckks_ciphertext_real`'s own doc comment)
//! wouldn't necessarily show up in any single per-operation test.
//!
//! Real rotation isn't wired up for any scheme yet (`SECURITY.md`: BGV/BFV
//! still only call the raw-coefficient `rotate_coefficients` placeholder;
//! CKKS's real path has no rotation method at all) - so "rotations" is
//! covered by the transparent-scaffold pipelines instead, honestly
//! reflecting what's actually implemented today rather than exercising an
//! operation on a real ciphertext that isn't proven correct there.

use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bfv::{BfvContext, BfvParams};
use phantom_schemes::bgv::{BgvContext, BgvParams};
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use phantom_schemes::serialization;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const REAL_DEGREE: usize = 8;
const REAL_MODULUS: u64 = 1_000_000_000_000_037;
const REAL_MODULUS_2: u64 = 1_000_000_000_000_091;
const REAL_T: u64 = 17;
const P1: u64 = 1_000_000_000_000_091;
const P2: u64 = 1_000_000_000_000_159;
const CKKS_RESCALE_MODULUS: u64 = 1_073_741_827;
const CKKS_SCALE_BITS: u32 = 30;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([31; 32])
}

fn bgv_real_params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![
            Modulus::new(REAL_MODULUS).unwrap(),
            Modulus::new(REAL_MODULUS_2).unwrap(),
        ],
    )
    .unwrap();
    BgvParams::new(ring, REAL_T).unwrap()
}

fn bfv_real_params() -> BfvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(REAL_MODULUS).unwrap()],
    )
    .unwrap();
    BfvParams::new(ring, REAL_T).unwrap()
}

fn ckks_real_params() -> CkksParams {
    CkksParams::builder()
        .degree(REAL_DEGREE)
        .moduli(vec![REAL_MODULUS, CKKS_RESCALE_MODULUS])
        .default_scale_bits(CKKS_SCALE_BITS)
        .build()
        .unwrap()
}

fn toy_bgv_params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(257).unwrap(), Modulus::new(769).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, REAL_T).unwrap()
}

fn toy_ckks_params() -> CkksParams {
    CkksParams::builder()
        .degree(REAL_DEGREE)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

#[allow(clippy::needless_range_loop)]
fn negacyclic_mul_mod(a: &[u64], b: &[u64], t: u64) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0i64; n];
    for i in 0..n {
        for j in 0..n {
            let k = i + j;
            let term = (a[i] * b[j]) as i64;
            if k >= n {
                out[k - n] -= term;
            } else {
                out[k] += term;
            }
        }
    }
    out.into_iter()
        .map(|v| v.rem_euclid(t as i64) as u64)
        .collect()
}

// `bgv_real_pipeline_*` below was originally split into two tests rather
// than one long encrypt->add->multiply->relinearize->switch->serialize
// chain, because building that single chain is exactly what surfaced a
// genuine, previously-unknown correctness gap: relinearize_real's output,
// though it decrypts correctly on its own, produced wrong results when
// *subsequently* modulus-switched, for a ring with more than one auxiliary
// modulus. Root-caused since: not a BGV-specific interaction at all, but a
// soundness gap in the shared `phantom_lattice::rgsw::GadgetDecomposition`
// primitive on any ring with more than one RNS modulus (see that module's
// own doc comment for the full derivation) - now fixed there directly, so
// both split tests below AND the combined chain
// (`bgv_real_pipeline_encrypt_add_multiply_relinearize_switch_and_serialize`)
// are verified correct. The split tests are kept anyway (redundant with the
// combined one, but cheap and each isolates one operation's own
// correctness without the other).

#[test]
fn bgv_real_pipeline_encrypt_add_multiply_relinearize_and_serialize() {
    let ctx = BgvContext::new(bgv_real_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair_real(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i % REAL_T).collect();
    let b_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| (3 * i) % REAL_T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    // encrypt -> add
    let sum = evaluator.add(&a_ct, &b_ct).unwrap();

    // add -> multiply (raw, unrelinearized)
    let product = evaluator.mul(&sum, &a_ct, None).unwrap();

    // multiply -> relinearize
    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();
    let relin_key = keygen
        .generate_relinearization_key_real(&keys.secret, decomposition_params, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();

    // relinearize -> serialize -> deserialize -> decrypt
    let bytes = serialization::encode_bgv_ciphertext(&relinearized).unwrap();
    let decoded = serialization::decode_bgv_ciphertext(&bytes).unwrap();
    let decrypted = decryptor.decrypt(&decoded).unwrap();

    // add is elementwise, but mul is the negacyclic ring product (see the
    // module doc comment on `negacyclic_mul_mod`) - expected = (a+b) (x) a.
    let ab_sum: Vec<u64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| (a + b) % REAL_T)
        .collect();
    let expected = negacyclic_mul_mod(&ab_sum, &a_values, REAL_T);
    assert_eq!(encoder.decode_u64(&decrypted).unwrap(), expected);
}

#[test]
fn bgv_real_pipeline_encrypt_add_switch_and_serialize() {
    let ctx = BgvContext::new(bgv_real_params());
    let mut rng = rng();
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i % REAL_T).collect();
    let b_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| (3 * i) % REAL_T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    // encrypt -> add
    let sum = evaluator.add(&a_ct, &b_ct).unwrap();

    // add -> modulus switch
    let switched = evaluator.modulus_switch_next_real(&sum).unwrap();
    let switched_params = evaluator.next_modulus_switch_params().unwrap();
    let switched_secret = evaluator.switch_secret_key(&keys.secret).unwrap();

    // modulus switch -> serialize -> deserialize
    let bytes = serialization::encode_bgv_ciphertext(&switched).unwrap();
    let decoded = serialization::decode_bgv_ciphertext(&bytes).unwrap();

    // deserialize -> decrypt (against the switched ring's own smaller
    // params/encoder - modulus switching drops a component, so the
    // original full-ring encoder's decode would dimension-mismatch)
    let switched_ctx = BgvContext::new(switched_params);
    let switched_encoder = switched_ctx.encoder();
    let decryptor = switched_ctx.decryptor(switched_secret).unwrap();
    let decrypted = decryptor.decrypt(&decoded).unwrap();

    let expected: Vec<u64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| (a + b) % REAL_T)
        .collect();
    assert_eq!(switched_encoder.decode_u64(&decrypted).unwrap(), expected);
}

// Regression coverage for the fixed `GadgetDecomposition` gap (see this
// file's own module doc comment above and
// `phantom_lattice::rgsw::decomposition`'s): the full chain that used to
// produce an incorrect plaintext - relinearizing a real BGV ciphertext on a
// multi-modulus ring, then modulus-switching the result.
#[test]
fn bgv_real_pipeline_encrypt_add_multiply_relinearize_switch_and_serialize() {
    let ctx = BgvContext::new(bgv_real_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair_real(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i % REAL_T).collect();
    let b_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| (3 * i) % REAL_T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    // encrypt -> add
    let sum = evaluator.add(&a_ct, &b_ct).unwrap();

    // add -> multiply (raw, unrelinearized)
    let product = evaluator.mul(&sum, &a_ct, None).unwrap();

    // multiply -> relinearize
    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();
    let relin_key = keygen
        .generate_relinearization_key_real(&keys.secret, decomposition_params, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();

    // relinearize -> modulus switch
    let switched = evaluator.modulus_switch_next_real(&relinearized).unwrap();
    let switched_params = evaluator.next_modulus_switch_params().unwrap();
    let switched_secret = evaluator.switch_secret_key(&keys.secret).unwrap();

    // modulus switch -> serialize -> deserialize -> decrypt (against the
    // switched ring's own smaller params/encoder)
    let bytes = serialization::encode_bgv_ciphertext(&switched).unwrap();
    let decoded = serialization::decode_bgv_ciphertext(&bytes).unwrap();
    let switched_ctx = BgvContext::new(switched_params);
    let switched_encoder = switched_ctx.encoder();
    let decryptor = switched_ctx.decryptor(switched_secret).unwrap();
    let decrypted = decryptor.decrypt(&decoded).unwrap();

    // add is elementwise, but mul is the negacyclic ring product - expected
    // = (a+b) (x) a.
    let ab_sum: Vec<u64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| (a + b) % REAL_T)
        .collect();
    let expected = negacyclic_mul_mod(&ab_sum, &a_values, REAL_T);
    assert_eq!(switched_encoder.decode_u64(&decrypted).unwrap(), expected);
}

#[test]
fn bfv_real_pipeline_encrypt_add_multiply_relinearize_and_serialize() {
    let ctx = BfvContext::new(bfv_real_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());

    let a_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i % REAL_T).collect();
    let b_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| (3 * i) % REAL_T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    let evaluator = ctx.evaluator().unwrap();
    // encrypt -> add
    let sum = evaluator.add(&a_ct, &b_ct).unwrap();

    // add -> multiply (tensor-and-rescale)
    let p_moduli = [Modulus::new(P1).unwrap(), Modulus::new(P2).unwrap()];
    let product = evaluator.mul_real(&sum, &a_ct, &p_moduli).unwrap();

    // multiply -> relinearize
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();

    // relinearize -> serialize -> deserialize -> decrypt
    let bytes = serialization::encode_bfv_ciphertext(&relinearized).unwrap();
    let decoded = serialization::decode_bfv_ciphertext(&bytes).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let decrypted = decryptor.decrypt(&decoded).unwrap();

    let ab_sum: Vec<u64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| (a + b) % REAL_T)
        .collect();
    let expected = negacyclic_mul_mod(&ab_sum, &a_values, REAL_T);
    assert_eq!(encoder.decode_u64_real(&decrypted).unwrap(), expected);
}

#[test]
fn ckks_real_pipeline_encrypt_add_multiply_relinearize_rescale_and_serialize() {
    let ctx = CkksContext::new(ckks_real_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let evaluator = ctx.evaluator();

    let a_values = [Complex64::new(1.0, 0.5), Complex64::new(-2.0, 1.0)];
    let b_values = [Complex64::new(0.5, -0.5), Complex64::new(1.0, 2.0)];
    let a_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&b_values).unwrap(), &mut rng)
        .unwrap();

    // encrypt -> add
    let sum = evaluator.add_real(&a_ct, &b_ct).unwrap();

    // add -> multiply (raw tensor)
    let product = evaluator.mul_real(&sum, &a_ct).unwrap();

    // multiply -> relinearize
    let p_moduli = [Modulus::new(P1).unwrap(), Modulus::new(P2).unwrap()];
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();

    // relinearize -> rescale
    let rescaled = evaluator.rescale_next_real(&relinearized).unwrap();

    // rescale -> serialize -> deserialize
    let bytes = serialization::encode_ckks_ciphertext_real(&rescaled).unwrap();
    let decoded = serialization::decode_ckks_ciphertext_real(&bytes).unwrap();
    assert_eq!(decoded.level(), rescaled.level());

    // deserialize -> decrypt -> decode
    let decryptor = ctx.real_decryptor(keys.secret).unwrap();
    let decrypted = decryptor.decrypt_real(&decoded).unwrap();
    let decoded_values = encoder.decode_complex_real(&decrypted).unwrap();

    let expected: Vec<Complex64> = {
        let sum: Vec<Complex64> = a_values
            .iter()
            .zip(&b_values)
            .map(|(a, b)| *a + *b)
            .collect();
        sum.iter().zip(&a_values).map(|(s, a)| *s * *a).collect()
    };
    for (actual, expected) in decoded_values.iter().zip(&expected) {
        assert!(
            (actual.re - expected.re).abs() < 1e-3,
            "{actual:?} != {expected:?}"
        );
        assert!(
            (actual.im - expected.im).abs() < 1e-3,
            "{actual:?} != {expected:?}"
        );
    }
}

#[test]
fn bgv_transparent_pipeline_covers_rotation_and_serialization() {
    let ctx = BgvContext::new(toy_bgv_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let eval_keys = keygen.generate_evaluation_keys(&keys.secret, &[1]);
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&[1, 2, 3, 4]).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&[5, 6, 7, 8]).unwrap(), &mut rng)
        .unwrap();

    // encrypt -> add -> multiply(+relinearize) -> rotate -> serialize -> deserialize -> decrypt
    let sum = evaluator.add(&a_ct, &b_ct).unwrap();
    let product = evaluator.mul(&sum, &a_ct, Some(&eval_keys)).unwrap();
    let rotated = evaluator.rotate_slots(&product, 1).unwrap();

    let bytes = serialization::encode_bgv_ciphertext(&rotated).unwrap();
    let decoded = serialization::decode_bgv_ciphertext(&bytes).unwrap();
    let decrypted = decryptor.decrypt(&decoded).unwrap();

    // encode_u64 zero-pads to the full ring degree (8); mul is the
    // negacyclic ring product (see the module doc comment on
    // `negacyclic_mul_mod`), and rotate_slots is a plain coefficient
    // `Vec::rotate_left` (`phantom_lattice::rlwe::Evaluator::rotate_coefficients`'s
    // own implementation) - both applied here across the full 8 slots to
    // match what the pipeline itself does.
    let a = vec![1u64, 2, 3, 4, 0, 0, 0, 0];
    let b = vec![5u64, 6, 7, 8, 0, 0, 0, 0];
    let ab_sum: Vec<u64> = a.iter().zip(&b).map(|(x, y)| (x + y) % REAL_T).collect();
    let mut expected = negacyclic_mul_mod(&ab_sum, &a, REAL_T);
    expected.rotate_left(1);
    assert_eq!(encoder.decode_u64(&decrypted).unwrap(), expected);
}

#[test]
fn ckks_transparent_pipeline_covers_rotation_and_serialization() {
    let ctx = CkksContext::new(toy_ckks_params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator();

    let a_ct = encryptor
        .encrypt(&encoder.encode_real(&[1.0, 2.0]).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_real(&[3.0, 4.0]).unwrap(), &mut rng)
        .unwrap();

    // encrypt -> add -> rotate -> serialize -> deserialize -> decrypt
    let sum = evaluator.add(&a_ct, &b_ct).unwrap();
    let rotated = evaluator.rotate_slots(&sum, 1).unwrap();

    let bytes = serialization::encode_ckks_ciphertext(&rotated).unwrap();
    let decoded = serialization::decode_ckks_ciphertext(&bytes).unwrap();
    let decrypted = decryptor.decrypt(&decoded).unwrap();

    let mut expected = [4.0, 6.0];
    expected.rotate_left(1);
    let actual = encoder.decode_real(&decrypted).unwrap();
    assert!((actual[0] - expected[0]).abs() < 1e-9);
    assert!((actual[1] - expected[1]).abs() < 1e-9);
}
