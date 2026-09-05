use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bgv::{BgvContext, BgvParams};
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use phantom_schemes::{bfv, serialization, SchemesError};
use proptest::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bgv_params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(257).unwrap(), Modulus::new(769).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, 17).unwrap()
}

fn bfv_params() -> bfv::BfvParams {
    bfv::BfvParams::new(bgv_params().ring().clone(), 17).unwrap()
}

fn ckks_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

#[test]
fn bgv_params_plaintexts_and_ciphertexts_round_trip() {
    let params = bgv_params();
    let decoded_params =
        serialization::decode_bgv_params(&serialization::encode_bgv_params(&params).unwrap())
            .unwrap();
    assert_same_ring(decoded_params.ring(), params.ring());
    assert_eq!(
        decoded_params.plaintext_modulus(),
        params.plaintext_modulus()
    );

    let ctx = BgvContext::new(params);
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_u64(&[3, 4, 5]).unwrap();
    let decoded_plaintext = serialization::decode_bgv_plaintext(
        &serialization::encode_bgv_plaintext(&plaintext).unwrap(),
    )
    .unwrap();
    assert_eq!(
        encoder.decode_u64(&decoded_plaintext).unwrap(),
        encoder.decode_u64(&plaintext).unwrap()
    );

    let mut rng = ChaCha20Rng::from_seed([17; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let ciphertext = ctx
        .encryptor(keys.public)
        .unwrap()
        .encrypt(&plaintext, &mut rng)
        .unwrap();
    let decoded_ciphertext = serialization::decode_bgv_ciphertext(
        &serialization::encode_bgv_ciphertext(&ciphertext).unwrap(),
    )
    .unwrap();
    let decrypted = ctx
        .decryptor(keys.secret)
        .unwrap()
        .decrypt(&decoded_ciphertext)
        .unwrap();
    assert_eq!(&encoder.decode_u64(&decrypted).unwrap()[..3], &[3, 4, 5]);
}

#[test]
fn bfv_params_plaintexts_and_ciphertexts_round_trip() {
    let params = bfv_params();
    let decoded_params =
        serialization::decode_bfv_params(&serialization::encode_bfv_params(&params).unwrap())
            .unwrap();
    assert_same_ring(decoded_params.ring(), params.ring());
    assert_eq!(
        decoded_params.plaintext_modulus(),
        params.plaintext_modulus()
    );

    let ctx = bfv::BfvContext::new(params);
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_i64(&[-3, 4, -5]).unwrap();
    let decoded_plaintext = serialization::decode_bfv_plaintext(
        &serialization::encode_bfv_plaintext(&plaintext).unwrap(),
    )
    .unwrap();
    assert_eq!(
        encoder.decode_i64(&decoded_plaintext).unwrap(),
        encoder.decode_i64(&plaintext).unwrap()
    );

    let mut rng = ChaCha20Rng::from_seed([18; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let ciphertext = ctx
        .encryptor(keys.public)
        .unwrap()
        .encrypt(&plaintext, &mut rng)
        .unwrap();
    let decoded_ciphertext = serialization::decode_bfv_ciphertext(
        &serialization::encode_bfv_ciphertext(&ciphertext).unwrap(),
    )
    .unwrap();
    let decrypted = ctx
        .decryptor(keys.secret)
        .unwrap()
        .decrypt(&decoded_ciphertext)
        .unwrap();
    assert_eq!(&encoder.decode_i64(&decrypted).unwrap()[..3], &[-3, 4, -5]);
}

#[test]
fn ckks_params_plaintexts_and_ciphertexts_round_trip() {
    let params = ckks_params();
    let decoded_params =
        serialization::decode_ckks_params(&serialization::encode_ckks_params(&params).unwrap())
            .unwrap();
    assert_same_ring(decoded_params.ring(), params.ring());
    assert_eq!(decoded_params.default_scale(), params.default_scale());
    assert_eq!(
        decoded_params.conjugate_invariant(),
        params.conjugate_invariant()
    );

    let ctx = CkksContext::new(params);
    let plaintext = ctx
        .encoder()
        .encode_complex(&[Complex64::new(1.25, -0.5), Complex64::real(2.0)])
        .unwrap();
    let decoded_plaintext = serialization::decode_ckks_plaintext(
        &serialization::encode_ckks_plaintext(&plaintext).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded_plaintext.slots(), plaintext.slots());
    assert_eq!(decoded_plaintext.scale(), plaintext.scale());
    assert_eq!(decoded_plaintext.level(), plaintext.level());

    let mut rng = ChaCha20Rng::from_seed([19; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let ciphertext = ctx
        .encryptor(keys.public)
        .unwrap()
        .encrypt(&plaintext, &mut rng)
        .unwrap();
    let decoded_ciphertext = serialization::decode_ckks_ciphertext(
        &serialization::encode_ckks_ciphertext(&ciphertext).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded_ciphertext.slots(), ciphertext.slots());
    assert_eq!(decoded_ciphertext.scale(), ciphertext.scale());
    assert_eq!(decoded_ciphertext.level(), ciphertext.level());
    assert_eq!(decoded_ciphertext.degree(), ciphertext.degree());
}

#[test]
fn ckks_real_plaintext_and_ciphertext_round_trip() {
    // encode_ckks_plaintext/encode_ckks_ciphertext (the transparent path
    // above) only ever write `slots` - reusing them on a real
    // plaintext/ciphertext would silently drop its actual `poly` content,
    // a gap `cross_operations.rs`'s own pipeline test found. These need
    // the dedicated real encode/decode pair instead.
    let params = CkksParams::builder()
        .degree(8)
        .moduli(vec![1_000_000_000_000_037, 1_073_741_827])
        .default_scale_bits(30)
        .build()
        .unwrap();
    let ctx = CkksContext::new(params);
    let mut rng = ChaCha20Rng::from_seed([20; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();

    let values = [Complex64::new(1.5, -0.5), Complex64::new(-2.0, 1.0)];
    let plaintext = encoder.encode_complex_real(&values).unwrap();
    let decoded_plaintext = serialization::decode_ckks_plaintext_real(
        &serialization::encode_ckks_plaintext_real(&plaintext).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded_plaintext.scale(), plaintext.scale());
    assert_eq!(decoded_plaintext.level(), plaintext.level());
    let redecoded = encoder.decode_complex_real(&decoded_plaintext).unwrap();
    let original = encoder.decode_complex_real(&plaintext).unwrap();
    for (a, b) in redecoded.iter().zip(&original) {
        assert!((a.re - b.re).abs() < 1e-9 && (a.im - b.im).abs() < 1e-9);
    }

    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let ciphertext = encryptor.encrypt_real(&plaintext, &mut rng).unwrap();
    let decoded_ciphertext = serialization::decode_ckks_ciphertext_real(
        &serialization::encode_ckks_ciphertext_real(&ciphertext).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded_ciphertext.scale(), ciphertext.scale());
    assert_eq!(decoded_ciphertext.level(), ciphertext.level());
    assert_eq!(decoded_ciphertext.degree(), ciphertext.degree());

    let decryptor = ctx.real_decryptor(keys.secret).unwrap();
    let decrypted = decryptor.decrypt_real(&decoded_ciphertext).unwrap();
    let decoded_values = encoder.decode_complex_real(&decrypted).unwrap();
    for (a, b) in decoded_values.iter().zip(&values) {
        assert!((a.re - b.re).abs() < 1e-6 && (a.im - b.im).abs() < 1e-6);
    }
}

#[test]
fn ckks_real_encoding_rejects_transparent_values() {
    let ctx = CkksContext::new(ckks_params());
    let transparent = ctx
        .encoder()
        .encode_complex(&[Complex64::real(1.0)])
        .unwrap();
    assert!(serialization::encode_ckks_plaintext_real(&transparent).is_err());
}

fn assert_same_ring(actual: &Ring, expected: &Ring) {
    assert_eq!(actual.degree(), expected.degree());
    assert_eq!(
        actual
            .moduli()
            .iter()
            .map(|modulus| modulus.value())
            .collect::<Vec<_>>(),
        expected
            .moduli()
            .iter()
            .map(|modulus| modulus.value())
            .collect::<Vec<_>>()
    );
}

#[test]
fn rejects_wrong_domain_and_truncated_payloads() {
    let bgv = serialization::encode_bgv_params(&bgv_params()).unwrap();
    assert!(serialization::decode_bfv_params(&bgv).is_err());

    let mut truncated = serialization::encode_ckks_params(&ckks_params()).unwrap();
    truncated.pop();
    assert!(serialization::decode_ckks_params(&truncated).is_err());
}

// Golden-byte fixtures (Workstream 8 item 1) - one per type pair, generated
// once (not hand-computed) against the identical fixtures/seeds the
// round-trip tests above already use, then pinned here. See
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent comment
// for why this catches something round-trip tests can't: a round trip only
// proves this build's own encoder and decoder agree with *each other*, not
// that the wire shape hasn't silently drifted from what's already out
// there.
const GOLDEN_BGV_PARAMS: &[u8] = &[
    66, 71, 86, 80, 82, 77, 48, 49, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0,
];
const GOLDEN_BGV_PLAINTEXT: &[u8] = &[
    66, 71, 86, 80, 76, 84, 48, 49, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0,
    0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0,
    0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const GOLDEN_BGV_CIPHERTEXT: &[u8] = &[
    66, 71, 86, 67, 84, 88, 84, 49, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0,
    0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];
const GOLDEN_BFV_PARAMS: &[u8] = &[
    66, 70, 86, 80, 82, 77, 48, 49, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0,
];
const GOLDEN_BFV_PLAINTEXT: &[u8] = &[
    66, 70, 86, 80, 76, 84, 48, 49, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0,
    0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14,
    0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const GOLDEN_BFV_CIPHERTEXT: &[u8] = &[
    66, 70, 86, 67, 84, 88, 84, 49, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0,
    0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
];
const GOLDEN_CKKS_PARAMS: &[u8] = &[
    67, 75, 75, 83, 80, 82, 48, 49, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0, 0, 0, 1, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 64, 0,
];
const GOLDEN_CKKS_PLAINTEXT: &[u8] = &[
    67, 75, 75, 83, 80, 76, 48, 49, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 244, 63, 0, 0,
    0, 0, 0, 0, 224, 191, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144,
    64, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 64,
];
const GOLDEN_CKKS_CIPHERTEXT: &[u8] = &[
    67, 75, 75, 83, 67, 84, 48, 49, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 244, 63, 0, 0,
    0, 0, 0, 0, 224, 191, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144,
    64, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
];
const GOLDEN_CKKS_PLAINTEXT_REAL: &[u8] = &[
    67, 75, 75, 80, 76, 82, 48, 49, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 37, 128,
    198, 156, 126, 141, 3, 0, 194, 187, 35, 46, 0, 0, 0, 0, 102, 158, 160, 22, 0, 0, 0, 0, 183,
    181, 225, 130, 126, 141, 3, 0, 0, 0, 0, 8, 0, 0, 0, 0, 51, 163, 221, 6, 0, 0, 0, 0, 37, 244,
    52, 108, 126, 141, 3, 0, 137, 183, 19, 142, 126, 141, 3, 0, 3, 0, 0, 56, 0, 0, 0, 0, 194, 187,
    35, 46, 0, 0, 0, 0, 102, 158, 160, 22, 0, 0, 0, 0, 149, 53, 27, 30, 0, 0, 0, 0, 0, 0, 0, 8, 0,
    0, 0, 0, 51, 163, 221, 6, 0, 0, 0, 0, 3, 116, 110, 7, 0, 0, 0, 0, 103, 55, 77, 41, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 208, 65, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 64,
];
const GOLDEN_CKKS_CIPHERTEXT_REAL: &[u8] = &[
    67, 75, 75, 67, 84, 82, 48, 49, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0,
    0, 0, 0, 0, 0, 150, 222, 251, 32, 114, 34, 1, 0, 196, 60, 228, 207, 8, 76, 0, 0, 238, 183, 50,
    98, 125, 49, 2, 0, 96, 208, 147, 160, 242, 103, 1, 0, 145, 10, 169, 129, 17, 229, 2, 0, 235,
    107, 192, 138, 150, 19, 0, 0, 108, 144, 161, 213, 33, 86, 2, 0, 83, 86, 207, 163, 19, 226, 0,
    0, 139, 193, 12, 62, 0, 0, 0, 0, 135, 166, 119, 19, 0, 0, 0, 0, 39, 0, 170, 28, 0, 0, 0, 0, 18,
    163, 158, 59, 0, 0, 0, 0, 24, 115, 189, 20, 0, 0, 0, 0, 17, 146, 108, 22, 0, 0, 0, 0, 89, 225,
    15, 42, 0, 0, 0, 0, 42, 165, 227, 20, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0,
    0, 137, 187, 65, 115, 75, 241, 1, 0, 89, 92, 231, 5, 7, 96, 0, 0, 252, 84, 76, 128, 246, 218,
    1, 0, 45, 212, 254, 115, 176, 8, 1, 0, 145, 76, 127, 198, 241, 18, 2, 0, 159, 12, 23, 16, 159,
    249, 2, 0, 27, 177, 145, 202, 247, 74, 2, 0, 28, 228, 250, 43, 5, 50, 3, 0, 159, 217, 76, 48,
    0, 0, 0, 0, 109, 220, 145, 27, 0, 0, 0, 0, 161, 95, 183, 9, 0, 0, 0, 0, 163, 106, 194, 51, 0,
    0, 0, 0, 231, 185, 18, 35, 0, 0, 0, 0, 120, 109, 237, 24, 0, 0, 0, 0, 113, 128, 164, 63, 0, 0,
    0, 0, 63, 115, 44, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 65, 1, 0, 0, 0, 0, 0, 0, 0, 146, 203,
    208, 30, 150, 173, 54, 64, 1, 0, 0, 0, 0, 0, 0, 0,
];

#[test]
fn golden_bgv_bytes_are_stable() {
    assert_eq!(
        serialization::encode_bgv_params(&bgv_params()).unwrap(),
        GOLDEN_BGV_PARAMS
    );
    serialization::decode_bgv_params(GOLDEN_BGV_PARAMS).unwrap();

    let ctx = BgvContext::new(bgv_params());
    let plaintext = ctx.encoder().encode_u64(&[3, 4, 5]).unwrap();
    assert_eq!(
        serialization::encode_bgv_plaintext(&plaintext).unwrap(),
        GOLDEN_BGV_PLAINTEXT
    );
    serialization::decode_bgv_plaintext(GOLDEN_BGV_PLAINTEXT).unwrap();

    let mut rng = ChaCha20Rng::from_seed([17; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let ciphertext = ctx
        .encryptor(keys.public)
        .unwrap()
        .encrypt(&plaintext, &mut rng)
        .unwrap();
    assert_eq!(
        serialization::encode_bgv_ciphertext(&ciphertext).unwrap(),
        GOLDEN_BGV_CIPHERTEXT
    );
    serialization::decode_bgv_ciphertext(GOLDEN_BGV_CIPHERTEXT).unwrap();
}

#[test]
fn golden_bfv_bytes_are_stable() {
    assert_eq!(
        serialization::encode_bfv_params(&bfv_params()).unwrap(),
        GOLDEN_BFV_PARAMS
    );
    serialization::decode_bfv_params(GOLDEN_BFV_PARAMS).unwrap();

    let ctx = bfv::BfvContext::new(bfv_params());
    let plaintext = ctx.encoder().encode_i64(&[-3, 4, -5]).unwrap();
    assert_eq!(
        serialization::encode_bfv_plaintext(&plaintext).unwrap(),
        GOLDEN_BFV_PLAINTEXT
    );
    serialization::decode_bfv_plaintext(GOLDEN_BFV_PLAINTEXT).unwrap();

    let mut rng = ChaCha20Rng::from_seed([18; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let ciphertext = ctx
        .encryptor(keys.public)
        .unwrap()
        .encrypt(&plaintext, &mut rng)
        .unwrap();
    assert_eq!(
        serialization::encode_bfv_ciphertext(&ciphertext).unwrap(),
        GOLDEN_BFV_CIPHERTEXT
    );
    serialization::decode_bfv_ciphertext(GOLDEN_BFV_CIPHERTEXT).unwrap();
}

#[test]
fn golden_ckks_bytes_are_stable() {
    assert_eq!(
        serialization::encode_ckks_params(&ckks_params()).unwrap(),
        GOLDEN_CKKS_PARAMS
    );
    serialization::decode_ckks_params(GOLDEN_CKKS_PARAMS).unwrap();

    let ctx = CkksContext::new(ckks_params());
    let plaintext = ctx
        .encoder()
        .encode_complex(&[Complex64::new(1.25, -0.5), Complex64::real(2.0)])
        .unwrap();
    assert_eq!(
        serialization::encode_ckks_plaintext(&plaintext).unwrap(),
        GOLDEN_CKKS_PLAINTEXT
    );
    serialization::decode_ckks_plaintext(GOLDEN_CKKS_PLAINTEXT).unwrap();

    let mut rng = ChaCha20Rng::from_seed([19; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let ciphertext = ctx
        .encryptor(keys.public)
        .unwrap()
        .encrypt(&plaintext, &mut rng)
        .unwrap();
    assert_eq!(
        serialization::encode_ckks_ciphertext(&ciphertext).unwrap(),
        GOLDEN_CKKS_CIPHERTEXT
    );
    serialization::decode_ckks_ciphertext(GOLDEN_CKKS_CIPHERTEXT).unwrap();
}

#[test]
fn golden_ckks_real_bytes_are_stable() {
    let params = CkksParams::builder()
        .degree(8)
        .moduli(vec![1_000_000_000_000_037, 1_073_741_827])
        .default_scale_bits(30)
        .build()
        .unwrap();
    let ctx = CkksContext::new(params);
    let mut rng = ChaCha20Rng::from_seed([20; 32]);
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let values = [Complex64::new(1.5, -0.5), Complex64::new(-2.0, 1.0)];
    let plaintext = encoder.encode_complex_real(&values).unwrap();
    assert_eq!(
        serialization::encode_ckks_plaintext_real(&plaintext).unwrap(),
        GOLDEN_CKKS_PLAINTEXT_REAL
    );
    serialization::decode_ckks_plaintext_real(GOLDEN_CKKS_PLAINTEXT_REAL).unwrap();

    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let ciphertext = encryptor.encrypt_real(&plaintext, &mut rng).unwrap();
    assert_eq!(
        serialization::encode_ckks_ciphertext_real(&ciphertext).unwrap(),
        GOLDEN_CKKS_CIPHERTEXT_REAL
    );
    serialization::decode_ckks_ciphertext_real(GOLDEN_CKKS_CIPHERTEXT_REAL).unwrap();
}

// Exhaustive domain/version-mismatch rejection (Workstream 8 item 2): every
// type pair, both a wrong-domain payload (paired sequentially so each of
// the 11 types is used as the "wrong" input exactly once, rather than all
// 110 pairwise combinations) and a wrong-version payload (same domain,
// corrupted version bytes) - the latter untested anywhere before this.
// Header layout is `domain (8 bytes) || version (u16 LE)`.
fn flip_version_byte(mut encoded: Vec<u8>) -> Vec<u8> {
    encoded[8] = encoded[8].wrapping_add(1);
    encoded
}

#[test]
fn every_type_rejects_a_wrong_domain() {
    assert!(matches!(
        serialization::decode_bfv_params(GOLDEN_BGV_PARAMS).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_bfv_plaintext(GOLDEN_BGV_PLAINTEXT).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_bfv_ciphertext(GOLDEN_BGV_CIPHERTEXT).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_ckks_params(GOLDEN_BFV_PARAMS).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_ckks_plaintext(GOLDEN_BFV_PLAINTEXT).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_ckks_ciphertext(GOLDEN_BFV_CIPHERTEXT).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_bgv_params(GOLDEN_CKKS_PARAMS).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_ckks_plaintext_real(GOLDEN_CKKS_PLAINTEXT).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_ckks_ciphertext_real(GOLDEN_CKKS_CIPHERTEXT).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_ckks_plaintext(GOLDEN_CKKS_PLAINTEXT_REAL).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
    assert!(matches!(
        serialization::decode_ckks_ciphertext(GOLDEN_CKKS_CIPHERTEXT_REAL).unwrap_err(),
        SchemesError::Utils(phantom_utils::UtilsError::InvalidDomain { .. })
    ));
}

#[test]
fn every_type_rejects_a_wrong_version() {
    type Decoder = fn(&[u8]) -> Result<(), ()>;

    let cases: Vec<Vec<u8>> = vec![
        GOLDEN_BGV_PARAMS.to_vec(),
        GOLDEN_BGV_PLAINTEXT.to_vec(),
        GOLDEN_BGV_CIPHERTEXT.to_vec(),
        GOLDEN_BFV_PARAMS.to_vec(),
        GOLDEN_BFV_PLAINTEXT.to_vec(),
        GOLDEN_BFV_CIPHERTEXT.to_vec(),
        GOLDEN_CKKS_PARAMS.to_vec(),
        GOLDEN_CKKS_PLAINTEXT.to_vec(),
        GOLDEN_CKKS_CIPHERTEXT.to_vec(),
        GOLDEN_CKKS_PLAINTEXT_REAL.to_vec(),
        GOLDEN_CKKS_CIPHERTEXT_REAL.to_vec(),
    ];
    let decoders: Vec<Decoder> = vec![
        |b| serialization::decode_bgv_params(b).map(drop).map_err(drop),
        |b| {
            serialization::decode_bgv_plaintext(b)
                .map(drop)
                .map_err(drop)
        },
        |b| {
            serialization::decode_bgv_ciphertext(b)
                .map(drop)
                .map_err(drop)
        },
        |b| serialization::decode_bfv_params(b).map(drop).map_err(drop),
        |b| {
            serialization::decode_bfv_plaintext(b)
                .map(drop)
                .map_err(drop)
        },
        |b| {
            serialization::decode_bfv_ciphertext(b)
                .map(drop)
                .map_err(drop)
        },
        |b| serialization::decode_ckks_params(b).map(drop).map_err(drop),
        |b| {
            serialization::decode_ckks_plaintext(b)
                .map(drop)
                .map_err(drop)
        },
        |b| {
            serialization::decode_ckks_ciphertext(b)
                .map(drop)
                .map_err(drop)
        },
        |b| {
            serialization::decode_ckks_plaintext_real(b)
                .map(drop)
                .map_err(drop)
        },
        |b| {
            serialization::decode_ckks_ciphertext_real(b)
                .map(drop)
                .map_err(drop)
        },
    ];
    for (bytes, decode) in cases.into_iter().zip(decoders) {
        assert!(decode(&flip_version_byte(bytes)).is_err());
    }
}

// Fuzz/property tests for decode rejection (Workstream 8 item 3) - see
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent
// comment: the property is "never panics," proptest catches panics itself.
proptest! {
    #[test]
    fn decode_bgv_params_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_bgv_params(&bytes);
    }
    #[test]
    fn decode_bgv_plaintext_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_bgv_plaintext(&bytes);
    }
    #[test]
    fn decode_bgv_ciphertext_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_bgv_ciphertext(&bytes);
    }
    #[test]
    fn decode_bfv_params_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_bfv_params(&bytes);
    }
    #[test]
    fn decode_bfv_plaintext_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_bfv_plaintext(&bytes);
    }
    #[test]
    fn decode_bfv_ciphertext_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_bfv_ciphertext(&bytes);
    }
    #[test]
    fn decode_ckks_params_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_ckks_params(&bytes);
    }
    #[test]
    fn decode_ckks_plaintext_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_ckks_plaintext(&bytes);
    }
    #[test]
    fn decode_ckks_ciphertext_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_ckks_ciphertext(&bytes);
    }
    #[test]
    fn decode_ckks_plaintext_real_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_ckks_plaintext_real(&bytes);
    }
    #[test]
    fn decode_ckks_ciphertext_real_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = serialization::decode_ckks_ciphertext_real(&bytes);
    }
}
