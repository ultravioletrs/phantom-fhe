use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bgv::{BgvContext, BgvParams};
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use phantom_schemes::{bfv, serialization};
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
