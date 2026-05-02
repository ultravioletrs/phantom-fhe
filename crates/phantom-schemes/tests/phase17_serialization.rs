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
