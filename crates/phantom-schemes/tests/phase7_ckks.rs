use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64, Scale};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

// `params()`'s toy scale (2^10) has less headroom than a single fresh RLWE
// noise term (see `phantom_schemes::ckks::noise::fresh_precision_bits`'s
// own doc comment), so a freshly-encrypted ciphertext there now correctly
// starts at 0 bits of precision - too little for this test's own "precision
// decreases after a multiply" claim to say anything meaningful. A larger
// scale, otherwise identical, gives it real headroom to observe.
fn precision_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(40)
        .build()
        .unwrap()
}

fn real_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .conjugate_invariant(true)
        .build()
        .unwrap()
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([11; 32])
}

fn assert_close(actual: &[f64], expected: &[f64]) {
    for (actual, expected) in actual.iter().zip(expected) {
        assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
    }
}

#[test]
fn encode_decode_complex_and_real_slots() {
    let ctx = CkksContext::new(params());
    let encoder = ctx.encoder();

    let pt = encoder
        .encode_complex(&[Complex64::new(1.0, 2.0), Complex64::new(-3.5, 0.25)])
        .unwrap();
    let decoded = encoder.decode_complex(&pt).unwrap();
    assert_eq!(decoded[0], Complex64::new(1.0, 2.0));
    assert_eq!(decoded[1], Complex64::new(-3.5, 0.25));

    let pt = encoder.encode_real(&[1.25, -2.5, 3.0]).unwrap();
    assert_close(&encoder.decode_real(&pt).unwrap(), &[1.25, -2.5, 3.0]);
}

#[test]
fn encrypt_decrypt_roundtrip_is_approximate() {
    let ctx = CkksContext::new(params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();

    let pt = encoder.encode_real(&[0.5, -1.25, 4.0]).unwrap();
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
    let out = decryptor.decrypt(&ct).unwrap();

    assert_close(&encoder.decode_real(&out).unwrap(), &[0.5, -1.25, 4.0]);
}

#[test]
fn add_mul_and_rescale_track_scale_level_and_precision() {
    let ctx = CkksContext::new(precision_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let eval_keys = keygen.generate_evaluation_keys(&keys.secret, &[1]);
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator();

    let lhs = encryptor
        .encrypt(&encoder.encode_real(&[1.5, 2.0]).unwrap(), &mut rng)
        .unwrap();
    let rhs = encryptor
        .encrypt(&encoder.encode_real(&[3.0, -4.0]).unwrap(), &mut rng)
        .unwrap();

    let sum = decryptor
        .decrypt(&evaluator.add(&lhs, &rhs).unwrap())
        .unwrap();
    assert_close(&encoder.decode_real(&sum).unwrap(), &[4.5, -2.0]);

    let product = evaluator.mul(&lhs, &rhs, Some(&eval_keys)).unwrap();
    assert_eq!(product.degree(), 1);
    assert!(product.scale().value() > lhs.scale().value());
    let product = evaluator.rescale_next(&product).unwrap();
    assert_eq!(product.level(), precision_params().initial_level() - 1);
    assert_eq!(product.scale(), precision_params().default_scale());
    assert!(product.precision().bits() < lhs.precision().bits());
    let product = decryptor.decrypt(&product).unwrap();
    assert_close(&encoder.decode_real(&product).unwrap(), &[4.5, -8.0]);
}

#[test]
fn rotation_conjugation_and_plain_ops_work() {
    let ctx = CkksContext::new(params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator();

    let pt = encoder
        .encode_complex(&[
            Complex64::new(1.0, 1.0),
            Complex64::new(2.0, -1.0),
            Complex64::new(3.0, 0.5),
        ])
        .unwrap();
    let plain = encoder
        .encode_complex(&[
            Complex64::new(1.0, 0.0),
            Complex64::new(10.0, 0.0),
            Complex64::new(-1.0, 0.0),
        ])
        .unwrap();
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

    let rotated = decryptor
        .decrypt(&evaluator.rotate_slots(&ct, 1).unwrap())
        .unwrap();
    assert_eq!(
        encoder.decode_complex(&rotated).unwrap()[0],
        Complex64::new(2.0, -1.0)
    );

    let conjugated = decryptor
        .decrypt(&evaluator.conjugate(&ct).unwrap())
        .unwrap();
    assert_eq!(
        encoder.decode_complex(&conjugated).unwrap()[0],
        Complex64::new(1.0, -1.0)
    );

    let added = decryptor
        .decrypt(&evaluator.add_plain(&ct, &plain).unwrap())
        .unwrap();
    assert_eq!(
        encoder.decode_complex(&added).unwrap()[1],
        Complex64::new(12.0, -1.0)
    );
}

#[test]
fn rejects_scale_mismatch_and_supports_conjugate_invariant_real_slots() {
    let ctx = CkksContext::new(params());
    let encoder = ctx.encoder();
    let evaluator = ctx.evaluator();
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encryptor = ctx.encryptor(keys.public).unwrap();

    let lhs = encryptor
        .encrypt(&encoder.encode_real(&[1.0]).unwrap(), &mut rng)
        .unwrap();
    let rhs_pt = encoder
        .encode_complex_with_scale(&[Complex64::real(1.0)], Scale::from_bits(8).unwrap())
        .unwrap();
    let rhs = encryptor.encrypt(&rhs_pt, &mut rng).unwrap();
    assert!(evaluator.add(&lhs, &rhs).is_err());

    let real_ctx = CkksContext::new(real_params());
    let real_encoder = real_ctx.encoder();
    let real = real_encoder.encode_real(&[1.0, -2.0]).unwrap();
    assert_close(&real_encoder.decode_real(&real).unwrap(), &[1.0, -2.0]);
    assert!(real_encoder
        .encode_complex(&[Complex64::new(1.0, 1.0)])
        .is_err());
}
