use phantom_core::rlwe::{
    key_switch_identity, Ciphertext, Decryptor, Encryptor, Evaluator, KeyGenerator, Plaintext,
    RlweParams, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn params() -> RlweParams {
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    RlweParams::builder().ring(ring).build().unwrap()
}

fn plaintext(values: &[u64]) -> Plaintext {
    Plaintext::new(Poly::from_coeffs(vec![values.to_vec()]).unwrap())
}

fn key_material() -> (
    RlweParams,
    phantom_core::rlwe::SecretKey,
    phantom_core::rlwe::PublicKey,
) {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
    (params, sk, pk)
}

#[test]
fn secret_key_encrypt_decrypt_round_trip() {
    let (params, sk, _) = key_material();
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let pt = plaintext(&[1, 2, 3, 4]);

    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params, sk);
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
    let out = decryptor.decrypt(&ct).unwrap();

    assert_eq!(out, pt);
}

#[test]
fn public_key_encrypt_decrypt_round_trip() {
    let (params, sk, pk) = key_material();
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let pt = plaintext(&[4, 3, 2, 1]);

    let encryptor = Encryptor::with_public_key(params.clone(), pk);
    let decryptor = Decryptor::new(params, sk);
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
    let out = decryptor.decrypt(&ct).unwrap();

    assert_eq!(out, pt);
}

#[test]
fn homomorphic_add_sub_preserve_plaintext_semantics() {
    let (params, sk, pk) = key_material();
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let encryptor = Encryptor::with_public_key(params.clone(), pk);
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params);

    let a = plaintext(&[1, 2, 3, 4]);
    let b = plaintext(&[4, 3, 2, 1]);
    let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
    let ct_b = encryptor.encrypt(&b, &mut rng).unwrap();

    let sum = evaluator.add(&ct_a, &ct_b).unwrap();
    assert_eq!(decryptor.decrypt(&sum).unwrap(), plaintext(&[5, 5, 5, 5]));

    let diff = evaluator.sub(&ct_a, &ct_b).unwrap();
    assert_eq!(
        decryptor.decrypt(&diff).unwrap(),
        plaintext(&[14, 16, 1, 3])
    );
}

#[test]
fn multiplication_outputs_degree_two_and_decrypts() {
    let (params, sk, pk) = key_material();
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let encryptor = Encryptor::with_public_key(params.clone(), pk);
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    let a = plaintext(&[1, 1, 0, 0]);
    let b = plaintext(&[1, 2, 0, 0]);
    let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
    let ct_b = encryptor.encrypt(&b, &mut rng).unwrap();

    let product = evaluator.mul(&ct_a, &ct_b).unwrap();

    assert_eq!(product.degree(), 2);
    assert_eq!(
        decryptor.decrypt(&product).unwrap(),
        Plaintext::new(params.ring().schoolbook_mul(a.value(), b.value()).unwrap())
    );
}

#[test]
fn key_switch_and_relinearization_preserve_decryptability() {
    let (params, sk, pk) = key_material();
    let keygen = KeyGenerator::new(params.clone());
    let relin_key = keygen.generate_relinearization_key(&sk);
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let encryptor = Encryptor::with_public_key(params.clone(), pk);
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params);

    let ct = encryptor
        .encrypt(&plaintext(&[1, 2, 3, 4]), &mut rng)
        .unwrap();
    let switched = key_switch_identity(&ct).unwrap();
    assert_eq!(
        decryptor.decrypt(&switched).unwrap(),
        plaintext(&[1, 2, 3, 4])
    );

    let relinearized = evaluator.relinearize(&switched, &relin_key).unwrap();
    assert_eq!(
        decryptor.decrypt(&relinearized).unwrap(),
        plaintext(&[1, 2, 3, 4])
    );
}

#[test]
fn rotation_changes_coefficients_without_changing_shape() {
    let params = params();
    let evaluator = Evaluator::new(params.clone());
    let ct = Ciphertext::new(vec![
        Poly::from_coeffs(vec![vec![1, 2, 3, 4]]).unwrap(),
        Poly::from_coeffs(vec![vec![5, 6, 7, 8]]).unwrap(),
    ]);

    let rotated = evaluator.rotate_coefficients(&ct, 1).unwrap();

    assert_eq!(rotated.degree(), ct.degree());
    assert_eq!(rotated.value()[0].coeffs()[0], vec![2, 3, 4, 1]);
    assert_eq!(rotated.value()[1].coeffs()[0], vec![6, 7, 8, 5]);
}

#[test]
fn secret_key_debug_is_redacted() {
    let (_, sk, _) = key_material();
    let debug = format!("{sk:?}");

    assert!(debug.contains("redacted"));
    assert!(!debug.contains("coeffs"));
}
