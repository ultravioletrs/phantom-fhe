use phantom_lattice::rgsw::{
    external_product, GadgetDecomposition, GadgetDecompositionParams, RgswCiphertext, RgswKey,
    RgswParams,
};
use phantom_lattice::rlwe::{
    Decryptor, Encryptor, KeyGenerator, Plaintext, RlweParams, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn params() -> RlweParams {
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(97).unwrap()]).unwrap();
    RlweParams::builder().ring(ring).build().unwrap()
}

fn key_material() -> (RlweParams, phantom_lattice::rlwe::SecretKey) {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    (params, sk)
}

#[test]
fn rgsw_params_validate_decomposition_settings() {
    let params = params();

    assert!(RgswParams::new(params.clone(), 4, 3).is_ok());
    assert!(RgswParams::new(params.clone(), 0, 3).is_err());
    assert!(RgswParams::new(params, 4, 0).is_err());
}

#[test]
fn gadget_decomposition_recomposes_small_polynomial() {
    let params = params();
    let poly = Poly::from_coeffs(vec![vec![0, 1, 17, 96]]).unwrap();
    let decomposition_params = GadgetDecompositionParams::new(2, 4).unwrap();

    let decomposition = GadgetDecomposition::decompose(&poly, decomposition_params).unwrap();
    let recomposed = decomposition.recompose(params.ring().moduli()).unwrap();

    assert_eq!(recomposed, poly);
}

#[test]
fn rgsw_ciphertext_keeps_plaintext_backed_message_for_toy_semantics() {
    let (_, sk) = key_material();
    let key = RgswKey::new(sk);
    let message = Poly::from_coeffs(vec![vec![1, 0, 0, 0]]).unwrap();
    let ct = RgswCiphertext::from_message(message.clone());

    assert_eq!(key.secret().value().degree(), 4);
    assert_eq!(ct.message(), &message);
    assert!(ct.rows().is_empty());
}

#[test]
fn external_product_multiplies_underlying_plaintexts() {
    let (params, sk) = key_material();
    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk);

    let pt = Plaintext::new(Poly::from_coeffs(vec![vec![1, 2, 0, 0]]).unwrap());
    let multiplier = Poly::from_coeffs(vec![vec![3, 1, 0, 0]]).unwrap();
    let rgsw = RgswCiphertext::from_message(multiplier.clone());
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

    let product_ct = external_product(&params, &ct, &rgsw).unwrap();
    let product_pt = decryptor.decrypt(&product_ct).unwrap();
    let expected = params
        .ring()
        .schoolbook_mul(pt.value(), &multiplier)
        .unwrap();

    assert_eq!(product_pt, Plaintext::new(expected));
}
