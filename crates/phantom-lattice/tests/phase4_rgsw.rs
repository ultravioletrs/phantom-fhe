use phantom_lattice::noise::{fresh_secret_key_noise_bound, ring_product_bound};
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

// Real RLWE encryption now carries real noise, which modulus=97 above has no
// room for (fresh_secret_key_noise_bound() alone can reach 20, comparable to
// the whole modulus) - params()/key_material() stay small for the
// noise-free structural tests below (gadget decomposition, boundary values
// tied to modulus=97 specifically), and external_product_multiplies_
// underlying_plaintexts gets its own noise-tolerant ring instead.
const NOISY_DEGREE: usize = 4;
const NOISY_MODULUS: u64 = 5009; // prime, (NOISY_MODULUS - 1) % (2 * NOISY_DEGREE) == 0

fn noisy_params() -> RlweParams {
    let ring = Ring::new_ntt(
        Degree::new(NOISY_DEGREE).unwrap(),
        vec![Modulus::new(NOISY_MODULUS).unwrap()],
    )
    .unwrap();
    RlweParams::builder().ring(ring).build().unwrap()
}

fn noisy_key_material() -> (RlweParams, phantom_lattice::rlwe::SecretKey) {
    let params = noisy_params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    (params, sk)
}

/// See `phase3_rlwe.rs`'s identical helper for why centered-residue
/// comparison is the right way to check RLWE decryption noise.
fn assert_noise_bounded(actual: &Plaintext, expected: &Plaintext, bound: u64, modulus: u64) {
    for (&a, &e) in actual.value().coeffs()[0]
        .iter()
        .zip(expected.value().coeffs()[0].iter())
    {
        let diff = (a + modulus - e) % modulus;
        let centered = diff.min(modulus - diff);
        assert!(
            centered <= bound,
            "noise {centered} exceeds bound {bound} (actual={a}, expected={e}, modulus={modulus})"
        );
    }
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
    let (params, sk) = noisy_key_material();
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

    // external_product multiplies every RLWE component (including the
    // noise-carrying one) by the plaintext-known multiplier polynomial, so
    // the resulting noise is that same ring product applied to the fresh
    // secret-key encryption's own noise bound (multiplier's max coefficient
    // is 3 here).
    let bound = ring_product_bound(NOISY_DEGREE, 3, fresh_secret_key_noise_bound());
    assert_noise_bounded(&product_pt, &Plaintext::new(expected), bound, NOISY_MODULUS);
}
