use phantom_lattice::noise::{
    fresh_public_key_noise_bound, fresh_secret_key_noise_bound, mul_noise_bound,
};
use phantom_lattice::rlwe::{
    key_switch_identity, Ciphertext, Decryptor, Encryptor, Evaluator, KeyGenerator, Plaintext,
    RlweParams, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// Auxiliary "P" moduli for real hybrid relinearization - comparable in size
// to MODULUS, the actual requirement hybrid key-switching has (see
// phantom_lattice::rlwe::keyswitch's own module doc comment). Unlike Q,
// these don't need NTT-friendliness: generate_key_switch_key builds the
// extended QP ring via Ring::new, not Ring::new_ntt.
const P_MODULI: [u64; 2] = [4_000_063, 4_000_067];

// Real RLWE encryption now carries real Gaussian noise (sigma = 3.2, see
// phantom_lattice::security), so decryption recovers "plaintext plus small
// noise," not the plaintext exactly - the old degree=4/modulus=17 params
// couldn't hold real noise at all (sigma=3.2's ~6-sigma tail alone can reach
// 20, larger than the whole modulus). MODULUS is sized with real headroom
// over even the worst-case (pessimistic, see noise::ring_product_bound's own
// doc comment) post-multiplication noise bound at DEGREE=8, not just fresh
// encryption - see assert_noise_bounded's callers below for the exact
// bounds each operation is checked against.
const DEGREE: usize = 8;
const MODULUS: u64 = 4_000_081; // prime, (MODULUS - 1) % (2 * DEGREE) == 0

fn params() -> RlweParams {
    let ring = Ring::new_ntt(
        Degree::new(DEGREE).unwrap(),
        vec![Modulus::new(MODULUS).unwrap()],
    )
    .unwrap();
    RlweParams::builder().ring(ring).build().unwrap()
}

fn plaintext(values: &[u64]) -> Plaintext {
    let mut coeffs = values.to_vec();
    coeffs.resize(DEGREE, 0);
    Plaintext::new(Poly::from_coeffs(vec![coeffs]).unwrap())
}

fn key_material() -> (
    RlweParams,
    phantom_lattice::rlwe::SecretKey,
    phantom_lattice::rlwe::PublicKey,
) {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
    (params, sk, pk)
}

/// Asserts every coefficient of `actual` is within `bound` of the
/// corresponding coefficient of `expected`, using the centered residue
/// (mapping `[0, modulus)` to `(-modulus/2, modulus/2]`) - the standard way
/// to measure RLWE decryption noise, since "close to the true value" means
/// close in either direction around the modular wraparound.
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
fn secret_key_encrypt_decrypt_round_trip() {
    let (params, sk, _) = key_material();
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let pt = plaintext(&[1, 2, 3, 4]);

    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params, sk);
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
    let out = decryptor.decrypt(&ct).unwrap();

    assert_noise_bounded(&out, &pt, fresh_secret_key_noise_bound(), MODULUS);
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

    assert_noise_bounded(&out, &pt, fresh_public_key_noise_bound(DEGREE), MODULUS);
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

    // Addition/subtraction combine two independent fresh-noise ciphertexts
    // linearly, so the resulting noise is bounded by the sum of their
    // individual bounds.
    let combined_bound = 2 * fresh_public_key_noise_bound(DEGREE);

    let sum = evaluator.add(&ct_a, &ct_b).unwrap();
    assert_noise_bounded(
        &decryptor.decrypt(&sum).unwrap(),
        &plaintext(&[5, 5, 5, 5]),
        combined_bound,
        MODULUS,
    );

    let diff = evaluator.sub(&ct_a, &ct_b).unwrap();
    assert_noise_bounded(
        &decryptor.decrypt(&diff).unwrap(),
        &plaintext(&[MODULUS - 3, MODULUS - 1, 1, 3]),
        combined_bound,
        MODULUS,
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
    let expected = Plaintext::new(params.ring().schoolbook_mul(a.value(), b.value()).unwrap());
    // Both operands' plaintext coefficients are <= 2; see
    // noise::mul_noise_bound's own doc comment for the worst-case
    // derivation this bound comes from.
    let bound = mul_noise_bound(DEGREE, 2, fresh_public_key_noise_bound(DEGREE));
    assert_noise_bounded(
        &decryptor.decrypt(&product).unwrap(),
        &expected,
        bound,
        MODULUS,
    );
}

#[test]
fn real_relinearization_reduces_degree_and_preserves_the_product() {
    let (params, sk, _) = key_material();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);

    let p_moduli: Vec<Modulus> = P_MODULI.iter().map(|&p| Modulus::new(p).unwrap()).collect();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&sk, &p_moduli, &mut rng)
        .unwrap();

    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    let a = plaintext(&[1, 1, 0, 0]);
    let b = plaintext(&[1, 2, 0, 0]);
    let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
    let ct_b = encryptor.encrypt(&b, &mut rng).unwrap();

    let product = evaluator.mul(&ct_a, &ct_b).unwrap();
    assert_eq!(product.degree(), 2);

    let relinearized = evaluator.relinearize(&product, &relin_key).unwrap();
    assert_eq!(
        relinearized.degree(),
        1,
        "real relinearization must bring a degree-2 ciphertext back to degree 1"
    );

    let expected = Plaintext::new(params.ring().schoolbook_mul(a.value(), b.value()).unwrap());
    // Pre-relinearization multiplication noise (mul_noise_bound, same as
    // multiplication_outputs_degree_two_and_decrypts above) plus real
    // key-switching's own modest contribution - see key_switch.rs's own
    // noise_bound() for why 4x fresh_secret_key_noise_bound() is a safe,
    // deliberately generous (not yet formally derived) margin for that part.
    let bound = mul_noise_bound(DEGREE, 2, fresh_secret_key_noise_bound())
        + 4 * fresh_secret_key_noise_bound();
    assert_noise_bounded(
        &decryptor.decrypt(&relinearized).unwrap(),
        &expected,
        bound,
        MODULUS,
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

    let pt = plaintext(&[1, 2, 3, 4]);
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
    let bound = fresh_public_key_noise_bound(DEGREE);

    let switched = key_switch_identity(&ct).unwrap();
    assert_noise_bounded(&decryptor.decrypt(&switched).unwrap(), &pt, bound, MODULUS);

    let relinearized = evaluator.relinearize(&switched, &relin_key).unwrap();
    assert_noise_bounded(
        &decryptor.decrypt(&relinearized).unwrap(),
        &pt,
        bound,
        MODULUS,
    );
}

#[test]
fn real_galois_automorphism_matches_plaintext_sigma_and_preserves_decryptability() {
    let (params, sk, _) = key_material();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);

    // element=3 is coprime to 2*DEGREE=16 (the same small example hand-
    // verified against direct polynomial substitution in
    // phantom-ring/tests/automorphism.rs).
    let element = 3;
    let p_moduli: Vec<Modulus> = P_MODULI.iter().map(|&p| Modulus::new(p).unwrap()).collect();
    let galois_key = keygen
        .generate_hybrid_galois_key(element, &sk, &p_moduli, &mut rng)
        .unwrap();

    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    let pt = plaintext(&[1, 2, 3, 4]);
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

    let rotated = evaluator
        .apply_galois_automorphism(&ct, &galois_key)
        .unwrap();
    assert_eq!(rotated.degree(), 1);

    let expected = Plaintext::new(
        params
            .ring()
            .apply_automorphism(pt.value(), element)
            .unwrap(),
    );
    // Fresh encryption noise plus real key-switching's own modest
    // contribution - same margin as real_relinearization's own bound above.
    let bound = fresh_secret_key_noise_bound() + 4 * fresh_secret_key_noise_bound();
    assert_noise_bounded(
        &decryptor.decrypt(&rotated).unwrap(),
        &expected,
        bound,
        MODULUS,
    );
}

#[test]
fn repack_combines_scalar_ciphertexts_into_one_coefficient_packed_ciphertext() {
    let (params, sk, _) = key_material();
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    let messages = [7u64, 11, 13, 17];
    let cts: Vec<Ciphertext> = messages
        .iter()
        .map(|&m| encryptor.encrypt(&plaintext(&[m]), &mut rng).unwrap())
        .collect();

    let repacked = evaluator.repack(&cts).unwrap();
    assert_eq!(repacked.degree(), 1);

    let expected = plaintext(&messages);
    // Each input contributes independent fresh noise, permuted (not grown)
    // by its own monomial shift, then summed - N independent noise sources,
    // triangle-inequality bounded by N times a single fresh bound.
    let bound = messages.len() as u64 * fresh_secret_key_noise_bound();
    assert_noise_bounded(
        &decryptor.decrypt(&repacked).unwrap(),
        &expected,
        bound,
        MODULUS,
    );
}

#[test]
fn repack_rejects_empty_input_and_too_many_ciphertexts() {
    let (params, sk, _) = key_material();
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk);
    let evaluator = Evaluator::new(params);

    assert!(evaluator.repack(&[]).is_err());

    let ct = encryptor.encrypt(&plaintext(&[1]), &mut rng).unwrap();
    let too_many: Vec<Ciphertext> = (0..=DEGREE).map(|_| ct.clone()).collect();
    assert!(evaluator.repack(&too_many).is_err());
}

#[test]
fn rotation_changes_coefficients_without_changing_shape() {
    // Pure coefficient-rotation mechanics, no encryption/noise involved -
    // kept on its own small ring rather than the shared noise-tolerant
    // params() above, since it only needs to match Ciphertext's own degree.
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    let params = RlweParams::builder().ring(ring).build().unwrap();
    let evaluator = Evaluator::new(params);
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
