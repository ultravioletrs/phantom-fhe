use phantom_lattice::noise::{external_product_noise_bound, fresh_secret_key_noise_bound};
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

// Real RLWE/RGSW encryption both now carry real noise, which modulus=97
// above has no room for (fresh_secret_key_noise_bound() alone can reach 20,
// comparable to the whole modulus) - params() stays small for the
// noise-free structural tests below (gadget decomposition, boundary
// values tied to modulus=97 specifically), and the encryption-carrying
// tests get their own noise-tolerant ring, matching phase3_rlwe.rs's
// degree/modulus exactly (chosen there with real headroom over even the
// worst-case post-multiplication bound, comfortably enough for RGSW's own
// larger worst-case bound too).
const NOISY_DEGREE: usize = 8;
const NOISY_MODULUS: u64 = 4_000_081; // prime, (NOISY_MODULUS - 1) % (2 * NOISY_DEGREE) == 0

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

fn noisy_plaintext(values: &[u64]) -> Poly {
    let mut coeffs = values.to_vec();
    coeffs.resize(NOISY_DEGREE, 0);
    Poly::from_coeffs(vec![coeffs]).unwrap()
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

    let decomposition =
        GadgetDecomposition::decompose(&poly, decomposition_params, params.ring().moduli())
            .unwrap();
    let recomposed = decomposition.recompose(params.ring().moduli()).unwrap();

    assert_eq!(recomposed, poly);
}

#[test]
fn rgsw_encrypt_produces_a_two_block_gadget_matrix_of_the_right_shape() {
    let (params, sk) = noisy_key_material();
    let key = RgswKey::new(sk);
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    let message = noisy_plaintext(&[1, 0, 0, 0]);
    let decomposition_params = GadgetDecompositionParams::new(8, 3).unwrap();

    let ct =
        RgswCiphertext::encrypt(&params, &message, &key, decomposition_params, &mut rng).unwrap();

    assert_eq!(ct.rows()[0].len(), decomposition_params.levels());
    assert_eq!(ct.rows()[1].len(), decomposition_params.levels());
    for row in ct.rows().iter().flatten() {
        // Each row is a real (c0, c1) RLWE ciphertext, not a bare polynomial.
        assert_eq!(row.value().len(), 2);
    }
}

#[test]
fn external_product_multiplies_underlying_plaintexts() {
    let (params, sk) = noisy_key_material();
    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk.clone());
    let key = RgswKey::new(sk);
    let decomposition_params = GadgetDecompositionParams::new(8, 3).unwrap();

    let pt = Plaintext::new(noisy_plaintext(&[1, 2, 0, 0]));
    let multiplier = noisy_plaintext(&[3, 1, 0, 0]);
    let rgsw = RgswCiphertext::encrypt(&params, &multiplier, &key, decomposition_params, &mut rng)
        .unwrap();
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

    let product_ct = external_product(&params, decomposition_params, &ct, &rgsw).unwrap();
    let product_pt = decryptor.decrypt(&product_ct).unwrap();
    let expected = params
        .ring()
        .schoolbook_mul(pt.value(), &multiplier)
        .unwrap();

    // multiplier's max coefficient is 3; ct's own noise bound is a fresh
    // secret-key encryption's.
    let bound = external_product_noise_bound(
        NOISY_DEGREE,
        3,
        fresh_secret_key_noise_bound(),
        decomposition_params.levels(),
        decomposition_params.base_log(),
    );
    assert_noise_bounded(&product_pt, &Plaintext::new(expected), bound, NOISY_MODULUS);
}
