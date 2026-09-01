//! Multi-modulus regression coverage for `GadgetDecomposition`/RGSW's
//! external product - the primitive whose per-modulus bit-slicing was
//! unsound for any ring with more than one RNS modulus (see
//! `phantom_lattice::rgsw::decomposition`'s own module doc comment for the
//! full derivation), a gap every other RGSW test in this crate never
//! exercised (`phase4_rgsw.rs`/`randomized.rs` both use single-modulus
//! rings). Mirrors those files' own structure and helper style, just with a
//! genuinely multi-modulus ring.

use phantom_lattice::noise::{external_product_noise_bound, fresh_secret_key_noise_bound};
use phantom_lattice::rgsw::{
    external_product, GadgetDecomposition, GadgetDecompositionParams, RgswCiphertext, RgswKey,
};
use phantom_lattice::rlwe::{
    Decryptor, Encryptor, KeyGenerator, Plaintext, RlweParams, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DEGREE: usize = 8;
const MODULUS_0: u64 = 1_000_000_000_000_037;
const MODULUS_1: u64 = 1_000_000_000_000_091;

fn params() -> RlweParams {
    let ring = Ring::new(
        Degree::new(DEGREE).unwrap(),
        vec![
            Modulus::new(MODULUS_0).unwrap(),
            Modulus::new(MODULUS_1).unwrap(),
        ],
    )
    .unwrap();
    RlweParams::builder().ring(ring).build().unwrap()
}

fn plaintext(values: &[u64]) -> Poly {
    let mut coeffs = values.to_vec();
    coeffs.resize(DEGREE, 0);
    Poly::from_coeffs(vec![coeffs; 2]).unwrap()
}

fn assert_noise_bounded(actual: &Plaintext, expected: &Plaintext, bound: u64, moduli: &[u64]) {
    for (j, &modulus) in moduli.iter().enumerate() {
        for (&a, &e) in actual.value().coeffs()[j]
            .iter()
            .zip(expected.value().coeffs()[j].iter())
        {
            let diff = (a + modulus - e) % modulus;
            let centered = diff.min(modulus - diff);
            assert!(
                centered <= bound,
                "component {j}: noise {centered} exceeds bound {bound} (actual={a}, expected={e}, modulus={modulus})"
            );
        }
    }
}

#[test]
fn gadget_decomposition_recomposes_a_multi_modulus_polynomial() {
    let params = params();
    let poly = Poly::from_coeffs(vec![
        vec![0, 1, 12345, MODULUS_0 - 1, 999999999999999, 42, 7, 8],
        vec![0, 1, 54321, MODULUS_1 - 1, 111111111111111, 24, 6, 9],
    ])
    .unwrap();
    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();

    let decomposition =
        GadgetDecomposition::decompose(&poly, decomposition_params, params.ring().moduli())
            .unwrap();
    let recomposed = decomposition.recompose(params.ring().moduli()).unwrap();

    assert_eq!(recomposed, poly);
}

#[test]
fn external_product_multiplies_underlying_plaintexts_on_a_multi_modulus_ring() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk.clone());
    let key = RgswKey::new(sk);
    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();

    let pt = Plaintext::new(plaintext(&[1, 2, 0, 0]));
    let multiplier = plaintext(&[3, 1, 0, 0]);
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
    // secret-key encryption's; total_levels = moduli.len() * levels() = 14.
    let bound = external_product_noise_bound(
        DEGREE,
        3,
        fresh_secret_key_noise_bound(),
        params.ring().moduli().len() * decomposition_params.levels(),
        decomposition_params.base_log(),
    );
    assert_noise_bounded(
        &product_pt,
        &Plaintext::new(expected),
        bound,
        &[MODULUS_0, MODULUS_1],
    );
}
