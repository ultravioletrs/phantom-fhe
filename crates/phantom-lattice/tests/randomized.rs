//! Larger randomized end-to-end tests across `phantom-lattice`'s RLWE/RGSW
//! operations (Workstream 4 item 9) - complementing `phase3_rlwe.rs`'s and
//! `phase4_rgsw.rs`'s fixed-seed, handful-of-cases coverage with many random
//! trials per operation, matching the style `phantom-ring/tests/
//! rns_randomized.rs` established (`ChaCha20Rng`, hundreds of trials inside
//! one `#[test]`, rather than one `#[test]` per case). Key material (secret
//! key, relinearization key, Galois key, RGSW key) is generated once per
//! test and reused across trials - only plaintext content and encryption
//! randomness vary per trial, matching realistic usage.

use phantom_lattice::noise::{
    external_product_noise_bound, fresh_public_key_noise_bound, fresh_secret_key_noise_bound,
    mul_noise_bound,
};
use phantom_lattice::rgsw::{external_product, GadgetDecompositionParams, RgswCiphertext, RgswKey};
use phantom_lattice::rlwe::{
    Ciphertext, Decryptor, Encryptor, Evaluator, KeyGenerator, Plaintext, RlweParams,
    SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

const TRIALS: usize = 300;

// Same realistically-sized ring and auxiliary P moduli phase3_rlwe.rs and
// phase4_rgsw.rs use (real σ=3.2 noise needs the headroom - see their own
// comments for the derivation).
const DEGREE: usize = 8;
const MODULUS: u64 = 4_000_081;
const P_MODULI: [u64; 2] = [4_000_063, 4_000_067];

fn params() -> RlweParams {
    let ring = Ring::new_ntt(
        Degree::new(DEGREE).unwrap(),
        vec![Modulus::new(MODULUS).unwrap()],
    )
    .unwrap();
    RlweParams::builder().ring(ring).build().unwrap()
}

fn p_moduli() -> Vec<Modulus> {
    P_MODULI.iter().map(|&p| Modulus::new(p).unwrap()).collect()
}

/// A random plaintext with every coefficient drawn uniformly from
/// `[0, bound)`.
fn random_plaintext(rng: &mut ChaCha20Rng, bound: u64) -> Plaintext {
    Plaintext::new(random_poly(rng, bound))
}

fn random_poly(rng: &mut ChaCha20Rng, bound: u64) -> Poly {
    Poly::from_coeffs(vec![(0..DEGREE).map(|_| rng.next_u64() % bound).collect()]).unwrap()
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
fn secret_key_round_trip_holds_across_many_random_messages() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([100u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params, sk);

    for _ in 0..TRIALS {
        let pt = random_plaintext(&mut rng, MODULUS);
        let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
        let out = decryptor.decrypt(&ct).unwrap();
        assert_noise_bounded(&out, &pt, fresh_secret_key_noise_bound(), MODULUS);
    }
}

#[test]
fn public_key_round_trip_holds_across_many_random_messages() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([101u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
    let encryptor = Encryptor::with_public_key(params.clone(), pk);
    let decryptor = Decryptor::new(params, sk);

    for _ in 0..TRIALS {
        let pt = random_plaintext(&mut rng, MODULUS);
        let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
        let out = decryptor.decrypt(&ct).unwrap();
        assert_noise_bounded(&out, &pt, fresh_public_key_noise_bound(DEGREE), MODULUS);
    }
}

#[test]
fn add_and_sub_match_independent_modular_arithmetic_across_many_random_pairs() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([102u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
    let encryptor = Encryptor::with_public_key(params.clone(), pk);
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());
    let combined_bound = 2 * fresh_public_key_noise_bound(DEGREE);

    for _ in 0..TRIALS {
        let a = random_plaintext(&mut rng, MODULUS);
        let b = random_plaintext(&mut rng, MODULUS);
        let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
        let ct_b = encryptor.encrypt(&b, &mut rng).unwrap();

        let expected_sum = Plaintext::new(params.ring().add(a.value(), b.value()).unwrap());
        let sum = evaluator.add(&ct_a, &ct_b).unwrap();
        assert_noise_bounded(
            &decryptor.decrypt(&sum).unwrap(),
            &expected_sum,
            combined_bound,
            MODULUS,
        );

        let expected_diff = Plaintext::new(params.ring().sub(a.value(), b.value()).unwrap());
        let diff = evaluator.sub(&ct_a, &ct_b).unwrap();
        assert_noise_bounded(
            &decryptor.decrypt(&diff).unwrap(),
            &expected_diff,
            combined_bound,
            MODULUS,
        );
    }
}

#[test]
fn multiplication_matches_schoolbook_reference_across_many_random_pairs() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([103u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
    let encryptor = Encryptor::with_public_key(params.clone(), pk);
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    // Keep operand coefficients small (as multiplication_outputs_degree_two_
    // and_decrypts in phase3_rlwe.rs does) - mul_noise_bound's derivation is
    // in terms of a bounded plaintext coefficient magnitude, not a full
    // modulus-sized one.
    let coeff_bound = 8;
    let bound = mul_noise_bound(
        DEGREE,
        coeff_bound - 1,
        fresh_public_key_noise_bound(DEGREE),
    );

    for _ in 0..TRIALS {
        let a = random_plaintext(&mut rng, coeff_bound);
        let b = random_plaintext(&mut rng, coeff_bound);
        let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
        let ct_b = encryptor.encrypt(&b, &mut rng).unwrap();

        let product = evaluator.mul(&ct_a, &ct_b).unwrap();
        assert_eq!(product.degree(), 2);

        let expected = Plaintext::new(params.ring().schoolbook_mul(a.value(), b.value()).unwrap());
        assert_noise_bounded(
            &decryptor.decrypt(&product).unwrap(),
            &expected,
            bound,
            MODULUS,
        );
    }
}

#[test]
fn real_relinearization_matches_the_true_product_across_many_random_pairs() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([104u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&sk, &p_moduli(), &mut rng)
        .unwrap();
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    let coeff_bound = 8;
    let bound = mul_noise_bound(DEGREE, coeff_bound - 1, fresh_secret_key_noise_bound())
        + 4 * fresh_secret_key_noise_bound();

    for _ in 0..TRIALS {
        let a = random_plaintext(&mut rng, coeff_bound);
        let b = random_plaintext(&mut rng, coeff_bound);
        let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
        let ct_b = encryptor.encrypt(&b, &mut rng).unwrap();

        let product = evaluator.mul(&ct_a, &ct_b).unwrap();
        let relinearized = evaluator.relinearize(&product, &relin_key).unwrap();
        assert_eq!(relinearized.degree(), 1);

        let expected = Plaintext::new(params.ring().schoolbook_mul(a.value(), b.value()).unwrap());
        assert_noise_bounded(
            &decryptor.decrypt(&relinearized).unwrap(),
            &expected,
            bound,
            MODULUS,
        );
    }
}

#[test]
fn real_galois_automorphism_matches_plaintext_sigma_across_many_random_messages() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([105u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    // element=3 is coprime to 2*DEGREE=16 - the same element phase3_rlwe.rs
    // uses, hand-verified against direct polynomial substitution in
    // phantom-ring/tests/automorphism.rs.
    let element = 3;
    let galois_key = keygen
        .generate_hybrid_galois_key(element, &sk, &p_moduli(), &mut rng)
        .unwrap();
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    let bound = fresh_secret_key_noise_bound() + 4 * fresh_secret_key_noise_bound();

    for _ in 0..TRIALS {
        let pt = random_plaintext(&mut rng, MODULUS);
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
        assert_noise_bounded(
            &decryptor.decrypt(&rotated).unwrap(),
            &expected,
            bound,
            MODULUS,
        );
    }
}

#[test]
fn repack_matches_coefficient_packing_across_many_random_message_sets() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([106u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());

    let bound = DEGREE as u64 * fresh_secret_key_noise_bound();

    for _ in 0..TRIALS {
        let messages: Vec<u64> = (0..DEGREE).map(|_| rng.next_u64() % MODULUS).collect();
        let cts: Vec<Ciphertext> = messages
            .iter()
            .map(|&m| {
                let single = Plaintext::new(
                    Poly::from_coeffs(vec![{
                        let mut c = vec![0u64; DEGREE];
                        c[0] = m;
                        c
                    }])
                    .unwrap(),
                );
                encryptor.encrypt(&single, &mut rng).unwrap()
            })
            .collect();

        let repacked = evaluator.repack(&cts).unwrap();
        let expected = Plaintext::new(Poly::from_coeffs(vec![messages.clone()]).unwrap());
        assert_noise_bounded(
            &decryptor.decrypt(&repacked).unwrap(),
            &expected,
            bound,
            MODULUS,
        );
    }
}

#[test]
fn rgsw_external_product_matches_schoolbook_reference_across_many_random_pairs() {
    let params = params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([107u8; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let encryptor = Encryptor::with_secret_key(params.clone(), sk.clone());
    let decryptor = Decryptor::new(params.clone(), sk.clone());
    let key = RgswKey::new(sk);
    let decomposition_params = GadgetDecompositionParams::new(8, 3).unwrap();

    let coeff_bound = 4;
    let bound = external_product_noise_bound(
        DEGREE,
        coeff_bound - 1,
        fresh_secret_key_noise_bound(),
        decomposition_params.levels(),
        decomposition_params.base_log(),
    );

    for _ in 0..TRIALS {
        let pt = random_plaintext(&mut rng, coeff_bound);
        let multiplier = random_poly(&mut rng, coeff_bound);
        let rgsw =
            RgswCiphertext::encrypt(&params, &multiplier, &key, decomposition_params, &mut rng)
                .unwrap();
        let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

        let product_ct = external_product(&params, decomposition_params, &ct, &rgsw).unwrap();
        let product_pt = decryptor.decrypt(&product_ct).unwrap();
        let expected = params
            .ring()
            .schoolbook_mul(pt.value(), &multiplier)
            .unwrap();

        assert_noise_bounded(&product_pt, &Plaintext::new(expected), bound, MODULUS);
    }
}
