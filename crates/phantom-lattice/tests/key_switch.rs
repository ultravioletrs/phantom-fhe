//! Tests for real RNS hybrid key-switching (Workstream 4 item 3).

use phantom_lattice::rlwe::{
    generate_key_switch_key, key_switch, rebase_ternary_secret, Decryptor, Encryptor, KeyGenerator,
    Plaintext, RlweParams, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// Q: 3 moduli (exercises the RNS-ness of the technique - a single-modulus Q
// would never distinguish this from a textbook key-switch). P: 2 auxiliary
// moduli of comparable size to Q's own, the real requirement hybrid
// switching has for keeping the key-switching key's own noise contribution
// small after mod-down.
const DEGREE: usize = 8;
const Q_MODULI: [u64; 3] = [4000037, 4000039, 4000043];
const P_MODULI: [u64; 2] = [4000063, 4000067];

fn q_params() -> RlweParams {
    let ring = Ring::new(
        Degree::new(DEGREE).unwrap(),
        Q_MODULI.iter().map(|&q| Modulus::new(q).unwrap()).collect(),
    )
    .unwrap();
    RlweParams::builder().ring(ring).build().unwrap()
}

fn p_moduli() -> Vec<Modulus> {
    P_MODULI.iter().map(|&p| Modulus::new(p).unwrap()).collect()
}

fn qp_ring() -> Ring {
    let qp_moduli: Vec<Modulus> = Q_MODULI
        .iter()
        .map(|&q| Modulus::new(q).unwrap())
        .chain(p_moduli())
        .collect();
    Ring::new(Degree::new(DEGREE).unwrap(), qp_moduli).unwrap()
}

fn plaintext(values: &[u64]) -> Plaintext {
    let mut coeffs = values.to_vec();
    coeffs.resize(DEGREE, 0);
    Plaintext::new(Poly::from_coeffs(vec![coeffs; Q_MODULI.len()]).unwrap())
}

/// Centered-residue distance mod `modulus` - the standard way to measure
/// RLWE decryption noise, matching `phase3_rlwe.rs`'s identical helper.
fn centered_distance(a: u64, b: u64, modulus: u64) -> u64 {
    let diff = (a + modulus - b) % modulus;
    diff.min(modulus - diff)
}

/// `fresh_secret_key_noise_bound()` covers `ct`'s own pre-switch noise;
/// key-switching itself adds a small amount on top (each KSK row's fresh
/// noise, scaled by a gadget digit up to a whole Q-modulus in size, but then
/// shrunk back down by dividing by `P` - the whole point of the hybrid
/// technique - plus ModDown's own `O(1)`-per-Q-modulus rounding). Observed
/// noise across this file's trials peaks in the single digits, far under
/// `fresh_secret_key_noise_bound()` (~20) alone; `4x` that bound is a safety
/// margin, not a tight formally-derived key-switching bound - deriving one
/// precisely is real follow-up work (see `noise.rs`'s own scoping note on
/// tightening bounds), not attempted here.
fn noise_bound() -> u64 {
    phantom_lattice::noise::fresh_secret_key_noise_bound() * 4
}

/// Runs one key-switch trial end to end and asserts every coefficient of
/// every Q-basis component decrypts within [`noise_bound`] of the true
/// plaintext.
fn run_trial(seed: u8, values: &[u64]) {
    let params = q_params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);

    let s_old = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let s_new = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);

    let encryptor = Encryptor::with_secret_key(params.clone(), s_old.clone());
    let pt = plaintext(values);
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

    // s_old needs to live in the extended QP ring for generate_key_switch_key;
    // it's ternary here (unlike relinearization's s^2), so the same simple
    // rebase used internally for s_new applies directly.
    let p = p_moduli();
    let s_old_qp =
        rebase_ternary_secret(&s_old, Modulus::new(Q_MODULI[0]).unwrap(), &qp_ring()).unwrap();

    let ksk = generate_key_switch_key(&params, &p, &s_old_qp, &s_new, &mut rng).unwrap();
    let switched = key_switch(&ct, &ksk, &params).unwrap();

    let decryptor = Decryptor::new(params.clone(), s_new);
    let decrypted = decryptor.decrypt(&switched).unwrap();
    let bound = noise_bound();

    for (j, &q) in Q_MODULI.iter().enumerate() {
        let expected = &pt.value().coeffs()[j];
        let actual = &decrypted.value().coeffs()[j];
        for (i, (&e, &a)) in expected.iter().zip(actual.iter()).enumerate() {
            let noise = centered_distance(a, e, q);
            assert!(
                noise <= bound,
                "seed={seed}, component {j}, coefficient {i}: noise {noise} exceeds bound {bound} (expected={e}, actual={a}, modulus={q})"
            );
        }
    }
}

#[test]
fn key_switch_moves_a_ciphertext_to_a_different_ternary_secret() {
    run_trial(21, &[7, 11, 13, 5]);
}

#[test]
fn key_switch_works_across_several_independent_trials() {
    for seed in [1u8, 42, 100, 200, 255] {
        run_trial(seed, &[1, 2, 3, 4]);
    }
}

#[test]
fn key_switch_rejects_a_component_count_mismatch_against_its_own_key() {
    let params = q_params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let s_old = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let s_new = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);

    let p = p_moduli();
    let s_old_qp =
        rebase_ternary_secret(&s_old, Modulus::new(Q_MODULI[0]).unwrap(), &qp_ring()).unwrap();
    let ksk = generate_key_switch_key(&params, &p, &s_old_qp, &s_new, &mut rng).unwrap();

    // A ciphertext built directly with the wrong RNS shape (2 components
    // instead of Q_MODULI.len() == 3) should be rejected, not silently
    // misinterpreted.
    let bad_ct = phantom_lattice::rlwe::Ciphertext::new(vec![
        Poly::from_coeffs(vec![vec![0; DEGREE], vec![0; DEGREE]]).unwrap(),
        Poly::from_coeffs(vec![vec![0; DEGREE], vec![0; DEGREE]]).unwrap(),
    ]);
    assert!(key_switch(&bad_ct, &ksk, &params).is_err());
}

#[test]
fn generate_key_switch_key_rejects_empty_p_moduli() {
    let params = q_params();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let s_old = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let s_new = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);

    let s_old_qp =
        rebase_ternary_secret(&s_old, Modulus::new(Q_MODULI[0]).unwrap(), &qp_ring()).unwrap();
    assert!(generate_key_switch_key(&params, &[], &s_old_qp, &s_new, &mut rng).is_err());
}
