//! Cross-checks for Workstream 5 item 5's noise/error estimates
//! (`bgv::noise`, `bfv::noise`) against *actual* real encrypt/multiply/
//! relinearize pipelines - not just the formulas' own internal
//! consistency (covered by each module's unit tests), but that a positive
//! predicted budget genuinely corresponds to a still-decryptable
//! ciphertext at realistically-sized parameters.

use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bfv::{self, BfvContext, BfvParams};
use phantom_schemes::bgv::{self, BgvContext, BgvParams};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const REAL_DEGREE: usize = 8;
const REAL_MODULUS: u64 = 1_000_000_000_000_037;
const REAL_T: u64 = 17;

fn bgv_params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(REAL_MODULUS).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, REAL_T).unwrap()
}

fn bfv_params() -> BfvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(REAL_MODULUS).unwrap()],
    )
    .unwrap();
    BfvParams::new(ring, REAL_T).unwrap()
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([21; 32])
}

/// `mul`/`mul_real` perform raw negacyclic polynomial multiplication of
/// the encoded coefficient vectors (confirmed by `phase5_bgv.rs`'s own
/// hand-checked example, `[2,3,4,0]*[5,6,1,0] = [10,10,6,10]`, not the
/// elementwise product) - matches that here so the expected product is
/// computed the same way the real evaluator computes it, not guessed.
// `i`/`j` index `a`/`b` while also computing `k` for `out` - no single
// iterator covers all three, matching this crate's existing precedent for
// this exact shape (e.g. `phantom_ring::rns::extension::reconstruct_true_values`).
#[allow(clippy::needless_range_loop)]
fn negacyclic_mul_mod(a: &[u64], b: &[u64], t: u64) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0i64; n];
    for i in 0..n {
        for j in 0..n {
            let k = i + j;
            let term = (a[i] * b[j]) as i64;
            if k >= n {
                out[k - n] -= term;
            } else {
                out[k] += term;
            }
        }
    }
    out.into_iter()
        .map(|v| v.rem_euclid(t as i64) as u64)
        .collect()
}

#[test]
fn bgv_context_noise_budget_methods_match_the_free_functions() {
    let ctx = BgvContext::new(bgv_params());
    let moduli = [REAL_MODULUS];

    let fresh_sk = bgv::noise::fresh_secret_key_noise_bound();
    assert_eq!(
        ctx.fresh_secret_key_noise_budget_bits(),
        bgv::noise::noise_budget_bits(&moduli, REAL_T, fresh_sk)
    );

    let fresh_pk = bgv::noise::fresh_public_key_noise_bound(REAL_DEGREE);
    assert_eq!(
        ctx.fresh_public_key_noise_budget_bits(),
        bgv::noise::noise_budget_bits(&moduli, REAL_T, fresh_pk)
    );

    assert_eq!(
        ctx.noise_budget_bits(12345),
        bgv::noise::noise_budget_bits(&moduli, REAL_T, 12345)
    );
}

#[test]
fn bgv_noise_budget_predicts_correctness_across_encrypt_mul_and_relinearize() {
    let ctx = BgvContext::new(bgv_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair_real(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i % REAL_T).collect();
    let b_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| (2 * i) % REAL_T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    let fresh_noise = bgv::noise::fresh_secret_key_noise_bound();
    assert!(ctx.noise_budget_bits(fresh_noise) > 0.0);

    let product = evaluator.mul(&a_ct, &b_ct, None).unwrap();
    let after_mul = bgv::noise::mul_noise_bound(REAL_DEGREE, REAL_T, fresh_noise);
    assert!(ctx.noise_budget_bits(after_mul) > 0.0);
    let decrypted_product = decryptor.decrypt(&product).unwrap();
    let expected = negacyclic_mul_mod(&a_values, &b_values, REAL_T);
    assert_eq!(encoder.decode_u64(&decrypted_product).unwrap(), expected);

    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();
    let relin_key = keygen
        .generate_relinearization_key_real(&keys.secret, decomposition_params, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
    let after_relin = bgv::noise::relinearize_noise_bound(REAL_DEGREE, 7, 8, after_mul);
    assert!(ctx.noise_budget_bits(after_relin) > 0.0);
    let decrypted_relinearized = decryptor.decrypt(&relinearized).unwrap();
    assert_eq!(
        encoder.decode_u64(&decrypted_relinearized).unwrap(),
        expected
    );
}

#[test]
fn bfv_context_noise_budget_methods_match_the_free_functions() {
    let ctx = BfvContext::new(bfv_params());
    let moduli = [REAL_MODULUS];

    let fresh_sk = bfv::noise::fresh_secret_key_noise_bound();
    assert_eq!(
        ctx.fresh_secret_key_noise_budget_bits(),
        bfv::noise::noise_budget_bits(&moduli, REAL_T, fresh_sk)
    );

    let fresh_pk = bfv::noise::fresh_public_key_noise_bound(REAL_DEGREE);
    assert_eq!(
        ctx.fresh_public_key_noise_budget_bits(),
        bfv::noise::noise_budget_bits(&moduli, REAL_T, fresh_pk)
    );
}

#[test]
fn bfv_noise_budget_predicts_correctness_across_encrypt_and_multiply() {
    let ctx = BfvContext::new(bfv_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i % REAL_T).collect();
    let b_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| (2 * i) % REAL_T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    let fresh_noise = bfv::noise::fresh_secret_key_noise_bound();
    assert!(ctx.noise_budget_bits(fresh_noise) > 0.0);

    let p_moduli = [
        Modulus::new(1_000_000_000_000_091).unwrap(),
        Modulus::new(1_000_000_000_000_159).unwrap(),
    ];
    let product = evaluator.mul_real(&a_ct, &b_ct, &p_moduli).unwrap();
    let after_mul = bfv::noise::mul_noise_bound(REAL_DEGREE, REAL_T, fresh_noise);
    assert!(ctx.noise_budget_bits(after_mul) > 0.0);

    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
    let decrypted = decryptor.decrypt(&relinearized).unwrap();
    let expected = negacyclic_mul_mod(&a_values, &b_values, REAL_T);
    assert_eq!(encoder.decode_u64_real(&decrypted).unwrap(), expected);
}
