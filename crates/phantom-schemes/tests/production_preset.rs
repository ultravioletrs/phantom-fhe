//! A production-shaped parameter preset (Alpha Hardening Workstream 2 item
//! 2): every other preset in this crate's own tests, examples, and docs is
//! a tiny `degree=8` development size (see
//! `docs/user-guide.md#choosing-parameters`) - there is no example anywhere
//! of parameters sized for real security. This file is that one example:
//! a degree/modulus choice that actually passes
//! `.require_128_bit_security()` against the homomorphicencryption.org
//! table `phantom_lattice::security::max_secure_total_modulus_bits_128`
//! already reproduces, proven correct end to end (real keygen, encrypt,
//! multiply, relinearize, decrypt) for BGV, BFV, and CKKS alike - not just
//! asserted in prose.
//!
//! This is deliberately narrow: one representative preset for one
//! multiplication of depth, not a general production-parameter methodology
//! or a family of presets for different circuit depths, and not an
//! independent cryptographic security review of the choice - see
//! `docs/user-guide.md#choosing-parameters` and `SECURITY.md` for the exact
//! scope this is (and isn't) claiming.
//!
//! # Parameters
//!
//! - Degree `N = 8192` (the homomorphicencryption.org table's own 128-bit
//!   budget at this degree is 218 bits of total ciphertext modulus).
//! - `Q` (ciphertext moduli): 3 NTT-friendly primes `q ≡ 1 (mod 2N)`, each
//!   ~55 bits, totalling ~165 bits - comfortably under the 218-bit cap,
//!   independently verified prime via a Python-side deterministic
//!   Miller-Rabin check before use here (the same "verify in Python before
//!   trusting it in Rust" discipline `phantom-ring/tests/phase2.rs`'s own
//!   large-basis test already uses).
//! - `P` (auxiliary hybrid key-switching *and* BFV `mul_real` extended-basis
//!   moduli): 4 primes, no NTT requirement (`P` is never part of `Ring`'s
//!   own NTT structure, only RNS basis extension - see
//!   `phantom_lattice::rlwe::keyswitch`'s own module doc comment), each ~58
//!   bits, totalling ~232 bits. Sized for the *stricter* of two
//!   requirements: hybrid key-switching only needs `P` comparable to `Q`'s
//!   largest single prime, but BFV's own `mul_real`/`rescale_and_round`
//!   needs the combined `QP` to exceed `degree * (Q/2)^2` (~341 bits here)
//!   to reconstruct its raw tensor product without wraparound - `QP` here
//!   is ~397 bits, ~56 bits of margin. An earlier, smaller `P` (2 primes,
//!   ~116 bits total - enough for key-switching alone) silently produced a
//!   completely wrong BFV decryption, found and fixed by computing the
//!   actual bound `rescale_and_round`'s own doc comment states, not by
//!   guessing.
//!   **Known limitation, stated explicitly rather than silently assumed
//!   safe:** `.require_128_bit_security()` checks only `Q` against the
//!   standard table - it has no concept of `P` at all (`P` is passed
//!   separately to `generate_hybrid_relinearization_key`/`mul_real`, never
//!   part of `BgvParams`/`BfvParams`/`CkksParams` themselves), so `QP`'s
//!   bit-length here has not been checked against any published table for
//!   an extended-dimension RLWE instance.
//! - Plaintext modulus (BGV/BFV): `t = 65537` (prime, coprime to every `Q`
//!   prime by construction, far below the smallest `Q` prime).
//! - CKKS default scale: `2^55`, deliberately close to `Q`'s own ~55-bit
//!   prime size - CKKS's rescale step divides out exactly one `Q` modulus,
//!   so precision is best when that modulus is close in size to the
//!   tracked scale; a scale far smaller than the modulus it rescales by
//!   leaves real, structural extra imprecision beyond ordinary noise growth.
//!
//! These three tests are `#[ignore]`d by default - real computation at this
//! degree takes minutes on today's unoptimized RNS/bignum hot paths (see
//! `docs/technical-manual.md#performance`), too slow for every routine
//! `cargo test`/`make check` run. Run them explicitly with `cargo test -p
//! phantom-schemes --test production_preset -- --ignored --nocapture`.

use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_ring::Modulus;
use phantom_schemes::bfv::{BfvContext, BfvParams};
use phantom_schemes::bgv::{BgvContext, BgvParams};
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DEGREE: usize = 8192;
const Q0: u64 = 36_028_797_018_652_673;
const Q1: u64 = 36_028_797_017_571_329;
const Q2: u64 = 36_028_797_017_456_641;
const P0: u64 = 288_230_376_151_711_717;
const P1: u64 = 288_230_376_151_711_687;
const P2: u64 = 288_230_376_151_711_681;
const P3: u64 = 288_230_376_151_711_607;
const T: u64 = 65_537;
// Matches Q's own ~55-bit prime size deliberately: CKKS's rescale step
// divides out exactly one Q modulus, so precision is best when that
// modulus is close in size to the tracked scale itself - a scale far
// smaller than the modulus it rescales by (an earlier, smaller value here)
// leaves real, structural extra imprecision beyond noise growth alone.
const CKKS_SCALE_BITS: u32 = 55;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([41; 32])
}

fn q_moduli() -> Vec<u64> {
    vec![Q0, Q1, Q2]
}

// 4 primes (~232 bits total), not the 2 (~116 bits) an earlier version of
// this preset used: BFV's `mul_real` tensors within the extended `QP` ring
// and then needs to reconstruct the *true*, unreduced coefficient value via
// CRT before rescaling - `rescale_and_round`'s own doc comment gives the
// exact bound, `degree * (Q/2)^2` (Q ~165 bits, degree=8192 here, needing
// QP > ~341 bits) - a stricter requirement than hybrid key-switching's own
// "P at least comparable to Q's largest single prime" rule, which is all
// the 2-prime version above satisfied. Found the hard way: the 2-prime
// version silently produced a completely wrong (not just imprecise) BFV
// decryption, every single decoded value different from expected -
// wraparound in `rescale_and_round`'s CRT reconstruction, exactly the
// failure mode its own doc comment warns about.
fn p_moduli() -> [Modulus; 4] {
    [
        Modulus::new(P0).unwrap(),
        Modulus::new(P1).unwrap(),
        Modulus::new(P2).unwrap(),
        Modulus::new(P3).unwrap(),
    ]
}

fn bgv_production_params() -> BgvParams {
    BgvParams::builder()
        .degree(DEGREE)
        .moduli(q_moduli())
        .plaintext_modulus(T)
        .require_128_bit_security()
        .build()
        .unwrap_or_else(|e| {
            panic!("production BGV preset failed its security/consistency check: {e}")
        })
}

fn bfv_production_params() -> BfvParams {
    BfvParams::builder()
        .degree(DEGREE)
        .moduli(q_moduli())
        .plaintext_modulus(T)
        .require_128_bit_security()
        .build()
        .unwrap_or_else(|e| {
            panic!("production BFV preset failed its security/consistency check: {e}")
        })
}

fn ckks_production_params() -> CkksParams {
    CkksParams::builder()
        .degree(DEGREE)
        .moduli(q_moduli())
        .default_scale_bits(CKKS_SCALE_BITS)
        .require_128_bit_security()
        .build()
        .unwrap_or_else(|e| {
            panic!("production CKKS preset failed its security/consistency check: {e}")
        })
}

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
#[ignore = "slow at production scale (N=8192) on today's unoptimized RNS/bignum hot paths - run explicitly with `--ignored`"]
fn bgv_production_preset_passes_128_bit_security_and_round_trips_after_one_multiplication() {
    let params = bgv_production_params();
    let ctx = BgvContext::new(params);
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair_real(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..DEGREE as u64).map(|i| i % T).collect();
    let b_values: Vec<u64> = (0..DEGREE as u64).map(|i| (3 * i) % T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    let product = evaluator.mul(&a_ct, &b_ct, None).unwrap();

    let decomposition_params = GadgetDecompositionParams::new(16, 4).unwrap();
    let relin_key = keygen
        .generate_relinearization_key_real(&keys.secret, decomposition_params, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();

    let decrypted = decryptor.decrypt(&relinearized).unwrap();
    let expected = negacyclic_mul_mod(&a_values, &b_values, T);
    assert_eq!(encoder.decode_u64(&decrypted).unwrap(), expected);

    // Real, not just nominal, headroom: chain the same noise-bound
    // functions bgv::noise's own unit tests use, at this preset's actual
    // scale, and confirm decryption correctness has real margin behind it.
    let fresh = phantom_schemes::bgv::noise::fresh_secret_key_noise_bound();
    let after_mul = phantom_schemes::bgv::noise::mul_noise_bound(DEGREE, T, fresh);
    let total_levels = q_moduli().len() * decomposition_params.levels();
    let after_relin = phantom_schemes::bgv::noise::relinearize_noise_bound(
        DEGREE,
        total_levels,
        decomposition_params.base_log(),
        after_mul,
    );
    let budget = ctx.noise_budget_bits(after_relin);
    println!("bgv production preset noise budget after mul+relinearize: {budget} bits");
    assert!(budget > 0.0, "expected positive noise budget, got {budget}");
}

#[test]
#[ignore = "slow at production scale (N=8192) on today's unoptimized RNS/bignum hot paths - run explicitly with `--ignored`"]
fn bfv_production_preset_passes_128_bit_security_and_round_trips_after_one_multiplication() {
    let params = bfv_production_params();
    let ctx = BfvContext::new(params);
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..DEGREE as u64).map(|i| i % T).collect();
    let b_values: Vec<u64> = (0..DEGREE as u64).map(|i| (3 * i) % T).collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    let p_moduli = p_moduli();
    let product = evaluator.mul_real(&a_ct, &b_ct, &p_moduli).unwrap();

    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();

    let decrypted = decryptor.decrypt(&relinearized).unwrap();
    let expected = negacyclic_mul_mod(&a_values, &b_values, T);
    assert_eq!(encoder.decode_u64_real(&decrypted).unwrap(), expected);

    // BFV's own noise module has no formally-derived relinearization bound
    // yet (see SECURITY.md) - only the pre-relinearization multiplication
    // bound is checked here, honestly reflecting what's actually derived.
    let fresh = phantom_schemes::bfv::noise::fresh_secret_key_noise_bound();
    let after_mul = phantom_schemes::bfv::noise::mul_noise_bound(DEGREE, T, fresh);
    let budget = ctx.noise_budget_bits(after_mul);
    println!("bfv production preset noise budget after mul (pre-relinearize): {budget} bits");
    assert!(budget > 0.0, "expected positive noise budget, got {budget}");
}

#[test]
#[ignore = "slow at production scale (N=8192) on today's unoptimized RNS/bignum hot paths - run explicitly with `--ignored`"]
fn ckks_production_preset_passes_128_bit_security_and_round_trips_after_one_multiplication() {
    let params = ckks_production_params();
    let ctx = CkksContext::new(params);
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator();

    let a_values = [Complex64::new(1.0, 0.5), Complex64::new(-2.0, 1.0)];
    let b_values = [Complex64::new(0.5, -0.5), Complex64::new(1.0, 2.0)];
    let a_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&b_values).unwrap(), &mut rng)
        .unwrap();

    let product = evaluator.mul_real(&a_ct, &b_ct).unwrap();

    let p_moduli = p_moduli();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
    let rescaled = evaluator.rescale_next_real(&relinearized).unwrap();

    let decrypted = decryptor.decrypt_real(&rescaled).unwrap();
    let decoded_values = encoder.decode_complex_real(&decrypted).unwrap();

    let expected: Vec<Complex64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| *a * *b)
        .collect();
    for (actual, expected) in decoded_values.iter().zip(&expected) {
        assert!(
            (actual.re - expected.re).abs() < 1e-3,
            "{actual:?} != {expected:?}"
        );
        assert!(
            (actual.im - expected.im).abs() < 1e-3,
            "{actual:?} != {expected:?}"
        );
    }

    let precision_bits = rescaled.precision().bits();
    println!(
        "ckks production preset precision after mul+relinearize+rescale: {precision_bits} bits"
    );
    assert!(
        precision_bits > 0.0,
        "expected positive precision, got {precision_bits}"
    );
}
