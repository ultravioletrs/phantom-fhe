use phantom_bootstrapping::ckks::{
    default_bootstrap_params, BootstrapKeyGenerator, BootstrapParams, BootstrapParamsLiteral,
    Bootstrapper, CoeffsToSlots, EvalMod, Packer, SlotsToCoeffs, Unpacker,
};
use phantom_bootstrapping::{bfv, bgv};
use phantom_lattice::rlwe::{KeyGenerator as RlweKeyGenerator, SecretDistribution};
use phantom_ring::Modulus;
use phantom_schemes::ckks::{
    Ciphertext, CkksContext, CkksKeyGenerator, CkksParams, Complex64, Precision, Scale,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn ckks_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

fn real_ckks_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .conjugate_invariant(true)
        .build()
        .unwrap()
}

fn ciphertext(slots: &[Complex64], level: usize, precision_bits: f64) -> Ciphertext {
    Ciphertext::new(
        slots.to_vec(),
        Scale::from_bits(7).unwrap(),
        level,
        Precision::new(precision_bits),
        1,
    )
}

fn assert_close(actual: Complex64, expected: Complex64) {
    assert!(
        (actual.re - expected.re).abs() < 1e-9 && (actual.im - expected.im).abs() < 1e-9,
        "{actual:?} != {expected:?}"
    );
}

#[test]
fn bootstrap_params_validate_inputs_and_defaults_work() {
    let params = ckks_params();
    let bootstrap = default_bootstrap_params(params.clone()).unwrap();
    assert_eq!(bootstrap.target_level(), params.initial_level());
    assert_eq!(bootstrap.sparse_slot_count(), params.slot_count());
    assert_eq!(bootstrap.batch_size(), 1);

    assert!(BootstrapParams::builder(params.clone())
        .target_level(params.initial_level() + 1)
        .build()
        .is_err());
    assert!(BootstrapParams::builder(params.clone())
        .target_precision_bits(0.0)
        .build()
        .is_err());
    assert!(BootstrapParams::builder(params)
        .sparse_slot_count(0)
        .build()
        .is_err());
}

#[test]
fn ckks_bootstrap_preserves_message_and_refreshes_metadata() {
    let ckks = ckks_params();
    let params = BootstrapParams::builder(ckks.clone())
        .target_level(ckks.initial_level())
        .target_precision_bits(18.0)
        .build()
        .unwrap();
    let key = BootstrapKeyGenerator::new(params.clone()).generate(&[1, 2]);
    let bootstrapper = Bootstrapper::new(params.clone(), key);
    let input = ciphertext(
        &[
            Complex64::new(1.25, -0.5),
            Complex64::real(-2.0),
            Complex64::new(0.25, 0.75),
        ],
        0,
        4.0,
    );

    let output = bootstrapper.bootstrap(&input).unwrap();

    for (actual, expected) in output.slots().iter().zip(input.slots()) {
        assert_close(*actual, *expected);
    }
    assert_eq!(output.level(), params.target_level());
    assert_eq!(output.scale(), ckks.default_scale());
    assert_eq!(output.precision().bits(), 18.0);
}

#[test]
fn coeffs_to_slots_and_slots_to_coeffs_round_trip() {
    let params = default_bootstrap_params(ckks_params()).unwrap();
    let c2s = CoeffsToSlots::new(params.clone());
    let s2c = SlotsToCoeffs::new(params);
    let input = ciphertext(
        &[
            Complex64::real(1.0),
            Complex64::new(0.0, 1.0),
            Complex64::real(-1.0),
            Complex64::new(0.0, -1.0),
        ],
        1,
        8.0,
    );

    let slots = c2s.apply(&input).unwrap();
    let roundtrip = s2c.apply(&slots).unwrap();

    for (actual, expected) in roundtrip.slots().iter().zip(input.slots()) {
        assert_close(*actual, *expected);
    }
}

#[test]
fn eval_mod_exposes_centered_fractional_part_without_forcing_bootstrap_to_change_messages() {
    let params = default_bootstrap_params(ckks_params()).unwrap();
    let eval_mod = EvalMod::new(params);
    let input = ciphertext(
        &[
            Complex64::real(1.25),
            Complex64::real(-1.25),
            Complex64::real(2.75),
        ],
        1,
        8.0,
    );

    let centered = eval_mod.centered_fractional_part(&input).unwrap();
    assert_close(centered.slots()[0], Complex64::real(0.25));
    assert_close(centered.slots()[1], Complex64::real(-0.25));
    assert_close(centered.slots()[2], Complex64::real(-0.25));

    let preserved = eval_mod.preserve_message(&input).unwrap();
    assert_eq!(preserved.slots(), input.slots());
}

#[test]
fn ckks_bootstrap_removes_an_unknown_multiple_of_the_raise_modulus() {
    // The genuinely meaningful case `preserve_message` could never pass:
    // an `input` engineered so that, once coeffs_to_slots (forward DFT)
    // transforms it, eval-mod actually sees per-slot values that look
    // like a real modulus-raised ciphertext's own - `message +
    // raise_modulus * I` for a nonzero, per-slot-varying integer `I` -
    // and bootstrap() still recovers the true message end to end, proving
    // eval-mod is now doing real (scaled) modular reduction, not an
    // identity.
    //
    // Since DFT is linear, `coeffs_to_slots(input) == message_slots + q*I`
    // is satisfied exactly by taking `input := slots_to_coeffs(message +
    // q*I)` - i.e. applying the *inverse* transform to the whole combined
    // slot-domain target at once, then relying on the round-trip identity
    // `coeffs_to_slots(slots_to_coeffs(x)) == x` (this file's own
    // `coeffs_to_slots_and_slots_to_coeffs_round_trip` test already
    // establishes this). Building `input` as `message + slots_to_coeffs(q*I)`
    // instead - adding the raw message directly rather than also passing
    // it through the inverse transform - silently assumes `message` is
    // already a fixed point of the forward DFT, which it isn't.
    let ckks = ckks_params();
    let raise_modulus = 100.0;
    let params = BootstrapParams::builder(ckks.clone())
        .target_level(ckks.initial_level())
        .target_precision_bits(18.0)
        .raise_modulus(raise_modulus)
        .build()
        .unwrap();
    let key = BootstrapKeyGenerator::new(params.clone()).generate(&[1, 2]);
    let bootstrapper = Bootstrapper::new(params.clone(), key);
    let s2c = SlotsToCoeffs::new(params.clone());

    let messages = [
        Complex64::new(12.5, -7.0),
        Complex64::real(-30.0),
        Complex64::new(5.0, 40.0),
    ];
    let wrap_integers = [(2i64, -1i64), (-3, 0), (0, 4)];
    let wraparound: Vec<Complex64> = wrap_integers
        .iter()
        .map(|&(ire, iim)| Complex64::new(raise_modulus * ire as f64, raise_modulus * iim as f64))
        .collect();
    let combined: Vec<Complex64> = messages
        .iter()
        .zip(&wraparound)
        .map(|(m, w)| Complex64::new(m.re + w.re, m.im + w.im))
        .collect();
    let input = s2c.apply(&ciphertext(&combined, 0, 4.0)).unwrap();

    let output = bootstrapper.bootstrap(&input).unwrap();

    // `output`'s raw field is coefficient-domain (bootstrap's own last step
    // is slots_to_coeffs), so the recovered message must be compared
    // against `slots_to_coeffs(messages)`, not `messages` directly - the
    // same domain `input` itself was built in above.
    let expected_output = s2c.apply(&ciphertext(&messages, 0, 4.0)).unwrap();
    for (actual, expected) in output.slots().iter().zip(expected_output.slots()) {
        assert_close(*actual, *expected);
    }
    assert_eq!(output.level(), params.target_level());
}

#[test]
fn batch_bootstrap_and_sparse_pack_unpack_are_correct() {
    let ckks = ckks_params();
    let params = BootstrapParams::builder(ckks)
        .sparse_slot_count(2)
        .batch_size(2)
        .target_precision_bits(16.0)
        .build()
        .unwrap();
    let key = BootstrapKeyGenerator::new(params.clone()).generate(&[1]);
    let bootstrapper = Bootstrapper::new(params.clone(), key);
    let inputs = vec![
        ciphertext(&[Complex64::real(1.0), Complex64::real(2.0)], 0, 4.0),
        ciphertext(&[Complex64::real(3.0), Complex64::real(4.0)], 0, 4.0),
    ];

    let batch = bootstrapper.bootstrap_batch(&inputs).unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].precision().bits(), 16.0);
    assert_close(batch[1].slots()[1], Complex64::real(4.0));

    let packed = Packer::new(params.clone()).pack(&inputs).unwrap();
    assert_eq!(packed.slots().len(), params.ckks_params().slot_count());
    let unpacked = Unpacker::new(params).unpack(&packed, 2).unwrap();
    assert_eq!(unpacked.len(), 2);
    assert_close(unpacked[0].slots()[0], Complex64::real(1.0));
    assert_close(unpacked[1].slots()[1], Complex64::real(4.0));
}

#[test]
fn conjugate_invariant_bootstrap_accepts_real_and_rejects_complex_slots() {
    let ckks = real_ckks_params();
    let params = default_bootstrap_params(ckks).unwrap();
    let key = BootstrapKeyGenerator::new(params.clone()).generate(&[]);
    let bootstrapper = Bootstrapper::new(params, key);

    let real = ciphertext(&[Complex64::real(1.0), Complex64::real(-2.0)], 0, 4.0);
    assert!(bootstrapper.bootstrap(&real).is_ok());

    let complex = ciphertext(&[Complex64::new(1.0, 1.0)], 0, 4.0);
    assert!(bootstrapper.bootstrap(&complex).is_err());
}

#[test]
fn exact_scheme_bootstrap_modules_are_reserved_placeholders() {
    assert!(bgv::BootstrapParams::experimental().is_experimental());
    assert!(bfv::BootstrapParams::experimental().is_experimental());
    assert!(bgv::Evaluator.bootstrap_unimplemented().is_err());
    assert!(bfv::Evaluator.bootstrap_unimplemented().is_err());
}

// A ring with real noise headroom (unlike ckks_params()'s toy
// [257, 769, 3329] moduli) - the auxiliary "P" moduli below need this much
// room too, so this reuses the same sizing `phantom-schemes`'s own
// `ckks_real_arithmetic.rs` fixture already verified (Miller-Rabin checked
// in Python before use there). Two rescale-sized moduli (not just one),
// since a real coeffs_to_slots/slots_to_coeffs round trip needs to survive
// two chained `LinearTransformEvaluator::apply_real` calls, each consuming
// one level via its own internal rescale (see that method's own doc
// comment for why it rescales).
fn real_arith_ckks_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![1_000_000_000_000_037, 1_073_741_827, 1_073_741_831])
        .default_scale_bits(30)
        .build()
        .unwrap()
}

fn p_moduli() -> Vec<Modulus> {
    vec![
        Modulus::new(1_000_000_000_000_091).unwrap(),
        Modulus::new(1_000_000_000_000_159).unwrap(),
    ]
}

#[test]
fn bootstrap_key_generator_generate_real_produces_real_galois_keys() {
    let ckks = real_arith_ckks_params();
    let params = BootstrapParams::builder(ckks.clone()).build().unwrap();
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let sk = RlweKeyGenerator::new(ckks.rlwe_params().unwrap())
        .generate_secret_key(&mut rng, SecretDistribution::Ternary);

    // element=1 and element=3 are both odd and coprime to 2*degree=16.
    let key = BootstrapKeyGenerator::new(params.clone())
        .generate_real(&sk, &[1, 3], &p_moduli(), &mut rng)
        .unwrap();

    assert_eq!(key.rotation_elements(), &[1, 3]);
    assert_eq!(key.galois_keys().len(), 2);
    assert!(key
        .galois_keys()
        .iter()
        .all(|galois_key| galois_key.key_switch_key().is_some()));
    assert_eq!(key.galois_keys()[0].element(), 1);
    assert_eq!(key.galois_keys()[1].element(), 3);

    // The pre-existing transparent marker path is unaffected by this
    // addition - still no key material.
    let marker = BootstrapKeyGenerator::new(params).generate(&[1, 3]);
    assert!(marker.galois_keys().is_empty());
    assert_eq!(marker.rotation_elements(), &[1, 3]);
}

#[test]
fn bootstrap_params_literal_builds_matching_params_and_still_validates() {
    let ckks = ckks_params();
    let literal = BootstrapParamsLiteral {
        target_level: ckks.initial_level(),
        target_precision_bits: 18.0,
        sparse_slot_count: ckks.slot_count(),
        batch_size: 2,
        raise_modulus: 100.0,
    };

    let built = literal.build(ckks.clone()).unwrap();
    assert_eq!(built.target_level(), ckks.initial_level());
    assert_eq!(built.target_precision_bits(), 18.0);
    assert_eq!(built.sparse_slot_count(), ckks.slot_count());
    assert_eq!(built.batch_size(), 2);
    assert_eq!(built.raise_modulus(), 100.0);

    // Same validation BootstrapParams::new always runs - a literal that
    // doesn't fit ckks_params is still rejected, not silently accepted.
    let too_high = BootstrapParamsLiteral {
        target_level: ckks.initial_level() + 1,
        ..literal
    };
    assert!(too_high.build(ckks).is_err());
}

/// One real `GaloisKey` per rotation offset `1..n` a dense `n x n` DFT
/// matrix's diagonal decomposition needs (every offset, since the DFT is
/// dense, not sparse).
/// One real Galois key per rotation offset `1..n`, valid at `level`
/// specifically - `LinearTransformEvaluator::apply_real` operates entirely
/// at its input ciphertext's own level, and (like relinearization keys) a
/// Galois key generated for one level isn't usable at another, so a
/// multi-call chain that rescales between calls (coefficients-to-slots
/// followed by slots-to-coefficients, each an `apply_real` call - see
/// `CoeffsToSlots::apply_real`'s own doc comment for why each rescales)
/// needs its own key set per level it calls `apply_real` at.
fn dft_galois_keys(
    ckks: &CkksParams,
    sk: &phantom_lattice::rlwe::SecretKey,
    n: usize,
    level: usize,
    rng: &mut ChaCha20Rng,
) -> Vec<phantom_lattice::rlwe::GaloisKey> {
    let keygen = CkksKeyGenerator::new(ckks.clone()).unwrap();
    (1..n)
        .map(|shift| {
            let element = ckks.rotation_element(shift);
            keygen
                .generate_hybrid_galois_key_at_level(element, sk, level, &p_moduli(), rng)
                .unwrap()
        })
        .collect()
}

#[test]
fn coeffs_to_slots_and_slots_to_coeffs_apply_real_round_trip() {
    let ckks = real_arith_ckks_params();
    let params = BootstrapParams::builder(ckks.clone()).build().unwrap();
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let ctx = CkksContext::new(ckks.clone());
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.real_decryptor(keys.secret.clone()).unwrap();

    let n = ckks.slot_count();
    let values: Vec<Complex64> = (0..n)
        .map(|i| Complex64::new(i as f64 - 1.5, 0.25 * i as f64))
        .collect();
    let ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();

    // apply_real rescales, dropping one level - c2s operates at ct's own
    // level, s2c at whatever level c2s's own rescale leaves it at, so each
    // needs its own key set (see dft_galois_keys's own doc comment).
    let forward_keys = dft_galois_keys(&ckks, &keys.secret, n, ct.level(), &mut rng);

    let c2s = CoeffsToSlots::new(params.clone());
    let s2c = SlotsToCoeffs::new(params);

    let forward = c2s.apply_real(&ct, &forward_keys).unwrap();
    let inverse_keys = dft_galois_keys(&ckks, &keys.secret, n, forward.level(), &mut rng);
    let round_tripped = s2c.apply_real(&forward, &inverse_keys).unwrap();

    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&round_tripped).unwrap())
        .unwrap();
    // Real noise, not the transparent scaffold's exact arithmetic - two
    // chained apply_real calls each carry real ciphertext noise (n
    // rotations' own key-switch noise, n plaintext multiplies, a rescale),
    // so this needs the same order-of-magnitude tolerance the rest of
    // `phantom-schemes`'s own real CKKS multi-step tests use, not
    // `assert_close`'s `1e-9` (calibrated for the transparent scaffold's
    // exact float arithmetic).
    for (actual, expected) in decoded.iter().zip(&values) {
        assert!(
            (actual.re - expected.re).abs() < 1e-3 && (actual.im - expected.im).abs() < 1e-3,
            "{actual:?} != {expected:?}"
        );
    }
}
