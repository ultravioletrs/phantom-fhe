use phantom_bootstrapping::ckks::{
    default_bootstrap_params, BootstrapKeyGenerator, BootstrapParams, Bootstrapper, CoeffsToSlots,
    EvalMod, Packer, SlotsToCoeffs, Unpacker,
};
use phantom_bootstrapping::{bfv, bgv};
use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64, Precision, Scale};

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
