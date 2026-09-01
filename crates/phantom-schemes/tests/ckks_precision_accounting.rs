//! Evaluator-level integration tests for CKKS's real, parameter-derived
//! precision-degradation formulas (`ckks::noise`, Workstream 5 item 4) -
//! complements `ckks::noise`'s own pure-function unit tests by checking the
//! formulas actually flow through `Evaluator`'s transparent scaffold the
//! way the module doc comment claims. Doesn't touch the real path (see
//! `ckks_real_arithmetic.rs` for that).

use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([13; 32])
}

// `params()`'s toy moduli give a scale of only 2^10 - far too little
// headroom for even a single fresh RLWE noise term, let alone the
// `mod_down` floor-division's own constant "+1" rounding artifact (see
// `ckks::noise`'s module doc comment), to stay negligible against; most
// tests below need a realistically-sized scale (matching
// `ckks_real_arithmetic.rs`'s own moduli) to demonstrate real behavior
// instead of everything flooring to zero - the previous flat-constant
// model didn't distinguish toy from realistic parameters at all, which is
// itself part of what this hardening fixes (see
// `toy_preset_fresh_precision_gracefully_clamps_to_zero_instead_of_going_negative`
// for the toy case).
fn realistic_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![
            1_000_000_000_000_037,
            1_000_000_000_000_091,
            1_073_741_827,
        ])
        .default_scale_bits(30)
        .build()
        .unwrap()
}

#[test]
fn add_costs_close_to_one_bit_for_equal_precision_operands() {
    let ctx = CkksContext::new(realistic_params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let evaluator = ctx.evaluator();

    let lhs = encryptor
        .encrypt(&encoder.encode_real(&[1.0, 2.0]).unwrap(), &mut rng)
        .unwrap();
    let rhs = encryptor
        .encrypt(&encoder.encode_real(&[3.0, 4.0]).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(lhs.precision().bits(), rhs.precision().bits());

    let sum = evaluator.add(&lhs, &rhs).unwrap();
    let degrade = lhs.precision().bits() - sum.precision().bits();
    assert!((degrade - 1.0).abs() < 0.01, "degrade={degrade}");
}

#[test]
fn mul_costs_more_precision_for_larger_magnitude_slots() {
    let ctx = CkksContext::new(realistic_params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let evaluator = ctx.evaluator();

    let small = encryptor
        .encrypt(&encoder.encode_real(&[0.5, 0.5]).unwrap(), &mut rng)
        .unwrap();
    let large = encryptor
        .encrypt(&encoder.encode_real(&[500.0, 500.0]).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(small.precision().bits(), large.precision().bits());

    let small_product = evaluator.mul(&small, &small, None).unwrap();
    let large_product = evaluator.mul(&large, &large, None).unwrap();
    assert!(large_product.precision().bits() < small_product.precision().bits());
}

#[test]
fn toy_preset_fresh_precision_gracefully_clamps_to_zero_instead_of_going_negative() {
    // The toy `params()` preset's scale (2^10) has far less headroom than
    // even a single fresh RLWE noise term - see
    // `ckks::noise::fresh_precision_bits`'s own doc comment. The result
    // should clamp to exactly 0.0 (no precision left), not go negative or
    // panic, and every operation built on top of it should keep working.
    let ctx = CkksContext::new(params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let evaluator = ctx.evaluator();

    let ct = encryptor
        .encrypt(&encoder.encode_real(&[1.0]).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(ct.precision().bits(), 0.0);

    let sum = evaluator.add(&ct, &ct).unwrap();
    assert_eq!(sum.precision().bits(), 0.0);
}

#[test]
fn rescale_after_multiplication_recovers_most_of_the_precision_lost_to_the_squared_scale() {
    let ctx = CkksContext::new(realistic_params());
    let mut rng = rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let eval_keys = keygen.generate_evaluation_keys(&keys.secret, &[]);
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let evaluator = ctx.evaluator();

    let lhs = encryptor
        .encrypt(&encoder.encode_real(&[1.5, 2.0]).unwrap(), &mut rng)
        .unwrap();
    let rhs = encryptor
        .encrypt(&encoder.encode_real(&[3.0, -4.0]).unwrap(), &mut rng)
        .unwrap();
    let fresh_precision = lhs.precision().bits();

    let product = evaluator.mul(&lhs, &rhs, Some(&eval_keys)).unwrap();
    let rescaled = evaluator.rescale_next(&product).unwrap();

    // Rescale is designed to be close to precision-neutral (see
    // ckks::noise's module doc comment) - the precision remaining after
    // mul+rescale should stay within a handful of bits of the fresh
    // precision, not collapse toward zero the way a full extra "1 bit per
    // level" penalty (the previous flat-constant model) would push it for
    // a ring this small.
    assert!(rescaled.precision().bits() > fresh_precision - 10.0);
}

#[test]
fn align_levels_costs_less_than_one_bit_per_level_dropped() {
    let ctx = CkksContext::new(realistic_params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let evaluator = ctx.evaluator();

    let low_level = encryptor
        .encrypt(&encoder.encode_real(&[1.0]).unwrap(), &mut rng)
        .unwrap();
    let low_level = evaluator.rescale_next(&low_level).unwrap();
    let low_level = evaluator.rescale_next(&low_level).unwrap();

    let high_level = encryptor
        .encrypt(&encoder.encode_real(&[1.0]).unwrap(), &mut rng)
        .unwrap();
    assert_eq!(high_level.level() - low_level.level(), 2);

    let (aligned_high, _) = evaluator.align_levels(&high_level, &low_level).unwrap();
    assert_eq!(aligned_high.level(), low_level.level());
    let degrade = high_level.precision().bits() - aligned_high.precision().bits();
    // The previous flat model charged exactly 1 bit per level (2 bits
    // total here); the real formula should charge noticeably less.
    assert!(degrade < 1.5, "degrade={degrade}");
}

#[test]
fn rotate_and_conjugate_no_longer_degrade_precision() {
    let ctx = CkksContext::new(params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let evaluator = ctx.evaluator();

    let ct = encryptor
        .encrypt(
            &encoder
                .encode_complex(&[Complex64::new(1.0, 2.0), Complex64::new(3.0, -1.0)])
                .unwrap(),
            &mut rng,
        )
        .unwrap();

    let rotated = evaluator.rotate_slots(&ct, 1).unwrap();
    assert_eq!(rotated.precision().bits(), ct.precision().bits());

    let conjugated = evaluator.conjugate(&ct).unwrap();
    assert_eq!(conjugated.precision().bits(), ct.precision().bits());
}
