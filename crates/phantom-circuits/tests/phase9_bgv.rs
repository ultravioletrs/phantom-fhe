use phantom_circuits::bgv::{LinearTransformEvaluator, PolynomialEvaluator};
use phantom_circuits::common::{LinearTransform, PolynomialEvalStrategy};
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bgv::{BgvContext, BgvParams};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(257).unwrap(), Modulus::new(769).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, 17).unwrap()
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([13; 32])
}

#[test]
fn bgv_linear_transform_applies_dense_matrix_to_slots() {
    let ctx = BgvContext::new(params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let circuit = LinearTransformEvaluator::new(params());

    let input = encryptor
        .encrypt(
            &encoder.encode_u64(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            &mut rng,
        )
        .unwrap();
    let transform = LinearTransform::dense(vec![
        vec![1, 1, 0, 0, 0, 0, 0, 0],
        vec![0, 1, 1, 0, 0, 0, 0, 0],
        vec![0, 0, 1, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 1, 0, 0, 0],
        vec![0, 0, 0, 0, 1, 1, 0, 0],
        vec![0, 0, 0, 0, 0, 1, 1, 0],
        vec![0, 0, 0, 0, 0, 0, 1, 1],
        vec![1, 0, 0, 0, 0, 0, 0, 1],
    ])
    .unwrap();

    let output = circuit.apply(&input, &transform).unwrap();
    let decrypted = decryptor.decrypt(&output).unwrap();

    assert_eq!(
        encoder.decode_u64(&decrypted).unwrap(),
        vec![3, 5, 7, 9, 11, 13, 15, 9]
    );
}

#[test]
fn bgv_linear_transform_reuses_common_diagonal_and_bsgs_plans() {
    let circuit = LinearTransformEvaluator::new(params());
    let transform = LinearTransform::slot_permutation(8, 1, 0u64, 1u64).unwrap();

    let diagonals = circuit.diagonalize(&transform).unwrap();
    let plan = circuit.bsgs_plan(&transform, 2).unwrap();

    assert_eq!(diagonals.diagonals().len(), 1);
    assert_eq!(diagonals.diagonals()[0].offset(), 1);
    assert_eq!(plan.diagonal_offsets(), &[1]);
    assert_eq!(plan.decompose_offset(1), Some((0, 1)));
}

#[test]
fn bgv_diagonal_transform_matches_dense_application() {
    let ctx = BgvContext::new(params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let circuit = LinearTransformEvaluator::new(params());

    let input = encryptor
        .encrypt(&encoder.encode_u64(&[4, 3, 2, 1]).unwrap(), &mut rng)
        .unwrap();
    let transform = LinearTransform::slot_permutation(8, 1, 0u64, 1u64).unwrap();
    let diagonals = circuit.diagonalize(&transform).unwrap();

    let output = circuit.apply_diagonal(&input, &diagonals).unwrap();
    let decrypted = decryptor.decrypt(&output).unwrap();

    assert_eq!(
        &encoder.decode_u64(&decrypted).unwrap()[..5],
        &[3, 2, 1, 0, 0]
    );
}

#[test]
fn bgv_polynomial_evaluator_applies_exact_modular_polynomial() {
    let ctx = BgvContext::new(params());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let circuit = PolynomialEvaluator::new(params()).unwrap();

    let input = encryptor
        .encrypt(&encoder.encode_u64(&[0, 1, 2, 3, 4]).unwrap(), &mut rng)
        .unwrap();
    let output = circuit.evaluate(&input, &[5, 3, 2], None).unwrap();
    let decrypted = decryptor.decrypt(&output).unwrap();

    assert_eq!(
        &encoder.decode_u64(&decrypted).unwrap()[..5],
        &[5, 10, 2, 15, 15]
    );
}

#[test]
fn bgv_polynomial_evaluator_exposes_common_planning() {
    let circuit = PolynomialEvaluator::new(params()).unwrap();
    let plan = circuit.plan(&[1u64, 0, 2, 0, 3, 4, 5, 6, 7]).unwrap();

    assert_eq!(plan.degree(), 8);
    assert_eq!(plan.strategy(), PolynomialEvalStrategy::PatersonStockmeyer);
    assert!(plan.paterson_stockmeyer().is_some());
}
