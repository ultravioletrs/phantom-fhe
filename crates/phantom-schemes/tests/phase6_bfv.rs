use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bfv::{BfvContext, BfvParams, Plaintext};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Independent oracle for what a BFV ciphertext-ciphertext multiplication
/// should decode to: multiplies the two *plaintext* polynomials directly
/// via `schoolbook_mul` (independent of the encryption/decryption pipeline
/// under test - both operands are small, `< t`, so the raw product stays
/// far below `Q`, meaning no `Delta`-rescale is needed to decode it - a
/// plain `decode_u64`, not `decode_u64_real`, correctly recovers `mod t`
/// from this already-small value).
fn expected_product(ctx: &BfvContext, a: &Plaintext, b: &Plaintext) -> Vec<u64> {
    let product = ctx
        .params()
        .ring()
        .schoolbook_mul(a.inner().inner().value(), b.inner().inner().value())
        .unwrap();
    let plaintext = Plaintext::new(phantom_schemes::bgv::Plaintext::new(
        phantom_lattice::rlwe::Plaintext::new(product),
    ));
    ctx.encoder().decode_u64(&plaintext).unwrap()
}

fn params() -> BfvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(257).unwrap(), Modulus::new(769).unwrap()],
    )
    .unwrap();
    BfvParams::new(ring, 17).unwrap()
}

fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([9; 32])
}

// Real BFV encryption scales the message by Delta = floor(q/t) instead of
// scaling noise the way BGV does (see bfv::Encryptor's own module doc
// comment) - the toy [257, 769] moduli params() uses give Delta far too
// small to hold any real noise headroom. Reuses BGV's own real-test
// modulus for consistency (bgv::tests::phase5_bgv.rs), though BFV's
// headroom requirement is actually looser (raw, not t-scaled, noise).
const REAL_DEGREE: usize = 8;
const REAL_MODULUS: u64 = 1_000_000_000_000_037;
const REAL_T: u64 = 17;

fn real_params() -> BfvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(REAL_MODULUS).unwrap()],
    )
    .unwrap();
    BfvParams::new(ring, REAL_T).unwrap()
}

// Auxiliary "P" moduli for real BFV multiplication's rescale-and-round step
// (see Evaluator::mul_real's own doc comment) - needs enough headroom that
// Q*P1*P2 comfortably exceeds the raw tensor product's worst-case true
// magnitude, roughly degree*(Q/2)^2. Both individually prime (Miller-Rabin
// verified in Python before use, matching REAL_MODULUS's own precedent).
const P1: u64 = 1_000_000_000_000_091;
const P2: u64 = 1_000_000_000_000_159;

fn p_moduli() -> Vec<Modulus> {
    vec![Modulus::new(P1).unwrap(), Modulus::new(P2).unwrap()]
}

#[test]
fn encode_decode_unsigned_and_signed_slots() {
    let ctx = BfvContext::new(params());
    let encoder = ctx.encoder();

    let unsigned = encoder.encode_u64(&[1, 18, 34, 8]).unwrap();
    assert_eq!(&encoder.decode_u64(&unsigned).unwrap()[..4], &[1, 1, 0, 8]);

    let signed = encoder.encode_i64(&[-1, -3, 0, 4]).unwrap();
    assert_eq!(&encoder.decode_i64(&signed).unwrap()[..4], &[-1, -3, 0, 4]);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let ctx = BfvContext::new(params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_i64(&[-2, 3, 5, -6]).unwrap();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();

    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();

    assert_eq!(
        &encoder.decode_i64(&decrypted).unwrap()[..4],
        &[-2, 3, 5, -6]
    );
}

#[test]
fn add_sub_neg_and_plain_ops_are_exact_mod_t() {
    let ctx = BfvContext::new(params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let lhs_pt = encoder.encode_u64(&[2, 4, 6, 8]).unwrap();
    let rhs_pt = encoder.encode_u64(&[1, 3, 5, 7]).unwrap();
    let lhs = encryptor.encrypt(&lhs_pt, &mut rng).unwrap();
    let rhs = encryptor.encrypt(&rhs_pt, &mut rng).unwrap();

    let sum = decryptor
        .decrypt(&evaluator.add(&lhs, &rhs).unwrap())
        .unwrap();
    assert_eq!(&encoder.decode_u64(&sum).unwrap()[..4], &[3, 7, 11, 15]);

    let diff = decryptor
        .decrypt(&evaluator.sub(&lhs, &rhs).unwrap())
        .unwrap();
    assert_eq!(&encoder.decode_u64(&diff).unwrap()[..4], &[1, 1, 1, 1]);

    let neg = decryptor.decrypt(&evaluator.neg(&rhs).unwrap()).unwrap();
    assert_eq!(&encoder.decode_u64(&neg).unwrap()[..4], &[16, 14, 12, 10]);

    let plus_plain = decryptor
        .decrypt(&evaluator.add_plain(&lhs, &rhs_pt).unwrap())
        .unwrap();
    assert_eq!(
        &encoder.decode_u64(&plus_plain).unwrap()[..4],
        &[3, 7, 11, 15]
    );
}

#[test]
fn multiplication_and_plain_multiplication_are_exact() {
    let ctx = BfvContext::new(params());
    let mut rng = seeded_rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let eval_keys = keygen.generate_evaluation_keys(&keys.secret, &[1, 2]);
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let lhs_pt = encoder.encode_u64(&[2, 3, 4, 0]).unwrap();
    let rhs_pt = encoder.encode_u64(&[5, 6, 1, 0]).unwrap();
    let lhs = encryptor.encrypt(&lhs_pt, &mut rng).unwrap();
    let rhs = encryptor.encrypt(&rhs_pt, &mut rng).unwrap();

    let product = evaluator.mul(&lhs, &rhs, Some(&eval_keys)).unwrap();
    let decrypted = decryptor.decrypt(&product).unwrap();
    assert_eq!(
        &encoder.decode_u64(&decrypted).unwrap()[..4],
        &[10, 10, 6, 10]
    );

    let plain_product = evaluator.mul_plain(&lhs, &rhs_pt).unwrap();
    let decrypted = decryptor.decrypt(&plain_product).unwrap();
    assert_eq!(
        &encoder.decode_u64(&decrypted).unwrap()[..4],
        &[10, 10, 6, 10]
    );
}

#[test]
fn real_secret_key_round_trip_recovers_exact_values() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();

    for trial in 0..50u64 {
        let values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (i + trial) % REAL_T)
            .collect();
        let pt = encoder.encode_u64(&values).unwrap();
        let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
        let decrypted = decryptor.decrypt(&ct).unwrap();
        assert_eq!(encoder.decode_u64_real(&decrypted).unwrap(), values);
    }
}

#[test]
fn real_public_key_round_trip_recovers_exact_values() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(keys.public);
    let decryptor = ctx.decryptor(keys.secret).unwrap();

    for trial in 0..50u64 {
        let values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (i * 3 + trial) % REAL_T)
            .collect();
        let pt = encoder.encode_u64(&values).unwrap();
        let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
        let decrypted = decryptor.decrypt(&ct).unwrap();
        assert_eq!(encoder.decode_u64_real(&decrypted).unwrap(), values);
    }
}

#[test]
fn real_homomorphic_add_sub_neg_are_exact() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let lhs_pt = encoder.encode_u64(&[2, 4, 6, 8]).unwrap();
    let rhs_pt = encoder.encode_u64(&[1, 3, 5, 7]).unwrap();
    let lhs = encryptor.encrypt(&lhs_pt, &mut rng).unwrap();
    let rhs = encryptor.encrypt(&rhs_pt, &mut rng).unwrap();

    let sum = decryptor
        .decrypt(&evaluator.add(&lhs, &rhs).unwrap())
        .unwrap();
    assert_eq!(
        &encoder.decode_u64_real(&sum).unwrap()[..4],
        &[3, 7, 11, 15]
    );

    let diff = decryptor
        .decrypt(&evaluator.sub(&lhs, &rhs).unwrap())
        .unwrap();
    assert_eq!(&encoder.decode_u64_real(&diff).unwrap()[..4], &[1, 1, 1, 1]);

    let neg = decryptor.decrypt(&evaluator.neg(&rhs).unwrap()).unwrap();
    assert_eq!(
        &encoder.decode_u64_real(&neg).unwrap()[..4],
        &[16, 14, 12, 10]
    );
}

#[test]
fn real_add_plain_and_mul_plain_are_exact() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    for trial in 0..30u64 {
        let a_values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (i + trial) % REAL_T)
            .collect();
        let b_values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (2 * i + trial) % REAL_T)
            .collect();
        let a_pt = encoder.encode_u64(&a_values).unwrap();
        let b_pt = encoder.encode_u64(&b_values).unwrap();
        let a_ct = encryptor.encrypt(&a_pt, &mut rng).unwrap();

        // add_plain_real: scales the plaintext operand by Delta first (see
        // Evaluator::add_plain_real's own doc comment) - plain add_plain
        // would be wrong here.
        let sum = decryptor
            .decrypt(&evaluator.add_plain_real(&a_ct, &b_pt).unwrap())
            .unwrap();
        let expected_sum: Vec<u64> = a_values
            .iter()
            .zip(b_values.iter())
            .map(|(&x, &y)| (x + y) % REAL_T)
            .collect();
        assert_eq!(
            encoder.decode_u64_real(&sum).unwrap(),
            expected_sum,
            "add_plain_real trial {trial}"
        );

        // mul_plain needs no _real counterpart - verified to already be
        // correct for real ciphertexts (see Evaluator::add_plain_real's own
        // doc comment for why multiplication doesn't have add's problem).
        let product = decryptor
            .decrypt(&evaluator.mul_plain(&a_ct, &b_pt).unwrap())
            .unwrap();
        assert_eq!(
            encoder.decode_u64_real(&product).unwrap(),
            expected_product(&ctx, &a_pt, &b_pt),
            "mul_plain trial {trial}"
        );
    }
}

#[test]
fn real_multiplication_matches_schoolbook_reference_across_many_random_pairs() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();
    let p_moduli = p_moduli();

    for trial in 0..30u64 {
        let a_values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (i + trial) % REAL_T)
            .collect();
        let b_values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (2 * i + trial) % REAL_T)
            .collect();
        let a_pt = encoder.encode_u64(&a_values).unwrap();
        let b_pt = encoder.encode_u64(&b_values).unwrap();
        let a_ct = encryptor.encrypt(&a_pt, &mut rng).unwrap();
        let b_ct = encryptor.encrypt(&b_pt, &mut rng).unwrap();

        let product = evaluator.mul_real(&a_ct, &b_ct, &p_moduli).unwrap();
        assert_eq!(product.degree(), 2);
        let decrypted = decryptor.decrypt(&product).unwrap();
        let decoded = encoder.decode_u64_real(&decrypted).unwrap();

        assert_eq!(
            decoded,
            expected_product(&ctx, &a_pt, &b_pt),
            "trial {trial}"
        );
    }
}

#[test]
fn real_relinearization_reduces_degree_and_preserves_the_product() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let p_moduli = p_moduli();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();

    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    for trial in 0..30u64 {
        let a_values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (i + trial) % REAL_T)
            .collect();
        let b_values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (2 * i + trial) % REAL_T)
            .collect();
        let a_pt = encoder.encode_u64(&a_values).unwrap();
        let b_pt = encoder.encode_u64(&b_values).unwrap();
        let a_ct = encryptor.encrypt(&a_pt, &mut rng).unwrap();
        let b_ct = encryptor.encrypt(&b_pt, &mut rng).unwrap();

        let product = evaluator.mul_real(&a_ct, &b_ct, &p_moduli).unwrap();
        let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
        assert_eq!(
            relinearized.degree(),
            1,
            "real relinearization must bring a degree-2 ciphertext back to degree 1"
        );

        let decrypted = decryptor.decrypt(&relinearized).unwrap();
        let decoded = encoder.decode_u64_real(&decrypted).unwrap();
        assert_eq!(
            decoded,
            expected_product(&ctx, &a_pt, &b_pt),
            "trial {trial}"
        );
    }
}

#[test]
fn rotation_and_slot_sum_are_exact() {
    let ctx = BfvContext::new(params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();
    let plaintext = encoder.encode_u64(&[1, 2, 3, 4]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();

    let rotated = decryptor
        .decrypt(&evaluator.rotate_slots(&ciphertext, 1).unwrap())
        .unwrap();
    assert_eq!(&encoder.decode_u64(&rotated).unwrap()[..4], &[2, 3, 4, 0]);

    let summed = decryptor
        .decrypt(&evaluator.sum_slots(&ciphertext, 4).unwrap())
        .unwrap();
    assert_eq!(&encoder.decode_u64(&summed).unwrap()[..4], &[10, 9, 7, 4]);
}

#[test]
fn encode_batched_decode_batched_real_round_trips_through_real_encryption() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();

    for trial in 0..30u64 {
        let values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (3 * i + trial) % REAL_T)
            .collect();
        let pt = encoder.encode_batched(&values).unwrap();
        let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
        let decrypted = decryptor.decrypt(&ct).unwrap();
        let decoded = encoder.decode_batched_real(&decrypted).unwrap();
        assert_eq!(decoded, values, "trial {trial}");
    }
}

#[test]
fn encode_batched_supports_genuine_elementwise_simd_multiplication() {
    let ctx = BfvContext::new(real_params());
    let mut rng = seeded_rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let p_moduli = p_moduli();
    let relin_key = keygen
        .generate_hybrid_relinearization_key(&keys.secret, &p_moduli, &mut rng)
        .unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let a_values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| (i + 1) % REAL_T).collect();
    let b_values: Vec<u64> = (0..REAL_DEGREE as u64)
        .map(|i| (2 * i + 3) % REAL_T)
        .collect();
    let a_pt = encoder.encode_batched(&a_values).unwrap();
    let b_pt = encoder.encode_batched(&b_values).unwrap();
    let a_ct = encryptor.encrypt(&a_pt, &mut rng).unwrap();
    let b_ct = encryptor.encrypt(&b_pt, &mut rng).unwrap();

    let product = evaluator.mul_real(&a_ct, &b_ct, &p_moduli).unwrap();
    let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
    let decrypted = decryptor.decrypt(&relinearized).unwrap();
    let decoded = encoder.decode_batched_real(&decrypted).unwrap();

    let expected: Vec<u64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| (a * b) % REAL_T)
        .collect();
    assert_eq!(decoded, expected);
}

#[test]
fn rotate_real_shifts_both_rows_for_every_amount() {
    let params = real_params();
    let ctx = BfvContext::new(params.clone());
    let mut rng = seeded_rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let p_moduli = p_moduli();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let half = REAL_DEGREE / 2;
    let values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i + 1).collect();
    let pt = encoder.encode_batched(&values).unwrap();
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

    for shift in 1..half {
        let element = params.rotation_element(shift);
        let key = keygen
            .generate_hybrid_galois_key(element, &keys.secret, &p_moduli, &mut rng)
            .unwrap();
        let rotated = evaluator.rotate_real(&ct, &key).unwrap();
        let decoded = encoder
            .decode_batched_real(&decryptor.decrypt(&rotated).unwrap())
            .unwrap();

        let mut expected_row0 = values[..half].to_vec();
        expected_row0.rotate_left(shift);
        let mut expected_row1 = values[half..].to_vec();
        expected_row1.rotate_left(shift);
        let expected: Vec<u64> = expected_row0.into_iter().chain(expected_row1).collect();
        assert_eq!(decoded, expected, "shift={shift}");
    }
}

#[test]
fn rotate_real_swaps_rows() {
    let params = real_params();
    let ctx = BfvContext::new(params.clone());
    let mut rng = seeded_rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair(&mut rng).unwrap();
    let p_moduli = p_moduli();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = ctx.evaluator().unwrap();

    let half = REAL_DEGREE / 2;
    let values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i + 1).collect();
    let pt = encoder.encode_batched(&values).unwrap();
    let ct = encryptor.encrypt(&pt, &mut rng).unwrap();

    let element = params.row_swap_element();
    let key = keygen
        .generate_hybrid_galois_key(element, &keys.secret, &p_moduli, &mut rng)
        .unwrap();
    let swapped = evaluator.rotate_real(&ct, &key).unwrap();
    let decoded = encoder
        .decode_batched_real(&decryptor.decrypt(&swapped).unwrap())
        .unwrap();

    let expected: Vec<u64> = values[half..]
        .iter()
        .chain(values[..half].iter())
        .copied()
        .collect();
    assert_eq!(decoded, expected);
}
