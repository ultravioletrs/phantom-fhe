use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_lattice::rlwe;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bgv::{BgvContext, BgvParams, Plaintext};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Independent oracle for what a BGV ciphertext-ciphertext or
/// ciphertext-plaintext multiplication should decode to: `mul`/`mul_plain`
/// are full negacyclic ring products (polynomial multiplication mod `X^N +
/// 1`), not a coefficientwise/elementwise multiply - this multiplies the
/// two *plaintext* polynomials directly via `schoolbook_mul` (independent
/// of the encryption/decryption pipeline under test) and decodes the result
/// the same way any decrypted ciphertext would be.
fn expected_product(ctx: &BgvContext, a: &Plaintext, b: &Plaintext) -> Vec<u64> {
    let product = ctx
        .params()
        .ring()
        .schoolbook_mul(a.inner().value(), b.inner().value())
        .unwrap();
    let plaintext = Plaintext::new(phantom_lattice::rlwe::Plaintext::new(product));
    ctx.encoder().decode_u64(&plaintext).unwrap()
}

fn params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(257).unwrap(), Modulus::new(769).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, 17).unwrap()
}

fn seeded_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([7; 32])
}

// Real BGV encryption injects noise scaled by the plaintext modulus t=17
// (see bgv::Encryptor's own module doc comment) - the toy [257, 769]
// moduli params() uses have no room for that at all (t * fresh noise alone
// already exceeds 257). This ring is sized with real headroom over even a
// raw (pre-relinearization) multiplication's worst-case noise: hand-computed
// via phantom_lattice::noise::mul_noise_bound(8, 16, 17 *
// fresh_public_key_noise_bound(8)) = 268,862,080, this modulus exceeds that
// by roughly 1800x.
const REAL_DEGREE: usize = 8;
const REAL_MODULUS: u64 = 1_000_000_000_000_037;
const REAL_T: u64 = 17;

fn real_params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(REAL_MODULUS).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, REAL_T).unwrap()
}

// Real modulus switching needs a genuinely multi-modulus RNS ring to drop a
// modulus *from* - both primes individually as large as REAL_MODULUS above,
// so the ciphertext still decodes correctly even after switching all the
// way down to just one of them.
const REAL_MODULUS_2: u64 = 1_000_000_000_000_091;

fn real_multi_modulus_params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![
            Modulus::new(REAL_MODULUS).unwrap(),
            Modulus::new(REAL_MODULUS_2).unwrap(),
        ],
    )
    .unwrap();
    BgvParams::new(ring, REAL_T).unwrap()
}

#[test]
fn encode_decode_is_exact_mod_plaintext_modulus() {
    let ctx = BgvContext::new(params());
    let encoder = ctx.encoder();

    let plaintext = encoder.encode_u64(&[1, 2, 18, 34, 8]).unwrap();
    let decoded = encoder.decode_u64(&plaintext).unwrap();

    assert_eq!(&decoded[..5], &[1, 2, 1, 0, 8]);
    assert_eq!(decoded.len(), encoder.slot_count());
}

#[test]
fn encrypt_decrypt_roundtrip_with_public_key() {
    let ctx = BgvContext::new(params());
    let mut rng = seeded_rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_u64(&[3, 4, 5, 6]).unwrap();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();

    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();

    assert_eq!(&encoder.decode_u64(&decrypted).unwrap()[..4], &[3, 4, 5, 6]);
}

#[test]
fn add_sub_neg_and_plain_ops_are_exact() {
    let ctx = BgvContext::new(params());
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
fn multiplication_and_relinearization_scaffold_are_exact() {
    let ctx = BgvContext::new(params());
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
}

#[test]
fn real_secret_key_round_trip_recovers_exact_values() {
    let ctx = BgvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();
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
        assert_eq!(encoder.decode_u64(&decrypted).unwrap(), values);
    }
}

#[test]
fn real_public_key_round_trip_recovers_exact_values() {
    let ctx = BgvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();
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
        assert_eq!(encoder.decode_u64(&decrypted).unwrap(), values);
    }
}

#[test]
fn real_homomorphic_add_sub_and_plain_ops_are_exact() {
    let ctx = BgvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(keys.public);
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

    let times_plain = decryptor
        .decrypt(&evaluator.mul_plain(&lhs, &rhs_pt).unwrap())
        .unwrap();
    assert_eq!(
        encoder.decode_u64(&times_plain).unwrap(),
        expected_product(&ctx, &lhs_pt, &rhs_pt)
    );
}

#[test]
fn real_raw_multiplication_without_relinearization_is_exact() {
    let ctx = BgvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
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

        // No relinearization key supplied - stays degree 2, matching the
        // still-transparent-placeholder relinearization path (see bgv's own
        // module docs); Decryptor::decrypt already generalizes to any
        // ciphertext degree via sum_i c_i * s^i.
        let product = evaluator.mul(&a_ct, &b_ct, None).unwrap();
        assert_eq!(product.degree(), 2);
        let decrypted = decryptor.decrypt(&product).unwrap();
        let decoded = encoder.decode_u64(&decrypted).unwrap();

        assert_eq!(
            decoded,
            expected_product(&ctx, &a_pt, &b_pt),
            "trial {trial}"
        );
    }
}

#[test]
fn real_relinearization_reduces_degree_and_preserves_the_product_exactly() {
    let ctx = BgvContext::new(real_params());
    let mut rng = seeded_rng();
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair_real(&mut rng).unwrap();
    // base=2^8=256, 7 levels covers REAL_MODULUS's ~50 bits (7*8=56) with
    // margin - see BgvRelinearizationKey's own module doc comment for why
    // a small base matters here (a large one reintroduces the same kind of
    // exactness problem this whole primitive exists to avoid).
    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();
    let relin_key = keygen
        .generate_relinearization_key_real(&keys.secret, decomposition_params, &mut rng)
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

        let product = evaluator.mul(&a_ct, &b_ct, None).unwrap();
        let relinearized = evaluator.relinearize_real(&product, &relin_key).unwrap();
        assert_eq!(
            relinearized.degree(),
            1,
            "real BGV relinearization must bring a degree-2 ciphertext back to degree 1"
        );

        let decrypted = decryptor.decrypt(&relinearized).unwrap();
        let decoded = encoder.decode_u64(&decrypted).unwrap();

        // Exact, not just within a noise bound: this is the whole point of
        // the classical-gadget-decomposition construction - see
        // BgvRelinearizationKey's own module doc comment for why the RNS
        // hybrid technique can't give this.
        assert_eq!(
            decoded,
            expected_product(&ctx, &a_pt, &b_pt),
            "trial {trial}"
        );
    }
}

#[test]
fn real_modulus_switch_reduces_ring_and_preserves_plaintext() {
    let ctx = BgvContext::new(real_multi_modulus_params());
    let mut rng = seeded_rng();
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let evaluator = ctx.evaluator().unwrap();

    let next_params = evaluator.next_modulus_switch_params().unwrap();
    let next_secret = evaluator.switch_secret_key(&keys.secret).unwrap();
    let next_ctx = BgvContext::new(next_params);
    let next_decryptor = next_ctx.decryptor(next_secret).unwrap();
    let next_encoder = next_ctx.encoder();

    for trial in 0..30u64 {
        let values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (i + trial) % REAL_T)
            .collect();
        let pt = encoder.encode_u64(&values).unwrap();
        let ct = encryptor.encrypt(&pt, &mut rng).unwrap();
        assert_eq!(ct.inner().value()[0].moduli_count(), 2);

        let switched = evaluator.modulus_switch_next_real(&ct).unwrap();
        assert_eq!(switched.inner().value()[0].moduli_count(), 1);

        let decrypted = next_decryptor.decrypt(&switched).unwrap();
        assert_eq!(
            next_encoder.decode_u64(&decrypted).unwrap(),
            values,
            "trial {trial}"
        );
    }
}

#[test]
fn rotation_slot_sum_and_modulus_switch_preserve_plaintext() {
    let ctx = BgvContext::new(params());
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

    let switched = decryptor
        .decrypt(&evaluator.modulus_switch_next(&ciphertext).unwrap())
        .unwrap();
    assert_eq!(&encoder.decode_u64(&switched).unwrap()[..4], &[1, 2, 3, 4]);
}

// t=17 already happens to be NTT-friendly at REAL_DEGREE=8 (17-1=16, and
// 2*REAL_DEGREE=16 divides that exactly) - the existing real_params()
// fixture (Workstream 6 item 2's own prerequisite) needs no new parameters.

#[test]
fn encode_batched_decode_batched_round_trips_exactly() {
    let ctx = BgvContext::new(real_params());
    let encoder = ctx.encoder();

    for trial in 0..30u64 {
        let values: Vec<u64> = (0..REAL_DEGREE as u64)
            .map(|i| (3 * i + trial) % REAL_T)
            .collect();
        let plaintext = encoder.encode_batched(&values).unwrap();
        let decoded = encoder.decode_batched(&plaintext).unwrap();
        assert_eq!(decoded, values, "trial {trial}");
    }
}

#[test]
fn encode_batched_supports_genuine_elementwise_simd_multiplication() {
    // The actual payoff of real batching, unlike encode_u64: real BGV
    // ciphertext multiplication is negacyclic ring convolution across every
    // coefficient jointly, but under CRT-based batching that convolution in
    // coefficient space corresponds to an *elementwise* product in slot
    // space - the standard SIMD guarantee, checked here against a real
    // (encrypted) multiplication, not just the plaintext encoding math.
    let ctx = BgvContext::new(real_params());
    let mut rng = seeded_rng();
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
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

    // No relinearization key - Decryptor::decrypt generalizes to any
    // ciphertext degree, matching real_raw_multiplication_without_
    // relinearization_is_exact's own reasoning above.
    let product = evaluator.mul(&a_ct, &b_ct, None).unwrap();
    let decrypted = decryptor.decrypt(&product).unwrap();
    let decoded = encoder.decode_batched(&decrypted).unwrap();

    let expected: Vec<u64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| (a * b) % REAL_T)
        .collect();
    assert_eq!(decoded, expected);
}

#[test]
fn encode_batched_slot_layout_supports_row_rotation_and_row_swap() {
    // Direct proof of the module doc comment's own claim: X -> X^(5^shift)
    // rotates both rows together by shift, and X -> X^(-1) swaps them -
    // driven straight at the ring automorphism level (no bgv::Evaluator
    // rotation primitive for real ciphertexts exists yet - that's the next
    // piece item 2 still needs, not attempted here), matching this
    // property's own Python verification before implementation.
    let params = real_params();
    let ring = params.ring();
    let half = REAL_DEGREE / 2;
    let two_n = 2 * REAL_DEGREE;
    let ctx = BgvContext::new(params.clone());
    let encoder = ctx.encoder();

    let values: Vec<u64> = (0..REAL_DEGREE as u64).map(|i| i + 1).collect();
    let plaintext = encoder.encode_batched(&values).unwrap();

    let decode_after_automorphism = |k: usize| -> Vec<u64> {
        let rotated_poly = ring
            .apply_automorphism(plaintext.inner().value(), k)
            .unwrap();
        let rotated = Plaintext::new(rlwe::Plaintext::new(rotated_poly));
        encoder.decode_batched(&rotated).unwrap()
    };

    for shift in 1..half {
        let mut k = 1usize;
        for _ in 0..shift {
            k = (k * 5) % two_n;
        }
        let mut expected_row0 = values[..half].to_vec();
        expected_row0.rotate_left(shift);
        let mut expected_row1 = values[half..].to_vec();
        expected_row1.rotate_left(shift);
        let expected: Vec<u64> = expected_row0.into_iter().chain(expected_row1).collect();
        assert_eq!(decode_after_automorphism(k), expected, "shift={shift}");
    }

    let expected_swap: Vec<u64> = values[half..]
        .iter()
        .chain(values[..half].iter())
        .copied()
        .collect();
    assert_eq!(decode_after_automorphism(two_n - 1), expected_swap);
}

#[test]
fn encode_batched_rejects_a_plaintext_modulus_that_is_not_ntt_friendly() {
    // t=19: prime, but 19-1=18 isn't divisible by 2*REAL_DEGREE=16.
    let ring = Ring::new(
        Degree::new(REAL_DEGREE).unwrap(),
        vec![Modulus::new(REAL_MODULUS).unwrap()],
    )
    .unwrap();
    let params = BgvParams::new(ring, 19).unwrap();
    let encoder = BgvContext::new(params).encoder();

    assert!(encoder.encode_batched(&[1, 2, 3]).is_err());
}
