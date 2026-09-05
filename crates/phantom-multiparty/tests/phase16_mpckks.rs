use phantom_bootstrapping::ckks::BootstrapParams;
use phantom_lattice::rlwe::SecretKey;
use phantom_multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, ReplayGuard, SessionId, SessionState,
    ShareAggregator, ShareKind,
};
use phantom_multiparty::mpckks::{
    CollectiveKeyGen, GaloisKeyGen, InteractiveBootstrap, PartialDecryptor, ReEncryptor,
    RelinearizationKeyGen,
};
use phantom_multiparty::MultipartyError;
use phantom_ring::rns::extension::embed_centered_coeffs;
use phantom_ring::Modulus;
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn id(value: u64) -> ParticipantId {
    ParticipantId::new(value).unwrap()
}

fn params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()
        .unwrap()
}

// Real CKKS encryption needs noise-safe parameters - `params()`'s own toy
// preset was only ever exercised against the transparent scaffold. Unlike
// BGV/BFV, CKKS's own smudging noise directly costs *decode precision*
// rather than being stripped by an exact modular reduction (there is none -
// see `mpckks::reencryption`'s own doc comment): `smudging_std_dev` at the
// recommended 40-bit statistical target comes out to a fixed ~2^28.4
// (`phantom_lattice::security::smudging_std_dev(340, 40)`, independent of
// scale, since `fresh_public_key_noise_bound(8) = 340` round-trips through
// `ckks::noise::{precision_bits_from_noise, noise_bound_from_precision}`
// unchanged), so the scale needs to be comfortably larger than that for the
// smudged decode to still recover a useful value - confirmed directly: a
// 30-bit scale (this file's own toy-adjacent first attempt) left decode
// errors of order 1-10, completely swamping values of the same magnitude.
// A 45-bit scale leaves ~17 bits of margin below the smudging noise floor
// (decode error ~2^-17, comfortably under any reasonable test tolerance).
// Two already Miller-Rabin-verified primes (`phase6_bfv.rs`'s own
// `p_moduli()` pair) give a ~2^100 modulus, far more than a 45-bit scale
// needs - no rescaling happens in these tests, so a smaller, rescale-sized
// second modulus isn't needed the way `ckks_real_arithmetic.rs`'s own
// `real_arith_params()` needs one.
fn real_params() -> CkksParams {
    CkksParams::builder()
        .degree(8)
        .moduli(vec![1_000_000_000_000_037, 1_000_000_000_000_091])
        .default_scale_bits(45)
        .build()
        .unwrap()
}

fn session(protocol: ProtocolKind) -> SessionState {
    SessionState::new(
        SessionId::new(protocol_tag(protocol) as u64 + 200).unwrap(),
        protocol,
        ParticipantSet::new(vec![id(1), id(2), id(3)]).unwrap(),
        2,
    )
    .unwrap()
}

fn protocol_tag(protocol: ProtocolKind) -> u32 {
    match protocol {
        ProtocolKind::CollectiveKeyGen => 1,
        ProtocolKind::RelinearizationKeyGen => 2,
        ProtocolKind::GaloisKeyGen => 3,
        ProtocolKind::PartialDecryption => 4,
        ProtocolKind::ReEncryption => 5,
        ProtocolKind::InteractiveBootstrap => 6,
        ProtocolKind::Custom(tag) => tag,
    }
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([29; 32])
}

fn assert_complex_close(actual: Complex64, expected: Complex64) {
    assert!(
        (actual.re - expected.re).abs() < 1e-9 && (actual.im - expected.im).abs() < 1e-9,
        "{actual:?} != {expected:?}"
    );
}

// Real CKKS encryption needs a real noise-tolerant approximate comparison,
// not the exact `assert_close` the transparent scaffold's tests use -
// mirrors `ckks_real_arithmetic.rs`'s own real-path tolerance.
fn assert_real_close(actual: &[Complex64], expected: &[f64]) {
    for (actual, expected) in actual.iter().zip(expected) {
        assert!(
            (actual.re - expected).abs() < 1e-3 && actual.im.abs() < 1e-3,
            "{actual:?} != {expected}"
        );
    }
}

#[test]
fn collective_public_key_generation_via_dkg_produces_a_genuinely_decryptable_key() {
    // Real, end-to-end proof that `CollectiveKeyGen` is genuine CKKS key
    // generation for a collective secret `s = sum_d s_d`, mirroring
    // `phase15_mpbfv.rs`'s own equivalent test - identical construction to
    // BFV's own CKG, no `t`-scaling (see `mpckks::ckg`'s own doc comment).
    let params = real_params();
    let ring = params.ring();
    let n = 3;
    let ckg_session = session(ProtocolKind::CollectiveKeyGen);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();
    let mut rng = rng();

    let secrets: Vec<Vec<i128>> = (0..n)
        .map(|_| {
            (0..ring.degree())
                .map(|_| (rng.next_u32() % 3) as i128 - 1)
                .collect()
        })
        .collect();
    let local_secret_shares: Vec<SecretKey> = secrets
        .iter()
        .map(|secret| SecretKey::new(embed_centered_coeffs(secret, ring.moduli()).unwrap()))
        .collect();
    let mut replay_guards: Vec<ReplayGuard> =
        participants.iter().map(|_| ReplayGuard::new()).collect();

    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        aggregator
            .add_share(
                ckg.create_share(participant, local_secret_share, replay_guard, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let public_key = ckg.aggregate_public_key(&aggregator).unwrap();

    // Test-only: sum the already-locally-known secrets to verify
    // correctness against an independently-derived collective secret - not
    // a production pattern, since a real deployment never assembles this.
    let collective_secret_coeffs: Vec<i128> = (0..ring.degree())
        .map(|coeff| secrets.iter().map(|s| s[coeff]).sum())
        .collect();
    let collective_secret =
        SecretKey::new(embed_centered_coeffs(&collective_secret_coeffs, ring.moduli()).unwrap());

    let ctx = CkksContext::new(params);
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(public_key);
    let decryptor = ctx.real_decryptor(collective_secret).unwrap();
    let values = vec![
        Complex64::real(1.5),
        Complex64::real(-2.0),
        Complex64::real(3.25),
    ];
    let plaintext = encoder.encode_complex_real(&values).unwrap();
    let ciphertext = encryptor.encrypt_real(&plaintext, &mut rng).unwrap();
    let decrypted = decryptor.decrypt_real(&ciphertext).unwrap();

    assert_real_close(
        &encoder.decode_complex_real(&decrypted).unwrap()[..3],
        &[1.5, -2.0, 3.25],
    );
}

#[test]
fn replay_guard_rejects_a_second_share_for_the_same_session_round_and_participant() {
    // Mirrors `phase14_mpbgv.rs`'s own equivalent test: `ReplayGuard` is
    // wired into every real `mpckks` protocol's `create_share*` the same
    // way it is for `mpbgv`'s, but until now only `mpbgv` had a test
    // proving it actually fires.
    let params = real_params();
    let secret = SecretKey::new(
        embed_centered_coeffs(&vec![0i128; params.ring().degree()], params.ring().moduli())
            .unwrap(),
    );
    let mut rng = rng();
    let mut replay_guard = ReplayGuard::new();

    let ckg = CollectiveKeyGen::new(params.clone(), session(ProtocolKind::CollectiveKeyGen));

    ckg.create_share(id(1), &secret, &mut replay_guard, &mut rng)
        .unwrap();

    assert_eq!(
        ckg.create_share(id(1), &secret, &mut replay_guard, &mut rng),
        Err(MultipartyError::ReplayedShare)
    );

    ckg.create_share(id(2), &secret, &mut replay_guard, &mut rng)
        .unwrap();

    let other_ckg = CollectiveKeyGen::new(params, session(ProtocolKind::GaloisKeyGen));
    other_ckg
        .create_share(id(1), &secret, &mut replay_guard, &mut rng)
        .unwrap();
}

#[test]
fn relinearization_key_generation_round0_share_is_rejected_by_the_round1_aggregator() {
    // Mirrors `phase14_mpbgv.rs`'s own equivalent test for the newer
    // three-round hybrid construction (round 0 builds a collective public
    // key over `QP`, then rounds 1/2 mirror `mpbgv::rkg`'s own two) - all
    // three rounds reuse the identical `ShareKind::RelinearizationKeyGen`
    // tag, so only the session's own `round` number tells them apart.
    let params = real_params();
    let ring = params.ring();
    let p_moduli = vec![Modulus::new(1_000_000_000_000_159).unwrap()];
    let rkg_session = session(ProtocolKind::RelinearizationKeyGen);
    let secret =
        SecretKey::new(embed_centered_coeffs(&vec![0i128; ring.degree()], ring.moduli()).unwrap());
    let mut rng = rng();
    let mut replay_guard = ReplayGuard::new();

    let rkg = RelinearizationKeyGen::new(params, rkg_session.clone(), p_moduli);
    let round0_share = rkg
        .create_qp_ckg_share(id(1), &secret, &mut replay_guard, &mut rng)
        .unwrap();

    let mut round1_aggregator =
        ShareAggregator::new(rkg.round1_session(), ShareKind::RelinearizationKeyGen);
    assert_eq!(
        round1_aggregator.add_share(round0_share).unwrap_err(),
        MultipartyError::StaleShare
    );
}

#[test]
fn galois_key_generation_rejects_a_mismatched_shared_constant() {
    // Simulates a malicious or buggy participant computing their own row
    // against the wrong rotation `element` - `common::hybrid`'s own `a_j`
    // purpose label is derived from `element`, so this produces genuine,
    // well-formed rows whose shared constant doesn't match the other
    // participant's. `aggregate_keys` must detect this: it checks, but
    // never sums, `a_j`. Mirrors `phase14_mpbgv.rs`'s own equivalent test
    // for the newer RNS-hybrid construction.
    let params = real_params();
    let ring = params.ring();
    let p_moduli = vec![Modulus::new(1_000_000_000_000_159).unwrap()];
    let gkg_session = session(ProtocolKind::GaloisKeyGen);
    let mut rng = rng();
    let secret1 =
        SecretKey::new(embed_centered_coeffs(&vec![0i128; ring.degree()], ring.moduli()).unwrap());
    let secret2 =
        SecretKey::new(embed_centered_coeffs(&vec![1i128; ring.degree()], ring.moduli()).unwrap());
    let mut guard1 = ReplayGuard::new();
    let mut guard2 = ReplayGuard::new();

    let element1 = params.rotation_element(1);
    let element2 = params.rotation_element(2);
    let gkg_honest = GaloisKeyGen::new(
        params.clone(),
        gkg_session.clone(),
        element1,
        p_moduli.clone(),
    );
    let gkg_wrong_element = GaloisKeyGen::new(params, gkg_session.clone(), element2, p_moduli);

    let share1 = gkg_honest
        .create_share(id(1), &secret1, &mut guard1, &mut rng)
        .unwrap();
    let share2 = gkg_wrong_element
        .create_share(id(2), &secret2, &mut guard2, &mut rng)
        .unwrap();

    let mut aggregator = ShareAggregator::new(gkg_session, ShareKind::GaloisKeyGen);
    aggregator.add_share(share1).unwrap();
    aggregator.add_share(share2).unwrap();

    assert_eq!(
        gkg_honest.aggregate_keys(&aggregator).unwrap_err(),
        MultipartyError::MalformedMessage
    );
}

#[test]
fn collective_galois_key_generation_via_real_dkg_rotates_a_genuine_ciphertext() {
    // Real, end-to-end proof that `GaloisKeyGen` produces genuine RNS-hybrid
    // CKKS rotation key material - mirrors `phase15_mpbfv.rs`'s own
    // equivalent test, using the shared `common::hybrid` construction (see
    // `mpckks::gkg`'s own doc comment).
    let params = real_params();
    let ring = params.ring();
    let p_moduli = vec![Modulus::new(1_000_000_000_000_159).unwrap()];
    let n = 3;
    let ckg_session = session(ProtocolKind::CollectiveKeyGen);
    let gkg_session = session(ProtocolKind::GaloisKeyGen);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();
    let mut rng = rng();

    let secrets: Vec<Vec<i128>> = (0..n)
        .map(|_| {
            (0..ring.degree())
                .map(|_| (rng.next_u32() % 3) as i128 - 1)
                .collect()
        })
        .collect();
    let local_secret_shares: Vec<SecretKey> = secrets
        .iter()
        .map(|secret| SecretKey::new(embed_centered_coeffs(secret, ring.moduli()).unwrap()))
        .collect();
    let mut replay_guards: Vec<ReplayGuard> =
        participants.iter().map(|_| ReplayGuard::new()).collect();

    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut ckg_aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        ckg_aggregator
            .add_share(
                ckg.create_share(participant, local_secret_share, replay_guard, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key = ckg.aggregate_public_key(&ckg_aggregator).unwrap();

    let shift = 1;
    let element = params.rotation_element(shift);
    let gkg = GaloisKeyGen::new(params.clone(), gkg_session.clone(), element, p_moduli);
    let mut gkg_aggregator = ShareAggregator::new(gkg_session, ShareKind::GaloisKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        gkg_aggregator
            .add_share(
                gkg.create_share(participant, local_secret_share, replay_guard, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_rotation_key = gkg.aggregate_keys(&gkg_aggregator).unwrap();

    let ctx = CkksContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    // Fill every slot (`slot_count = degree/2`) - a partial fill would
    // implicitly zero-pad the remaining slots, and `rotate_left` on the
    // real, fully-populated array wouldn't match `rotate_left` on a
    // shorter test-only vector missing that padding.
    let values: Vec<Complex64> = (1..=params.slot_count() as i64)
        .map(|v| Complex64::real(v as f64))
        .collect();
    let ciphertext = encryptor
        .encrypt_real(&encoder.encode_complex_real(&values).unwrap(), &mut rng)
        .unwrap();

    let evaluator = ctx.evaluator();
    let rotated = evaluator
        .rotate_real(&ciphertext, &collective_rotation_key)
        .unwrap();

    // Test-only: sum the already-locally-known secrets to verify
    // correctness against an independently-derived collective secret - not
    // a production pattern, since a real deployment never assembles this.
    let collective_secret_coeffs: Vec<i128> = (0..ring.degree())
        .map(|coeff| secrets.iter().map(|s| s[coeff]).sum())
        .collect();
    let collective_secret =
        SecretKey::new(embed_centered_coeffs(&collective_secret_coeffs, ring.moduli()).unwrap());
    let decryptor = ctx.real_decryptor(collective_secret).unwrap();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&rotated).unwrap())
        .unwrap();

    let mut expected = values.clone();
    expected.rotate_left(shift);
    assert_real_close(
        &decoded[..params.slot_count()],
        &expected.iter().map(|v| v.re).collect::<Vec<_>>(),
    );
}

#[test]
fn collective_relinearization_key_generation_via_real_dkg_relinearizes_a_genuine_product() {
    // Real, end-to-end proof that `RelinearizationKeyGen` produces genuine
    // RNS-hybrid CKKS relinearization key material via its own three-round
    // protocol (see `mpckks::rkg`'s own doc comment). Correctness is
    // checked against the expected plaintext product directly, mirroring
    // `ckks_real_arithmetic.rs`'s own `real_relinearization_reduces_degree_and_preserves_the_product`.
    let params = real_params();
    let ring = params.ring();
    let p_moduli = vec![Modulus::new(1_000_000_000_000_159).unwrap()];
    let n = 3;
    let ckg_session = session(ProtocolKind::CollectiveKeyGen);
    let rkg_session = session(ProtocolKind::RelinearizationKeyGen);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();
    let mut rng = rng();

    let secrets: Vec<Vec<i128>> = (0..n)
        .map(|_| {
            (0..ring.degree())
                .map(|_| (rng.next_u32() % 3) as i128 - 1)
                .collect()
        })
        .collect();
    let local_secret_shares: Vec<SecretKey> = secrets
        .iter()
        .map(|secret| SecretKey::new(embed_centered_coeffs(secret, ring.moduli()).unwrap()))
        .collect();
    let mut replay_guards: Vec<ReplayGuard> =
        participants.iter().map(|_| ReplayGuard::new()).collect();

    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut ckg_aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        ckg_aggregator
            .add_share(
                ckg.create_share(participant, local_secret_share, replay_guard, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key = ckg.aggregate_public_key(&ckg_aggregator).unwrap();

    let round0_session = rkg_session.clone();
    let rkg = RelinearizationKeyGen::new(params.clone(), rkg_session, p_moduli);

    let mut round0_aggregator =
        ShareAggregator::new(round0_session, ShareKind::RelinearizationKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        round0_aggregator
            .add_share(
                rkg.create_qp_ckg_share(participant, local_secret_share, replay_guard, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key_qp = rkg.aggregate_qp_public_key(&round0_aggregator).unwrap();

    let mut round1_aggregator =
        ShareAggregator::new(rkg.round1_session(), ShareKind::RelinearizationKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        round1_aggregator
            .add_share(
                rkg.create_share_round1(
                    participant,
                    local_secret_share,
                    &collective_public_key_qp,
                    replay_guard,
                    &mut rng,
                )
                .unwrap(),
            )
            .unwrap();
    }
    let round1_aggregate = rkg.aggregate_round1(&round1_aggregator).unwrap();

    let mut round2_aggregator =
        ShareAggregator::new(rkg.round2_session(), ShareKind::RelinearizationKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        round2_aggregator
            .add_share(
                rkg.create_share_round2(
                    participant,
                    local_secret_share,
                    &collective_public_key_qp,
                    &round1_aggregate,
                    replay_guard,
                    &mut rng,
                )
                .unwrap(),
            )
            .unwrap();
    }
    let collective_relin_key = rkg.aggregate_key(&round2_aggregator).unwrap();

    let ctx = CkksContext::new(params.clone());
    let encoder = ctx.encoder();
    let evaluator = ctx.evaluator();
    let encryptor = ctx.real_encryptor(collective_public_key);

    let a_values = vec![
        Complex64::real(1.5),
        Complex64::real(-2.0),
        Complex64::real(3.0),
    ];
    let b_values = vec![
        Complex64::real(2.0),
        Complex64::real(1.5),
        Complex64::real(-1.0),
    ];
    let a_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt_real(&encoder.encode_complex_real(&b_values).unwrap(), &mut rng)
        .unwrap();

    let product = evaluator.mul_real(&a_ct, &b_ct).unwrap();
    let relinearized = evaluator
        .relinearize_real(&product, &collective_relin_key)
        .unwrap();
    assert_eq!(relinearized.degree(), 1);

    let collective_secret_coeffs: Vec<i128> = (0..ring.degree())
        .map(|coeff| secrets.iter().map(|s| s[coeff]).sum())
        .collect();
    let collective_secret =
        SecretKey::new(embed_centered_coeffs(&collective_secret_coeffs, ring.moduli()).unwrap());
    let decryptor = ctx.real_decryptor(collective_secret).unwrap();

    let expected: Vec<f64> = a_values
        .iter()
        .zip(&b_values)
        .map(|(a, b)| (*a * *b).re)
        .collect();
    let decoded = encoder
        .decode_complex_real(&decryptor.decrypt_real(&relinearized).unwrap())
        .unwrap();
    assert_real_close(&decoded[..3], &expected);
}

#[test]
fn partial_decryption_reconstructs_ckks_values_with_tolerance() {
    // Real, end-to-end proof that `PartialDecryptor` is genuine collective
    // decryption - `aggregate_plaintext`'s own output already *is* the
    // decrypted plaintext, no test-only secret reconstruction needed at
    // all, mirroring `phase15_mpbfv.rs`'s own equivalent test.
    let params = real_params();
    let ring = params.ring();
    let n = 3;
    let ckg_session = session(ProtocolKind::CollectiveKeyGen);
    let partial_session = session(ProtocolKind::PartialDecryption);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();
    let mut rng = rng();

    let secrets: Vec<Vec<i128>> = (0..n)
        .map(|_| {
            (0..ring.degree())
                .map(|_| (rng.next_u32() % 3) as i128 - 1)
                .collect()
        })
        .collect();
    let local_secret_shares: Vec<SecretKey> = secrets
        .iter()
        .map(|secret| SecretKey::new(embed_centered_coeffs(secret, ring.moduli()).unwrap()))
        .collect();
    let mut replay_guards: Vec<ReplayGuard> =
        participants.iter().map(|_| ReplayGuard::new()).collect();

    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut ckg_aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        ckg_aggregator
            .add_share(
                ckg.create_share(participant, local_secret_share, replay_guard, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key = ckg.aggregate_public_key(&ckg_aggregator).unwrap();

    let ctx = CkksContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let values = vec![
        Complex64::real(0.5),
        Complex64::real(-1.25),
        Complex64::real(4.0),
    ];
    let plaintext = encoder.encode_complex_real(&values).unwrap();
    let ciphertext = encryptor.encrypt_real(&plaintext, &mut rng).unwrap();

    let partial = PartialDecryptor::new(
        params,
        partial_session.clone(),
        phantom_lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS,
    );
    let mut partial_aggregator =
        ShareAggregator::new(partial_session, ShareKind::PartialDecryption);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        partial_aggregator
            .add_share(
                partial
                    .create_share(
                        participant,
                        local_secret_share,
                        &ciphertext,
                        replay_guard,
                        &mut rng,
                    )
                    .unwrap(),
            )
            .unwrap();
    }
    let reconstructed = partial
        .aggregate_plaintext(&partial_aggregator, &ciphertext)
        .unwrap();

    assert_real_close(
        &encoder.decode_complex_real(&reconstructed).unwrap()[..3],
        &[0.5, -1.25, 4.0],
    );
}

#[test]
fn invalid_ckks_shares_are_detected() {
    // This test's own point is `ShareAggregator`-level validation
    // (duplicate participants, stale sessions), orthogonal to whether
    // `PartialDecryptor`'s own cryptography is real - see
    // `phase15_mpbfv.rs`'s own equivalent test for the identical rationale.
    let params = real_params();
    let ring = params.ring();
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(keys.public);
    let ciphertext = encryptor
        .encrypt_real(
            &encoder
                .encode_complex_real(&[Complex64::real(1.0), Complex64::real(2.0)])
                .unwrap(),
            &mut rng,
        )
        .unwrap();
    let secret =
        SecretKey::new(embed_centered_coeffs(&vec![0i128; ring.degree()], ring.moduli()).unwrap());
    let mut replay_guard = ReplayGuard::new();

    let partial = PartialDecryptor::new(
        params.clone(),
        session(ProtocolKind::PartialDecryption),
        phantom_lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS,
    );
    let share = partial
        .create_share(id(1), &secret, &ciphertext, &mut replay_guard, &mut rng)
        .unwrap();
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::PartialDecryption),
        ShareKind::PartialDecryption,
    );
    aggregator.add_share(share.clone()).unwrap();
    assert_eq!(
        aggregator.add_share(share).unwrap_err(),
        MultipartyError::DuplicateParticipant
    );

    let stale_partial = PartialDecryptor::new(
        params,
        SessionState::new(
            SessionId::new(999).unwrap(),
            ProtocolKind::PartialDecryption,
            ParticipantSet::new(vec![id(1), id(2), id(3)]).unwrap(),
            2,
        )
        .unwrap(),
        phantom_lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS,
    );
    let stale = stale_partial
        .create_share(id(2), &secret, &ciphertext, &mut replay_guard, &mut rng)
        .unwrap();
    assert_eq!(
        aggregator.add_share(stale).unwrap_err(),
        MultipartyError::StaleShare
    );
}

#[test]
fn reencryption_via_pcks_delivers_the_result_to_a_genuinely_separate_recipient() {
    // Real, end-to-end proof that `ReEncryptor` is genuine collaborative
    // key-switching (PCKS) for CKKS, mirroring `phase15_mpbfv.rs`'s own
    // equivalent test: `n` participants generate a real collective key,
    // then collectively re-encrypt a ciphertext under it toward a wholly
    // separate recipient keypair.
    let params = real_params();
    let ring = params.ring();
    let n = 3;
    let ckg_session = session(ProtocolKind::CollectiveKeyGen);
    let reenc_session = session(ProtocolKind::ReEncryption);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();
    let mut rng = rng();

    let secrets: Vec<Vec<i128>> = (0..n)
        .map(|_| {
            (0..ring.degree())
                .map(|_| (rng.next_u32() % 3) as i128 - 1)
                .collect()
        })
        .collect();
    let local_secret_shares: Vec<SecretKey> = secrets
        .iter()
        .map(|secret| SecretKey::new(embed_centered_coeffs(secret, ring.moduli()).unwrap()))
        .collect();
    let mut replay_guards: Vec<ReplayGuard> =
        participants.iter().map(|_| ReplayGuard::new()).collect();

    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut ckg_aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        ckg_aggregator
            .add_share(
                ckg.create_share(participant, local_secret_share, replay_guard, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key = ckg.aggregate_public_key(&ckg_aggregator).unwrap();

    let ctx = CkksContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let values = vec![
        Complex64::real(2.0),
        Complex64::real(4.0),
        Complex64::real(6.0),
    ];
    let plaintext = encoder.encode_complex_real(&values).unwrap();
    let ciphertext = encryptor.encrypt_real(&plaintext, &mut rng).unwrap();

    // A wholly separate recipient keypair - never part of DKG.
    let recipient_keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();

    let reencryption = ReEncryptor::new(
        params,
        reenc_session.clone(),
        phantom_lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS,
    );
    let mut reenc_aggregator = ShareAggregator::new(reenc_session, ShareKind::ReEncryption);
    for ((&participant, local_secret_share), replay_guard) in participants
        .iter()
        .zip(&local_secret_shares)
        .zip(&mut replay_guards)
    {
        reenc_aggregator
            .add_share(
                reencryption
                    .create_share(
                        participant,
                        local_secret_share,
                        &ciphertext,
                        &recipient_keys.public,
                        replay_guard,
                        &mut rng,
                    )
                    .unwrap(),
            )
            .unwrap();
    }
    let ct_recipient = reencryption
        .aggregate_ciphertext(&reenc_aggregator, &ciphertext)
        .unwrap();

    let decryptor = ctx.real_decryptor(recipient_keys.secret).unwrap();
    let decrypted = decryptor.decrypt_real(&ct_recipient).unwrap();
    assert_real_close(
        &encoder.decode_complex_real(&decrypted).unwrap()[..3],
        &[2.0, 4.0, 6.0],
    );
}

#[test]
fn interactive_ckks_bootstrap_preserves_values_and_refreshes_metadata() {
    // `InteractiveBootstrap` remains a placeholder for CKKS - out of scope
    // for this item (CKG/PCKS/PartialDecryptor only). Confirmed
    // independent of all five protocols: it calls the transparent
    // `Bootstrapper::bootstrap` scaffold, not `bootstrap_real`, and doesn't
    // consume a real `CollectiveKeyGen` public key or `PartialDecryptor`
    // output.
    let params = params();
    let bootstrap_params = BootstrapParams::builder(params.clone())
        .target_precision_bits(18.0)
        .target_level(params.initial_level())
        .build()
        .unwrap();
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public.clone()).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let ciphertext = encryptor
        .encrypt(
            &encoder
                .encode_complex(&[Complex64::new(1.0, 0.5), Complex64::new(-2.0, 1.0)])
                .unwrap(),
            &mut rng,
        )
        .unwrap();
    let bootstrap = InteractiveBootstrap::new(
        params,
        bootstrap_params.clone(),
        session(ProtocolKind::InteractiveBootstrap),
    );
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::InteractiveBootstrap),
        ShareKind::InteractiveBootstrap,
    );
    aggregator
        .add_share(bootstrap.create_share(id(1), &ciphertext).unwrap())
        .unwrap();
    aggregator
        .add_share(bootstrap.create_share(id(2), &ciphertext).unwrap())
        .unwrap();

    let refreshed = bootstrap.aggregate_refreshed(&aggregator).unwrap();
    let decrypted = decryptor.decrypt(&refreshed).unwrap();
    let decoded = encoder.decode_complex(&decrypted).unwrap();
    assert_complex_close(decoded[0], Complex64::new(1.0, 0.5));
    assert_complex_close(decoded[1], Complex64::new(-2.0, 1.0));
    assert_eq!(refreshed.level(), bootstrap_params.target_level());
    assert_eq!(refreshed.precision().bits(), 18.0);
}
