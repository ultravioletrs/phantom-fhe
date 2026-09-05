use phantom_lattice::rlwe::SecretKey;
use phantom_multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, ReplayGuard, SessionId, SessionState,
    ShareAggregator, ShareKind,
};
use phantom_multiparty::mpbfv::{
    CollectiveKeyGen, GaloisKeyGen, InteractiveBootstrap, PartialDecryptor, ReEncryptor,
    RelinearizationKeyGen,
};
use phantom_multiparty::MultipartyError;
use phantom_ring::rns::extension::embed_centered_coeffs;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bfv::{BfvContext, BfvParams};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn id(value: u64) -> ParticipantId {
    ParticipantId::new(value).unwrap()
}

fn params() -> BfvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(257).unwrap(), Modulus::new(769).unwrap()],
    )
    .unwrap();
    BfvParams::new(ring, 17).unwrap()
}

// Real BFV encryption needs noise-safe parameters - `params()`'s own toy
// [257, 769] moduli were only ever exercised against the transparent
// scaffold. Reusing `phantom-schemes/tests/phase6_bfv.rs`'s own
// `real_params()` fixture (same modulus, same rationale) rather than
// re-deriving a new one - the same precedent `phantom-multiparty`'s own
// `phase14_mpbgv.rs` set for BGV.
fn real_params() -> BfvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(1_000_000_000_000_037).unwrap()],
    )
    .unwrap();
    BfvParams::new(ring, 17).unwrap()
}

// Auxiliary "P" moduli for the real RNS-hybrid GKG/RKG construction - the
// same pair `phantom-schemes/tests/phase6_bfv.rs`'s own `p_moduli()` uses
// for real BFV multiplication's own rescale-and-round step, already
// Miller-Rabin verified there.
fn p_moduli() -> Vec<Modulus> {
    vec![
        Modulus::new(1_000_000_000_000_091).unwrap(),
        Modulus::new(1_000_000_000_000_159).unwrap(),
    ]
}

fn session(protocol: ProtocolKind) -> SessionState {
    SessionState::new(
        SessionId::new(protocol_tag(protocol) as u64 + 150).unwrap(),
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
    ChaCha20Rng::from_seed([31; 32])
}

#[test]
fn collective_public_key_generation_via_dkg_produces_a_genuinely_decryptable_key() {
    // Real, end-to-end proof that `CollectiveKeyGen` is genuine BFV key
    // generation for a collective secret `s = sum_d s_d`, not just
    // arithmetic that happens not to crash - mirrors `phase14_mpbgv.rs`'s
    // own equivalent test, minus the `t`-scaling BGV's own construction
    // needs and BFV's own real path doesn't (see `mpbfv::ckg`'s own doc
    // comment).
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

    let ctx = BfvContext::new(params);
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(public_key);
    let decryptor = ctx.decryptor(collective_secret).unwrap();
    let plaintext = encoder.encode_i64(&[-3, 4, -5, 6]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();

    assert_eq!(
        &encoder.decode_i64_real(&decrypted).unwrap()[..4],
        &[-3, 4, -5, 6]
    );
}

#[test]
fn collective_galois_key_generation_via_real_dkg_rotates_a_genuine_ciphertext() {
    // Real, end-to-end proof that `GaloisKeyGen` produces genuine RNS-hybrid
    // BFV rotation key material - mirrors `phase14_mpbgv.rs`'s own
    // equivalent test, using the shared `common::hybrid` construction
    // (see `mpbfv::gkg`'s own doc comment) instead of BGV's own bespoke
    // classical-gadget-decomposition one.
    let params = real_params();
    let ring = params.ring();
    let p_moduli = p_moduli();
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

    let ctx = BfvContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let half = ring.degree() / 2;
    let values: Vec<u64> = (0..ring.degree() as u64).map(|i| i + 1).collect();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_batched(&values).unwrap(), &mut rng)
        .unwrap();

    let evaluator = ctx.evaluator().unwrap();
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
    let decryptor = ctx.decryptor(collective_secret).unwrap();
    let decoded = encoder
        .decode_batched_real(&decryptor.decrypt(&rotated).unwrap())
        .unwrap();

    let mut expected_row0 = values[..half].to_vec();
    expected_row0.rotate_left(shift);
    let mut expected_row1 = values[half..].to_vec();
    expected_row1.rotate_left(shift);
    let expected: Vec<u64> = expected_row0.into_iter().chain(expected_row1).collect();
    assert_eq!(decoded, expected);
}

#[test]
fn collective_relinearization_key_generation_via_real_dkg_relinearizes_a_genuine_product() {
    // Real, end-to-end proof that `RelinearizationKeyGen` produces genuine
    // RNS-hybrid BFV relinearization key material via its own three-round
    // protocol (see `mpbfv::rkg`'s own doc comment for why this needs one
    // more round than `mpbgv::rkg`'s two). Correctness is checked against
    // the *raw*, not-yet-relinearized product ciphertext, mirroring
    // `phase14_mpbgv.rs`'s own equivalent test.
    let params = real_params();
    let ring = params.ring();
    let p_moduli = p_moduli();
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

    // Round 0 runs against `rkg`'s own `session` constructor argument
    // (round1/round2 are one/two rounds advanced from it) - clone it before
    // it's moved into `RelinearizationKeyGen::new` so this test can also
    // build round 0's own aggregator against the identical session.
    let round0_session = rkg_session.clone();
    let rkg = RelinearizationKeyGen::new(params.clone(), rkg_session, p_moduli.clone());

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

    let ctx = BfvContext::new(params.clone());
    let encoder = ctx.encoder();
    let evaluator = ctx.evaluator().unwrap();
    let encryptor = ctx.real_encryptor(collective_public_key);

    let a_values: Vec<u64> = (0..ring.degree() as u64).map(|i| i % 17).collect();
    let b_values: Vec<u64> = (0..ring.degree() as u64)
        .map(|i| (2 * i + 1) % 17)
        .collect();
    let a_ct = encryptor
        .encrypt(&encoder.encode_u64(&a_values).unwrap(), &mut rng)
        .unwrap();
    let b_ct = encryptor
        .encrypt(&encoder.encode_u64(&b_values).unwrap(), &mut rng)
        .unwrap();

    let product = evaluator.mul_real(&a_ct, &b_ct, &p_moduli).unwrap();
    assert_eq!(product.degree(), 2);
    let relinearized = evaluator
        .relinearize_real(&product, &collective_relin_key)
        .unwrap();
    assert_eq!(relinearized.degree(), 1);

    let collective_secret_coeffs: Vec<i128> = (0..ring.degree())
        .map(|coeff| secrets.iter().map(|s| s[coeff]).sum())
        .collect();
    let collective_secret =
        SecretKey::new(embed_centered_coeffs(&collective_secret_coeffs, ring.moduli()).unwrap());
    let decryptor = ctx.decryptor(collective_secret).unwrap();

    let raw_decoded = encoder
        .decode_u64_real(&decryptor.decrypt(&product).unwrap())
        .unwrap();
    let relinearized_decoded = encoder
        .decode_u64_real(&decryptor.decrypt(&relinearized).unwrap())
        .unwrap();
    assert_eq!(relinearized_decoded, raw_decoded);
}

#[test]
fn partial_decryption_reconstructs_signed_bfv_plaintext() {
    // Real, end-to-end proof that `PartialDecryptor` is genuine collective
    // decryption - `aggregate_plaintext`'s own output already *is* the
    // decrypted plaintext, no test-only secret reconstruction needed at
    // all, mirroring `phase14_mpbgv.rs`'s own equivalent test.
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

    let ctx = BfvContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let plaintext = encoder.encode_i64(&[-2, 3, 5, -6]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();

    let ciphertext_noise_bound =
        phantom_schemes::bfv::noise::fresh_public_key_noise_bound(ring.degree());
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
                        ciphertext_noise_bound,
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

    assert_eq!(
        &encoder.decode_i64_real(&reconstructed).unwrap()[..4],
        &[-2, 3, 5, -6]
    );
}

#[test]
fn invalid_bfv_shares_are_detected() {
    // This test's own point is `ShareAggregator`-level validation
    // (duplicate participants, stale sessions), orthogonal to whether
    // `PartialDecryptor`'s own cryptography is real - see
    // `phase14_mpbgv.rs`'s own equivalent test for the identical rationale.
    let params = real_params();
    let ring = params.ring();
    let ctx = BfvContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(keys.public);
    let ciphertext = encryptor
        .encrypt(&encoder.encode_u64(&[1, 2]).unwrap(), &mut rng)
        .unwrap();
    let secret =
        SecretKey::new(embed_centered_coeffs(&vec![0i128; ring.degree()], ring.moduli()).unwrap());
    let ciphertext_noise_bound =
        phantom_schemes::bfv::noise::fresh_public_key_noise_bound(ring.degree());
    let mut replay_guard = ReplayGuard::new();

    let partial = PartialDecryptor::new(
        params.clone(),
        session(ProtocolKind::PartialDecryption),
        phantom_lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS,
    );
    let share = partial
        .create_share(
            id(1),
            &secret,
            &ciphertext,
            ciphertext_noise_bound,
            &mut replay_guard,
            &mut rng,
        )
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
        .create_share(
            id(2),
            &secret,
            &ciphertext,
            ciphertext_noise_bound,
            &mut replay_guard,
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        aggregator.add_share(stale).unwrap_err(),
        MultipartyError::StaleShare
    );
}

#[test]
fn reencryption_via_pcks_delivers_the_result_to_a_genuinely_separate_recipient() {
    // Real, end-to-end proof that `ReEncryptor` is genuine collaborative
    // key-switching (PCKS) for BFV, mirroring `phase14_mpbgv.rs`'s own
    // equivalent test: `n` participants generate a real collective key,
    // then collectively re-encrypt a ciphertext under it toward a wholly
    // separate recipient keypair - the platform combining shares never
    // sees the plaintext, the collective secret, or the recipient's own
    // secret.
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

    let ctx = BfvContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let plaintext = encoder.encode_u64(&[2, 4, 6, 8]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();

    // A wholly separate recipient keypair - never part of DKG. BFV needs
    // no special "real" keypair generation (unlike BGV) - see
    // `mpbfv::ckg`'s own doc comment for why.
    let recipient_keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();

    let ciphertext_noise_bound =
        phantom_schemes::bfv::noise::fresh_public_key_noise_bound(ring.degree());
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
                        ciphertext_noise_bound,
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

    let decryptor = ctx.decryptor(recipient_keys.secret).unwrap();
    let decrypted = decryptor.decrypt(&ct_recipient).unwrap();
    assert_eq!(
        &encoder.decode_u64_real(&decrypted).unwrap()[..4],
        &[2, 4, 6, 8]
    );
}

#[test]
fn interactive_bfv_bootstrap_preserves_plaintext() {
    // `InteractiveBootstrap` remains a placeholder for BFV - out of scope
    // for this item (CKG/PCKS/PartialDecryptor only).
    let params = params();
    let ctx = BfvContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public.clone()).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_i64(&[-1, 2, -3, 4]).unwrap(), &mut rng)
        .unwrap();
    let bootstrap = InteractiveBootstrap::new(params, session(ProtocolKind::InteractiveBootstrap));
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
    assert_eq!(
        &encoder.decode_i64(&decrypted).unwrap()[..4],
        &[-1, 2, -3, 4]
    );
}
