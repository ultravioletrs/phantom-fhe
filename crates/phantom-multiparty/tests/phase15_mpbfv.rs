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
fn collective_bfv_evaluation_key_generation_returns_markers() {
    // RelinearizationKeyGen/GaloisKeyGen remain placeholders for BFV -
    // real RNS-hybrid multiparty key generation is separate, larger
    // follow-up work (Workstream 7), not part of this item's own scope
    // (CKG/PCKS/PartialDecryptor only).
    let rkg = RelinearizationKeyGen::new(session(ProtocolKind::RelinearizationKeyGen));
    let mut rkg_aggregator = ShareAggregator::new(
        session(ProtocolKind::RelinearizationKeyGen),
        ShareKind::RelinearizationKeyGen,
    );
    rkg_aggregator
        .add_share(rkg.create_share(id(1)).unwrap())
        .unwrap();
    rkg_aggregator
        .add_share(rkg.create_share(id(2)).unwrap())
        .unwrap();
    let _relin = rkg.aggregate_key(&rkg_aggregator).unwrap();

    let gkg = GaloisKeyGen::new(session(ProtocolKind::GaloisKeyGen), vec![1, 5]);
    let mut gkg_aggregator =
        ShareAggregator::new(session(ProtocolKind::GaloisKeyGen), ShareKind::GaloisKeyGen);
    gkg_aggregator
        .add_share(gkg.create_share(id(1)).unwrap())
        .unwrap();
    gkg_aggregator
        .add_share(gkg.create_share(id(2)).unwrap())
        .unwrap();
    let galois = gkg.aggregate_keys(&gkg_aggregator).unwrap();

    assert_eq!(galois.len(), 2);
    assert_eq!(galois[0].element(), 1);
    assert_eq!(galois[1].element(), 5);
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
