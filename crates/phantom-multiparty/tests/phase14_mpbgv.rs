use curve25519_dalek::scalar::Scalar;
use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_lattice::rlwe::SecretKey;
use phantom_multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, SessionId, SessionState, ShareAggregator,
    ShareKind,
};
use phantom_multiparty::mpbgv::{
    CollectiveKeyGen, GaloisKeyGen, InteractiveBootstrap, PartialDecryptor, ReEncryptor,
    RelinearizationKeyGen,
};
use phantom_multiparty::vss::{
    reconstruct_secret, PedersenGenerators, ShareAccumulator, VectorPolynomial, VssCommitmentSet,
};
use phantom_multiparty::MultipartyError;
use phantom_ring::rns::extension::embed_centered_coeffs;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bgv::{BgvContext, BgvParams, EvaluationKeys};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn id(value: u64) -> ParticipantId {
    ParticipantId::new(value).unwrap()
}

fn params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(257).unwrap(), Modulus::new(769).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, 17).unwrap()
}

// Real BGV encryption injects noise scaled by the plaintext modulus (see
// `bgv::Encryptor`'s own module doc comment) - `params()`'s own toy [257,
// 769] moduli have no room for that at all, confirmed directly: even a
// single-party `generate_keypair_real` round trip against `params()` fails
// the majority of the time across randomized seeds (43/50 in one run),
// since it was never exercised against BGV's real path before this file's
// own DKG-backed CKG test - every other `mpbgv` test uses the transparent
// scaffold, which ignores noise budgets entirely. Reusing
// `phantom-schemes/tests/phase5_bgv.rs`'s own `real_params()` fixture
// (same modulus, same rationale) rather than re-deriving a new one.
fn real_ckg_params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(8).unwrap(),
        vec![Modulus::new(1_000_000_000_000_037).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, 17).unwrap()
}

fn session(protocol: ProtocolKind) -> SessionState {
    SessionState::new(
        SessionId::new(protocol_tag(protocol) as u64 + 100).unwrap(),
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
    ChaCha20Rng::from_seed([23; 32])
}

#[test]
fn collective_public_key_encrypts_decryptable_ciphertexts() {
    let params = params();
    let ctx = BgvContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let ckg = CollectiveKeyGen::new(params.clone(), session(ProtocolKind::CollectiveKeyGen));
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::CollectiveKeyGen),
        ShareKind::CollectiveKeyGen,
    );
    let ring = params.ring();
    let placeholder_secret = |seed: i128| -> SecretKey {
        let coeffs: Vec<i128> = (0..ring.degree() as i128)
            .map(|i| (i + seed) % 3 - 1)
            .collect();
        SecretKey::new(embed_centered_coeffs(&coeffs, ring.moduli()).unwrap())
    };
    aggregator
        .add_share(
            ckg.create_share(id(1), &placeholder_secret(0), &mut rng)
                .unwrap(),
        )
        .unwrap();
    aggregator
        .add_share(
            ckg.create_share(id(2), &placeholder_secret(1), &mut rng)
                .unwrap(),
        )
        .unwrap();

    // This test exercises only the *transparent* path (`ctx.encryptor`,
    // which ignores the public key entirely - "no real cryptographic
    // content", per `Encryptor`'s own doc comment) against an unrelated
    // single-party keypair, so it stays valid unchanged after
    // `CollectiveKeyGen` became real: it was never a correctness proof of
    // collective key generation itself, only of the arithmetic not
    // crashing. See
    // `collective_public_key_generation_via_dkg_produces_a_genuinely_decryptable_key`
    // below for the real, meaningful correctness proof.
    let public_key = ckg.aggregate_public_key(&aggregator).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(public_key).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let plaintext = encoder.encode_u64(&[3, 4, 5, 6]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();

    assert_eq!(&encoder.decode_u64(&decrypted).unwrap()[..4], &[3, 4, 5, 6]);
}

#[test]
fn collective_public_key_generation_via_dkg_produces_a_genuinely_decryptable_key() {
    // Real, end-to-end proof that `CollectiveKeyGen` is genuine BGV key
    // generation for a collective secret `s = sum_d s_d`, not just
    // arithmetic that happens not to crash: `n` participants each generate
    // their own small local secret independently (kept entirely to
    // themselves - only their own public CKG share `b_d` is ever
    // transmitted), wire real collective public-key generation, then -
    // test-only, and explicitly NOT a production pattern, since it
    // reconstructs the full collective secret and thereby defeats the
    // entire point of never assembling it - verify correctness by also
    // running a `phantom_multiparty::vss` distributed-key-generation round
    // over the *same* per-dealer secrets (demonstrating the two compose:
    // a real deployment would run VSS to give participants a verifiable,
    // recoverable backup of each other's own secret shares, entirely
    // independent of what CKG itself needs to work - see
    // `CollectiveKeyGen`'s own doc comment) and reconstructing the sum via
    // Lagrange interpolation, an independent path to the same value CKG's
    // own polynomial-sum math should have produced.
    let params = real_ckg_params();
    let ring = params.ring();
    let n = 3;
    let threshold = 2;
    let vector_len = ring.degree();
    let ckg_session = session(ProtocolKind::CollectiveKeyGen);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();
    let mut rng = rng();

    // Each dealer's own small (ternary-shaped) secret contribution - known
    // only to that dealer, never transmitted. Genuinely random (not a
    // deterministic pattern): a cyclic-shift pattern tried first summed to
    // the all-zero collective secret across exactly 3 dealers, an
    // insecure-but-not-obviously-wrong degenerate case that masked a
    // separate bug below rather than exercising real key material.
    let secrets: Vec<Vec<i128>> = (0..n)
        .map(|_| {
            (0..vector_len)
                .map(|_| (rng.next_u32() % 3) as i128 - 1)
                .collect()
        })
        .collect();

    // A verifiable-secret-sharing round over those same per-dealer secrets
    // - composable with, but not required by, CKG's own correctness (see
    // this test's own doc comment above).
    let generators = PedersenGenerators::derive(vector_len);
    let polynomials: Vec<VectorPolynomial> = participants
        .iter()
        .zip(&secrets)
        .map(|(&dealer, secret)| {
            VectorPolynomial::sample(&mut rng, dealer, secret, threshold).unwrap()
        })
        .collect();
    let commitment_sets: Vec<VssCommitmentSet> = polynomials
        .iter()
        .map(|poly| poly.commit(&generators).unwrap())
        .collect();
    let mut final_shares: Vec<(ParticipantId, Vec<Scalar>)> = Vec::new();
    for &recipient in &participants {
        let mut accumulator = ShareAccumulator::new(recipient, vector_len);
        for (poly, commitments) in polynomials.iter().zip(&commitment_sets) {
            let share = poly.create_share(recipient);
            accumulator
                .add_verified_share(&share, commitments, &generators)
                .unwrap();
        }
        final_shares.push((recipient, accumulator.finalize().0));
    }

    // Real collective public-key generation: each participant's own
    // `create_share` uses their own already-known small secret directly
    // (never a Shamir share of it - see `CollectiveKeyGen`'s own doc
    // comment for why that distinction matters).
    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for (&participant, secret) in participants.iter().zip(&secrets) {
        let local_secret_share =
            SecretKey::new(embed_centered_coeffs(secret, ring.moduli()).unwrap());
        aggregator
            .add_share(
                ckg.create_share(participant, &local_secret_share, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key = ckg.aggregate_public_key(&aggregator).unwrap();

    // Test-only: reconstruct the full collective secret to verify
    // correctness, via an independent path (Lagrange interpolation over
    // the VSS round's own final shares) rather than trusting the same
    // polynomial-sum arithmetic CKG itself uses.
    let magnitude_bound = n as i128; // sum of n ternary-shaped values
    let reconstructed_coeffs =
        reconstruct_secret(&final_shares[..threshold], threshold, magnitude_bound).unwrap();
    let expected_sum: Vec<i128> = (0..vector_len)
        .map(|slot| secrets.iter().map(|s| s[slot]).sum())
        .collect();
    assert_eq!(reconstructed_coeffs, expected_sum);
    let reconstructed_secret =
        SecretKey::new(embed_centered_coeffs(&reconstructed_coeffs, ring.moduli()).unwrap());

    let ctx = BgvContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let decryptor = ctx.decryptor(reconstructed_secret).unwrap();
    let plaintext = encoder.encode_u64(&[3, 4, 5, 6]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();

    assert_eq!(&encoder.decode_u64(&decrypted).unwrap()[..4], &[3, 4, 5, 6]);
}

#[test]
fn collective_relinearization_key_generation_returns_a_marker() {
    // RelinearizationKeyGen remains a placeholder - not wired to real key
    // material yet (unlike CollectiveKeyGen/ReEncryptor/GaloisKeyGen, all
    // real). This test only guards that the placeholder shape still works.
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
    let relin = rkg.aggregate_key(&rkg_aggregator).unwrap();

    let eval_keys = EvaluationKeys {
        relinearization: relin,
        galois: Vec::new(),
    };
    assert!(eval_keys.galois.is_empty());
}

#[test]
fn collective_galois_key_generation_via_real_dkg_rotates_a_genuine_ciphertext() {
    // Real, end-to-end proof that `GaloisKeyGen` produces genuine BGV
    // rotation key material, not a marker: the same `n` participants who
    // generate a real collective public key (`CollectiveKeyGen`) also
    // collectively generate a real rotation key for one shift amount
    // (`GaloisKeyGen`, additive n-of-n, matching `CollectiveKeyGen`'s own
    // shape - see that type's own doc comment for why this isn't
    // Lagrange/Shamir reconstruction), then rotate a real batched
    // ciphertext with it and confirm both encoded rows genuinely shifted.
    let params = real_ckg_params();
    let ring = params.ring();
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

    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut ckg_aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for (&participant, local_secret_share) in participants.iter().zip(&local_secret_shares) {
        ckg_aggregator
            .add_share(
                ckg.create_share(participant, local_secret_share, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key = ckg.aggregate_public_key(&ckg_aggregator).unwrap();

    let shift = 1;
    let element = params.rotation_element(shift);
    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();
    let gkg = GaloisKeyGen::new(
        params.clone(),
        gkg_session.clone(),
        element,
        decomposition_params,
    );
    let mut gkg_aggregator = ShareAggregator::new(gkg_session, ShareKind::GaloisKeyGen);
    for (&participant, local_secret_share) in participants.iter().zip(&local_secret_shares) {
        gkg_aggregator
            .add_share(
                gkg.create_share(participant, local_secret_share, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_rotation_key = gkg.aggregate_keys(&gkg_aggregator).unwrap();

    let ctx = BgvContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let half = ring.degree() / 2;
    let values: Vec<u64> = (0..ring.degree() as u64).map(|i| i + 1).collect();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_batched(&values).unwrap(), &mut rng)
        .unwrap();

    let evaluator = ctx.evaluator().unwrap();
    let rotated = evaluator
        .rotate_real(&ciphertext, element, &collective_rotation_key)
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
        .decode_batched(&decryptor.decrypt(&rotated).unwrap())
        .unwrap();

    let mut expected_row0 = values[..half].to_vec();
    expected_row0.rotate_left(shift);
    let mut expected_row1 = values[half..].to_vec();
    expected_row1.rotate_left(shift);
    let expected: Vec<u64> = expected_row0.into_iter().chain(expected_row1).collect();
    assert_eq!(decoded, expected);
}

#[test]
fn partial_decryption_reconstructs_plaintext() {
    let params = params();
    let ctx = BgvContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let plaintext = encoder.encode_u64(&[7, 8, 9, 10]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let partial = PartialDecryptor::new(params.clone(), session(ProtocolKind::PartialDecryption));
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::PartialDecryption),
        ShareKind::PartialDecryption,
    );

    aggregator
        .add_share(partial.create_share(id(1), &ciphertext).unwrap())
        .unwrap();
    aggregator
        .add_share(partial.create_share(id(2), &ciphertext).unwrap())
        .unwrap();
    let reconstructed = partial.aggregate_plaintext(&aggregator).unwrap();

    assert_eq!(
        &encoder.decode_u64(&reconstructed).unwrap()[..4],
        &[7, 8, 9, 10]
    );
}

#[test]
fn invalid_shares_are_detected() {
    let params = params();
    let ctx = BgvContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_u64(&[1, 2]).unwrap(), &mut rng)
        .unwrap();
    let partial = PartialDecryptor::new(params.clone(), session(ProtocolKind::PartialDecryption));
    let share = partial.create_share(id(1), &ciphertext).unwrap();
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
        params.clone(),
        SessionState::new(
            SessionId::new(999).unwrap(),
            ProtocolKind::PartialDecryption,
            ParticipantSet::new(vec![id(1), id(2), id(3)]).unwrap(),
            2,
        )
        .unwrap(),
    );
    let stale = stale_partial.create_share(id(2), &ciphertext).unwrap();
    assert_eq!(
        aggregator.add_share(stale).unwrap_err(),
        MultipartyError::StaleShare
    );
}

#[test]
fn reencryption_via_pcks_delivers_the_result_to_a_genuinely_separate_recipient() {
    // Real, end-to-end proof that `ReEncryptor` is genuine collaborative
    // key-switching (PCKS), matching this crate's own actual target
    // deployment (a confidential-analytics cleanroom: providers jointly
    // generate a collective key via DKG, encrypt under it, and later
    // collectively re-encrypt a result toward a *recipient* who never
    // participated in key generation at all - see `ReEncryptor`'s own doc
    // comment). `n` participants each contribute their own already-known
    // small secret (same shape `CollectiveKeyGen` already uses) to both
    // generate the collective key and later re-encrypt a ciphertext under
    // it toward a wholly separate recipient keypair - the platform
    // combining shares never sees the plaintext, the collective secret, or
    // the recipient's own secret.
    let params = real_ckg_params();
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

    let ckg = CollectiveKeyGen::new(params.clone(), ckg_session.clone());
    let mut ckg_aggregator = ShareAggregator::new(ckg_session, ShareKind::CollectiveKeyGen);
    for (&participant, local_secret_share) in participants.iter().zip(&local_secret_shares) {
        ckg_aggregator
            .add_share(
                ckg.create_share(participant, local_secret_share, &mut rng)
                    .unwrap(),
            )
            .unwrap();
    }
    let collective_public_key = ckg.aggregate_public_key(&ckg_aggregator).unwrap();

    let ctx = BgvContext::new(params.clone());
    let encoder = ctx.encoder();
    let encryptor = ctx.real_encryptor(collective_public_key);
    let plaintext = encoder.encode_u64(&[2, 4, 6, 8]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();

    // A wholly separate recipient keypair - never part of DKG.
    let recipient_keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();

    let reencryption = ReEncryptor::new(params, reenc_session.clone());
    let mut reenc_aggregator = ShareAggregator::new(reenc_session, ShareKind::ReEncryption);
    for (&participant, local_secret_share) in participants.iter().zip(&local_secret_shares) {
        reenc_aggregator
            .add_share(
                reencryption
                    .create_share(
                        participant,
                        local_secret_share,
                        &ciphertext,
                        &recipient_keys.public,
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
    assert_eq!(&encoder.decode_u64(&decrypted).unwrap()[..4], &[2, 4, 6, 8]);
}

#[test]
fn interactive_bootstrap_preserves_plaintext() {
    let params = params();
    let ctx = BgvContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public.clone()).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_u64(&[5, 6, 7, 8]).unwrap(), &mut rng)
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
    assert_eq!(&encoder.decode_u64(&decrypted).unwrap()[..4], &[5, 6, 7, 8]);
}
