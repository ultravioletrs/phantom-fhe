use phantom_multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, SessionId, SessionState, ShareAggregator,
    ShareKind,
};
use phantom_multiparty::mpbgv::{
    CollectiveKeyGen, GaloisKeyGen, InteractiveBootstrap, PartialDecryptor, ReEncryptor,
    RelinearizationKeyGen,
};
use phantom_multiparty::MultipartyError;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bgv::{BgvContext, BgvParams, EvaluationKeys};
use rand_chacha::rand_core::SeedableRng;
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
    let ckg = CollectiveKeyGen::new(params, session(ProtocolKind::CollectiveKeyGen));
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::CollectiveKeyGen),
        ShareKind::CollectiveKeyGen,
    );
    aggregator
        .add_share(ckg.create_share(id(1)).unwrap())
        .unwrap();
    aggregator
        .add_share(ckg.create_share(id(2)).unwrap())
        .unwrap();

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
fn collective_evaluation_key_generation_returns_markers() {
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

    let gkg = GaloisKeyGen::new(session(ProtocolKind::GaloisKeyGen), vec![1, 3]);
    let mut gkg_aggregator =
        ShareAggregator::new(session(ProtocolKind::GaloisKeyGen), ShareKind::GaloisKeyGen);
    gkg_aggregator
        .add_share(gkg.create_share(id(1)).unwrap())
        .unwrap();
    gkg_aggregator
        .add_share(gkg.create_share(id(2)).unwrap())
        .unwrap();
    let galois = gkg.aggregate_keys(&gkg_aggregator).unwrap();

    let eval_keys = EvaluationKeys {
        relinearization: relin,
        galois,
    };
    assert_eq!(eval_keys.galois.len(), 2);
    assert_eq!(eval_keys.galois[0].element(), 1);
    assert_eq!(eval_keys.galois[1].element(), 3);
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
fn reencryption_from_shares_preserves_plaintext() {
    let params = params();
    let ctx = BgvContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public.clone()).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_u64(&[2, 4, 6, 8]).unwrap(), &mut rng)
        .unwrap();
    let reencryption = ReEncryptor::new(params, session(ProtocolKind::ReEncryption));
    let mut aggregator =
        ShareAggregator::new(session(ProtocolKind::ReEncryption), ShareKind::ReEncryption);
    aggregator
        .add_share(reencryption.create_share(id(1), &ciphertext).unwrap())
        .unwrap();
    aggregator
        .add_share(reencryption.create_share(id(2), &ciphertext).unwrap())
        .unwrap();

    let refreshed = reencryption.aggregate_ciphertext(&aggregator).unwrap();
    let decrypted = decryptor.decrypt(&refreshed).unwrap();
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
