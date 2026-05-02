use phantom_bootstrapping::ckks::BootstrapParams;
use phantom_multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, SessionId, SessionState, ShareAggregator,
    ShareKind,
};
use phantom_multiparty::mpckks::{
    CollectiveKeyGen, GaloisKeyGen, InteractiveBootstrap, PartialDecryptor, ReEncryptor,
    RelinearizationKeyGen,
};
use phantom_multiparty::MultipartyError;
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64, EvaluationKeys};
use rand_chacha::rand_core::SeedableRng;
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

fn assert_close(actual: &[f64], expected: &[f64]) {
    for (actual, expected) in actual.iter().zip(expected) {
        assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
    }
}

fn assert_complex_close(actual: Complex64, expected: Complex64) {
    assert!(
        (actual.re - expected.re).abs() < 1e-9 && (actual.im - expected.im).abs() < 1e-9,
        "{actual:?} != {expected:?}"
    );
}

#[test]
fn collective_public_key_encrypts_decryptable_ckks_ciphertexts() {
    let params = params();
    let ctx = CkksContext::new(params.clone());
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
    let plaintext = encoder.encode_real(&[1.5, -2.0, 3.25]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();

    assert_close(
        &encoder.decode_real(&decrypted).unwrap()[..3],
        &[1.5, -2.0, 3.25],
    );
}

#[test]
fn collective_ckks_evaluation_key_generation_returns_markers() {
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

    let gkg = GaloisKeyGen::new(session(ProtocolKind::GaloisKeyGen), vec![1, 2]);
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
    assert_eq!(eval_keys.galois[1].element(), 2);
}

#[test]
fn partial_decryption_reconstructs_ckks_values_with_tolerance() {
    let params = params();
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let plaintext = encoder.encode_real(&[0.5, -1.25, 4.0]).unwrap();
    let ciphertext = encryptor.encrypt(&plaintext, &mut rng).unwrap();
    let partial = PartialDecryptor::new(params, session(ProtocolKind::PartialDecryption));
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

    assert_close(
        &encoder.decode_real(&reconstructed).unwrap()[..3],
        &[0.5, -1.25, 4.0],
    );
}

#[test]
fn invalid_ckks_shares_are_detected() {
    let params = params();
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public).unwrap();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_real(&[1.0, 2.0]).unwrap(), &mut rng)
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
        params,
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
fn reencryption_from_ckks_shares_preserves_values() {
    let params = params();
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng();
    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public.clone()).unwrap();
    let decryptor = ctx.decryptor(keys.secret).unwrap();
    let ciphertext = encryptor
        .encrypt(&encoder.encode_real(&[2.0, 4.0, 6.0]).unwrap(), &mut rng)
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
    assert_close(
        &encoder.decode_real(&decrypted).unwrap()[..3],
        &[2.0, 4.0, 6.0],
    );
}

#[test]
fn interactive_ckks_bootstrap_preserves_values_and_refreshes_metadata() {
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
