use phantom_multiparty::common::{
    aggregate_u64_shares_mod, ParticipantId, ParticipantSet, ProtocolKind, SessionId, SessionState,
    Share, ShareAggregator, ShareKind, Transcript, TranscriptMessage,
};
use phantom_multiparty::MultipartyError;

fn id(value: u64) -> ParticipantId {
    ParticipantId::new(value).unwrap()
}

fn session() -> SessionState {
    SessionState::new(
        SessionId::new(42).unwrap(),
        ProtocolKind::PartialDecryption,
        ParticipantSet::new(vec![id(3), id(1), id(2)]).unwrap(),
        2,
    )
    .unwrap()
}

fn payload(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

#[test]
fn participant_and_session_validation_reject_bad_inputs() {
    assert!(ParticipantId::new(0).is_err());
    assert!(SessionId::new(0).is_err());
    assert_eq!(
        ParticipantSet::new(vec![id(1), id(1)]).unwrap_err(),
        MultipartyError::DuplicateParticipant
    );

    let participants = ParticipantSet::new(vec![id(3), id(1), id(2)]).unwrap();
    assert_eq!(participants.participants(), &[id(1), id(2), id(3)]);
    assert!(SessionState::new(
        SessionId::new(1).unwrap(),
        ProtocolKind::CollectiveKeyGen,
        participants.clone(),
        0
    )
    .is_err());
    assert!(SessionState::new(
        SessionId::new(1).unwrap(),
        ProtocolKind::CollectiveKeyGen,
        participants,
        4
    )
    .is_err());
}

#[test]
fn transcript_encoding_and_hashing_are_deterministic() {
    let session = session();
    let msg1 = TranscriptMessage::new(&session, id(1), b"round-share", b"abc").unwrap();
    let msg2 = TranscriptMessage::new(&session, id(2), b"round-share", b"def").unwrap();
    let decoded = TranscriptMessage::decode(&msg1.encode()).unwrap();
    assert_eq!(decoded, msg1);

    let mut transcript_a = Transcript::new(session.clone());
    transcript_a.append(msg1.clone()).unwrap();
    transcript_a.append(msg2.clone()).unwrap();

    let mut transcript_b = Transcript::new(session);
    transcript_b.append(msg1).unwrap();
    transcript_b.append(msg2).unwrap();

    assert_eq!(transcript_a.encode(), transcript_b.encode());
    assert_eq!(transcript_a.hash(), transcript_b.hash());
}

#[test]
fn transcript_rejects_stale_or_unknown_messages() {
    let session = session();
    assert!(TranscriptMessage::new(&session, id(9), b"share", b"x").is_err());

    let mut next_round = session.clone();
    next_round.advance_round();
    let stale = TranscriptMessage::new(&next_round, id(1), b"share", b"x").unwrap();
    let mut transcript = Transcript::new(session);
    assert_eq!(
        transcript.append(stale).unwrap_err(),
        MultipartyError::StaleShare
    );
}

#[test]
fn share_encoding_round_trips_and_aggregation_is_ordered() {
    let session = session();
    let share1 = Share::new(
        &session,
        id(2),
        ShareKind::PartialDecryption,
        payload(&[5, 7]),
    )
    .unwrap();
    let share2 = Share::new(
        &session,
        id(1),
        ShareKind::PartialDecryption,
        payload(&[10, 11]),
    )
    .unwrap();
    assert_eq!(Share::decode(&share1.encode()).unwrap(), share1);

    let mut aggregator = ShareAggregator::new(session, ShareKind::PartialDecryption);
    assert!(!aggregator.is_ready());
    assert_eq!(
        aggregator.aggregate().unwrap_err(),
        MultipartyError::ThresholdNotMet
    );
    aggregator.add_share(share1).unwrap();
    aggregator.add_share(share2).unwrap();
    assert!(aggregator.is_ready());

    let shares = aggregator.aggregate().unwrap();
    assert_eq!(shares[0].participant(), id(1));
    assert_eq!(shares[1].participant(), id(2));
    assert_eq!(aggregate_u64_shares_mod(&shares, 17).unwrap(), vec![15, 1]);
}

#[test]
fn share_aggregator_rejects_duplicate_unknown_stale_and_malformed_shares() {
    let session = session();
    let share = Share::new(&session, id(1), ShareKind::PartialDecryption, payload(&[1])).unwrap();
    let mut aggregator = ShareAggregator::new(session.clone(), ShareKind::PartialDecryption);
    aggregator.add_share(share.clone()).unwrap();
    assert_eq!(
        aggregator.add_share(share).unwrap_err(),
        MultipartyError::DuplicateParticipant
    );

    assert_eq!(
        Share::new(&session, id(9), ShareKind::PartialDecryption, payload(&[1])).unwrap_err(),
        MultipartyError::UnknownParticipant
    );

    let mut next_round = session.clone();
    next_round.advance_round();
    let stale = Share::new(
        &next_round,
        id(2),
        ShareKind::PartialDecryption,
        payload(&[1]),
    )
    .unwrap();
    assert_eq!(
        aggregator.add_share(stale).unwrap_err(),
        MultipartyError::StaleShare
    );

    let wrong_kind =
        Share::new(&session, id(2), ShareKind::CollectiveKeyGen, payload(&[1])).unwrap();
    assert_eq!(
        aggregator.add_share(wrong_kind).unwrap_err(),
        MultipartyError::MalformedMessage
    );

    assert_eq!(
        aggregate_u64_shares_mod(
            &[Share::new(&session, id(2), ShareKind::PartialDecryption, vec![1, 2]).unwrap()],
            17
        )
        .unwrap_err(),
        MultipartyError::MalformedMessage
    );
}
