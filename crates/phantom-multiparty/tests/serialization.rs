//! Serialization coverage for `phantom-multiparty`'s own bespoke wire
//! formats (Workstream 8) - `common::shares::Share` and
//! `vss::share::{VssCommitmentSet, VssShare}`. Unlike the four crates
//! using `phantom_utils::serialization::SerializationHeader`, these
//! formats use their own hand-rolled magic-byte tag with no separate
//! version field (see each type's own `encode`/`decode`), so there is no
//! wrong-version case to test here - only wrong-tag and truncation.

use phantom_multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, SessionId, SessionState, Share, ShareKind,
};
use phantom_multiparty::vss::{PedersenGenerators, VectorPolynomial, VssCommitmentSet, VssShare};
use phantom_multiparty::MultipartyError;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn id(value: u64) -> ParticipantId {
    ParticipantId::new(value).unwrap()
}

fn session() -> SessionState {
    SessionState::new(
        SessionId::new(1).unwrap(),
        ProtocolKind::PartialDecryption,
        ParticipantSet::new(vec![id(1), id(2)]).unwrap(),
        2,
    )
    .unwrap()
}

// Golden-byte fixtures (Workstream 8 item 1) - see
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent
// comment for why this catches something round-trip tests can't.
const GOLDEN_SHARE: &[u8] = &[
    80, 77, 83, 72, 82, 49, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    0, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 7, 8, 9,
];
const GOLDEN_VSS_COMMITMENT_SET: &[u8] = &[
    80, 77, 86, 83, 67, 49, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 130, 111, 106, 190,
    224, 44, 93, 134, 218, 140, 94, 180, 144, 123, 73, 230, 66, 7, 34, 103, 122, 108, 30, 170, 113,
    250, 218, 169, 69, 247, 86, 8, 78, 92, 48, 75, 129, 78, 143, 101, 142, 95, 24, 74, 109, 141,
    226, 217, 149, 213, 209, 47, 21, 0, 9, 174, 33, 113, 248, 140, 7, 195, 44, 86,
];
const GOLDEN_VSS_SHARE: &[u8] = &[
    80, 77, 86, 83, 72, 49, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
    140, 181, 212, 146, 3, 149, 49, 145, 98, 2, 53, 233, 147, 104, 38, 165, 65, 86, 64, 194, 133,
    13, 33, 52, 237, 13, 77, 220, 162, 109, 32, 2, 60, 92, 209, 153, 255, 161, 81, 220, 46, 185,
    129, 214, 103, 237, 186, 114, 227, 157, 152, 171, 148, 105, 244, 229, 175, 239, 95, 119, 242,
    114, 223, 0, 33, 229, 26, 170, 65, 255, 14, 142, 169, 175, 160, 174, 17, 20, 48, 172, 235, 219,
    5, 40, 187, 200, 139, 101, 84, 243, 7, 4, 58, 99, 86, 10,
];

#[test]
fn golden_share_bytes_are_stable() {
    let share = Share::new(
        &session(),
        id(1),
        ShareKind::PartialDecryption,
        vec![7, 8, 9],
    )
    .unwrap();
    assert_eq!(share.encode(), GOLDEN_SHARE);
    let decoded = Share::decode(GOLDEN_SHARE).unwrap();
    assert_eq!(decoded, share);
}

#[test]
fn golden_vss_commitment_set_bytes_are_stable() {
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let generators = PedersenGenerators::derive(2);
    let polynomial = VectorPolynomial::sample(&mut rng, id(1), &[1, -1], 2).unwrap();
    let commitments = polynomial.commit(&generators).unwrap();
    assert_eq!(commitments.encode(), GOLDEN_VSS_COMMITMENT_SET);
    let decoded = VssCommitmentSet::decode(GOLDEN_VSS_COMMITMENT_SET).unwrap();
    assert_eq!(decoded, commitments);
}

#[test]
fn golden_vss_share_bytes_are_stable() {
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let polynomial = VectorPolynomial::sample(&mut rng, id(1), &[1, -1], 2).unwrap();
    let vss_share = polynomial.create_share(id(2));
    assert_eq!(vss_share.encode(), GOLDEN_VSS_SHARE);
    let decoded = VssShare::decode(GOLDEN_VSS_SHARE).unwrap();
    assert_eq!(decoded, vss_share);
}

// Wrong-tag and truncation rejection (Workstream 8 item 2's own equivalent
// for this bespoke format - no separate version field exists here to
// mismatch, see this file's own module doc comment).
#[test]
fn every_type_rejects_a_wrong_tag_and_truncated_payloads() {
    let share_bytes = Share::new(
        &session(),
        id(1),
        ShareKind::PartialDecryption,
        vec![7, 8, 9],
    )
    .unwrap()
    .encode();
    assert_eq!(
        VssCommitmentSet::decode(&share_bytes).unwrap_err(),
        MultipartyError::MalformedMessage
    );
    assert_eq!(
        VssShare::decode(&share_bytes).unwrap_err(),
        MultipartyError::MalformedMessage
    );

    let mut truncated = share_bytes.clone();
    truncated.pop();
    assert_eq!(
        Share::decode(&truncated).unwrap_err(),
        MultipartyError::MalformedMessage
    );

    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let generators = PedersenGenerators::derive(2);
    let polynomial = VectorPolynomial::sample(&mut rng, id(1), &[1, -1], 2).unwrap();
    let commitments_bytes = polynomial.commit(&generators).unwrap().encode();
    assert_eq!(
        Share::decode(&commitments_bytes).unwrap_err(),
        MultipartyError::MalformedMessage
    );
    assert_eq!(
        VssShare::decode(&commitments_bytes).unwrap_err(),
        MultipartyError::MalformedMessage
    );

    let mut truncated_commitments = commitments_bytes.clone();
    truncated_commitments.pop();
    assert_eq!(
        VssCommitmentSet::decode(&truncated_commitments).unwrap_err(),
        MultipartyError::MalformedMessage
    );

    let vss_share_bytes = polynomial.create_share(id(2)).encode();
    assert_eq!(
        Share::decode(&vss_share_bytes).unwrap_err(),
        MultipartyError::MalformedMessage
    );
    assert_eq!(
        VssCommitmentSet::decode(&vss_share_bytes).unwrap_err(),
        MultipartyError::MalformedMessage
    );

    let mut truncated_vss_share = vss_share_bytes.clone();
    truncated_vss_share.pop();
    assert_eq!(
        VssShare::decode(&truncated_vss_share).unwrap_err(),
        MultipartyError::MalformedMessage
    );
}

// Fuzz/property tests for decode rejection (Workstream 8 item 3) - see
// `phantom-lattice/tests/phase17_serialization.rs`'s own equivalent
// comment: the property is "never panics," proptest catches panics itself.
proptest! {
    #[test]
    fn decode_share_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Share::decode(&bytes);
    }

    #[test]
    fn decode_vss_commitment_set_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = VssCommitmentSet::decode(&bytes);
    }

    #[test]
    fn decode_vss_share_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = VssShare::decode(&bytes);
    }
}
