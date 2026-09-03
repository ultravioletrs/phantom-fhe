//! Per-participant protection against retrying a share-generation call.

use std::collections::HashSet;

use super::{ParticipantId, SessionId, SessionState};
use crate::{MultipartyError, Result};

/// Tracks which `(session id, round, protocol, participant)` tuples this
/// participant has already produced a share for, and refuses a second one.
///
/// Each `mpbgv` real protocol's public randomness (e.g.
/// [`super::derive_common_ring_element`]) is derived *deterministically*
/// from the session - producing a second share for the same session/round
/// exposes a participant's own secret contribution twice against the same
/// public value, which lets an observer recover it via ordinary linear
/// algebra (the standard "insecurity of retries" finding in the
/// threshold-FHE literature), regardless of how large that call's own
/// smudging noise is (see `phantom_lattice::security::smudging_std_dev`'s
/// own doc comment - a different failure mode, noise magnitude doesn't help
/// here).
///
/// One instance belongs to *one participant's own process*, reused across
/// every `create_share`/`create_share_round1`/`create_share_round2` call
/// that participant makes over its lifetime - it is not shared with other
/// participants or the combiner. This guards an honest participant against
/// accidentally re-exposing their own key material (e.g. retrying after a
/// crash or network partition); it cannot stop a malicious participant from
/// simply not using one, and it only protects across calls made against the
/// *same* `ReplayGuard` instance - a caller whose process restarts must
/// persist and restore this state themselves to keep the protection across
/// restarts, this type does no I/O of its own.
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    used: HashSet<(SessionId, u64, u32, ParticipantId)>,
}

impl ReplayGuard {
    /// Creates an empty replay guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `participant` is about to produce a share for
    /// `session`'s current round. Returns
    /// [`MultipartyError::ReplayedShare`] if this exact `(session id,
    /// round, protocol, participant)` was already recorded on this guard -
    /// callers must not proceed with share generation when this returns an
    /// error, since the whole point is to refuse *before* any crypto work,
    /// not after.
    pub fn record_use(&mut self, session: &SessionState, participant: ParticipantId) -> Result<()> {
        let key = (
            session.id(),
            session.round(),
            session.protocol().tag(),
            participant,
        );
        if !self.used.insert(key) {
            return Err(MultipartyError::ReplayedShare);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{ParticipantSet, ProtocolKind};

    fn session(id: u64, protocol: ProtocolKind) -> SessionState {
        SessionState::new(
            SessionId::new(id).unwrap(),
            protocol,
            ParticipantSet::new(vec![ParticipantId::new(1).unwrap()]).unwrap(),
            1,
        )
        .unwrap()
    }

    #[test]
    fn first_use_succeeds_second_identical_use_is_rejected() {
        let mut guard = ReplayGuard::new();
        let session = session(1, ProtocolKind::CollectiveKeyGen);
        let participant = ParticipantId::new(1).unwrap();

        guard.record_use(&session, participant).unwrap();
        assert_eq!(
            guard.record_use(&session, participant),
            Err(MultipartyError::ReplayedShare)
        );
    }

    #[test]
    fn a_different_round_session_or_participant_is_independent() {
        let mut guard = ReplayGuard::new();
        let first_session = session(1, ProtocolKind::CollectiveKeyGen);
        let participant = ParticipantId::new(1).unwrap();
        let other_participant = ParticipantId::new(2).unwrap();
        guard.record_use(&first_session, participant).unwrap();

        // A different participant, same session/round.
        guard.record_use(&first_session, other_participant).unwrap();

        // A different round, same session/participant.
        let mut next_round = first_session.clone();
        next_round.advance_round();
        guard.record_use(&next_round, participant).unwrap();

        // A different session id, same round/participant.
        let other_session = session(2, ProtocolKind::CollectiveKeyGen);
        guard.record_use(&other_session, participant).unwrap();

        // A different protocol kind, same session id/round/participant.
        let other_protocol = session(1, ProtocolKind::GaloisKeyGen);
        guard.record_use(&other_protocol, participant).unwrap();
    }
}
