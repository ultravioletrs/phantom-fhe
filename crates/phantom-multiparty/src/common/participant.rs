//! Participant identifiers and sets.

use std::collections::BTreeSet;

use crate::{MultipartyError, Result};

/// Stable participant identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantId(u64);

impl ParticipantId {
    /// Creates a nonzero participant identifier.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(MultipartyError::InvalidParameters(
                "participant id must be nonzero",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the raw participant id.
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
}

/// Validated ordered participant set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantSet {
    participants: Vec<ParticipantId>,
}

impl ParticipantSet {
    /// Creates a participant set with deterministic ordering.
    pub fn new(mut participants: Vec<ParticipantId>) -> Result<Self> {
        if participants.is_empty() {
            return Err(MultipartyError::InvalidParameters(
                "participant set must be nonempty",
            ));
        }
        participants.sort_unstable();
        let mut seen = BTreeSet::new();
        for participant in &participants {
            if !seen.insert(*participant) {
                return Err(MultipartyError::DuplicateParticipant);
            }
        }
        Ok(Self { participants })
    }

    /// Returns participants in canonical order.
    pub fn participants(&self) -> &[ParticipantId] {
        &self.participants
    }

    /// Returns whether the set contains `participant`.
    pub fn contains(&self, participant: ParticipantId) -> bool {
        self.participants.binary_search(&participant).is_ok()
    }

    /// Returns the number of participants.
    pub fn len(&self) -> usize {
        self.participants.len()
    }

    /// Returns whether the participant set is empty.
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.participants.len() as u64).to_le_bytes());
        for participant in &self.participants {
            participant.encode(out);
        }
    }
}
