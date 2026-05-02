//! Multiparty protocol session state.

use crate::{MultipartyError, Result};

use super::{ParticipantId, ParticipantSet};

/// Stable session identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Creates a nonzero session identifier.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(MultipartyError::InvalidParameters(
                "session id must be nonzero",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the raw session id.
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
}

/// Common protocol kind identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolKind {
    /// Collective key generation.
    CollectiveKeyGen,
    /// Collective relinearization key generation.
    RelinearizationKeyGen,
    /// Collective Galois key generation.
    GaloisKeyGen,
    /// Partial decryption.
    PartialDecryption,
    /// Re-encryption.
    ReEncryption,
    /// Interactive bootstrapping.
    InteractiveBootstrap,
    /// Custom protocol domain.
    Custom(u32),
}

impl ProtocolKind {
    pub(crate) fn tag(self) -> u32 {
        match self {
            Self::CollectiveKeyGen => 1,
            Self::RelinearizationKeyGen => 2,
            Self::GaloisKeyGen => 3,
            Self::PartialDecryption => 4,
            Self::ReEncryption => 5,
            Self::InteractiveBootstrap => 6,
            Self::Custom(tag) => tag,
        }
    }

    pub(crate) fn from_tag(tag: u32) -> Self {
        match tag {
            1 => Self::CollectiveKeyGen,
            2 => Self::RelinearizationKeyGen,
            3 => Self::GaloisKeyGen,
            4 => Self::PartialDecryption,
            5 => Self::ReEncryption,
            6 => Self::InteractiveBootstrap,
            tag => Self::Custom(tag),
        }
    }
}

/// Validated protocol session state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionState {
    id: SessionId,
    protocol: ProtocolKind,
    participants: ParticipantSet,
    threshold: usize,
    round: u64,
}

impl SessionState {
    /// Creates a protocol session.
    pub fn new(
        id: SessionId,
        protocol: ProtocolKind,
        participants: ParticipantSet,
        threshold: usize,
    ) -> Result<Self> {
        if threshold == 0 || threshold > participants.len() {
            return Err(MultipartyError::InvalidParameters(
                "threshold must be in 1..=participant_count",
            ));
        }
        Ok(Self {
            id,
            protocol,
            participants,
            threshold,
            round: 0,
        })
    }

    /// Returns the session id.
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Returns the protocol kind.
    pub const fn protocol(&self) -> ProtocolKind {
        self.protocol
    }

    /// Returns session participants.
    pub const fn participants(&self) -> &ParticipantSet {
        &self.participants
    }

    /// Returns the threshold.
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the current protocol round.
    pub const fn round(&self) -> u64 {
        self.round
    }

    /// Advances to the next round.
    pub fn advance_round(&mut self) {
        self.round = self.round.saturating_add(1);
    }

    /// Checks that a participant belongs to this session.
    pub fn check_participant(&self, participant: ParticipantId) -> Result<()> {
        if self.participants.contains(participant) {
            Ok(())
        } else {
            Err(MultipartyError::UnknownParticipant)
        }
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.id.encode(out);
        out.extend_from_slice(&self.protocol.tag().to_le_bytes());
        out.extend_from_slice(&(self.threshold as u64).to_le_bytes());
        out.extend_from_slice(&self.round.to_le_bytes());
        self.participants.encode(out);
    }
}
