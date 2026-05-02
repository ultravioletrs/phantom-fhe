//! Typed shares and aggregation helpers.

use std::collections::BTreeMap;

use crate::{MultipartyError, Result};

use super::transcript::{encode_bytes, ByteReader};
use super::{ParticipantId, ProtocolKind, SessionId, SessionState};

/// Common share type identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShareKind {
    /// Collective public key generation share.
    CollectiveKeyGen,
    /// Relinearization key generation share.
    RelinearizationKeyGen,
    /// Galois key generation share.
    GaloisKeyGen,
    /// Partial decryption share.
    PartialDecryption,
    /// Re-encryption share.
    ReEncryption,
    /// Interactive bootstrapping share.
    InteractiveBootstrap,
    /// Custom share domain.
    Custom(u32),
}

impl ShareKind {
    fn tag(self) -> u32 {
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

    fn from_tag(tag: u32) -> Self {
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

/// Public typed protocol share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    session_id: SessionId,
    protocol: ProtocolKind,
    round: u64,
    participant: ParticipantId,
    kind: ShareKind,
    payload: Vec<u8>,
}

impl Share {
    /// Creates a typed share bound to a session.
    pub fn new(
        session: &SessionState,
        participant: ParticipantId,
        kind: ShareKind,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        session.check_participant(participant)?;
        let payload = payload.into();
        if payload.is_empty() {
            return Err(MultipartyError::MalformedMessage);
        }
        Ok(Self {
            session_id: session.id(),
            protocol: session.protocol(),
            round: session.round(),
            participant,
            kind,
            payload,
        })
    }

    /// Returns the participant that produced the share.
    pub const fn participant(&self) -> ParticipantId {
        self.participant
    }

    /// Returns the share kind.
    pub const fn kind(&self) -> ShareKind {
        self.kind
    }

    /// Returns the payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes this share deterministically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PMSHR1");
        self.session_id.encode(&mut out);
        out.extend_from_slice(&self.protocol.tag().to_le_bytes());
        out.extend_from_slice(&self.round.to_le_bytes());
        self.participant.encode(&mut out);
        out.extend_from_slice(&self.kind.tag().to_le_bytes());
        encode_bytes(&self.payload, &mut out);
        out
    }

    /// Decodes a share from deterministic encoding.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(input);
        reader.expect(b"PMSHR1")?;
        let session_id = SessionId::new(reader.u64()?)?;
        let protocol = ProtocolKind::from_tag(reader.u32()?);
        let round = reader.u64()?;
        let participant = ParticipantId::new(reader.u64()?)?;
        let kind = ShareKind::from_tag(reader.u32()?);
        let payload = reader.bytes()?;
        if !reader.is_finished() || payload.is_empty() {
            return Err(MultipartyError::MalformedMessage);
        }
        Ok(Self {
            session_id,
            protocol,
            round,
            participant,
            kind,
            payload,
        })
    }

    fn check_for_session(&self, session: &SessionState, kind: ShareKind) -> Result<()> {
        if self.session_id != session.id()
            || self.protocol.tag() != session.protocol().tag()
            || self.round != session.round()
        {
            return Err(MultipartyError::StaleShare);
        }
        if self.kind != kind {
            return Err(MultipartyError::MalformedMessage);
        }
        session.check_participant(self.participant)
    }
}

/// Aggregates shares for one session/kind.
#[derive(Clone, Debug)]
pub struct ShareAggregator {
    session: SessionState,
    kind: ShareKind,
    shares: BTreeMap<ParticipantId, Share>,
}

impl ShareAggregator {
    /// Creates a share aggregator.
    pub fn new(session: SessionState, kind: ShareKind) -> Self {
        Self {
            session,
            kind,
            shares: BTreeMap::new(),
        }
    }

    /// Adds one share.
    pub fn add_share(&mut self, share: Share) -> Result<()> {
        share.check_for_session(&self.session, self.kind)?;
        if self.shares.contains_key(&share.participant) {
            return Err(MultipartyError::DuplicateParticipant);
        }
        self.shares.insert(share.participant, share);
        Ok(())
    }

    /// Returns whether the aggregator has enough shares.
    pub fn is_ready(&self) -> bool {
        self.shares.len() >= self.session.threshold()
    }

    /// Returns shares in participant-id order once threshold is met.
    pub fn aggregate(&self) -> Result<Vec<Share>> {
        if !self.is_ready() {
            return Err(MultipartyError::ThresholdNotMet);
        }
        Ok(self
            .shares
            .values()
            .take(self.session.threshold())
            .cloned()
            .collect())
    }

    /// Returns the number of collected shares.
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Returns whether no shares have been collected.
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }
}

/// Aggregates little-endian `u64` vector shares modulo `modulus`.
pub fn aggregate_u64_shares_mod(shares: &[Share], modulus: u64) -> Result<Vec<u64>> {
    if modulus <= 1 {
        return Err(MultipartyError::InvalidParameters(
            "aggregation modulus must be greater than one",
        ));
    }
    if shares.is_empty() {
        return Err(MultipartyError::MissingShare);
    }
    let first = decode_u64_payload(shares[0].payload())?;
    let mut acc = vec![0u64; first.len()];
    for share in shares {
        let values = decode_u64_payload(share.payload())?;
        if values.len() != acc.len() {
            return Err(MultipartyError::MalformedMessage);
        }
        for (acc, value) in acc.iter_mut().zip(values) {
            *acc = ((*acc as u128 + (value % modulus) as u128) % modulus as u128) as u64;
        }
    }
    Ok(acc)
}

fn decode_u64_payload(payload: &[u8]) -> Result<Vec<u64>> {
    if payload.len() % 8 != 0 {
        return Err(MultipartyError::MalformedMessage);
    }
    Ok(payload
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect())
}
