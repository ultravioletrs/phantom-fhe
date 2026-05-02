//! Deterministic transcript encoding and hashing.

use crate::{MultipartyError, Result};

use super::{ParticipantId, ProtocolKind, SessionId, SessionState};

/// Deterministic 256-bit transcript hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TranscriptHash([u8; 32]);

impl TranscriptHash {
    /// Returns raw hash bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One public transcript message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptMessage {
    session_id: SessionId,
    protocol: ProtocolKind,
    round: u64,
    sender: ParticipantId,
    label: Vec<u8>,
    payload: Vec<u8>,
}

impl TranscriptMessage {
    /// Creates a transcript message bound to a session state.
    pub fn new(
        session: &SessionState,
        sender: ParticipantId,
        label: impl Into<Vec<u8>>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        session.check_participant(sender)?;
        let label = label.into();
        if label.is_empty() {
            return Err(MultipartyError::MalformedMessage);
        }
        Ok(Self {
            session_id: session.id(),
            protocol: session.protocol(),
            round: session.round(),
            sender,
            label,
            payload: payload.into(),
        })
    }

    /// Encodes the message deterministically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PMMSG1");
        self.session_id.encode(&mut out);
        out.extend_from_slice(&self.protocol.tag().to_le_bytes());
        out.extend_from_slice(&self.round.to_le_bytes());
        self.sender.encode(&mut out);
        encode_bytes(&self.label, &mut out);
        encode_bytes(&self.payload, &mut out);
        out
    }

    /// Decodes a message from deterministic encoding.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(input);
        reader.expect(b"PMMSG1")?;
        let session_id = SessionId::new(reader.u64()?)?;
        let protocol = ProtocolKind::from_tag(reader.u32()?);
        let round = reader.u64()?;
        let sender = ParticipantId::new(reader.u64()?)?;
        let label = reader.bytes()?;
        let payload = reader.bytes()?;
        if !reader.is_finished() || label.is_empty() {
            return Err(MultipartyError::MalformedMessage);
        }
        Ok(Self {
            session_id,
            protocol,
            round,
            sender,
            label,
            payload,
        })
    }

    /// Returns the sender.
    pub const fn sender(&self) -> ParticipantId {
        self.sender
    }

    /// Returns the payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Ordered public protocol transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    session: SessionState,
    messages: Vec<TranscriptMessage>,
}

impl Transcript {
    /// Creates an empty transcript for a session.
    pub fn new(session: SessionState) -> Self {
        Self {
            session,
            messages: Vec::new(),
        }
    }

    /// Returns the session.
    pub const fn session(&self) -> &SessionState {
        &self.session
    }

    /// Returns transcript messages in append order.
    pub fn messages(&self) -> &[TranscriptMessage] {
        &self.messages
    }

    /// Appends a transcript message.
    pub fn append(&mut self, message: TranscriptMessage) -> Result<()> {
        if message.session_id != self.session.id()
            || message.protocol.tag() != self.session.protocol().tag()
            || message.round != self.session.round()
        {
            return Err(MultipartyError::StaleShare);
        }
        self.messages.push(message);
        Ok(())
    }

    /// Encodes the transcript deterministically.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PMTRN1");
        self.session.encode(&mut out);
        out.extend_from_slice(&(self.messages.len() as u64).to_le_bytes());
        for message in &self.messages {
            encode_bytes(&message.encode(), &mut out);
        }
        out
    }

    /// Computes a deterministic transcript hash.
    pub fn hash(&self) -> TranscriptHash {
        stable_hash_256(&self.encode())
    }
}

pub(crate) fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn stable_hash_256(input: &[u8]) -> TranscriptHash {
    let mut state = [
        0x243f_6a88_85a3_08d3u64,
        0x1319_8a2e_0370_7344u64,
        0xa409_3822_299f_31d0u64,
        0x082e_fa98_ec4e_6c89u64,
    ];
    for (index, byte) in input.iter().copied().enumerate() {
        let lane = index % 4;
        state[lane] ^= byte as u64;
        state[lane] = state[lane].wrapping_mul(0x100_0000_01b3);
        state[lane] = state[lane].rotate_left(13) ^ ((index as u64) << 32);
    }
    let mut out = [0u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        out[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    TranscriptHash(out)
}

pub(crate) struct ByteReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn expect(&mut self, expected: &[u8]) -> Result<()> {
        if self.input.get(self.offset..self.offset + expected.len()) != Some(expected) {
            return Err(MultipartyError::MalformedMessage);
        }
        self.offset += expected.len();
        Ok(())
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.u64()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(MultipartyError::MalformedMessage)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(MultipartyError::MalformedMessage)?;
        self.offset = end;
        Ok(bytes)
    }
}
