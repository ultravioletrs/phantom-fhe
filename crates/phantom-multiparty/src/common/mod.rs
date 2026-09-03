//! Scheme-independent multiparty protocol building blocks.

pub mod participant;
pub mod randomness;
pub mod session;
pub mod shares;
pub mod transcript;

pub use participant::{ParticipantId, ParticipantSet};
pub use randomness::derive_common_ring_element;
pub use session::{ProtocolKind, SessionId, SessionState};
pub use shares::{aggregate_u64_shares_mod, Share, ShareAggregator, ShareKind};
pub use transcript::{Transcript, TranscriptHash, TranscriptMessage};
