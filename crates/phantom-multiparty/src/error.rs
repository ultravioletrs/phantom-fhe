//! Error types for multiparty protocols.

use thiserror::Error;

/// Result alias used by `phantom-multiparty`.
pub type Result<T> = core::result::Result<T, MultipartyError>;

/// Errors emitted by multiparty protocol components.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultipartyError {
    /// Parameters or message contents are invalid.
    #[error("invalid parameters: {0}")]
    InvalidParameters(&'static str),

    /// A participant appears more than once.
    #[error("duplicate participant")]
    DuplicateParticipant,

    /// A required participant or share is missing.
    #[error("missing share")]
    MissingShare,

    /// A share was submitted by a participant outside the session.
    #[error("unknown participant")]
    UnknownParticipant,

    /// A share belongs to a stale or unrelated session.
    #[error("stale share")]
    StaleShare,

    /// A share or transcript message is malformed.
    #[error("malformed message")]
    MalformedMessage,

    /// The threshold cannot be met with the available shares.
    #[error("threshold not met")]
    ThresholdNotMet,
}
