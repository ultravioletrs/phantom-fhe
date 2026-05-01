//! Error types for `phantom-utils`.

use thiserror::Error;

/// Result alias used by this crate.
pub type Result<T> = core::result::Result<T, UtilsError>;

/// Errors emitted by support utilities.
#[derive(Debug, Error)]
pub enum UtilsError {
    /// An underlying IO operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A domain tag was not exactly eight bytes.
    #[error("domain tags must be exactly 8 bytes, got {actual}")]
    InvalidDomainLength {
        /// The provided domain tag length.
        actual: usize,
    },

    /// A serialized object used an unexpected domain tag.
    #[error("invalid domain tag: expected {expected:?}, got {found:?}")]
    InvalidDomain {
        /// The expected domain tag.
        expected: [u8; 8],
        /// The domain tag found in the input.
        found: [u8; 8],
    },

    /// A serialized object used an unsupported version.
    #[error("unsupported version: expected {expected}, got {found}")]
    UnsupportedVersion {
        /// The supported version.
        expected: u16,
        /// The version found in the input.
        found: u16,
    },

    /// A length prefix could not fit into the target platform's `usize`.
    #[error("length {len} does not fit in usize")]
    LengthOverflow {
        /// The encoded length.
        len: u64,
    },
}
