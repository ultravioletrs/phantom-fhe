//! Error types for `phantom-lattice`.

use thiserror::Error;

/// Result alias used by `phantom-lattice`.
pub type Result<T> = core::result::Result<T, LatticeError>;

/// Errors emitted by lattice cryptographic primitives.
#[derive(Debug, Error)]
pub enum LatticeError {
    /// Ring-level operation failed.
    #[error("ring error: {0}")]
    Ring(#[from] phantom_ring::RingError),

    /// Ciphertext degree or dimensions are invalid for an operation.
    #[error("dimension mismatch")]
    DimensionMismatch,

    /// Parameters are invalid.
    #[error("invalid parameters: {0}")]
    InvalidParameters(&'static str),

    /// Requested key material is not available.
    #[error("missing key: {0}")]
    MissingKey(&'static str),

    /// Utility serialization or buffer failure.
    #[error(transparent)]
    Utils(#[from] phantom_utils::UtilsError),
}
