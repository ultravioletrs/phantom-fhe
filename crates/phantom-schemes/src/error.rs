//! Scheme-level errors.

/// Result type for scheme operations.
pub type Result<T> = std::result::Result<T, SchemesError>;

/// Errors returned by concrete scheme layers.
#[derive(Debug, thiserror::Error)]
pub enum SchemesError {
    /// Invalid scheme parameters.
    #[error("invalid scheme parameters: {0}")]
    InvalidParameters(&'static str),
    /// Input dimensions do not match the active context.
    #[error("dimension mismatch")]
    DimensionMismatch,
    /// A slot index or slot count is invalid.
    #[error("invalid slot count")]
    InvalidSlotCount,
    /// Ring-level failure.
    #[error(transparent)]
    Ring(#[from] phantom_ring::RingError),
    /// Lattice RLWE/RGSW failure.
    #[error(transparent)]
    Lattice(#[from] phantom_lattice::LatticeError),
    /// Utility serialization or buffer failure.
    #[error(transparent)]
    Utils(#[from] phantom_utils::UtilsError),
}
