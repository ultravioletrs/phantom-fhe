//! Error types for bootstrapping layers.

use thiserror::Error;

/// Result alias used by `phantom-bootstrapping`.
pub type Result<T> = core::result::Result<T, BootstrappingError>;

/// Errors emitted by bootstrapping components.
#[derive(Debug, Error)]
pub enum BootstrappingError {
    /// Parameters are invalid.
    #[error("invalid parameters: {0}")]
    InvalidParameters(&'static str),

    /// Input dimensions do not match active parameters.
    #[error("dimension mismatch")]
    DimensionMismatch,

    /// A scheme-level operation failed.
    #[error("scheme operation failed: {0}")]
    SchemeOperation(&'static str),

    /// A circuit-level operation failed.
    #[error("circuit operation failed: {0}")]
    CircuitOperation(&'static str),

    /// Scheme-layer failure.
    #[error(transparent)]
    Schemes(#[from] phantom_schemes::SchemesError),

    /// Utility serialization or buffer failure.
    #[error(transparent)]
    Utils(#[from] phantom_utils::UtilsError),
}
