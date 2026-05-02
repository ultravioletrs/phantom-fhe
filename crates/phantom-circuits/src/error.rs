//! Error types for circuit planning and evaluation layers.

use thiserror::Error;

/// Result alias used by `phantom-circuits`.
pub type Result<T> = core::result::Result<T, CircuitsError>;

/// Errors emitted by circuit planners.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircuitsError {
    /// Parameters or descriptor contents are invalid.
    #[error("invalid parameters: {0}")]
    InvalidParameters(&'static str),

    /// Matrix rows or vectors have inconsistent dimensions.
    #[error("dimension mismatch")]
    DimensionMismatch,

    /// A polynomial has no coefficients.
    #[error("empty polynomial")]
    EmptyPolynomial,

    /// A scheme-level circuit operation failed.
    #[error("scheme operation failed: {0}")]
    SchemeOperation(&'static str),
}

impl From<phantom_utils::UtilsError> for CircuitsError {
    fn from(_: phantom_utils::UtilsError) -> Self {
        Self::InvalidParameters("serialization failure")
    }
}
