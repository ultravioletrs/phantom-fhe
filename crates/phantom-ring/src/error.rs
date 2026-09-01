//! Error types for ring arithmetic.

use thiserror::Error;

/// Result alias used by `phantom-ring`.
pub type Result<T> = core::result::Result<T, RingError>;

/// Errors emitted by ring arithmetic.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum RingError {
    /// Ring degree is invalid.
    #[error("degree must be a non-zero power of two, got {0}")]
    InvalidDegree(usize),

    /// Modulus is invalid.
    #[error("modulus must be greater than 1 and odd, got {0}")]
    InvalidModulus(u64),

    /// Modulus does not support the requested NTT.
    #[error("modulus {modulus} is not congruent to 1 modulo 2N={two_n}")]
    InvalidNttModulus {
        /// Modulus value.
        modulus: u64,
        /// Twice the ring degree.
        two_n: usize,
    },

    /// A polynomial does not match the ring dimensions.
    #[error("dimension mismatch")]
    DimensionMismatch,

    /// An index was outside the available RNS level.
    #[error("level {level} is out of bounds for {moduli} moduli")]
    LevelOutOfBounds {
        /// Requested level.
        level: usize,
        /// Number of available moduli.
        moduli: usize,
    },

    /// CRT reconstruction exceeded the simple debug implementation capacity.
    #[error("CRT product overflowed u128")]
    CrtOverflow,

    /// A required root of unity could not be found.
    #[error("no root of unity found for modulus {0}")]
    MissingRoot(u64),

    /// Modulus exceeds the range [`crate::reduce::MontgomeryReducer`] currently supports.
    #[error("modulus {modulus} exceeds the maximum {max} supported by MontgomeryReducer")]
    ModulusTooLargeForReducer {
        /// The requested modulus.
        modulus: u64,
        /// The largest modulus currently supported.
        max: u64,
    },

    /// Modulus is too small for a reducer to operate on (needs at least 2).
    #[error("modulus must be at least 2, got {0}")]
    ModulusTooSmall(u64),

    /// Galois element for [`crate::Ring::apply_automorphism`] isn't coprime
    /// to `2 * degree`, so `X -> X^element` isn't a valid ring automorphism.
    #[error("automorphism element {element} must be coprime to 2N={two_n}")]
    InvalidAutomorphismElement {
        /// The requested element.
        element: usize,
        /// Twice the ring degree.
        two_n: usize,
    },
}
