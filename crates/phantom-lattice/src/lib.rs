//! Scheme-agnostic cryptographic primitives for `phantom-fhe`.

pub mod error;
pub mod rgsw;
pub mod rlwe;
pub mod serialization;

pub use error::{LatticeError, Result};
