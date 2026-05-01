//! Minimal cross-cutting support utilities for `phantom-fhe`.
//!
//! This crate intentionally stays small. Domain-specific helpers belong in the
//! crate that owns their mathematical or cryptographic semantics.

pub mod buffer;
pub mod error;
pub mod sampling;
pub mod serialization;

#[cfg(any(test, feature = "test-utils"))]
pub mod test;

pub use error::{Result, UtilsError};
