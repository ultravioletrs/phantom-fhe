//! Polynomial samplers.

pub mod gaussian;
pub mod ternary;
pub mod uniform;

pub use gaussian::{sample_discrete_gaussian, sample_smudging_gaussian};
pub use ternary::sample_ternary;
pub use uniform::sample_uniform;
