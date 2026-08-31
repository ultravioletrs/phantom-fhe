//! `phantom-fhe` is the top-level facade for the Phantom-FHE workspace.
//!
//! # Alpha / scaffold status
//!
//! This crate re-exports the current workspace crates unchanged. The
//! underlying ring, lattice, scheme, circuit, bootstrapping, and multiparty
//! implementations prioritize correct APIs and testable behavior over
//! production cryptographic hardness or performance. Do not use the current
//! parameter presets or primitives to protect real secrets. See
//! `SECURITY.md` in the repository root for the current security status.
//!
//! # Layout
//!
//! Each top-level module here is a re-export of the corresponding workspace
//! crate:
//!
//! - [`utils`] - cross-cutting support utilities (`phantom-utils`)
//! - [`ring`] - RNS polynomial ring arithmetic (`phantom-ring`)
//! - [`lattice`] - scheme-agnostic RLWE and RGSW primitives (`phantom-lattice`)
//! - [`schemes`] - concrete BGV, BFV, and CKKS scheme APIs (`phantom-schemes`)
//! - [`circuits`] - shared and scheme-specific circuit planning (`phantom-circuits`)
//! - [`bootstrapping`] - scheme bootstrapping scaffolds (`phantom-bootstrapping`)
//! - [`multiparty`] - threshold protocol scaffolds (`phantom-multiparty`)

pub use phantom_bootstrapping as bootstrapping;
pub use phantom_circuits as circuits;
pub use phantom_lattice as lattice;
pub use phantom_multiparty as multiparty;
pub use phantom_ring as ring;
pub use phantom_schemes as schemes;
pub use phantom_utils as utils;
