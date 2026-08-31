//! `phantom-fhe` is the top-level facade for the Phantom-FHE workspace.
//!
//! # Status
//!
//! This crate re-exports the current workspace crates unchanged. Phantom-FHE
//! is a research-stage implementation under active cryptographic hardening;
//! see `SECURITY.md` in the repository root for current status and the
//! hardening roadmap.
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
