//! Pedersen verifiable secret sharing (VSS) - the primitive underlying real
//! distributed key generation (DKG) for multiparty FHE (Workstream 7 items
//! 4/5 in `docs/internal/implementation-plan.md`).
//!
//! **What this solves**: today, `phantom-multiparty`'s collective key
//! generation is a placeholder (`ckg`/`rkg`/`gkg` across
//! `mpbgv`/`mpbfv`/`mpckks` ignore share content entirely) and threshold
//! decryption/re-encryption only checks byte-equality across participants'
//! payloads rather than genuinely combining distinct secret contributions.
//! A real collective secret needs to come from *somewhere* without any
//! single party, or the infrastructure aggregating protocol messages
//! between them, ever holding it - not even momentarily. This module
//! implements exactly that: each party locally generates their own random
//! polynomial and distributes pieces of it to every other party; no party
//! or process ever assembles the full secret; every recipient
//! cryptographically verifies each received piece against a publicly
//! broadcast commitment before accepting it (catching a dealer who sends
//! inconsistent pieces to different recipients, not just an honest-mistake
//! transport error).
//!
//! **The scheme, in one paragraph**: dealer `d` samples a degree-`(t-1)`
//! polynomial whose vector-valued constant term is their own small
//! centered-integer secret (see [`embed_centered`] for the small-integer
//! embedding this relies on) and whose higher-degree coefficients are
//! uniformly random. They publish a compact Pedersen *vector* commitment to
//! each degree (one commitment per degree, not one per coordinate - see
//! [`VectorPolynomial::commit`]), then send each participant `i` the
//! polynomial evaluated at `i`'s own id ([`VectorPolynomial::create_share`]).
//! Each recipient verifies their share against the public commitment
//! ([`VssShare::verify`]) before accumulating it with every other dealer's
//! own share to them ([`ShareAccumulator`]). Reconstructing the *sum* of
//! every dealer's own secret (the collective secret) from `>= threshold`
//! participants' own final combined shares is standard Lagrange
//! interpolation ([`reconstruct_secret`]).
//!
//! **Explicitly not done here** (future, separate work - not started):
//! wiring this into `mpbgv`/`mpbfv`/`mpckks`'s own `ckg`/`rkg`/`gkg`/
//! `partial_decrypt`/`reencryption`/`interactive_bootstrap`; the bridge
//! from an RLWE `Poly`'s own RNS representation to/from the small centered
//! integers this module operates on (`phantom_ring::rns::extension::reconstruct_centered_values`
//! exists for one direction, the reverse embed-into-RNS direction needs its
//! own new helper); noise flooding/smudging. This is a standalone,
//! scheme-agnostic primitive, fully tested in isolation - see
//! `docs/internal/implementation-plan.md`'s own Workstream 7 entry for
//! tracked status.
//!
//! Built on Ristretto255 (`curve25519_dalek`) - the only elliptic-curve, or
//! more broadly discrete-log-hard, group anywhere in this workspace; see
//! `docs/internal/dependency-policy.md` for why this specific dependency,
//! feature set, and scope (`phantom-multiparty` only, not `phantom-lattice`,
//! which stays multiparty-agnostic).

mod generators;
mod polynomial;
mod reconstruct;
mod scalar_embed;
mod share;

pub use generators::PedersenGenerators;
pub use polynomial::VectorPolynomial;
pub use reconstruct::{lagrange_coefficient_at_zero, reconstruct_secret};
pub use scalar_embed::{embed_centered, recover_centered};
pub use share::{verify_combined, ShareAccumulator, VssCommitmentSet, VssShare};
