//! Deterministic Pedersen generator derivation.

use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha512};

/// Domain label for the per-coordinate generators `g_0..g_{N-1}`.
const GENERATOR_G_DOMAIN: &[u8] = b"phantom-fhe/vss/gen/g/v1";
/// Domain label for the blinding generator `h`.
const GENERATOR_H_DOMAIN: &[u8] = b"phantom-fhe/vss/gen/h/v1";

/// Public Pedersen vector-commitment generators: `N` per-coordinate
/// generators `g_0..g_{N-1}` plus one blinding generator `h`.
///
/// Derived deterministically via hash-to-group (`RistrettoPoint::from_uniform_bytes`
/// fed with `Sha512` output over a domain label and index) - "nothing up my
/// sleeve", no trusted setup, and reproducible by any party independently
/// from `vector_len` alone. Every party in a session must derive generators
/// for the *same* `vector_len` to interoperate; this is a protocol-wide
/// constant, not session-scoped (session/round/participant binding already
/// happens at the [`crate::common::Share`]/[`crate::common::Transcript`]
/// layer, not here).
#[derive(Clone, Debug)]
pub struct PedersenGenerators {
    g: Vec<RistrettoPoint>,
    h: RistrettoPoint,
}

impl PedersenGenerators {
    /// Derives generators for a vector of `vector_len` coordinates.
    pub fn derive(vector_len: usize) -> Self {
        let g = (0..vector_len)
            .map(|j| hash_to_point(GENERATOR_G_DOMAIN, j as u64))
            .collect();
        let h = hash_to_point(GENERATOR_H_DOMAIN, 0);
        Self { g, h }
    }

    /// Returns the number of per-coordinate generators (`N`).
    pub fn vector_len(&self) -> usize {
        self.g.len()
    }

    /// Returns the per-coordinate generators.
    pub(crate) fn g(&self) -> &[RistrettoPoint] {
        &self.g
    }

    /// Returns the blinding generator.
    pub(crate) const fn h(&self) -> RistrettoPoint {
        self.h
    }
}

/// Hashes `domain || index` (little-endian) into a uniformly-random
/// Ristretto point via `Sha512` (64 bytes of output, matching
/// [`RistrettoPoint::from_uniform_bytes`]'s own input width exactly - no
/// truncation or padding needed).
fn hash_to_point(domain: &[u8], index: u64) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(index.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&bytes)
}
