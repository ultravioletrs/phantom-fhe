//! Deterministic public randomness shared by every participant in a
//! session, with no extra communication round.

use phantom_ring::sampling::sample_uniform;
use phantom_ring::{Poly, Ring};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use super::SessionState;

/// Derives a ring element every participant in `session` can compute
/// independently and identically, with no extra communication round - e.g.
/// the common `a` component real collective public-key generation needs
/// (`mpbgv::CollectiveKeyGen`). Deterministic: `Sha256(purpose || session
/// id)` seeds a `ChaCha20Rng`, which then drives the same
/// `phantom_ring::sampling::sample_uniform` a normal fresh keypair's own
/// `a` uses - the only difference is the seed is public and reproducible
/// (derived from the session's own id, known to every participant), not
/// drawn from a caller's own private RNG.
///
/// `purpose` domain-separates different protocols (or different rounds of
/// the same protocol) deriving their own independent common element from
/// the same session - e.g. `b"ckg"` for collective public-key generation -
/// so two different uses within one session never collide.
pub fn derive_common_ring_element(ring: &Ring, session: &SessionState, purpose: &[u8]) -> Poly {
    let mut hasher = Sha256::new();
    hasher.update(purpose);
    hasher.update(session.id().get().to_le_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha20Rng::from_seed(seed);
    sample_uniform(ring, &mut rng)
}
