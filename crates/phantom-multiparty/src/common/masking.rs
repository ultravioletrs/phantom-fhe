//! Uniform-mod-`t` mask sampling for [`crate::mpbgv::InteractiveBootstrap`]/
//! [`crate::mpbfv::InteractiveBootstrap`]'s own collective-bootstrap
//! construction - each participant's own *private* additive mask share,
//! never transmitted, only ever seen through its cancellation on
//! combination. Shared here since BGV and BFV need the identical thing
//! (matching the "derive once" premise `common::hybrid` already
//! established for GKG/RKG).

use rand_core::{CryptoRng, RngCore};

/// Samples `count` values, each uniform over `[0, t)`, via rejection
/// sampling - the same technique
/// `phantom_ring::sampling::uniform::sample_bounded` uses internally
/// (`pub(crate)` there, not reusable directly; small enough to duplicate
/// rather than widen a `phantom-ring` internal for one caller).
pub fn sample_uniform_mod_t<R: RngCore + CryptoRng>(t: u64, count: usize, rng: &mut R) -> Vec<u64> {
    let zone = u64::MAX - (u64::MAX % t);
    (0..count)
        .map(|_| loop {
            let value = rng.next_u64();
            if value < zone {
                return value % t;
            }
        })
        .collect()
}
