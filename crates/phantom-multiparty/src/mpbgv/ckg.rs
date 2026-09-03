//! BGV collective public-key generation - real, DKG-backed.

use phantom_lattice::rlwe::{PublicKey, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::sampling::sample_discrete_gaussian;
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly, encode_poly};
use crate::common::{
    derive_common_ring_element, ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator,
    ShareKind,
};
use crate::{MultipartyError, Result};
use phantom_schemes::bgv::BgvParams;

/// Purpose label for [`derive_common_ring_element`]'s own domain
/// separation - distinct from whatever label a future `rkg`/`gkg` (or
/// another `mpbXXX::ckg`) derives its own common element with from the same
/// session.
const CKG_COMMON_A_PURPOSE: &[u8] = b"phantom-fhe/mpbgv/ckg/a/v1";

/// Collective public-key generation helper.
///
/// Computes a real BGV public key `(sum_i b_i, a)` for the collective
/// secret `s = sum_i s_i` - `s` itself is never assembled anywhere, by
/// anyone, including this type: each participant's own `local_secret_share`
/// (`s_i`) is a parameter *only* [`Self::create_share`] ever sees, stays
/// entirely local to that participant's own process, and is never
/// transmitted, encoded, or otherwise leaves the caller's hands - only the
/// public `b_i = t*e_i - a*s_i` this method derives from it is. `s_i` is an
/// ordinary small (ternary, or discrete-Gaussian-bounded) RLWE secret each
/// participant generates independently and keeps to themselves, the same
/// way a normal single-party `SecretKey` would be generated - **not** a
/// Shamir share of anything (a Shamir share, evaluated at a nonzero point,
/// is a large, uniformly-random-looking field element, not a small RLWE
/// secret - unsuitable as this parameter and not what this method expects).
/// Simple, independent per-party generation already gives the "no one, not
/// even the infrastructure aggregating shares, ever sees the collective
/// secret" property this needs: summing public `b_i` values never requires
/// anyone to see any `s_i`. A caller that additionally wants a *verifiable,
/// recoverable backup* of each participant's own `s_i` distributed among
/// the others (so a threshold subset can later reconstruct a missing
/// participant's contribution, e.g. for threshold decryption) can layer
/// [`phantom_multiparty::vss`](crate::vss) on top as a separate,
/// composable step, sharing this same `s_i` as its own dealt secret - see
/// this crate's own `tests/phase14_mpbgv.rs` for a worked example - but
/// that VSS round is not itself what makes `s_i` un-assembled here; simple
/// locality already does.
///
/// Every participant derives the same common `a` independently (via
/// [`derive_common_ring_element`], seeded from the session id - no separate
/// communication round needed for it) and computes their own public-key
/// share `b_i = t*e_i - a*s_i` (`t` = the plaintext modulus, `e_i` fresh
/// per-participant noise) - the same `t`-scaled shape
/// `phantom_schemes::bgv::keygen::BgvKeyGenerator::generate_keypair_real`
/// uses for a single-party keypair's own public key (`b = t*e_pk - a*s`),
/// required so the key's own noise doesn't survive decryption's final `mod
/// t` reduction (see that method's own doc comment). Summing every
/// participant's own `b_i` gives exactly that same shape for the collective
/// secret: `sum_i b_i = t*(sum_i e_i) - a*(sum_i s_i) = t*e_total - a*s`.
#[derive(Clone, Debug)]
pub struct CollectiveKeyGen {
    params: BgvParams,
    session: SessionState,
}

impl CollectiveKeyGen {
    /// Creates a collective key-generation helper.
    pub const fn new(params: BgvParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates this participant's own CKG share: `b_i = t*e_i - a*s_i`,
    /// where `s_i` is `local_secret_share` (this participant's own
    /// independently-generated small RLWE secret, never transmitted - only
    /// `b_i` is - see this type's own doc comment for why it must be an
    /// ordinary small secret, not a Shamir share of one) and `a` is derived
    /// deterministically from the session.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpbgv` protocol call this participant
    /// makes - refuses (before any crypto work) to produce a second share
    /// for the same `(session, round, participant)`, since `a` is
    /// deterministic and a second exposure would leak `s_i` via
    /// accumulated linear algebra. See [`ReplayGuard`]'s own doc comment.
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        replay_guard.record_use(&self.session, participant)?;
        let ring = self.params.ring();
        let a = derive_common_ring_element(ring, &self.session, CKG_COMMON_A_PURPOSE);
        let e_i = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
        let t_e_i = ring
            .scalar_mul(&e_i, self.params.plaintext_modulus())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: t*e_i failed"))?;
        let a_s_i = ring
            .mul(&a, local_secret_share.value())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: a*s_i failed"))?;
        let b_i = ring.sub(&t_e_i, &a_s_i).map_err(|_| {
            MultipartyError::InvalidParameters("create_share: t*e_i - a*s_i failed")
        })?;
        Share::new(
            &self.session,
            participant,
            ShareKind::CollectiveKeyGen,
            encode_poly(&b_i),
        )
    }

    /// Aggregates CKG shares into the real collective public key `(sum_i
    /// b_i, a)`. Sums *every* collected share (`ShareAggregator::all_shares`,
    /// not `aggregate` - see that method's own doc comment): CKG is an
    /// additive, not threshold, construction, so a public key must include
    /// every participant who contributed a share, not merely `threshold` of
    /// them.
    pub fn aggregate_public_key(&self, aggregator: &ShareAggregator) -> Result<PublicKey> {
        let ring = self.params.ring();
        let shares = aggregator.all_shares()?;
        let mut b_sum = ring.zero();
        for share in &shares {
            let b_i = decode_poly(share.payload(), ring)?;
            b_sum = ring.add(&b_sum, &b_i).map_err(|_| {
                MultipartyError::InvalidParameters("aggregate_public_key: sum failed")
            })?;
        }
        let a = derive_common_ring_element(ring, &self.session, CKG_COMMON_A_PURPOSE);
        Ok(PublicKey::new(b_sum, a))
    }
}
