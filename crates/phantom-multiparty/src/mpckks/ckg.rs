//! CKKS collective public-key generation - real, DKG-backed.

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
use phantom_schemes::ckks::CkksParams;

/// Purpose label for [`derive_common_ring_element`]'s own domain
/// separation - distinct from any other `mpbgv`/`mpbfv`/`mpckks` module's
/// own label sharing the same session.
const CKG_COMMON_A_PURPOSE: &[u8] = b"phantom-fhe/mpckks/ckg/a/v1";

/// Collective public-key generation helper for CKKS.
///
/// Computes a real CKKS public key `(sum_i b_i, a)` for the collective
/// secret `s = sum_i s_i` - `s` itself is never assembled anywhere, by
/// anyone, including this type. Identical construction to
/// [`super::super::mpbfv::CollectiveKeyGen`] (which see for the full
/// derivation): no `t`-scaling, since real CKKS's own public key needs none
/// either (`phantom_schemes::ckks::keygen`'s own doc comment: a real CKKS
/// ciphertext is structurally a plain RLWE ciphertext, the same reasoning
/// BFV's own real path documents). Every participant derives the same
/// common `a` independently (via [`derive_common_ring_element`]) and
/// computes their own public-key share `b_i = e_i - a*s_i` (`e_i` fresh
/// [`STANDARD_ERROR_STD_DEV`] noise). Summing every participant's own `b_i`
/// gives `sum_i b_i = e_total - a*s`.
///
/// Scoped to the top (full) level only - key generation happens once,
/// before any ciphertext (or rescale) exists, so there's no per-ciphertext
/// level to truncate to, unlike [`super::ReEncryptor`]/
/// [`super::PartialDecryptor`].
#[derive(Clone, Debug)]
pub struct CollectiveKeyGen {
    params: CkksParams,
    session: SessionState,
}

impl CollectiveKeyGen {
    /// Creates a collective key-generation helper.
    pub const fn new(params: CkksParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates this participant's own CKG share: `b_i = e_i - a*s_i` - see
    /// this type's own doc comment for why there is no `t`-scaling here.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpckks` protocol call this participant
    /// makes. See [`ReplayGuard`]'s own doc comment.
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
        let a_s_i = ring
            .mul(&a, local_secret_share.value())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: a*s_i failed"))?;
        let b_i = ring
            .sub(&e_i, &a_s_i)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: e_i - a*s_i failed"))?;
        Share::new(
            &self.session,
            participant,
            ShareKind::CollectiveKeyGen,
            encode_poly(&b_i),
        )
    }

    /// Aggregates CKG shares into the real collective public key `(sum_i
    /// b_i, a)`. Sums *every* collected share
    /// ([`ShareAggregator::all_shares`], not `aggregate`).
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
