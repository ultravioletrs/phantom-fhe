//! BGV collective Galois (rotation) key generation - real, additive n-of-n.
//!
//! Real BGV rotation keys are **not** the RNS-hybrid `KeySwitchKey`
//! construction other real Galois-key paths in this workspace use (BFV,
//! CKKS bootstrapping) - that construction's `mod_down` rounding step
//! doesn't distribute over `t`-scaled noise, corrupting BGV's own exact
//! `mod t` decode (see `phantom_schemes::bgv::relinearization`'s own module
//! doc comment for the full derivation). Real BGV instead uses
//! [`BgvRelinearizationKey`] - classical gadget decomposition over the
//! plain `Q` basis, no auxiliary modulus, exact integer arithmetic - for
//! *both* relinearization and rotation
//! (`bgv::keygen::BgvKeyGenerator::generate_rotation_key_real` is a thin
//! wrapper: apply the rotation automorphism to the secret, then generate a
//! `BgvRelinearizationKey` from the rotated secret to the original one).
//! This module builds the identical key material collectively.

use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_lattice::rlwe::{Ciphertext, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::rns::extension::crt_lift_constant;
use phantom_ring::sampling::sample_discrete_gaussian;
use phantom_ring::{Poly, RnsBasis};
use phantom_schemes::bgv::{scale_by_base_power_and_lift, BgvParams, BgvRelinearizationKey};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_rows, encode_poly_rows};
use crate::common::{
    derive_common_ring_element, ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator,
    ShareKind,
};
use crate::{MultipartyError, Result};

/// Purpose-label prefix for [`derive_common_ring_element`]'s own domain
/// separation - one row `(modulus_index, level)` needs its own independent
/// common `a`, so the label includes both plus this session's own rotation
/// `element`, keeping every row (and every distinct `GaloisKeyGen` session
/// for a different rotation amount) from colliding with any other.
const GKG_COMMON_A_PURPOSE_PREFIX: &str = "phantom-fhe/mpbgv/gkg/a";

/// Collective Galois (rotation) key generation helper for BGV. Scoped to
/// one rotation `element` per session (a caller needing several rotation
/// amounts runs several sessions) - matching
/// [`super::CollectiveKeyGen`]/[`super::ReEncryptor`]'s own "one clear
/// thing per session" shape rather than bundling many elements' worth of
/// key material into one round.
///
/// [`BgvRelinearizationKey::generate`]'s own single-party row formula (`row
/// (j,i)`, `moduli.len() * levels` rows total): `a_{j,i}` fresh uniform,
/// `b_{j,i} = scale_by_base_power_and_lift(s_old, base_log, i, lift_j) +
/// t*e_{j,i} - a_{j,i}*s_new`, where `s_old = sigma_element(s)`. Since ring
/// automorphisms are linear over addition (`sigma(sum_p(s_p)) =
/// sum_p(sigma(s_p))`), the collective version is the identical `t`-scaled
/// additive equation [`super::CollectiveKeyGen`] already established,
/// repeated per row: each participant `p` contributes, per row `(j,i)`,
/// `b_{j,i}^{(p)} = scale_by_base_power_and_lift(sigma(s_p), base_log, i,
/// lift_j) + t*e_{j,i}^{(p)} - a_{j,i}*s_p` (`a_{j,i}` the same common value
/// every participant derives independently, [`derive_common_ring_element`]
/// seeded per-row). Summing every participant's own `b_{j,i}^{(p)}` for a
/// fixed row reproduces the single-party row exactly, for the collective
/// secret `s = sum_p(s_p)`.
#[derive(Clone, Debug)]
pub struct GaloisKeyGen {
    params: BgvParams,
    session: SessionState,
    element: usize,
    decomposition_params: GadgetDecompositionParams,
}

impl GaloisKeyGen {
    /// Creates a collective Galois-key generation helper for rotation
    /// `element`. `decomposition_params` must be agreed by every
    /// participant in advance (part of the session configuration, like
    /// `element` itself) - it isn't derivable from `params` alone.
    pub const fn new(
        params: BgvParams,
        session: SessionState,
        element: usize,
        decomposition_params: GadgetDecompositionParams,
    ) -> Self {
        Self {
            params,
            session,
            element,
            decomposition_params,
        }
    }

    /// Creates this participant's own GKG share: every row's own
    /// `b_{j,i}^{(p)}` (see this type's own doc comment), from
    /// `local_secret_share` (this participant's own already-known small
    /// secret - the same one [`super::CollectiveKeyGen::create_share`]
    /// already uses, never transmitted - only the rows below are).
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpbgv` protocol call this participant
    /// makes - see [`super::CollectiveKeyGen::create_share`]'s own doc
    /// comment for why.
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        replay_guard.record_use(&self.session, participant)?;
        let ring = self.params.ring();
        let t = self.params.plaintext_modulus();
        let moduli = ring.moduli();
        let source_basis = RnsBasis::new(moduli.to_vec())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: invalid moduli"))?;
        let levels = self.decomposition_params.levels();
        let base_log = self.decomposition_params.base_log();

        let sigma_s = ring
            .apply_automorphism(local_secret_share.value(), self.element)
            .map_err(|_| {
                MultipartyError::InvalidParameters("create_share: apply_automorphism failed")
            })?;

        let mut rows = Vec::with_capacity(moduli.len() * levels);
        for modulus_index in 0..moduli.len() {
            let lift = crt_lift_constant(&source_basis, modulus_index, moduli).map_err(|_| {
                MultipartyError::InvalidParameters("create_share: crt_lift_constant failed")
            })?;
            for level in 0..levels {
                let purpose = format!(
                    "{GKG_COMMON_A_PURPOSE_PREFIX}/{}/{modulus_index}/{level}",
                    self.element
                );
                let a = derive_common_ring_element(ring, &self.session, purpose.as_bytes());

                let scaled = scale_by_base_power_and_lift(ring, &sigma_s, base_log, level, &lift)
                    .map_err(|_| {
                    MultipartyError::InvalidParameters(
                        "create_share: scale_by_base_power_and_lift failed",
                    )
                })?;
                let e = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let t_e = ring
                    .scalar_mul(&e, t)
                    .map_err(|_| MultipartyError::InvalidParameters("create_share: t*e failed"))?;
                let a_s = ring
                    .mul(&a, local_secret_share.value())
                    .map_err(|_| MultipartyError::InvalidParameters("create_share: a*s failed"))?;
                let b = ring
                    .add(&scaled, &t_e)
                    .and_then(|acc| ring.sub(&acc, &a_s))
                    .map_err(|_| MultipartyError::InvalidParameters("create_share: row failed"))?;

                rows.push((b, a));
            }
        }

        Share::new(
            &self.session,
            participant,
            ShareKind::GaloisKeyGen,
            encode_poly_rows(&rows),
        )
    }

    /// Aggregates every collected GKG share into the real collective
    /// rotation key. Sums *every* collected share's own `b_{j,i}^{(p)}`
    /// (`ShareAggregator::all_shares`, not `aggregate` - see that method's
    /// own doc comment): this is additive n-of-n, the same as
    /// [`super::CollectiveKeyGen`]/[`super::ReEncryptor`], not a threshold
    /// construction. Each row's own `a_{j,i}` is *not* summed - unlike
    /// `b_{j,i}^{(p)}`, it isn't a per-participant additive contribution at
    /// all: every participant derives the identical value
    /// ([`derive_common_ring_element`], the same purpose label), so it's
    /// kept as-is from whichever share is read first, and every other
    /// share's own copy is checked to match exactly (a mismatch means a
    /// malformed or malicious share, not something to silently sum away).
    pub fn aggregate_keys(&self, aggregator: &ShareAggregator) -> Result<BgvRelinearizationKey> {
        let ring = self.params.ring();
        let shares = aggregator.all_shares()?;

        let mut summed: Option<Vec<(Poly, Poly)>> = None;
        for share in &shares {
            let rows = decode_poly_rows(share.payload(), ring)?;
            summed = Some(match summed {
                None => rows,
                Some(accumulated) => {
                    if accumulated.len() != rows.len() {
                        return Err(MultipartyError::MalformedMessage);
                    }
                    let mut next = Vec::with_capacity(accumulated.len());
                    for ((acc_b, acc_a), (b, a)) in accumulated.into_iter().zip(rows) {
                        if acc_a != a {
                            return Err(MultipartyError::MalformedMessage);
                        }
                        let sum_b = ring.add(&acc_b, &b).map_err(|_| {
                            MultipartyError::InvalidParameters("aggregate_keys: row b sum failed")
                        })?;
                        next.push((sum_b, acc_a));
                    }
                    next
                }
            });
        }

        let rows = summed.ok_or(MultipartyError::MissingShare)?;
        let ciphertext_rows: Vec<Ciphertext> = rows
            .into_iter()
            .map(|(b, a)| Ciphertext::new(vec![b, a]))
            .collect();
        Ok(BgvRelinearizationKey::from_rows(
            self.decomposition_params,
            ciphertext_rows,
        ))
    }
}
