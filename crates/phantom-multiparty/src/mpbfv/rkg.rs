//! BFV collective relinearization-key generation - real, RNS-hybrid,
//! three-round.
//!
//! Real BFV relinearization keys are the RNS-hybrid `KeySwitchKey`
//! construction (`phantom_lattice::rlwe::KeyGenerator::generate_hybrid_relinearization_key`) -
//! unlike BGV, which needs its own bespoke classical-gadget-decomposition
//! construction instead (see `bgv::relinearization`'s own module doc
//! comment for why). The collective version is derived once,
//! scheme-agnostically, in `common::hybrid` (which see for the full
//! derivation, including why this needs an extra "collective public key
//! over `QP`" round `mpbgv::rkg`'s own two-round protocol didn't) - this
//! module is a thin wrapper supplying BFV's own `RlweParams` and handling
//! session/replay/wire concerns.
//!
//! Three rounds, each one further than `self.session`: round 0 (this
//! type's own `session`) builds the collective public key over `QP`;
//! round 1 ([`RelinearizationKeyGen::round1_session`]) and round 2
//! ([`RelinearizationKeyGen::round2_session`]) then mirror `mpbgv::rkg`'s
//! own two rounds, per row.

use phantom_lattice::rlwe::{Ciphertext, PublicKey, RelinearizationKey, SecretKey};
use phantom_ring::{Modulus, Poly, Ring};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly, decode_poly_rows, encode_poly, encode_poly_rows};
use crate::common::{
    hybrid, ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator, ShareKind,
};
use crate::{MultipartyError, Result};
use phantom_schemes::bfv::BfvParams;

/// Collective relinearization-key generation helper for BFV. See this
/// module's own doc comment for the three-round protocol.
#[derive(Clone, Debug)]
pub struct RelinearizationKeyGen {
    params: BfvParams,
    session: SessionState,
    p_moduli: Vec<Modulus>,
}

impl RelinearizationKeyGen {
    /// Creates a collective relinearization-key generation helper.
    /// `p_moduli` is the auxiliary basis, agreed by every participant in
    /// advance (the same parameter `KeyGenerator::generate_hybrid_relinearization_key`
    /// itself takes). `session` is round 0's (the `QP`-collective-public-key
    /// round's) session.
    pub fn new(params: BfvParams, session: SessionState, p_moduli: Vec<Modulus>) -> Self {
        Self {
            params,
            session,
            p_moduli,
        }
    }

    /// Returns the session round 1 runs against: round 0's session, one
    /// round advanced.
    pub fn round1_session(&self) -> SessionState {
        let mut session = self.session.clone();
        session.advance_round();
        session
    }

    /// Returns the session round 2 runs against: round 1's session, one
    /// round advanced.
    pub fn round2_session(&self) -> SessionState {
        let mut session = self.round1_session();
        session.advance_round();
        session
    }

    fn q_params(&self) -> Result<phantom_lattice::rlwe::RlweParams> {
        self.params
            .rlwe_params()
            .map_err(|_| MultipartyError::InvalidParameters("invalid params"))
    }

    /// Creates this participant's own round-0 share: a contribution to the
    /// collective public key over `QP` - see `common::hybrid`'s own doc
    /// comment.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpbfv` protocol call this participant
    /// makes (including [`Self::create_share_round1`]/
    /// [`Self::create_share_round2`], each their own independent round).
    pub fn create_qp_ckg_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        replay_guard.record_use(&self.session, participant)?;
        let q_params = self.q_params()?;
        let b_i = hybrid::qp_ckg_contribution(
            &q_params,
            &self.p_moduli,
            &self.session,
            local_secret_share,
            rng,
        )?;
        Share::new(
            &self.session,
            participant,
            ShareKind::RelinearizationKeyGen,
            encode_poly(&b_i),
        )
    }

    /// Aggregates every collected round-0 share into the real collective
    /// public key over `QP`.
    pub fn aggregate_qp_public_key(&self, aggregator: &ShareAggregator) -> Result<PublicKey> {
        let q_params = self.q_params()?;
        let qp_params = hybrid::qp_params(&q_params, &self.p_moduli)?;
        let shares = aggregator.all_shares()?;
        let contributions: Vec<Poly> = shares
            .iter()
            .map(|share| decode_poly(share.payload(), qp_params.ring()))
            .collect::<Result<_>>()?;
        hybrid::aggregate_qp_public_key(&q_params, &self.p_moduli, &self.session, &contributions)
    }

    /// Creates this participant's own round-1 share - see
    /// `common::hybrid`'s own doc comment for the construction.
    pub fn create_share_round1<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        collective_public_key_qp: &PublicKey,
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        let round1_session = self.round1_session();
        replay_guard.record_use(&round1_session, participant)?;
        let q_params = self.q_params()?;
        let rows = hybrid::rkg_round1_row_contributions(
            &q_params,
            &self.p_moduli,
            collective_public_key_qp,
            local_secret_share,
            rng,
        )?;
        Share::new(
            &round1_session,
            participant,
            ShareKind::RelinearizationKeyGen,
            encode_poly_rows(&rows),
        )
    }

    /// Aggregates every collected round-1 share into the public round-1
    /// aggregate rows - see `common::hybrid`'s own doc comment. Sums
    /// *every* collected share's own rows (both components are genuine
    /// per-participant contributions here, unlike GKG's per-row `a_j`).
    pub fn aggregate_round1(&self, aggregator: &ShareAggregator) -> Result<Vec<(Poly, Poly)>> {
        let q_params = self.q_params()?;
        let qp_params = hybrid::qp_params(&q_params, &self.p_moduli)?;
        sum_rows(qp_params.ring(), aggregator)
    }

    /// Creates this participant's own round-2 share, folding
    /// `local_secret_share` into round 1's public aggregate.
    pub fn create_share_round2<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        collective_public_key_qp: &PublicKey,
        round1_aggregate: &[(Poly, Poly)],
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        let round2_session = self.round2_session();
        replay_guard.record_use(&round2_session, participant)?;
        let q_params = self.q_params()?;
        let rows = hybrid::rkg_round2_row_contributions(
            &q_params,
            &self.p_moduli,
            collective_public_key_qp,
            round1_aggregate,
            local_secret_share,
            rng,
        )?;
        Share::new(
            &round2_session,
            participant,
            ShareKind::RelinearizationKeyGen,
            encode_poly_rows(&rows),
        )
    }

    /// Aggregates every collected round-2 share into the real collective
    /// relinearization key.
    pub fn aggregate_key(&self, aggregator: &ShareAggregator) -> Result<RelinearizationKey> {
        let q_params = self.q_params()?;
        let qp_params = hybrid::qp_params(&q_params, &self.p_moduli)?;
        let rows = sum_rows(qp_params.ring(), aggregator)?;
        let ciphertext_rows: Vec<Ciphertext> = rows
            .into_iter()
            .map(|(b, a)| Ciphertext::new(vec![b, a]))
            .collect();
        let ksk = phantom_lattice::rlwe::KeySwitchKey::from_rows(qp_params, ciphertext_rows);
        Ok(RelinearizationKey::from_key_switch_key(ksk))
    }
}

/// Sums every collected share's own row sequence componentwise - the
/// common aggregation shape both round 1 and round 2 need (no shared
/// constant in either round's rows, unlike GKG's per-row `a_j`).
fn sum_rows(ring: &Ring, aggregator: &ShareAggregator) -> Result<Vec<(Poly, Poly)>> {
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
                for ((acc_first, acc_second), (first, second)) in accumulated.into_iter().zip(rows)
                {
                    let sum_first = ring.add(&acc_first, &first).map_err(|_| {
                        MultipartyError::InvalidParameters("sum_rows: first component sum failed")
                    })?;
                    let sum_second = ring.add(&acc_second, &second).map_err(|_| {
                        MultipartyError::InvalidParameters("sum_rows: second component sum failed")
                    })?;
                    next.push((sum_first, sum_second));
                }
                next
            }
        });
    }

    summed.ok_or(MultipartyError::MissingShare)
}
