//! CKKS collective Galois (rotation) key generation - real, RNS-hybrid,
//! additive n-of-n.
//!
//! Real CKKS rotation keys are the RNS-hybrid `KeySwitchKey` construction
//! (`phantom_lattice::rlwe::KeyGenerator::generate_hybrid_galois_key`) -
//! CKKS is, per its own doc comments, actually the scheme this technique
//! was built for (unlike BGV, which needs its own bespoke classical-
//! gadget-decomposition construction instead - see `bgv::relinearization`'s
//! own module doc comment for why). The collective version of that
//! RNS-hybrid construction is derived once, scheme-agnostically, in
//! `common::hybrid` (which see for the full derivation, and
//! `mpbfv::gkg`'s own doc comment for the identical BFV wiring this
//! mirrors) - this module is a thin wrapper supplying CKKS's own
//! `RlweParams` and handling session/replay/wire concerns.

use phantom_lattice::rlwe::{Ciphertext, GaloisKey, KeySwitchKey, SecretKey};
use phantom_ring::{Modulus, Poly};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_rows, encode_poly_rows};
use crate::common::{
    hybrid, ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator, ShareKind,
};
use crate::{MultipartyError, Result};
use phantom_schemes::ckks::CkksParams;

/// Collective Galois-key generation helper for CKKS. Scoped to one
/// rotation `element` per session, matching `super::CollectiveKeyGen`'s
/// own "one clear thing per session" shape.
#[derive(Clone, Debug)]
pub struct GaloisKeyGen {
    params: CkksParams,
    session: SessionState,
    element: usize,
    p_moduli: Vec<Modulus>,
}

impl GaloisKeyGen {
    /// Creates a collective Galois-key generation helper for rotation
    /// `element`. `p_moduli` is the auxiliary basis, agreed by every
    /// participant in advance (the same parameter
    /// `CkksKeyGenerator::generate_hybrid_galois_key` itself takes).
    pub fn new(
        params: CkksParams,
        session: SessionState,
        element: usize,
        p_moduli: Vec<Modulus>,
    ) -> Self {
        Self {
            params,
            session,
            element,
            p_moduli,
        }
    }

    /// Creates this participant's own GKG share - see `common::hybrid`'s
    /// own doc comment for the row construction.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpckks` protocol call this participant
    /// makes.
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        replay_guard.record_use(&self.session, participant)?;
        let q_params = self
            .params
            .rlwe_params()
            .map_err(|_| MultipartyError::InvalidParameters("create_share: invalid params"))?;
        let rows = hybrid::gkg_row_contributions(
            &q_params,
            &self.p_moduli,
            &self.session,
            self.element,
            local_secret_share,
            rng,
        )?;
        Share::new(
            &self.session,
            participant,
            ShareKind::GaloisKeyGen,
            encode_poly_rows(&rows),
        )
    }

    /// Aggregates every collected GKG share into the real collective
    /// rotation key - see `mpbfv::gkg::aggregate_keys`'s own doc comment
    /// for the identical aggregation shape.
    pub fn aggregate_keys(&self, aggregator: &ShareAggregator) -> Result<GaloisKey> {
        let q_params = self
            .params
            .rlwe_params()
            .map_err(|_| MultipartyError::InvalidParameters("aggregate_keys: invalid params"))?;
        let qp_params = hybrid::qp_params(&q_params, &self.p_moduli)?;
        let qp_ring = qp_params.ring();

        let shares = aggregator.all_shares()?;
        let mut summed: Option<Vec<(Poly, Poly)>> = None;
        for share in &shares {
            let rows = decode_poly_rows(share.payload(), qp_ring)?;
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
                        let sum_b = qp_ring.add(&acc_b, &b).map_err(|_| {
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
        let ksk = KeySwitchKey::from_rows(qp_params, ciphertext_rows);
        Ok(GaloisKey::from_key_switch_key(self.element, ksk))
    }
}
