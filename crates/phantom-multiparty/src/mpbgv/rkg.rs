//! BGV collective relinearization-key generation - real, two-round.
//!
//! Unlike [`super::CollectiveKeyGen`]/[`super::GaloisKeyGen`]/[`super::ReEncryptor`]
//! (all additive n-of-n, linear in each participant's own secret `s_p`),
//! relinearization needs the collective secret's *square*: `s^2 =
//! (sum_p s_p)^2 = sum_p sum_q s_p*s_q`, which has cross terms `s_p*s_q` for
//! `p != q` that no single participant can form from their own secret alone.
//! This module runs a genuine two-round protocol instead, using the
//! already-established collective public key `(cpk_b, cpk_a)` (from
//! [`super::CollectiveKeyGen`]) as a tool:
//!
//! **Round 1** (per gadget row `i`, each party locally, no round-1 input
//! needed): fresh ephemeral ternary `u_i^(p)`,
//! `h0_i^(p) = cpk_b*u_i^(p) + t*e0_i^(p) + scale_i(s_p)`,
//! `h1_i^(p) = cpk_a*u_i^(p) + t*e1_i^(p)`. Summing every party's row gives a
//! **public** `(H0_i, H1_i) = (cpk_b*U_i + t*E0_i + scale_i(s), cpk_a*U_i +
//! t*E1_i)` - a fresh encryption of `scale_i(s)` under the collective key,
//! computable by anyone, decrypted by no one.
//!
//! **Round 2** (each party, using round 1's public aggregate): fresh
//! ephemeral ternary `v_i^(p)`, `h0'_i^(p) = s_p*H0_i + cpk_b*v_i^(p) +
//! t*e2_i^(p)`, `h1'_i^(p) = s_p*H1_i + cpk_a*v_i^(p) + t*e3_i^(p)`. Summing
//! every party's row gives `(Key0_i, Key1_i) = (s*H0_i + cpk_b*V_i + t*E2_i,
//! s*H1_i + cpk_a*V_i + t*E3_i)`, which decrypts under the collective secret
//! to `scale_i(s^2) + t*(noise)` - a genuine relinearization-key row, using
//! `cpk_b + cpk_a*s = t*e_pk` (the collective public key's own identity) and
//! `s*scale_i(s) = scale_i(s^2)`.
//!
//! `scale_i` is [`BgvRelinearizationKey::generate`]'s own
//! `scale_by_base_power_and_lift`, the same one [`super::GaloisKeyGen`]
//! reuses. Every summed quantity in both rounds is a genuine per-participant
//! contribution (unlike GKG's per-row `a`, there is no shared constant here
//! to accidentally sum), but row-count/shape agreement across shares is
//! still checked the same way GKG does.

use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_lattice::rlwe::{Ciphertext, PublicKey, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::rns::extension::crt_lift_constant;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary};
use phantom_ring::{Poly, RnsBasis};
use phantom_schemes::bgv::{scale_by_base_power_and_lift, BgvParams, BgvRelinearizationKey};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_rows, encode_poly_rows};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Collective relinearization-key generation helper for BGV. See this
/// module's own doc comment for the two-round protocol.
#[derive(Clone, Debug)]
pub struct RelinearizationKeyGen {
    params: BgvParams,
    session: SessionState,
    collective_public_key: PublicKey,
    decomposition_params: GadgetDecompositionParams,
}

impl RelinearizationKeyGen {
    /// Creates a collective relinearization-key generation helper.
    /// `collective_public_key` must already be the real collective public
    /// key for this same set of participants (from
    /// [`super::CollectiveKeyGen::aggregate_public_key`]) - round 1 and
    /// round 2 both use it as an encryption target. `session` is round 1's
    /// session; round 2 runs against [`Self::round2_session`].
    pub const fn new(
        params: BgvParams,
        session: SessionState,
        collective_public_key: PublicKey,
        decomposition_params: GadgetDecompositionParams,
    ) -> Self {
        Self {
            params,
            session,
            collective_public_key,
            decomposition_params,
        }
    }

    /// Returns the session round 2 runs against: round 1's session, one
    /// round advanced. Callers build round 2's [`ShareAggregator`] against
    /// this, matching how [`Share::new`]/[`ShareAggregator`] already bind
    /// every share to a specific session round.
    pub fn round2_session(&self) -> SessionState {
        let mut session = self.session.clone();
        session.advance_round();
        session
    }

    fn row_layout(&self) -> (RnsBasis, usize, u32) {
        let ring = self.params.ring();
        let moduli = ring.moduli();
        let source_basis =
            RnsBasis::new(moduli.to_vec()).expect("ring moduli already validated by BgvParams");
        (
            source_basis,
            self.decomposition_params.levels(),
            self.decomposition_params.base_log(),
        )
    }

    /// Creates this participant's own round-1 share: every row's own
    /// `(h0_i^(p), h1_i^(p))`, encrypting `scale_i(s_p)` under the
    /// collective public key.
    pub fn create_share_round1<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        rng: &mut R,
    ) -> Result<Share> {
        let ring = self.params.ring();
        let t = self.params.plaintext_modulus();
        let moduli = ring.moduli();
        let (source_basis, levels, base_log) = self.row_layout();
        let cpk_b = &self.collective_public_key.value()[0];
        let cpk_a = &self.collective_public_key.value()[1];

        let mut rows = Vec::with_capacity(moduli.len() * levels);
        for modulus_index in 0..moduli.len() {
            let lift = crt_lift_constant(&source_basis, modulus_index, moduli).map_err(|_| {
                MultipartyError::InvalidParameters("create_share_round1: crt_lift_constant failed")
            })?;
            for level in 0..levels {
                let scaled = scale_by_base_power_and_lift(
                    ring,
                    local_secret_share.value(),
                    base_log,
                    level,
                    &lift,
                )
                .map_err(|_| {
                    MultipartyError::InvalidParameters(
                        "create_share_round1: scale_by_base_power_and_lift failed",
                    )
                })?;

                let u = sample_ternary(ring, rng);
                let e0 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
                let e1 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);

                let h0 = ring
                    .mul(cpk_b, &u)
                    .and_then(|acc| ring.scalar_mul(&e0, t).map(|t_e0| (acc, t_e0)))
                    .and_then(|(acc, t_e0)| ring.add(&acc, &t_e0))
                    .and_then(|acc| ring.add(&acc, &scaled))
                    .map_err(|_| {
                        MultipartyError::InvalidParameters("create_share_round1: h0 failed")
                    })?;
                let h1 = ring
                    .mul(cpk_a, &u)
                    .and_then(|acc| ring.scalar_mul(&e1, t).map(|t_e1| (acc, t_e1)))
                    .and_then(|(acc, t_e1)| ring.add(&acc, &t_e1))
                    .map_err(|_| {
                        MultipartyError::InvalidParameters("create_share_round1: h1 failed")
                    })?;

                rows.push((h0, h1));
            }
        }

        Share::new(
            &self.session,
            participant,
            ShareKind::RelinearizationKeyGen,
            encode_poly_rows(&rows),
        )
    }

    /// Aggregates every collected round-1 share into the public round-1
    /// aggregate `(H0_i, H1_i)` rows - sums *every* collected share
    /// ([`ShareAggregator::all_shares`], not `aggregate`: this is additive
    /// n-of-n, the same as every other real `mpbgv` construction). This
    /// value is public (an encryption of `scale_i(s)` under the collective
    /// key, decrypted by no one) and is fed directly into
    /// [`Self::create_share_round2`].
    pub fn aggregate_round1(&self, aggregator: &ShareAggregator) -> Result<Vec<(Poly, Poly)>> {
        let ring = self.params.ring();
        sum_rows(ring, aggregator)
    }

    /// Creates this participant's own round-2 share: every row's own
    /// `(h0'_i^(p), h1'_i^(p))`, folding `local_secret_share` into round 1's
    /// public aggregate.
    pub fn create_share_round2<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        round1_aggregate: &[(Poly, Poly)],
        rng: &mut R,
    ) -> Result<Share> {
        let ring = self.params.ring();
        let t = self.params.plaintext_modulus();
        let cpk_b = &self.collective_public_key.value()[0];
        let cpk_a = &self.collective_public_key.value()[1];

        let mut rows = Vec::with_capacity(round1_aggregate.len());
        for (h0, h1) in round1_aggregate {
            let v = sample_ternary(ring, rng);
            let e2 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
            let e3 = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);

            let h0p = ring
                .mul(local_secret_share.value(), h0)
                .and_then(|acc| ring.mul(cpk_b, &v).map(|cb_v| (acc, cb_v)))
                .and_then(|(acc, cb_v)| ring.add(&acc, &cb_v))
                .and_then(|acc| ring.scalar_mul(&e2, t).map(|t_e2| (acc, t_e2)))
                .and_then(|(acc, t_e2)| ring.add(&acc, &t_e2))
                .map_err(|_| {
                    MultipartyError::InvalidParameters("create_share_round2: h0' failed")
                })?;
            let h1p = ring
                .mul(local_secret_share.value(), h1)
                .and_then(|acc| ring.mul(cpk_a, &v).map(|ca_v| (acc, ca_v)))
                .and_then(|(acc, ca_v)| ring.add(&acc, &ca_v))
                .and_then(|acc| ring.scalar_mul(&e3, t).map(|t_e3| (acc, t_e3)))
                .and_then(|(acc, t_e3)| ring.add(&acc, &t_e3))
                .map_err(|_| {
                    MultipartyError::InvalidParameters("create_share_round2: h1' failed")
                })?;

            rows.push((h0p, h1p));
        }

        Share::new(
            &self.round2_session(),
            participant,
            ShareKind::RelinearizationKeyGen,
            encode_poly_rows(&rows),
        )
    }

    /// Aggregates every collected round-2 share into the real collective
    /// relinearization key: sums *every* collected share's own `(h0'_i^(p),
    /// h1'_i^(p))` (additive n-of-n, same as round 1).
    pub fn aggregate_key(&self, aggregator: &ShareAggregator) -> Result<BgvRelinearizationKey> {
        let ring = self.params.ring();
        let rows = sum_rows(ring, aggregator)?;
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

/// Sums every collected share's own row sequence componentwise - the common
/// aggregation shape both `aggregate_round1` and `aggregate_key` need (no
/// shared constant in either round's rows, unlike [`super::GaloisKeyGen`]'s
/// per-row `a`: every component here is summed, not checked for equality).
fn sum_rows(ring: &phantom_ring::Ring, aggregator: &ShareAggregator) -> Result<Vec<(Poly, Poly)>> {
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
