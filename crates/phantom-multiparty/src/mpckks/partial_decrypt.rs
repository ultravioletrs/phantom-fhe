//! CKKS collective (partial) decryption - real, additive n-of-n.
//!
//! Identical construction to [`super::super::mpbfv::PartialDecryptor`] - see
//! that module's own doc comment for the full derivation - with the same
//! two CKKS-specific differences [`super::ReEncryptor`]'s own doc comment
//! explains at length: level-awareness (operates over
//! `self.params.at_level(ciphertext.level())`'s own ring, truncating
//! `local_secret_share` to match first via
//! [`phantom_ring::rns::rescale::drop_last_modulus`]), and smudging noise
//! costing decode precision directly rather than being stripped by an
//! exact modular reduction - the scale must be sized with that in mind, not
//! just for multiplicative depth.
//!
//! Given ciphertext `(c0, c1)` under the collective secret `s = sum_i s_i`,
//! each participant computes `d_i = c1*s_i + e_i` (`e_i` smudging-sized
//! noise, its own bound derived internally from `ciphertext.precision()` -
//! see [`super::ReEncryptor::create_share`]'s own doc comment for why CKKS
//! needs no explicit `ciphertext_noise_bound` parameter, unlike BGV/BFV).
//! Combining every participant's own `d_i`: `c0 + sum_i(d_i) = c0 + c1*s +
//! sum_i(e_i)` - exactly `ckks::Decryptor::decrypt_real`'s own single-party
//! algebra (`c0 + c1*s`) plus ordinary raw noise.
//!
//! Additive n-of-n, matching [`super::CollectiveKeyGen`]'s own default.

use phantom_lattice::rlwe::SecretKey;
use phantom_ring::rns::rescale::drop_last_modulus;
use phantom_ring::sampling::sample_smudging_gaussian;
use phantom_schemes::ckks::{Ciphertext, CkksParams, Plaintext};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly, encode_poly};
use crate::common::{ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Collective (partial) decryption helper for CKKS. See this module's own
/// doc comment for the construction.
#[derive(Clone, Debug)]
pub struct PartialDecryptor {
    params: CkksParams,
    session: SessionState,
    statistical_security_bits: u32,
}

impl PartialDecryptor {
    /// Creates a partial decryptor targeting `statistical_security_bits`
    /// bits of statistical security for its smudging noise -
    /// [`phantom_lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS`]
    /// unless a deployment has a specific reason to choose otherwise.
    pub const fn new(
        params: CkksParams,
        session: SessionState,
        statistical_security_bits: u32,
    ) -> Self {
        Self {
            params,
            session,
            statistical_security_bits,
        }
    }

    /// Creates this participant's own partial-decryption share, `d_i =
    /// c1*s_i + e_i` - see this module's own doc comment for the
    /// construction.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpckks` protocol call this participant
    /// makes - refuses (before any crypto work) to produce a second share
    /// for the same `(session, round, participant)`.
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        ciphertext: &Ciphertext,
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        replay_guard.record_use(&self.session, participant)?;
        let level_params = self
            .params
            .at_level(ciphertext.level())
            .map_err(|_| MultipartyError::MalformedMessage)?;
        let ring = level_params.ring();
        let target_moduli = ring.moduli().len();

        let poly_ct = ciphertext.poly().ok_or(MultipartyError::InvalidParameters(
            "create_share: ciphertext has no real ring representation",
        ))?;
        let c1 = poly_ct
            .value()
            .get(1)
            .ok_or(MultipartyError::MalformedMessage)?;
        ring.check_poly(c1)
            .map_err(|_| MultipartyError::MalformedMessage)?;

        let mut sk_value = local_secret_share.value().clone();
        while sk_value.moduli_count() > target_moduli {
            sk_value = drop_last_modulus(&sk_value)
                .map_err(|_| MultipartyError::InvalidParameters("create_share: sk drop failed"))?;
        }

        let noise_bound = phantom_schemes::ckks::noise::noise_bound_from_precision(
            ciphertext.precision().bits(),
            ciphertext.scale().value(),
            ring.degree(),
        )
        .ceil() as u64;
        let smudging_std_dev = phantom_lattice::security::smudging_std_dev(
            noise_bound,
            self.statistical_security_bits,
        );
        let e_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);

        let c1_s_i = ring
            .mul(c1, &sk_value)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: c1*s_i failed"))?;
        let d_i = ring
            .add(&c1_s_i, &e_i)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: d_i failed"))?;

        Share::new(
            &self.session,
            participant,
            ShareKind::PartialDecryption,
            encode_poly(&d_i),
        )
    }

    /// Aggregates every collected partial-decryption share into the
    /// decrypted plaintext: `c0 + sum_i(d_i)`, wrapped directly as a
    /// [`Plaintext`] with empty slots - matching
    /// `ckks::Decryptor::decrypt_real`'s own convention (decode separately
    /// via `ckks::Encoder::decode_complex_real`). Sums *every* collected
    /// share ([`ShareAggregator::all_shares`], not `aggregate`).
    pub fn aggregate_plaintext(
        &self,
        aggregator: &ShareAggregator,
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext> {
        let level_params = self
            .params
            .at_level(ciphertext.level())
            .map_err(|_| MultipartyError::MalformedMessage)?;
        let ring = level_params.ring();

        let poly_ct = ciphertext.poly().ok_or(MultipartyError::InvalidParameters(
            "aggregate_plaintext: ciphertext has no real ring representation",
        ))?;
        let c0 = poly_ct
            .value()
            .first()
            .ok_or(MultipartyError::MalformedMessage)?;
        ring.check_poly(c0)
            .map_err(|_| MultipartyError::MalformedMessage)?;

        let shares = aggregator.all_shares()?;
        let mut d_sum = ring.zero();
        for share in &shares {
            let d_i = decode_poly(share.payload(), ring)?;
            d_sum = ring.add(&d_sum, &d_i).map_err(|_| {
                MultipartyError::InvalidParameters("aggregate_plaintext: sum failed")
            })?;
        }

        let result = ring.add(c0, &d_sum).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_plaintext: c0 + d_sum failed")
        })?;
        Ok(Plaintext::new_real(
            Vec::new(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
            result,
        ))
    }
}
