//! BFV collective (partial) decryption - real, additive n-of-n.
//!
//! Identical construction to [`super::super::mpbgv::PartialDecryptor`] - see
//! that module's own doc comment for the full derivation and citation -
//! minus the `t`-scaling BGV's own noise needs and BFV's own real path
//! doesn't (see [`super::CollectiveKeyGen`]'s own doc comment for why).
//! Given ciphertext `(c0, c1)` under the collective secret `s = sum_i s_i`,
//! each participant computes `d_i = c1*s_i + e_i` (`e_i` smudging-sized
//! noise, same rationale as [`super::ReEncryptor`]'s own `e0_i`/`e1_i`).
//! Combining every participant's own `d_i`: `c0 + sum_i(d_i) = c0 + c1*s +
//! sum_i(e_i)` - exactly `bgv::Decryptor::decrypt`'s own single-party
//! algebra (`c0 + c1*s`, unmodified by BFV's own `Decryptor`, which
//! delegates straight to it) plus ordinary raw noise comfortably inside
//! BFV's own `Delta/2` correctness budget.
//!
//! Additive n-of-n, matching [`super::CollectiveKeyGen`]'s own default.

use phantom_lattice::rlwe::SecretKey;
use phantom_ring::sampling::sample_smudging_gaussian;
use phantom_schemes::bfv::{BfvParams, Ciphertext, Plaintext};
use phantom_schemes::bgv;
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly, encode_poly};
use crate::common::{ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Collective (partial) decryption helper for BFV. See this module's own
/// doc comment for the construction.
#[derive(Clone, Debug)]
pub struct PartialDecryptor {
    params: BfvParams,
    session: SessionState,
    statistical_security_bits: u32,
}

impl PartialDecryptor {
    /// Creates a partial decryptor targeting `statistical_security_bits`
    /// bits of statistical security for its smudging noise -
    /// [`phantom_lattice::security::RECOMMENDED_STATISTICAL_SECURITY_BITS`]
    /// unless a deployment has a specific reason to choose otherwise.
    pub const fn new(
        params: BfvParams,
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
    /// `ciphertext_noise_bound` must be the caller's own worst-case bound on
    /// `ciphertext`'s current decryption noise - see
    /// [`super::ReEncryptor::create_share`]'s own doc comment for why
    /// `PartialDecryptor` can't derive this itself.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpbfv` protocol call this participant
    /// makes - refuses (before any crypto work) to produce a second share
    /// for the same `(session, round, participant)`, which would leak
    /// `local_secret_share` via accumulated linear algebra against the
    /// deterministic public `c1`, regardless of the smudging noise above.
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        ciphertext: &Ciphertext,
        ciphertext_noise_bound: u64,
        replay_guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<Share> {
        replay_guard.record_use(&self.session, participant)?;
        let ring = self.params.ring();
        let c1 = ciphertext
            .inner()
            .inner()
            .value()
            .get(1)
            .ok_or(MultipartyError::MalformedMessage)?;
        ring.check_poly(c1)
            .map_err(|_| MultipartyError::MalformedMessage)?;

        let smudging_std_dev = phantom_lattice::security::smudging_std_dev(
            ciphertext_noise_bound,
            self.statistical_security_bits,
        );
        let e_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);

        let c1_s_i = ring
            .mul(c1, local_secret_share.value())
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
    /// [`Plaintext`] - matching `bfv::Decryptor::decrypt`'s own convention
    /// of returning the raw, not-yet-`Delta`-divided ring element for the
    /// caller's own encoder to decode. Sums *every* collected share
    /// ([`ShareAggregator::all_shares`], not `aggregate`).
    pub fn aggregate_plaintext(
        &self,
        aggregator: &ShareAggregator,
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext> {
        let ring = self.params.ring();
        let c0 = ciphertext
            .inner()
            .inner()
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
        Ok(Plaintext::new(bgv::Plaintext::new(
            phantom_lattice::rlwe::Plaintext::new(result),
        )))
    }
}
