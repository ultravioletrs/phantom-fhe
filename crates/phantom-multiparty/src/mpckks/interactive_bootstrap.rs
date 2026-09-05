//! CKKS interactive (collective) bootstrapping - real, single-round.
//!
//! Same overall shape as
//! [`super::super::mpbgv::InteractiveBootstrap`]/[`super::super::mpbfv::InteractiveBootstrap`]
//! (which see for the full derivation of the shared **ColBootstrap**
//! construction, [eprint 2020/304](https://eprint.iacr.org/2020/304),
//! Protocol 5) - fusing [`super::PartialDecryptor`]'s own decrypt-share
//! shape with [`super::CollectiveKeyGen`]'s own fresh-encryption-share
//! shape via a per-participant mask that cancels on combination - but CKKS
//! needs two genuine differences, not just a mechanical port:
//!
//! **No discrete mask, no discard - but a stronger, simpler mask.** BGV/BFV
//! mask uniform over the *finite* plaintext ring `[0, t)`, and the masked-
//! reveal step goes through an exact `mod t`/`Delta`-rounding decode that
//! *discards* everything below the rounding threshold - this is why their
//! bootstrapped output's noise is just the freshly-added `e1_i`, with the
//! input ciphertext's own noise discarded entirely. CKKS has no finite
//! plaintext ring and no discrete decode step (`mpckks::reencryption`'s own
//! doc comment: "the decoded value is the raw `(c0+c1*s)/Delta`") - so
//! nothing here is ever decoded through an encoder at all, and combination
//! is pure polynomial addition. The mask itself is
//! [`sample_uniform`] over the *entire* ciphertext ring `Z_Q` (the same
//! primitive [`derive_common_ring_element`]'s own common `a` already
//! uses) - since `Q` is astronomically larger than any real message's own
//! `Delta`-scaled magnitude, this hides the masked-reveal value completely
//! (a one-time pad over `Z_Q`, the same information-theoretic argument
//! BGV/BFV's own uniform-mod-`t` mask makes, just over the bigger ring) -
//! *not* a `smudging_std_dev`-sized Gaussian: that formula is calibrated
//! for flooding a small *noise* term (as `e0_i`/`e1_i` already are), and
//! sizing it instead for a `Delta`-scaled *message* bound was tried and
//! found to overflow the Gaussian sampler's own realistic range - uniform
//! masking avoids the problem entirely, and gives strictly better hiding
//! besides. The input ciphertext's own noise is *not* discarded, unlike
//! BGV/BFV - it persists into the output, on top of `e0_i`/`e1_i`. This is
//! still a genuine, useful bootstrap: it caps the *total* output noise/
//! precision to a known, parameter-derived floor (dominated by `e0_i`)
//! rather than letting it grow unboundedly through further multiplications,
//! matching this codebase's own already-documented "smudging costs CKKS
//! precision directly" finding (`mpckks::reencryption`'s own doc comment)
//! rather than contradicting it.
//!
//! **Level tracking**, the same technique [`super::ReEncryptor`]/
//! [`super::PartialDecryptor`] already use: operates over
//! `self.params.at_level(ciphertext.level())`'s own (possibly smaller) ring,
//! truncating `local_secret_share` to match via repeated
//! [`drop_last_modulus`].
//!
//! ```text
//! h0_i = c1*s_i + e0_i - M_i
//! h1_i = e1_i - a*s_i + M_i
//! ```
//!
//! combined as `ct_out0 = c0 + sum_i(h0_i) + sum_i(h1_i)`, `ct_out1 = a` -
//! pure polynomial addition throughout, no encoder involved.

use phantom_lattice::rlwe::SecretKey;
use phantom_lattice::security::{smudging_std_dev, STANDARD_ERROR_STD_DEV};
use phantom_ring::rns::rescale::drop_last_modulus;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_smudging_gaussian, sample_uniform};
use phantom_schemes::ckks::noise::{noise_bound_from_precision, precision_bits_from_noise};
use phantom_schemes::ckks::{Ciphertext, CkksParams, Precision};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_pair, encode_poly_pair};
use crate::common::{
    derive_common_ring_element, ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator,
    ShareKind,
};
use crate::{MultipartyError, Result};

/// Purpose label for [`derive_common_ring_element`]'s own domain separation
/// - distinct from `mpckks::ckg`/`gkg`/`rkg`'s own labels.
const IB_COMMON_A_PURPOSE: &[u8] = b"phantom-fhe/mpckks/interactive_bootstrap/a/v1";

/// Collective (interactive) bootstrapping helper for CKKS. See this
/// module's own doc comment for the single-round construction.
#[derive(Clone, Debug)]
pub struct InteractiveBootstrap {
    params: CkksParams,
    session: SessionState,
    statistical_security_bits: u32,
}

impl InteractiveBootstrap {
    /// Creates an interactive-bootstrap helper targeting
    /// `statistical_security_bits` bits of statistical security for its
    /// noise-hiding smudging term - matches [`super::PartialDecryptor::new`]'s
    /// own shape. The mask itself needs no security parameter - it's
    /// uniform over the entire ring, not sized off any bound (see this
    /// module's own doc comment for why).
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

    /// Creates this participant's own share `(h0_i, h1_i)` - see this
    /// module's own doc comment for the construction.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpckks` protocol call this participant
    /// makes.
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

        let a = derive_common_ring_element(ring, &self.session, IB_COMMON_A_PURPOSE);

        let noise_bound = noise_bound_from_precision(
            ciphertext.precision().bits(),
            ciphertext.scale().value(),
            ring.degree(),
        )
        .ceil() as u64;
        let e0_std = smudging_std_dev(noise_bound, self.statistical_security_bits);

        let mask = sample_uniform(ring, rng);
        let e0_i = sample_smudging_gaussian(ring, rng, e0_std);
        let e1_i = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);

        let c1_s_i = ring
            .mul(c1, &sk_value)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: c1*s_i failed"))?;
        let h0_i = ring
            .add(&c1_s_i, &e0_i)
            .and_then(|acc| ring.sub(&acc, &mask))
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h0_i failed"))?;

        let a_s_i = ring
            .mul(&a, &sk_value)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: a*s_i failed"))?;
        let h1_i = ring
            .sub(&e1_i, &a_s_i)
            .and_then(|acc| ring.add(&acc, &mask))
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h1_i failed"))?;

        Share::new(
            &self.session,
            participant,
            ShareKind::InteractiveBootstrap,
            encode_poly_pair(&h0_i, &h1_i),
        )
    }

    /// Aggregates every collected share into the real, bootstrapped
    /// ciphertext - see this module's own doc comment for the construction.
    /// Sums *every* collected share (`ShareAggregator::all_shares`, not
    /// `aggregate`), additive n-of-n like every other real `mpckks`
    /// construction. The output `Precision` is derived from the known
    /// smudging-noise floor (`e0_i`, recomputed identically since it's a
    /// deterministic function of `ciphertext`'s own precision/scale), not
    /// carried through from the input the way `ReEncryptor` does - here the
    /// whole point is that the output's own noise floor no longer depends
    /// on whatever the input's precision was.
    pub fn aggregate_refreshed(
        &self,
        aggregator: &ShareAggregator,
        ciphertext: &Ciphertext,
    ) -> Result<Ciphertext> {
        let level_params = self
            .params
            .at_level(ciphertext.level())
            .map_err(|_| MultipartyError::MalformedMessage)?;
        let ring = level_params.ring();

        let poly_ct = ciphertext.poly().ok_or(MultipartyError::InvalidParameters(
            "aggregate_refreshed: ciphertext has no real ring representation",
        ))?;
        let c0 = poly_ct
            .value()
            .first()
            .ok_or(MultipartyError::MalformedMessage)?;
        ring.check_poly(c0)
            .map_err(|_| MultipartyError::MalformedMessage)?;

        let shares = aggregator.all_shares()?;
        let mut h0_sum = ring.zero();
        let mut h1_sum = ring.zero();
        for share in &shares {
            let (h0_i, h1_i) = decode_poly_pair(share.payload(), ring)?;
            h0_sum = ring.add(&h0_sum, &h0_i).map_err(|_| {
                MultipartyError::InvalidParameters("aggregate_refreshed: h0 sum failed")
            })?;
            h1_sum = ring.add(&h1_sum, &h1_i).map_err(|_| {
                MultipartyError::InvalidParameters("aggregate_refreshed: h1 sum failed")
            })?;
        }

        let ct0_new = ring
            .add(c0, &h0_sum)
            .and_then(|acc| ring.add(&acc, &h1_sum))
            .map_err(|_| {
                MultipartyError::InvalidParameters("aggregate_refreshed: c0 + h0 + h1 failed")
            })?;
        let a = derive_common_ring_element(ring, &self.session, IB_COMMON_A_PURPOSE);

        let noise_bound = noise_bound_from_precision(
            ciphertext.precision().bits(),
            ciphertext.scale().value(),
            ring.degree(),
        )
        .ceil() as u64;
        let output_noise_bound = smudging_std_dev(noise_bound, self.statistical_security_bits);
        let output_precision = Precision::new(precision_bits_from_noise(
            ciphertext.scale().value(),
            ring.degree(),
            output_noise_bound,
        ));

        Ok(Ciphertext::new_real(
            phantom_lattice::rlwe::Ciphertext::new(vec![ct0_new, a]),
            ciphertext.scale(),
            ciphertext.level(),
            output_precision,
            ciphertext.degree(),
        ))
    }
}
