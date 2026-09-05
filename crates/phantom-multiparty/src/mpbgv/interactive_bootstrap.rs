//! BGV interactive (collective) bootstrapping - real, single-round.
//!
//! Fuses two already-real `mpbgv` constructions via a per-participant mask
//! that cancels exactly on combination: [`super::PartialDecryptor`]'s own
//! `d_i = c1*s_i + t*e_i` (decrypt-toward-the-null-key share) and
//! [`super::CollectiveKeyGen`]'s own `b_i = t*e_i - a*s_i` (fresh-encryption
//! share). This is the real single-round **ColBootstrap** protocol Mouchet,
//! Troncoso-Pastoriza, Bossuat & Hubaux describe for BFV
//! ([eprint 2020/304](https://eprint.iacr.org/2020/304), Protocol 5,
//! Section IV-H) adapted to BGV's own `t`-scaled noise convention - derived
//! from their own protocol box and verified numerically (Python, 400/400
//! trials) before implementing.
//!
//! Each participant samples a private mask `M_i` (uniform over `[0, t)` per
//! coefficient - perfect, information-theoretic hiding of the value this
//! reveals below, needing no smudging of its own) and discloses one share:
//!
//! ```text
//! a          <- common value (derive_common_ring_element, same technique CKG uses)
//! e0_i       <- smudging noise (sample_smudging_gaussian, sized off ciphertext_noise_bound)
//! e1_i       <- ordinary noise (sample_discrete_gaussian, STANDARD_ERROR_STD_DEV)
//! h0_i = c1*s_i + t*e0_i - M_i
//! h1_i = t*e1_i - a*s_i + M_i
//! ```
//!
//! Combining every share (`h0 = sum h0_i`, `h1 = sum h1_i`): `c0 + h0 = m -
//! sum(M_i) + t*(noise)`, which decodes (via the *exact* `mod t` reduction
//! [`phantom_schemes::bgv::BatchEncoder::decode_u64`] already performs,
//! discarding the noise entirely, the same as any ordinary decode) to `m -
//! sum(M_i) mod t` - revealed to the combiner (who needs no secret material,
//! the same trust level [`super::PartialDecryptor`]'s own combiner already
//! has), but hiding `m` completely since `sum(M_i)` is unknown to anyone.
//! Re-embedding that revealed value and adding `h1` gives `(m - sum(M_i)) +
//! t*e1 - a*s + sum(M_i) = m + t*e1 - a*s` - a genuine fresh BGV ciphertext
//! under the *same* collective secret, with noise reset to just `e1` (the
//! input ciphertext's own accumulated noise never appears in the result,
//! discarded by the reveal step's own exact `mod t` decode).
//!
//! Mask and reveal operate entirely on raw polynomial coefficients via
//! [`BatchEncoder::encode_u64`]/[`decode_u64`](BatchEncoder::decode_u64) -
//! correct regardless of whether the *original* ciphertext used raw or
//! batched encoding, since batching is a discrete transform applied on top
//! of the same per-coefficient `mod t` reduction `decode_u64` already
//! performs either way. This type never needs to know which encoder the
//! caller used.

use phantom_lattice::rlwe::{self, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_smudging_gaussian};
use phantom_schemes::bgv::{BatchEncoder, BgvParams, Ciphertext, Plaintext};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_pair, encode_poly_pair};
use crate::common::{
    derive_common_ring_element, sample_uniform_mod_t, ParticipantId, ReplayGuard, SessionState,
    Share, ShareAggregator, ShareKind,
};
use crate::{MultipartyError, Result};

/// Purpose label for [`derive_common_ring_element`]'s own domain separation
/// - distinct from `mpbgv::ckg`/`gkg`/`rkg`'s own labels.
const IB_COMMON_A_PURPOSE: &[u8] = b"phantom-fhe/mpbgv/interactive_bootstrap/a/v1";

/// Collective (interactive) bootstrapping helper for BGV. See this module's
/// own doc comment for the single-round construction.
#[derive(Clone, Debug)]
pub struct InteractiveBootstrap {
    params: BgvParams,
    session: SessionState,
    statistical_security_bits: u32,
}

impl InteractiveBootstrap {
    /// Creates an interactive-bootstrap helper targeting
    /// `statistical_security_bits` bits of statistical security for its
    /// smudging noise - matches [`super::PartialDecryptor::new`]'s own
    /// shape.
    pub const fn new(
        params: BgvParams,
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
    /// `ciphertext_noise_bound` must be the caller's own worst-case bound on
    /// `ciphertext`'s current decryption noise - see
    /// [`super::PartialDecryptor::create_share`]'s own doc comment for why
    /// this can't be derived internally.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpbgv` protocol call this participant
    /// makes.
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
        let t = self.params.plaintext_modulus();
        let c1 = ciphertext
            .inner()
            .value()
            .get(1)
            .ok_or(MultipartyError::MalformedMessage)?;
        ring.check_poly(c1)
            .map_err(|_| MultipartyError::MalformedMessage)?;

        let a = derive_common_ring_element(ring, &self.session, IB_COMMON_A_PURPOSE);
        let mask_values = sample_uniform_mod_t(t, ring.degree(), rng);
        let encoder = BatchEncoder::new(self.params.clone());
        let mask_poly = encoder
            .encode_u64(&mask_values)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: mask encode failed"))?
            .into_inner()
            .into_value();

        let smudging_std_dev = phantom_lattice::security::smudging_std_dev(
            ciphertext_noise_bound,
            self.statistical_security_bits,
        );
        let e0_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);
        let e1_i = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);

        let c1_s_i = ring
            .mul(c1, local_secret_share.value())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: c1*s_i failed"))?;
        let t_e0_i = ring
            .scalar_mul(&e0_i, t)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: t*e0_i failed"))?;
        let h0_i = ring
            .add(&c1_s_i, &t_e0_i)
            .and_then(|acc| ring.sub(&acc, &mask_poly))
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h0_i failed"))?;

        let a_s_i = ring
            .mul(&a, local_secret_share.value())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: a*s_i failed"))?;
        let t_e1_i = ring
            .scalar_mul(&e1_i, t)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: t*e1_i failed"))?;
        let h1_i = ring
            .sub(&t_e1_i, &a_s_i)
            .and_then(|acc| ring.add(&acc, &mask_poly))
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
    /// `aggregate` - see that method's own doc comment): additive n-of-n,
    /// the same as every other real `mpbgv` construction.
    pub fn aggregate_refreshed(
        &self,
        aggregator: &ShareAggregator,
        ciphertext: &Ciphertext,
    ) -> Result<Ciphertext> {
        let ring = self.params.ring();
        let c0 = ciphertext
            .inner()
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

        let masked_raw = ring.add(c0, &h0_sum).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_refreshed: c0 + h0 failed")
        })?;
        let encoder = BatchEncoder::new(self.params.clone());
        let masked_plaintext = Plaintext::new(rlwe::Plaintext::new(masked_raw));
        let revealed_values = encoder.decode_u64(&masked_plaintext).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_refreshed: decode failed")
        })?;
        let unmasked_poly = encoder
            .encode_u64(&revealed_values)
            .map_err(|_| MultipartyError::InvalidParameters("aggregate_refreshed: encode failed"))?
            .into_inner()
            .into_value();

        let ct0_new = ring.add(&unmasked_poly, &h1_sum).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_refreshed: unmasked + h1 failed")
        })?;
        let a = derive_common_ring_element(ring, &self.session, IB_COMMON_A_PURPOSE);
        Ok(Ciphertext::new(rlwe::Ciphertext::new(vec![ct0_new, a])))
    }
}
