//! BFV interactive (collective) bootstrapping - real, single-round.
//!
//! Identical construction to [`super::super::mpbgv::InteractiveBootstrap`] -
//! see that module's own doc comment for the full derivation (the real,
//! single-round **ColBootstrap** protocol Mouchet, Troncoso-Pastoriza,
//! Bossuat & Hubaux describe for BFV,
//! [eprint 2020/304](https://eprint.iacr.org/2020/304), Protocol 5, Section
//! IV-H) - with BGV's own `t`-scaled noise replaced by BFV's own
//! `Delta = floor(q/t)`-scaled message, the same difference every other
//! real `mpbfv` construction already has from its `mpbgv` counterpart:
//!
//! ```text
//! h0_i = c1*s_i + e0_i - Delta*M_i
//! h1_i = e1_i - a*s_i + Delta*M_i
//! ```
//!
//! Mask embedding and the masked reveal use
//! [`phantom_schemes::bfv::BatchEncoder::encode_u64_real`]/
//! [`decode_u64_real`](phantom_schemes::bfv::BatchEncoder::decode_u64_real) -
//! the `Delta`-aware counterparts to `mpbgv`'s own plain `encode_u64`/
//! `decode_u64`, matching how a real BFV ciphertext's own `c0` is always
//! `Delta`-scaled, unlike BGV's own unscaled message embedding.

use phantom_lattice::rlwe::SecretKey;
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_smudging_gaussian};
use phantom_schemes::bfv::{BatchEncoder, BfvParams, Ciphertext};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_pair, encode_poly_pair};
use crate::common::{
    derive_common_ring_element, sample_uniform_mod_t, ParticipantId, ReplayGuard, SessionState,
    Share, ShareAggregator, ShareKind,
};
use crate::{MultipartyError, Result};

/// Purpose label for [`derive_common_ring_element`]'s own domain separation
/// - distinct from `mpbfv::ckg`/`gkg`/`rkg`'s own labels.
const IB_COMMON_A_PURPOSE: &[u8] = b"phantom-fhe/mpbfv/interactive_bootstrap/a/v1";

/// Collective (interactive) bootstrapping helper for BFV. See this module's
/// own doc comment for the single-round construction.
#[derive(Clone, Debug)]
pub struct InteractiveBootstrap {
    params: BfvParams,
    session: SessionState,
    statistical_security_bits: u32,
}

impl InteractiveBootstrap {
    /// Creates an interactive-bootstrap helper targeting
    /// `statistical_security_bits` bits of statistical security for its
    /// smudging noise - matches [`super::PartialDecryptor::new`]'s own
    /// shape.
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

    /// Creates this participant's own share `(h0_i, h1_i)` - see this
    /// module's own doc comment for the construction.
    ///
    /// `ciphertext_noise_bound` must be the caller's own worst-case bound on
    /// `ciphertext`'s current decryption noise.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpbfv` protocol call this participant
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
        let c1 = ciphertext
            .inner()
            .inner()
            .value()
            .get(1)
            .ok_or(MultipartyError::MalformedMessage)?;
        ring.check_poly(c1)
            .map_err(|_| MultipartyError::MalformedMessage)?;

        let a = derive_common_ring_element(ring, &self.session, IB_COMMON_A_PURPOSE);
        let mask_values = sample_uniform_mod_t(self.params.plaintext_modulus(), ring.degree(), rng);
        let encoder = BatchEncoder::new(self.params.clone());
        let mask_poly = encoder
            .encode_u64_real(&mask_values)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: mask encode failed"))?
            .inner()
            .inner()
            .value()
            .clone();

        let smudging_std_dev = phantom_lattice::security::smudging_std_dev(
            ciphertext_noise_bound,
            self.statistical_security_bits,
        );
        let e0_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);
        let e1_i = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);

        let c1_s_i = ring
            .mul(c1, local_secret_share.value())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: c1*s_i failed"))?;
        let h0_i = ring
            .add(&c1_s_i, &e0_i)
            .and_then(|acc| ring.sub(&acc, &mask_poly))
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h0_i failed"))?;

        let a_s_i = ring
            .mul(&a, local_secret_share.value())
            .map_err(|_| MultipartyError::InvalidParameters("create_share: a*s_i failed"))?;
        let h1_i = ring
            .sub(&e1_i, &a_s_i)
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
    /// the same as every other real `mpbfv` construction.
    pub fn aggregate_refreshed(
        &self,
        aggregator: &ShareAggregator,
        ciphertext: &Ciphertext,
    ) -> Result<Ciphertext> {
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
        let masked_plaintext = phantom_schemes::bfv::Plaintext::new(
            phantom_schemes::bgv::Plaintext::new(phantom_lattice::rlwe::Plaintext::new(masked_raw)),
        );
        let revealed_values = encoder.decode_u64_real(&masked_plaintext).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_refreshed: decode failed")
        })?;
        let unmasked_poly = encoder
            .encode_u64_real(&revealed_values)
            .map_err(|_| MultipartyError::InvalidParameters("aggregate_refreshed: encode failed"))?
            .inner()
            .inner()
            .value()
            .clone();

        let ct0_new = ring.add(&unmasked_poly, &h1_sum).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_refreshed: unmasked + h1 failed")
        })?;
        let a = derive_common_ring_element(ring, &self.session, IB_COMMON_A_PURPOSE);
        Ok(Ciphertext::new(phantom_schemes::bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(vec![ct0_new, a]),
        )))
    }
}
