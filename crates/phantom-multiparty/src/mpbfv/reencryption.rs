//! BFV re-encryption - real collaborative key-switching (PCKS).

use phantom_lattice::rlwe::{PublicKey, SecretKey};
use phantom_ring::sampling::{sample_smudging_gaussian, sample_ternary};
use phantom_schemes::bfv::{BfvParams, Ciphertext};
use phantom_schemes::bgv;
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_pair, encode_poly_pair};
use crate::common::{ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Re-encryption helper for BFV: real collaborative key-switching (PCKS) -
/// converts a ciphertext under the collective public key
/// (`mpbfv::CollectiveKeyGen`) into a ciphertext under a *different*,
/// ordinary recipient's own public key, without any party (including
/// whoever combines the shares) ever seeing the plaintext, the collective
/// secret, or the recipient's own secret.
///
/// Identical construction to [`super::super::mpbgv::ReEncryptor`] - see
/// that type's own doc comment for the full derivation and citation - minus
/// the `t`-scaling BGV's own noise needs and BFV's own real path doesn't
/// (see [`super::CollectiveKeyGen`]'s own doc comment for why): given
/// ciphertext `(c0, c1)` and recipient public key `(b_r, a_r)`, each
/// participant computes
/// ```text
/// u_i        <- fresh ternary (per participant, per call)
/// e0_i, e1_i <- fresh smudging noise (see [`Self::create_share`]'s own doc
///               comment for why the noise must be sized this way)
/// h0_i = u_i*b_r + e0_i + s_i*c1
/// h1_i = u_i*a_r + e1_i
/// ```
/// combined as `ct_out0 = c0 + sum_i(h0_i)`, `ct_out1 = sum_i(h1_i)` - since
/// BFV's own real public key is `(b_r, a_r) = (-(a_r*s_r+e_r_pk), a_r)`
/// (plain, unscaled noise - `phantom_schemes::bfv::keygen`'s own doc
/// comment), `ct_out0 + ct_out1*s_r = c0 + c1*s + U*(b_r+a_r*s_r) +
/// (e0_total+e1_total*s_r) = c0 + c1*s - U*e_r_pk + (e0_total+e1_total*s_r)`,
/// exactly what decryption under the *collective* secret would have
/// produced, plus ordinary raw noise terms comfortably inside BFV's own
/// `Delta/2` correctness budget (the same budget a normal single-party
/// ciphertext's own noise already has to fit).
///
/// Additive n-of-n, matching [`super::CollectiveKeyGen`]'s own shape: sums
/// *every* collected share (`ShareAggregator::all_shares`, not `aggregate`).
#[derive(Clone, Debug)]
pub struct ReEncryptor {
    params: BfvParams,
    session: SessionState,
    statistical_security_bits: u32,
}

impl ReEncryptor {
    /// Creates a re-encryptor targeting `statistical_security_bits` bits of
    /// statistical security for its smudging noise -
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

    /// Creates this participant's own PCKS share, `(h0_i, h1_i)` - see this
    /// type's own doc comment for the construction.
    ///
    /// `ciphertext_noise_bound` must be the caller's own worst-case bound on
    /// `ciphertext`'s current decryption noise - see
    /// [`super::super::mpbgv::ReEncryptor::create_share`]'s own doc comment
    /// for why `ReEncryptor` can't derive this itself, and
    /// `phantom_schemes::bfv::noise` for BFV's own composable bound
    /// functions to compute it with.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpbfv` protocol call this participant
    /// makes. See [`ReplayGuard`]'s own doc comment.
    // Seven genuinely independent, already individually documented inputs -
    // not artificially bundled into an ad hoc struct just to dodge this
    // lint (see `mpbgv::ReEncryptor::create_share`'s own identical note).
    #[allow(clippy::too_many_arguments)]
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        ciphertext: &Ciphertext,
        ciphertext_noise_bound: u64,
        recipient_public_key: &PublicKey,
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

        let b_r = &recipient_public_key.value()[0];
        let a_r = &recipient_public_key.value()[1];

        let smudging_std_dev = phantom_lattice::security::smudging_std_dev(
            ciphertext_noise_bound,
            self.statistical_security_bits,
        );
        let u_i = sample_ternary(ring, rng);
        let e0_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);
        let e1_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);

        let u_b_r = ring
            .mul(&u_i, b_r)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: u_i*b_r failed"))?;
        let s_i_c1 = ring
            .mul(local_secret_share.value(), c1)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: s_i*c1 failed"))?;
        let h0_i = ring
            .add(&u_b_r, &e0_i)
            .and_then(|acc| ring.add(&acc, &s_i_c1))
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h0_i failed"))?;

        let u_a_r = ring
            .mul(&u_i, a_r)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: u_i*a_r failed"))?;
        let h1_i = ring
            .add(&u_a_r, &e1_i)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h1_i failed"))?;

        Share::new(
            &self.session,
            participant,
            ShareKind::ReEncryption,
            encode_poly_pair(&h0_i, &h1_i),
        )
    }

    /// Aggregates every collected PCKS share into the real re-encrypted
    /// ciphertext `(c0 + sum_i(h0_i), sum_i(h1_i))`, decryptable under the
    /// recipient's own secret - see this type's own doc comment.
    pub fn aggregate_ciphertext(
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
                MultipartyError::InvalidParameters("aggregate_ciphertext: h0 sum failed")
            })?;
            h1_sum = ring.add(&h1_sum, &h1_i).map_err(|_| {
                MultipartyError::InvalidParameters("aggregate_ciphertext: h1 sum failed")
            })?;
        }

        let ct_out0 = ring.add(c0, &h0_sum).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_ciphertext: c0 + h0_sum failed")
        })?;

        Ok(Ciphertext::new(bgv::Ciphertext::new(
            phantom_lattice::rlwe::Ciphertext::new(vec![ct_out0, h1_sum]),
        )))
    }
}
