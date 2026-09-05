//! CKKS re-encryption - real collaborative key-switching (PCKS).

use phantom_lattice::rlwe::{PublicKey, SecretKey};
use phantom_ring::rns::rescale::drop_last_modulus;
use phantom_ring::sampling::{sample_smudging_gaussian, sample_ternary};
use phantom_schemes::ckks::{Ciphertext, CkksParams};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_pair, encode_poly_pair};
use crate::common::{ParticipantId, ReplayGuard, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Re-encryption helper for CKKS: real collaborative key-switching (PCKS) -
/// converts a ciphertext under the collective public key
/// (`mpckks::CollectiveKeyGen`) into a ciphertext under a *different*,
/// ordinary recipient's own public key, without any party (including
/// whoever combines the shares) ever seeing the plaintext, the collective
/// secret, or the recipient's own secret.
///
/// Identical construction to [`super::super::mpbfv::ReEncryptor`] - see
/// that type's own doc comment for the full derivation - with two CKKS-
/// specific differences.
///
/// **Level tracking**: a CKKS ciphertext's own ring shrinks as it gets
/// rescaled (`level()`), so this operates over `self.params.at_level(
/// ciphertext.level())`'s own ring rather than assuming the full-level one,
/// truncating `local_secret_share` and the recipient's own public key to
/// match first (the identical technique `ckks::Decryptor::decrypt_real`/
/// `ckks::CkksKeyGenerator::generate_hybrid_relinearization_key_at_level`
/// already use: repeated [`drop_last_modulus`]).
///
/// **Smudging costs decode precision directly, unlike BGV/BFV.** BGV/BFV's
/// exact modular decode strips any noise below the correctness threshold
/// entirely - smudging costs modulus headroom, never precision. CKKS has no
/// such reduction: the decoded value is the raw `(c0+c1*s)/Delta`, so
/// smudging noise shows up directly in the result, scaled by
/// `degree/Delta` (see `ckks::noise`'s own module doc comment for the
/// exact expansion). Since `smudging_std_dev` (recommended 40-bit target)
/// comes out to a *fixed* magnitude independent of scale (it recovers
/// `fresh_public_key_noise_bound`, then multiplies by `2^20`), the scale
/// must be comfortably larger than that fixed floor for a useful result -
/// confirmed directly while testing: a 30-bit scale left decode errors of
/// order 1-10 (completely swamping values of the same magnitude), while a
/// 45-bit scale (`phase16_mpckks.rs`'s own `real_params()`) leaves ~17 bits
/// of margin. A real deployment needs to size its own scale with this
/// tradeoff in mind, not just for the usual multiplicative-depth reasons.
///
/// ```text
/// u_i        <- fresh ternary (per participant, per call)
/// e0_i, e1_i <- fresh smudging noise (see [`Self::create_share`]'s own doc
///               comment for why the noise must be sized this way)
/// h0_i = u_i*b_r + e0_i + s_i*c1
/// h1_i = u_i*a_r + e1_i
/// ```
/// combined as `ct_out0 = c0 + sum_i(h0_i)`, `ct_out1 = sum_i(h1_i)`,
/// carrying the input ciphertext's own `scale`/`level`/`degree` through
/// unchanged and its `precision` through as a conservative (optimistic)
/// estimate - re-encryption doesn't change what plaintext value the
/// ciphertext represents, only which secret decrypts it, and this doesn't
/// compute a tighter post-smudging precision estimate any more than
/// BGV/BFV's own multiparty ops do for their own noise growth.
///
/// Additive n-of-n, matching [`super::CollectiveKeyGen`]'s own shape: sums
/// *every* collected share (`ShareAggregator::all_shares`, not `aggregate`).
#[derive(Clone, Debug)]
pub struct ReEncryptor {
    params: CkksParams,
    session: SessionState,
    statistical_security_bits: u32,
}

impl ReEncryptor {
    /// Creates a re-encryptor targeting `statistical_security_bits` bits of
    /// statistical security for its smudging noise -
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

    /// Creates this participant's own PCKS share, `(h0_i, h1_i)` - see this
    /// type's own doc comment for the construction.
    ///
    /// Unlike [`super::super::mpbgv::ReEncryptor`]/[`super::super::mpbfv::ReEncryptor`],
    /// there is no `ciphertext_noise_bound` parameter: CKKS's own
    /// `Ciphertext` already tracks a [`phantom_schemes::ckks::Precision`]
    /// estimate (unlike BGV/BFV, which have no per-ciphertext noise field
    /// at all - see `CkksContext::fresh_precision_bits`'s own doc comment),
    /// so the bound is derived internally from `ciphertext.precision()` via
    /// `ckks::noise::noise_bound_from_precision`.
    ///
    /// `replay_guard` must be this participant's own [`ReplayGuard`],
    /// reused across every real `mpckks` protocol call this participant
    /// makes.
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        ciphertext: &Ciphertext,
        recipient_public_key: &PublicKey,
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

        let mut b_r = recipient_public_key.value()[0].clone();
        let mut a_r = recipient_public_key.value()[1].clone();
        while b_r.moduli_count() > target_moduli {
            b_r = drop_last_modulus(&b_r)
                .map_err(|_| MultipartyError::InvalidParameters("create_share: b_r drop failed"))?;
        }
        while a_r.moduli_count() > target_moduli {
            a_r = drop_last_modulus(&a_r)
                .map_err(|_| MultipartyError::InvalidParameters("create_share: a_r drop failed"))?;
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
        let u_i = sample_ternary(ring, rng);
        let e0_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);
        let e1_i = sample_smudging_gaussian(ring, rng, smudging_std_dev);

        let u_b_r = ring
            .mul(&u_i, &b_r)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: u_i*b_r failed"))?;
        let s_i_c1 = ring
            .mul(&sk_value, c1)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: s_i*c1 failed"))?;
        let h0_i = ring
            .add(&u_b_r, &e0_i)
            .and_then(|acc| ring.add(&acc, &s_i_c1))
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h0_i failed"))?;

        let u_a_r = ring
            .mul(&u_i, &a_r)
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
        let level_params = self
            .params
            .at_level(ciphertext.level())
            .map_err(|_| MultipartyError::MalformedMessage)?;
        let ring = level_params.ring();

        let poly_ct = ciphertext.poly().ok_or(MultipartyError::InvalidParameters(
            "aggregate_ciphertext: ciphertext has no real ring representation",
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
                MultipartyError::InvalidParameters("aggregate_ciphertext: h0 sum failed")
            })?;
            h1_sum = ring.add(&h1_sum, &h1_i).map_err(|_| {
                MultipartyError::InvalidParameters("aggregate_ciphertext: h1 sum failed")
            })?;
        }

        let ct_out0 = ring.add(c0, &h0_sum).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_ciphertext: c0 + h0_sum failed")
        })?;

        Ok(Ciphertext::new_real(
            phantom_lattice::rlwe::Ciphertext::new(vec![ct_out0, h1_sum]),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }
}
