//! BGV re-encryption - real collaborative key-switching (PCKS).

use phantom_lattice::rlwe::{PublicKey, SecretKey};
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary};
use phantom_schemes::bgv::{BgvParams, Ciphertext};
use rand_core::{CryptoRng, RngCore};

use super::wire::{decode_poly_pair, encode_poly_pair};
use crate::common::{ParticipantId, SessionState, Share, ShareAggregator, ShareKind};
use crate::{MultipartyError, Result};

/// Smudging-noise standard deviation for [`ReEncryptor::create_share`] -
/// deliberately larger than
/// [`phantom_lattice::security::STANDARD_ERROR_STD_DEV`] (ordinary
/// fresh-encryption noise), so a per-party contribution's own precise
/// magnitude isn't trivially distinguishable from any other party's own.
/// **Not** yet a rigorously calibrated statistical-hiding bound - that needs
/// tighter noise tracking than `phantom_lattice::noise`'s own worst-case
/// bounds currently provide (Workstream 7 item 5a's own job, tracked
/// separately) - this is a documented placeholder, generously larger than
/// ordinary noise, not a value proven sufficient for genuine statistical
/// hiding.
const SMUDGING_ERROR_STD_DEV: f64 = 10.0 * phantom_lattice::security::STANDARD_ERROR_STD_DEV;

/// Re-encryption helper for BGV: real collaborative key-switching (PCKS) -
/// converts a ciphertext under the collective public key
/// (`mpbgv::CollectiveKeyGen`) into a ciphertext under a *different*,
/// ordinary recipient's own public key, without any party (including
/// whoever combines the shares) ever seeing the plaintext, the collective
/// secret, or the recipient's own secret.
///
/// Given ciphertext `(c0, c1)` and recipient public key `(b_r, a_r)`, each
/// participant computes their own share from their own already-known local
/// secret `s_i` (the same one [`super::CollectiveKeyGen::create_share`]
/// already uses - never transmitted, only the share below is):
/// ```text
/// u_i          <- fresh ternary (per participant, per call - this is what
///                 makes reusing the recipient's own public a_r safe: every
///                 output ciphertext gets its own fresh randomization, the
///                 same role a normal encryption's own ephemeral u plays)
/// e0_i, e1_i   <- fresh smudging noise (see SMUDGING_ERROR_STD_DEV)
/// h0_i = u_i*b_r + t*e0_i + s_i*c1
/// h1_i = u_i*a_r + t*e1_i
/// ```
/// Combining *every* contributing participant's share (`t` = the plaintext
/// modulus):
/// ```text
/// ct_out0 = c0 + sum_i(h0_i)
/// ct_out1 =      sum_i(h1_i)
/// ```
/// Substituting the recipient's own real public key shape (`b_r =
/// t*e_r_pk - a_r*s_r`, the same `t`-scaled construction
/// `bgv::keygen::BgvKeyGenerator::generate_keypair_real` uses):
/// ```text
/// ct_out0 + ct_out1*s_r = c0 + c1*s + U*(b_r + a_r*s_r) + t*(e0_total + e1_total*s_r)
///                       = c0 + c1*s + t*U*e_r_pk + t*(e0_total + e1_total*s_r)
/// ```
/// (`s = sum_i(s_i)`, `U = sum_i(u_i)`) - every term beyond `c0 + c1*s`
/// (which is exactly what decryption under the *collective* secret would
/// have produced) is `t`-scaled, so it vanishes under decryption's own
/// final `mod t` reduction. Verified numerically (Python, 120 randomized
/// trials across 1-12 participants) before implementing, including
/// confirming the combined `ct_out0` alone (what whoever combines shares
/// actually sees) does not trivially reveal the plaintext.
///
/// This is an additive (n-of-n) construction, matching
/// [`super::CollectiveKeyGen`]'s own shape and this crate's actual target
/// deployment's own default (see that type's own doc comment for why): sums
/// *every* collected share (`ShareAggregator::all_shares`, not `aggregate`,
/// see that method's own doc comment), so a participant going offline
/// blocks re-encryption entirely rather than being tolerated by a threshold
/// subset. Genuine fault-tolerant (t-of-n) re-encryption is a separate,
/// larger, not-yet-attempted piece of work.
#[derive(Clone, Debug)]
pub struct ReEncryptor {
    params: BgvParams,
    session: SessionState,
}

impl ReEncryptor {
    /// Creates a re-encryptor.
    pub const fn new(params: BgvParams, session: SessionState) -> Self {
        Self { params, session }
    }

    /// Creates this participant's own PCKS share, `(h0_i, h1_i)` - see this
    /// type's own doc comment for the construction.
    pub fn create_share<R: RngCore + CryptoRng>(
        &self,
        participant: ParticipantId,
        local_secret_share: &SecretKey,
        ciphertext: &Ciphertext,
        recipient_public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<Share> {
        let ring = self.params.ring();
        let t = self.params.plaintext_modulus();
        let c1 = ciphertext
            .inner()
            .value()
            .get(1)
            .ok_or(MultipartyError::MalformedMessage)?;
        ring.check_poly(c1)
            .map_err(|_| MultipartyError::MalformedMessage)?;

        let b_r = &recipient_public_key.value()[0];
        let a_r = &recipient_public_key.value()[1];

        let u_i = sample_ternary(ring, rng);
        let e0_i = sample_discrete_gaussian(ring, rng, SMUDGING_ERROR_STD_DEV);
        let e1_i = sample_discrete_gaussian(ring, rng, SMUDGING_ERROR_STD_DEV);

        let u_b_r = ring
            .mul(&u_i, b_r)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: u_i*b_r failed"))?;
        let t_e0_i = ring
            .scalar_mul(&e0_i, t)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: t*e0_i failed"))?;
        let s_i_c1 = ring
            .mul(local_secret_share.value(), c1)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: s_i*c1 failed"))?;
        let h0_i = ring
            .add(&u_b_r, &t_e0_i)
            .and_then(|acc| ring.add(&acc, &s_i_c1))
            .map_err(|_| MultipartyError::InvalidParameters("create_share: h0_i failed"))?;

        let u_a_r = ring
            .mul(&u_i, a_r)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: u_i*a_r failed"))?;
        let t_e1_i = ring
            .scalar_mul(&e1_i, t)
            .map_err(|_| MultipartyError::InvalidParameters("create_share: t*e1_i failed"))?;
        let h1_i = ring
            .add(&u_a_r, &t_e1_i)
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

        Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
            vec![ct_out0, h1_sum],
        )))
    }
}
