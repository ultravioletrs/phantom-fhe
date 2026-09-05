//! Shared, ring-generic collective RNS-hybrid key-switching primitive for
//! GKG/RKG - the real relinearization/rotation-key construction BFV and
//! CKKS both need (BGV's own `mpbgv::gkg`/`rkg` deliberately use a
//! different, classical-gadget-decomposition construction instead, since
//! the RNS-hybrid technique's `mod_down` rounding corrupts BGV's exact
//! `mod t` decode - see `bgv::relinearization`'s own module doc comment).
//! BFV and CKKS already share the *identical* single-party construction
//! (`phantom_lattice::rlwe::KeyGenerator::generate_hybrid_relinearization_key`/
//! `generate_hybrid_galois_key`, built on `keyswitch::generate_key_switch_key`/
//! `key_switch`), so this module derives the collective version once, in
//! terms of `phantom_lattice::rlwe` primitives only (no scheme-specific
//! type anywhere) - `mpbfv`/`mpckks`'s own `gkg.rs`/`rkg.rs` are thin
//! wrappers around it, each supplying their own `RlweParams`/`p_moduli`.
//!
//! This module owns only the *per-participant row arithmetic* - session
//! bookkeeping, anti-replay, wire encoding, and aggregation (summing
//! `Vec<(Poly, Poly)>` and packaging the result into a `KeySwitchKey`) stay
//! in each scheme's own module, matching how `mpbgv::gkg`/`rkg` are
//! themselves structured (this crate doesn't factor multiparty protocol
//! orchestration into a shared engine anywhere else either).
//!
//! # Single-party row shape (see `keyswitch.rs`'s own module doc comment)
//!
//! One row per `Q`-modulus `j` (`j = 0..q_len` - the hybrid construction
//! has no "levels" dimension, unlike BGV's classical one): `b_j =
//! P*hat_Q_j*s_old + e_j - a_j*s_new` (`a_j` fresh uniform, `e_j` plain
//! [`STANDARD_ERROR_STD_DEV`] noise - confirmed from
//! `Encryptor::with_secret_key`'s own algebra, no `t`-scaling anywhere,
//! since neither BFV nor CKKS scales key-generation noise the way BGV
//! does), computed in the extended `QP` ring (`P*hat_Q_j` via
//! [`crt_basis_constant`] applied to the `QP` basis at position `j` - the
//! exact call `generate_key_switch_key` itself makes).
//!
//! # GKG (`s_old = sigma(s) = sum_p(sigma(s_p))`, linear - single round)
//!
//! [`gkg_row_contributions`]: each participant contributes, per row `j`,
//! `b_j^(p) = P*hat_Q_j*sigma(s_p) + e_j^(p) - a_j*s_p` (`a_j` common via
//! `common::derive_common_ring_element`, one label per row - exactly
//! `mpbgv::gkg`'s own pattern, [`crt_basis_constant`] in place of
//! `scale_by_base_power_and_lift`). Summing every participant's own `b_j`
//! (and verifying every share's own `a_j` matches, *not* summing it - the
//! same "shared constant, not a per-participant contribution" bug class
//! `mpbgv::gkg` already found and fixed) reproduces the single-party row
//! for `sigma(s)`/`s`. Each participant's own secret is rebased into `QP`
//! via [`rebase_ternary_secret`] (exact for a ternary value) - the
//! automorphism is applied *before* rebasing, matching
//! `generate_hybrid_galois_key`'s own order.
//!
//! # RKG (`s_old = s^2`, quadratic - needs a two-round protocol)
//!
//! Linear constructions (GKG, and BGV's own CKG/PCKS/PartialDecryptor) let
//! each participant compute their own additive contribution alone; `s^2 =
//! sum_p sum_q(s_p*s_q)` has cross terms `s_p*s_q` (`p != q`) that no
//! single participant can form from their own secret alone, so this needs
//! the same two-round trick `mpbgv::rkg` uses - adapted here to the `QP`
//! ring, with one extra ingredient BGV's own RKG didn't need: a
//! **collective public key over `QP`** ([`qp_ckg_contribution`]/
//! [`aggregate_qp_public_key`] - structurally identical to ordinary CKG,
//! `b_i = e_i - a*s_i_qp`, just over `QP` instead of `Q`; BGV's RKG reused
//! its already-existing *Q*-ring collective key directly, since it never
//! leaves `Q`).
//!
//! With that key in hand, round 1 ([`rkg_round1_row_contributions`]) and
//! round 2 ([`rkg_round2_row_contributions`]) mirror `mpbgv::rkg` exactly,
//! but *per row* `j` (not once), with [`crt_basis_constant`]'s own
//! `P*hat_Q_j` as the per-row public scale applied to the *signal* inside
//! round 1 (`scale_j(s_p)`), never to already-aggregated noise - scaling a
//! finished aggregate by `P*hat_Q_j` afterward would scale its own fresh
//! noise by the same (huge) factor, destroying the key, which is why each
//! row repeats the full two rounds with its own independently-sized fresh
//! noise rather than reusing one pass. Correctness (using the collective
//! `QP` public key's own identity `cpk_b_qp + cpk_a_qp*s_qp = e_pk_total`,
//! the same relation CKG's own construction gives): round 1's aggregate
//! `(H0_j, H1_j)` is a public encryption of `scale_j(s_qp)` under the `QP`
//! collective key that nobody decrypts; round 2's aggregate `(Key0_j,
//! Key1_j)` satisfies `Key0_j + Key1_j*s_qp = scale_j(s_qp^2) + noise` -
//! exactly row `j`'s target, using `s_qp*scale_j(s_qp) = scale_j(s_qp^2)`.
//!
//! Both constructions rest on a separate, numerically-confirmed fact:
//! summing each participant's own *individually rebased* ternary secret
//! into `QP` gives the same result as rebasing the true (non-ternary)
//! collective sum directly - small-integer CRT embedding commutes with
//! addition here, the same principle `phantom_ring::rns::extension::embed_centered_coeffs`
//! already relies on elsewhere in this codebase. Derived and numerically
//! verified (Python, 250 GKG+RKG trials across 1-8 parties, plus 200
//! trials on the rebase-commutes fact) before writing any of this.
//!
//! Ordinary key-generation noise throughout, not smudging - this is DKG,
//! not a reveal-to-an-outsider protocol, matching `mpbgv::gkg`/`rkg`'s own
//! convention exactly.

use phantom_lattice::rlwe::{rebase_ternary_secret, PublicKey, RlweParams, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::reduce::mul_mod;
use phantom_ring::rns::extension::crt_basis_constant;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_ternary};
use phantom_ring::{Degree, Modulus, Poly, Ring, RnsBasis};
use rand_core::{CryptoRng, RngCore};

use super::{derive_common_ring_element, SessionState};
use crate::{MultipartyError, Result};

const QP_CKG_A_PURPOSE: &str = "phantom-fhe/common/hybrid/qp_ckg/a/v1";
const GKG_A_PURPOSE_PREFIX: &str = "phantom-fhe/common/hybrid/gkg/a/v1";

/// Builds the extended `QP` ring's own [`RlweParams`] from the working
/// `Q`-basis params plus the auxiliary `p_moduli` - mirrors
/// `generate_key_switch_key`'s own inline construction, hoisted since every
/// function below needs it identically.
pub fn qp_params(q_params: &RlweParams, p_moduli: &[Modulus]) -> Result<RlweParams> {
    if p_moduli.is_empty() {
        return Err(MultipartyError::InvalidParameters(
            "qp_params: p_moduli must be non-empty",
        ));
    }
    let q_moduli = q_params.ring().moduli();
    let qp_moduli: Vec<Modulus> = q_moduli.iter().chain(p_moduli.iter()).copied().collect();
    let degree = Degree::new(q_params.ring().degree())
        .map_err(|_| MultipartyError::InvalidParameters("qp_params: invalid degree"))?;
    let qp_ring = Ring::new(degree, qp_moduli)
        .map_err(|_| MultipartyError::InvalidParameters("qp_params: invalid QP ring"))?;
    RlweParams::new(qp_ring)
        .map_err(|_| MultipartyError::InvalidParameters("qp_params: invalid QP params"))
}

/// This participant's own contribution to a collective public key over the
/// extended `QP` ring, `b_i = e_i - a*s_i_qp` - see this module's own doc
/// comment for why RKG needs this and GKG doesn't.
pub fn qp_ckg_contribution<R: RngCore + CryptoRng>(
    q_params: &RlweParams,
    p_moduli: &[Modulus],
    session: &SessionState,
    local_secret_share: &SecretKey,
    rng: &mut R,
) -> Result<Poly> {
    let qp_params = qp_params(q_params, p_moduli)?;
    let qp_ring = qp_params.ring();
    let q0 = q_params.ring().moduli()[0];
    let s_p_qp = rebase_ternary_secret(local_secret_share, q0, qp_ring)
        .map_err(|_| MultipartyError::InvalidParameters("qp_ckg_contribution: rebase failed"))?;

    let a = derive_common_ring_element(qp_ring, session, QP_CKG_A_PURPOSE.as_bytes());
    let e_i = sample_discrete_gaussian(qp_ring, rng, STANDARD_ERROR_STD_DEV);
    let a_s_i = qp_ring
        .mul(&a, &s_p_qp)
        .map_err(|_| MultipartyError::InvalidParameters("qp_ckg_contribution: a*s_i failed"))?;
    qp_ring
        .sub(&e_i, &a_s_i)
        .map_err(|_| MultipartyError::InvalidParameters("qp_ckg_contribution: e_i - a*s_i failed"))
}

/// Aggregates every participant's own [`qp_ckg_contribution`] into the real
/// collective public key over `QP`.
pub fn aggregate_qp_public_key(
    q_params: &RlweParams,
    p_moduli: &[Modulus],
    session: &SessionState,
    contributions: &[Poly],
) -> Result<PublicKey> {
    let qp_params = qp_params(q_params, p_moduli)?;
    let qp_ring = qp_params.ring();
    let mut b_sum = qp_ring.zero();
    for b_i in contributions {
        b_sum = qp_ring.add(&b_sum, b_i).map_err(|_| {
            MultipartyError::InvalidParameters("aggregate_qp_public_key: sum failed")
        })?;
    }
    let a = derive_common_ring_element(qp_ring, session, QP_CKG_A_PURPOSE.as_bytes());
    Ok(PublicKey::new(b_sum, a))
}

/// This participant's own GKG row contributions (one per `Q`-modulus) for
/// rotation `element` - see this module's own doc comment for the
/// construction. Returns `(b_j, a_j)` pairs; sum every participant's own
/// `b_j` and verify (not sum) `a_j` to aggregate.
pub fn gkg_row_contributions<R: RngCore + CryptoRng>(
    q_params: &RlweParams,
    p_moduli: &[Modulus],
    session: &SessionState,
    element: usize,
    local_secret_share: &SecretKey,
    rng: &mut R,
) -> Result<Vec<(Poly, Poly)>> {
    let qp_params = qp_params(q_params, p_moduli)?;
    let qp_ring = qp_params.ring();
    let q_moduli = q_params.ring().moduli();
    let q_len = q_moduli.len();
    let qp_moduli = qp_ring.moduli();
    let qp_basis = RnsBasis::new(qp_moduli.to_vec()).map_err(|_| {
        MultipartyError::InvalidParameters("gkg_row_contributions: qp_basis failed")
    })?;

    let sigma_s = q_params
        .ring()
        .apply_automorphism(local_secret_share.value(), element)
        .map_err(|_| {
            MultipartyError::InvalidParameters("gkg_row_contributions: automorphism failed")
        })?;
    let sigma_s_qp = rebase_ternary_secret(&SecretKey::new(sigma_s), q_moduli[0], qp_ring)
        .map_err(|_| {
            MultipartyError::InvalidParameters("gkg_row_contributions: rebase sigma_s failed")
        })?;
    let s_p_qp = rebase_ternary_secret(local_secret_share, q_moduli[0], qp_ring).map_err(|_| {
        MultipartyError::InvalidParameters("gkg_row_contributions: rebase s_p failed")
    })?;

    let mut rows = Vec::with_capacity(q_len);
    for j in 0..q_len {
        let purpose = format!("{GKG_A_PURPOSE_PREFIX}/{element}/{j}");
        let a_j = derive_common_ring_element(qp_ring, session, purpose.as_bytes());
        let scale_j = crt_basis_constant(&qp_basis, j, qp_moduli).map_err(|_| {
            MultipartyError::InvalidParameters("gkg_row_contributions: crt_basis_constant failed")
        })?;
        let scaled_sigma = scale_poly_per_component(qp_ring, &sigma_s_qp, &scale_j)?;
        let e_j = sample_discrete_gaussian(qp_ring, rng, STANDARD_ERROR_STD_DEV);
        let a_s_p = qp_ring.mul(&a_j, &s_p_qp).map_err(|_| {
            MultipartyError::InvalidParameters("gkg_row_contributions: a_j*s_p failed")
        })?;
        let b_j = qp_ring
            .add(&scaled_sigma, &e_j)
            .and_then(|acc| qp_ring.sub(&acc, &a_s_p))
            .map_err(|_| MultipartyError::InvalidParameters("gkg_row_contributions: b_j failed"))?;
        rows.push((b_j, a_j));
    }
    Ok(rows)
}

/// This participant's own RKG round-1 row contributions - see this
/// module's own doc comment for the construction.
pub fn rkg_round1_row_contributions<R: RngCore + CryptoRng>(
    q_params: &RlweParams,
    p_moduli: &[Modulus],
    collective_public_key_qp: &PublicKey,
    local_secret_share: &SecretKey,
    rng: &mut R,
) -> Result<Vec<(Poly, Poly)>> {
    let qp_params = qp_params(q_params, p_moduli)?;
    let qp_ring = qp_params.ring();
    let q_moduli = q_params.ring().moduli();
    let q_len = q_moduli.len();
    let qp_moduli = qp_ring.moduli();
    let qp_basis = RnsBasis::new(qp_moduli.to_vec())
        .map_err(|_| MultipartyError::InvalidParameters("rkg_round1: qp_basis failed"))?;
    let s_p_qp = rebase_ternary_secret(local_secret_share, q_moduli[0], qp_ring)
        .map_err(|_| MultipartyError::InvalidParameters("rkg_round1: rebase failed"))?;
    let cpk_b = &collective_public_key_qp.value()[0];
    let cpk_a = &collective_public_key_qp.value()[1];

    let mut rows = Vec::with_capacity(q_len);
    for j in 0..q_len {
        let scale_j = crt_basis_constant(&qp_basis, j, qp_moduli).map_err(|_| {
            MultipartyError::InvalidParameters("rkg_round1: crt_basis_constant failed")
        })?;
        let scaled_s_p = scale_poly_per_component(qp_ring, &s_p_qp, &scale_j)?;
        let u = sample_ternary(qp_ring, rng);
        let e0 = sample_discrete_gaussian(qp_ring, rng, STANDARD_ERROR_STD_DEV);
        let e1 = sample_discrete_gaussian(qp_ring, rng, STANDARD_ERROR_STD_DEV);

        let h0 = qp_ring
            .mul(cpk_b, &u)
            .and_then(|acc| qp_ring.add(&acc, &e0))
            .and_then(|acc| qp_ring.add(&acc, &scaled_s_p))
            .map_err(|_| MultipartyError::InvalidParameters("rkg_round1: h0 failed"))?;
        let h1 = qp_ring
            .mul(cpk_a, &u)
            .and_then(|acc| qp_ring.add(&acc, &e1))
            .map_err(|_| MultipartyError::InvalidParameters("rkg_round1: h1 failed"))?;
        rows.push((h0, h1));
    }
    Ok(rows)
}

/// This participant's own RKG round-2 row contributions, folding
/// `local_secret_share` into round 1's public aggregate - see this
/// module's own doc comment for the construction.
pub fn rkg_round2_row_contributions<R: RngCore + CryptoRng>(
    q_params: &RlweParams,
    p_moduli: &[Modulus],
    collective_public_key_qp: &PublicKey,
    round1_aggregate: &[(Poly, Poly)],
    local_secret_share: &SecretKey,
    rng: &mut R,
) -> Result<Vec<(Poly, Poly)>> {
    let qp_params = qp_params(q_params, p_moduli)?;
    let qp_ring = qp_params.ring();
    let q_moduli = q_params.ring().moduli();
    let s_p_qp = rebase_ternary_secret(local_secret_share, q_moduli[0], qp_ring)
        .map_err(|_| MultipartyError::InvalidParameters("rkg_round2: rebase failed"))?;
    let cpk_b = &collective_public_key_qp.value()[0];
    let cpk_a = &collective_public_key_qp.value()[1];

    let mut rows = Vec::with_capacity(round1_aggregate.len());
    for (h0, h1) in round1_aggregate {
        let v = sample_ternary(qp_ring, rng);
        let e2 = sample_discrete_gaussian(qp_ring, rng, STANDARD_ERROR_STD_DEV);
        let e3 = sample_discrete_gaussian(qp_ring, rng, STANDARD_ERROR_STD_DEV);

        let h0p = qp_ring
            .mul(&s_p_qp, h0)
            .and_then(|acc| qp_ring.mul(cpk_b, &v).map(|cb_v| (acc, cb_v)))
            .and_then(|(acc, cb_v)| qp_ring.add(&acc, &cb_v))
            .and_then(|acc| qp_ring.add(&acc, &e2))
            .map_err(|_| MultipartyError::InvalidParameters("rkg_round2: h0' failed"))?;
        let h1p = qp_ring
            .mul(&s_p_qp, h1)
            .and_then(|acc| qp_ring.mul(cpk_a, &v).map(|ca_v| (acc, ca_v)))
            .and_then(|(acc, ca_v)| qp_ring.add(&acc, &ca_v))
            .and_then(|acc| qp_ring.add(&acc, &e3))
            .map_err(|_| MultipartyError::InvalidParameters("rkg_round2: h1' failed"))?;
        rows.push((h0p, h1p));
    }
    Ok(rows)
}

/// Scales `poly` by a different constant per RNS component
/// (`scale_constants[j]` for component `j`) - the same operation
/// `keyswitch.rs`'s own private `scale_poly_per_component` performs,
/// duplicated here (small enough not to warrant exposing that one).
fn scale_poly_per_component(ring: &Ring, poly: &Poly, scale_constants: &[u64]) -> Result<Poly> {
    let mut coeffs = vec![vec![0u64; poly.degree()]; poly.moduli_count()];
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let scale = scale_constants[j];
        for (out, &c) in coeffs[j].iter_mut().zip(&poly.coeffs()[j]) {
            *out = mul_mod(c, scale, modulus.value());
        }
    }
    Poly::from_coeffs(coeffs)
        .map_err(|_| MultipartyError::InvalidParameters("scale_poly_per_component: failed"))
}
