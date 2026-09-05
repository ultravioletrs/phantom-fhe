//! RNS hybrid key-switching (Workstream 4 item 3).
//!
//! The standard modern (RNS-CKKS-era) technique: gadget-decompose the input
//! ciphertext's `c1` component *per RNS modulus* (rather than by powers of a
//! small base, as classical gadget decomposition does), apply each digit
//! against key-switching material generated in an *extended* auxiliary-
//! modulus basis `QP = Q ∪ P`, then "mod down" (divide by `P`, with
//! rounding) back to the working modulus `Q`. Growing the intermediate
//! computation into the bigger `QP` modulus and then dividing the result
//! back down by `P` is what keeps the key-switching key's own encryption
//! noise from blowing up the way it would if the digits (each comparable in
//! size to a whole RNS modulus, unlike classical gadget digits) were
//! applied directly in `Q`.
//!
//! # Algorithm
//!
//! Let `Q = q_1 * ... * q_L` (the working basis) and `P = p_1 * ... * p_k`
//! (the auxiliary basis), `QP = Q * P`. To switch a ciphertext `(c0, c1)`
//! encrypting `mu` under `s_old` (`c0 + c1*s_old = mu + e`) to one
//! encrypting the same `mu` under `s_new`:
//!
//! **Key generation** ([`generate_key_switch_key`]): for each `j = 1..L`,
//! sample a fresh RLWE-of-zero `(b_j, a_j)` under `s_new` *in the `QP`
//! ring*, then add `P * hat_Q_j * s_old` into `b_j`, where `hat_Q_j = Q /
//! q_j`. The extra factor of `P` here is what makes ModDown correctly
//! cancel it out at the end - encrypting `hat_Q_j * s_old` without it (an
//! easy mistake, initially made and caught while deriving this - see the
//! commit introducing this module) leaves an uncancelled `k * Q * s_old`
//! term after reconstruction, which does not vanish mod `QP` and corrupts
//! the result.
//!
//! **Key switch** ([`key_switch`]): for each `j`, compute digit `d_j = (c1
//! mod q_j) * y_j mod q_j` (`y_j = hat_Q_j⁻¹ mod q_j`), lift `d_j` to the
//! full `QP` basis (via [`extend_basis`] from the single-modulus source
//! basis `{q_j}`), and accumulate `sum_j d_j * (b_j, a_j)` over `QP`. Since
//! `sum_j d_j * hat_Q_j ≡ c1 (mod Q)` (the CRT reconstruction identity),
//! this accumulator equals `P * c1 * s_old + noise` (mod `QP`) - and
//! [`mod_down`] (dividing by `P`, back into `Q`) recovers `c1 * s_old +
//! (shrunk noise)`, which added to `c0` gives a ciphertext encrypting `mu`
//! under `s_new`.
//!
//! Verified by hand-deriving the algorithm and checking it numerically
//! (Python, arbitrary-precision integers, 200+ randomized trials) before
//! writing any of this - see `tests/key_switch.rs` for the Rust-level
//! regression coverage.

use rand_core::{CryptoRng, RngCore};

use phantom_ring::reduce::{inv_mod, mul_mod};
use phantom_ring::rns::extension::{crt_basis_constant, extend_basis};
use phantom_ring::rns::rescale::mod_down;
use phantom_ring::{Degree, Modulus, Poly, Result as RingResult, Ring, RnsBasis};

use crate::rlwe::{Ciphertext, Encryptor, Plaintext, RlweParams, SecretKey};
use crate::{LatticeError, Result};

/// Placeholder key-switch operation that preserves decryptability without
/// changing the underlying secret - kept for callers (e.g. relinearization,
/// Workstream 4 item 4, not yet built on the real primitive below) that
/// don't yet supply real key-switching material.
pub fn key_switch_identity(ct: &Ciphertext) -> Result<Ciphertext> {
    Ok(ct.clone())
}

/// A real RNS hybrid key-switching key: one row per `Q`-modulus, each row a
/// real RLWE ciphertext over the extended `QP` ring. See the module doc
/// comment for the algorithm.
#[derive(Clone, Debug)]
pub struct KeySwitchKey {
    qp_params: RlweParams,
    rows: Vec<Ciphertext>,
}

impl KeySwitchKey {
    /// Returns the extended `QP`-basis parameters this key's rows live in.
    pub const fn qp_params(&self) -> &RlweParams {
        &self.qp_params
    }

    /// Builds a key-switching key directly from already-computed rows,
    /// bypassing [`generate_key_switch_key`] (which needs `s_old` fully
    /// known - unusable when the rows are the collectively-combined output
    /// of a multiparty protocol that never assembles `s_old` anywhere).
    /// `rows.len()` must equal `qp_params.ring()`'s own moduli count minus
    /// `p_moduli`'s own count (i.e. `q_len`) for [`key_switch`] to accept
    /// the result - not checked here, since this constructor doesn't know
    /// where the `Q`/`P` split falls within `qp_params`'s own ring.
    pub const fn from_rows(qp_params: RlweParams, rows: Vec<Ciphertext>) -> Self {
        Self { qp_params, rows }
    }
}

/// Generates a key-switching key from `s_old` to `s_new`.
///
/// `s_old` must already be represented in the extended `QP` ring (`Q`'s own
/// moduli followed by `p_moduli`, same degree as `q_params`'s ring) - this
/// function does not lift it there itself, since how to do that correctly
/// depends on what `s_old` *is* (e.g. relinearization's `s^2` needs a
/// genuine centered CRT lift from `Q`, not just a coefficient copy - a
/// caller-specific concern deliberately kept out of this general primitive).
///
/// `s_new` must be ternary (the [`crate::security::recommended_secret_distribution`]
/// default) - its `Q`-basis representation is re-derived directly in the
/// `QP` ring from each coefficient's true `{-1, 0, 1}` value (not lifted via
/// CRT reconstruction, unlike `s_old`), which only works because ternary
/// values are simple enough to read off directly. A non-ternary `s_new`
/// (e.g. `SecretDistribution::Gaussian`) is rejected.
pub fn generate_key_switch_key<R>(
    q_params: &RlweParams,
    p_moduli: &[Modulus],
    s_old: &Poly,
    s_new: &SecretKey,
    rng: &mut R,
) -> Result<KeySwitchKey>
where
    R: RngCore + CryptoRng,
{
    if p_moduli.is_empty() {
        return Err(LatticeError::InvalidParameters(
            "p_moduli must be non-empty",
        ));
    }
    let q_moduli = q_params.ring().moduli();
    let q_len = q_moduli.len();
    let qp_moduli: Vec<Modulus> = q_moduli.iter().chain(p_moduli.iter()).copied().collect();
    let degree = Degree::new(q_params.ring().degree())?;
    let qp_ring = Ring::new(degree, qp_moduli.clone())?;
    let qp_params = RlweParams::new(qp_ring)?;
    qp_params.ring().check_poly(s_old)?;

    let s_new_qp = rebase_ternary_secret(s_new, q_moduli[0], qp_params.ring())?;
    let encryptor = Encryptor::with_secret_key(qp_params.clone(), SecretKey::new(s_new_qp));

    let qp_basis = RnsBasis::new(qp_moduli.clone())?;

    let mut rows = Vec::with_capacity(q_len);
    for j in 0..q_len {
        // P * hat_Q_j mod p, for every p in QP - i.e. QP/q_j mod p, which is
        // exactly crt_basis_constant applied to the *extended* basis QP at
        // q_j's own position within it (see the module doc comment for why
        // this factor of P belongs here).
        let scale_constants = crt_basis_constant(&qp_basis, j, &qp_moduli)?;
        let scaled_s_old = scale_poly_per_component(qp_params.ring(), s_old, &scale_constants)?;

        let zero = Plaintext::new(qp_params.ring().zero());
        let z = encryptor.encrypt(&zero, rng)?;
        let b_j = qp_params.ring().add(&z.value()[0], &scaled_s_old)?;
        rows.push(Ciphertext::new(vec![b_j, z.value()[1].clone()]));
    }

    Ok(KeySwitchKey { qp_params, rows })
}

/// Switches `ct` (encrypting some `mu` under the secret `generate_key_switch_key`
/// was given as `s_old`) to a ciphertext encrypting the same `mu` under
/// `ksk`'s `s_new`, over `q_params`'s ring. See the module doc comment for
/// the algorithm.
pub fn key_switch(
    ct: &Ciphertext,
    ksk: &KeySwitchKey,
    q_params: &RlweParams,
) -> Result<Ciphertext> {
    q_params.ring().check_poly(&ct.value()[0])?;
    q_params.ring().check_poly(&ct.value()[1])?;

    let q_moduli = q_params.ring().moduli();
    let q_len = q_moduli.len();
    let qp_ring = ksk.qp_params.ring();
    if ksk.rows.len() != q_len {
        return Err(LatticeError::DimensionMismatch);
    }
    let p_moduli = &qp_ring.moduli()[q_len..];
    if p_moduli.is_empty() {
        return Err(LatticeError::DimensionMismatch);
    }

    let q_basis = RnsBasis::new(q_moduli.to_vec())?;
    let p_basis = RnsBasis::new(p_moduli.to_vec())?;
    let qp_basis = RnsBasis::new(qp_ring.moduli().to_vec())?;

    let c1 = &ct.value()[1];
    let mut acc_b = qp_ring.zero();
    let mut acc_a = qp_ring.zero();

    // `j` indexes several independently-shaped collections at once
    // (`q_moduli`, `c1`'s own components, and `ksk.rows`), so there's no
    // single iterator to zip against.
    #[allow(clippy::needless_range_loop)]
    for j in 0..q_len {
        let qj = q_moduli[j].value();
        let single_q_basis = RnsBasis::new(vec![q_moduli[j]])?;
        let hat_qj_mod_qj = crt_basis_constant(&q_basis, j, &[q_moduli[j]])?[0];
        let y_j = inv_mod(hat_qj_mod_qj, qj);

        let d_j_coeffs: Vec<u64> = c1.coeffs()[j]
            .iter()
            .map(|&r| mul_mod(r, y_j, qj))
            .collect();
        let d_j_source = Poly::from_coeffs(vec![d_j_coeffs])?;
        let d_j_lifted = extend_basis(&d_j_source, &single_q_basis, &qp_basis)?;

        let row = &ksk.rows[j];
        acc_b = qp_ring.add(&acc_b, &qp_ring.mul(&d_j_lifted, &row.value()[0])?)?;
        acc_a = qp_ring.add(&acc_a, &qp_ring.mul(&d_j_lifted, &row.value()[1])?)?;
    }

    let a_down = mod_down(&acc_b, &q_basis, &p_basis)?;
    let bc_down = mod_down(&acc_a, &q_basis, &p_basis)?;

    let c0_final = q_params.ring().add(&ct.value()[0], &a_down)?;
    Ok(Ciphertext::new(vec![c0_final, bc_down]))
}

/// Scales `poly` by a different constant per RNS component
/// (`scale_constants[j]` for component `j`), each already reduced modulo
/// that component's own modulus.
fn scale_poly_per_component(ring: &Ring, poly: &Poly, scale_constants: &[u64]) -> RingResult<Poly> {
    let mut coeffs = vec![vec![0u64; poly.degree()]; poly.moduli_count()];
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let scale = scale_constants[j];
        for (out, &c) in coeffs[j].iter_mut().zip(&poly.coeffs()[j]) {
            *out = mul_mod(c, scale, modulus.value());
        }
    }
    Poly::from_coeffs(coeffs)
}

/// Re-derives a ternary secret key's true `{-1, 0, 1}` coefficient values
/// (read from its first `Q`-basis component, `source_modulus`) directly in
/// `target_ring`'s own moduli - not a CRT lift, since ternary values are
/// simple enough to read off and re-express directly. Errors if any
/// coefficient isn't exactly `0`, `1`, or `source_modulus - 1` (i.e. the key
/// wasn't actually ternary).
///
/// `pub` (not just used internally for `s_new`) because any caller that
/// wants to key-switch *between* two ternary secrets - the common case
/// this module's own tests use, distinct from relinearization's `s^2`,
/// which needs a genuine CRT lift instead - needs the same operation to
/// prepare `s_old` for [`generate_key_switch_key`].
pub fn rebase_ternary_secret(
    sk: &SecretKey,
    source_modulus: Modulus,
    target_ring: &Ring,
) -> Result<Poly> {
    let q0 = source_modulus.value();
    let source_component = sk
        .value()
        .component(0)
        .ok_or(LatticeError::DimensionMismatch)?;
    let degree = source_component.len();

    let mut coeffs = vec![vec![0u64; degree]; target_ring.moduli().len()];
    for (j, modulus) in target_ring.moduli().iter().enumerate() {
        let q = modulus.value();
        for (i, &v) in source_component.iter().enumerate() {
            coeffs[j][i] = if v == 0 {
                0
            } else if v == 1 {
                1
            } else if v == q0 - 1 {
                q - 1
            } else {
                return Err(LatticeError::InvalidParameters(
                    "s_new must be ternary to rebase into the extended QP ring",
                ));
            };
        }
    }
    Ok(Poly::from_coeffs(coeffs)?)
}
