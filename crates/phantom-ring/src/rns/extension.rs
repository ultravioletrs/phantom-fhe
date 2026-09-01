//! RNS basis extension.

use core::cmp::Ordering;

use crate::bignum::BigUint;
use crate::reduce::{inv_mod, mul_mod};
use crate::{Poly, Result, RingError, RnsBasis};

/// Extends `poly` from `source` basis into `target` basis.
///
/// Reconstructs each coefficient's true integer value via CRT and re-reduces
/// it into every `target` modulus. The reconstruction is carried out with an
/// exact `BigUint`, not `u128`: with realistic multi-modulus bases (e.g.
/// eight or more ~60-bit primes, as in RNS-CKKS/BGV), the product of the
/// source moduli routinely exceeds `2^128`, which would silently overflow a
/// `u128`-based implementation.
///
/// # Algorithm
///
/// Let `q_1, ..., q_k` be the source moduli, `Q = q_1 * ... * q_k`, and for
/// each coefficient let `r_i` be its residue mod `q_i`. Standard CRT
/// reconstruction gives the true value as
///
/// ```text
/// T = ( sum_i (r_i * y_i mod q_i) * M_i )  mod  Q
/// ```
///
/// where `M_i = Q / q_i` and `y_i = M_i^{-1} mod q_i`. Each target residue is
/// then `T mod q_target`.
///
/// This only needs bignum *addition*, *multiply-by-u64*, and *divide-by-u64*
/// - never general bignum/bignum division - because:
/// - `M_i` is computed once via `Q.divmod_u64(q_i)`, since `q_i` divides `Q`
///   exactly (`q_i` is one of `Q`'s own factors).
/// - Each term `(r_i * y_i mod q_i) * M_i` is `< q_i * M_i = Q` (the residue
///   factor is already reduced mod `q_i` before the multiply), so the raw sum
///   over `k` terms is `< k * Q`.
/// - Reducing a value `< k * Q` down to `< Q` therefore takes at most `k - 1`
///   subtractions of `Q` - a bounded loop, not division.
/// - Extracting each target residue is one more divide-by-u64.
pub fn extend_basis(poly: &Poly, source: &RnsBasis, target: &RnsBasis) -> Result<Poly> {
    if poly.moduli_count() != source.moduli().len() {
        return Err(RingError::DimensionMismatch);
    }

    let source_moduli: Vec<u64> = source.moduli().iter().map(|m| m.value()).collect();
    let component_count = source_moduli.len();

    let big_q = source_moduli
        .iter()
        .fold(BigUint::from_u64(1), |acc, &q| acc.mul_u64(q));

    // Per-source-modulus CRT constants, computed once and reused for every
    // coefficient: M_i = Q / q_i (exact - q_i divides Q by construction) and
    // y_i = (M_i mod q_i)^{-1} mod q_i.
    let mut m_values = Vec::with_capacity(component_count);
    let mut y_values = Vec::with_capacity(component_count);
    for &qi in &source_moduli {
        let (m_i, remainder) = big_q.divmod_u64(qi);
        debug_assert_eq!(
            remainder, 0,
            "source modulus must divide the basis product exactly"
        );
        let (_, m_i_mod_qi) = m_i.divmod_u64(qi);
        y_values.push(inv_mod(m_i_mod_qi, qi));
        m_values.push(m_i);
    }

    let degree = poly.degree();
    let mut coeffs = vec![vec![0u64; degree]; target.moduli().len()];

    // `i` indexes two independently-shaped collections at once (a source
    // component's coefficients and every target component's coefficients),
    // so there's no single iterator to zip against.
    #[allow(clippy::needless_range_loop)]
    for i in 0..degree {
        let mut t = BigUint::zero();
        for comp_idx in 0..component_count {
            let qi = source_moduli[comp_idx];
            let residue = poly
                .component(comp_idx)
                .ok_or(RingError::DimensionMismatch)?[i];
            let scaled_residue = mul_mod(residue, y_values[comp_idx], qi);
            t = t.add(&m_values[comp_idx].mul_u64(scaled_residue));
        }
        while t.cmp(&big_q) != Ordering::Less {
            t = t.sub(&big_q);
        }
        for (j, modulus) in target.moduli().iter().enumerate() {
            let (_, residue) = t.divmod_u64(modulus.value());
            coeffs[j][i] = residue;
        }
    }

    Poly::from_coeffs(coeffs)
}

/// Computes `(product(source.moduli()) / source.moduli()[index]) mod t` for
/// each `t` in `targets` - the CRT "`M_i`" basis constant for the modulus at
/// `index` within `source`, reduced into arbitrary target moduli.
///
/// [`extend_basis`] computes this exact same `M_i` internally (there, always
/// called `m_values[comp_idx]`) but only as scratch on the way to a full CRT
/// reconstruction - it never returns `M_i` standalone. RNS hybrid
/// key-switching key generation needs precisely that standalone value: with
/// `source` the *extended* `Q ∪ P` basis and `index` one of the `Q` moduli's
/// position within it, this gives `(QP / q_i) mod p` for every modulus `p`
/// in `QP` - the per-row scaling constant each key-switching key row
/// encrypts a secret times.
pub fn crt_basis_constant(
    source: &RnsBasis,
    index: usize,
    targets: &[crate::Modulus],
) -> Result<Vec<u64>> {
    let source_moduli: Vec<u64> = source.moduli().iter().map(|m| m.value()).collect();
    if index >= source_moduli.len() {
        return Err(RingError::DimensionMismatch);
    }

    let big_q = source_moduli
        .iter()
        .fold(BigUint::from_u64(1), |acc, &q| acc.mul_u64(q));
    let (m_i, remainder) = big_q.divmod_u64(source_moduli[index]);
    debug_assert_eq!(
        remainder, 0,
        "source modulus must divide the basis product exactly"
    );

    Ok(targets
        .iter()
        .map(|t| m_i.divmod_u64(t.value()).1)
        .collect())
}

/// Computes `floor(product(basis.moduli()) / divisor) mod q_j` for every
/// modulus `q_j` in `basis` - a genuine floor division, unlike
/// [`crt_basis_constant`]'s `M_i` (which only ever divides `Q` by one of
/// `Q`'s own factors, so it's always exact). This is BFV's "Delta" scaling
/// factor's own residues (`divisor` = the plaintext modulus `t`, `Delta =
/// floor(Q/t)`, the amount a plaintext message gets scaled by before
/// encryption so its noise has room to grow without overwhelming it) - or
/// any other "big constant reduced into a basis" computation with the same
/// shape.
pub fn floor_divide_residues(basis: &RnsBasis, divisor: u64) -> Vec<u64> {
    let moduli: Vec<u64> = basis.moduli().iter().map(|m| m.value()).collect();
    let big_q = moduli
        .iter()
        .fold(BigUint::from_u64(1), |acc, &q| acc.mul_u64(q));
    let (quotient, _remainder) = big_q.divmod_u64(divisor);
    moduli.iter().map(|&q| quotient.divmod_u64(q).1).collect()
}
