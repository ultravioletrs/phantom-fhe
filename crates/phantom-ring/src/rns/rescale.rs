//! RNS rescaling and modulus dropping helpers.

use core::cmp::Ordering;

use crate::bignum::BigUint;
use crate::reduce::{add_mod, inv_mod, mul_mod, neg_mod, sub_mod};
use crate::rns::extension::{extend_basis, reconstruct_true_values};
use crate::{Modulus, Poly, Result, RingError, RnsBasis};

/// Drops the last RNS component.
pub fn drop_last_modulus(poly: &Poly) -> Result<Poly> {
    if poly.moduli_count() <= 1 {
        return Err(RingError::DimensionMismatch);
    }
    let mut coeffs = poly.coeffs().to_vec();
    coeffs.pop();
    Poly::from_coeffs(coeffs)
}

/// "ModDown": divides `poly` (represented in the extended basis `q_basis ∪
/// p_basis`, with `poly`'s RNS components ordered `[q_basis components...,
/// p_basis components...]`) by `p_basis`'s modulus product, reducing the
/// result back into `q_basis` alone.
///
/// The standard RNS division-with-rounding operation hybrid key-switching
/// needs to bring a ciphertext computed in an extended `QP` basis back down
/// to `Q`, dividing out the noise contribution the extended computation
/// picked up along with it (the same "grow noise in a bigger modulus, then
/// divide it back down" trick CKKS rescaling uses).
///
/// # Algorithm
///
/// For each coefficient's true value `X` (known only through its residues):
/// `X = (X mod P) + P · floor(X/P)`, so
///
/// ```text
/// floor(X/P) mod q_i  =  (X_i - (X mod P)_i) · P⁻¹  mod q_i
/// ```
///
/// where `X_i = X mod q_i` is `poly`'s own `q_i` component (already
/// present, no computation needed) and `(X mod P)_i = (X mod P) mod q_i` is
/// computed via [`extend_basis`] from `p_basis` into `q_basis` (reusing the
/// exact same CRT-reconstruction machinery, applied to just `poly`'s
/// `p_basis` components). This computes an exact `floor`, not a
/// probabilistically-rounded division - the standard choice for
/// key-switching specifically (as opposed to CKKS's own rescale, where a
/// rounding correction term is more commonly included); the resulting
/// off-by-at-most-one is negligible against key-switching's other noise
/// terms.
pub fn mod_down(poly: &Poly, q_basis: &RnsBasis, p_basis: &RnsBasis) -> Result<Poly> {
    let q_len = q_basis.moduli().len();
    let p_len = p_basis.moduli().len();
    if poly.moduli_count() != q_len + p_len {
        return Err(RingError::DimensionMismatch);
    }

    let p_part = Poly::from_coeffs(poly.coeffs()[q_len..].to_vec())?;
    let p_mod_q = extend_basis(&p_part, p_basis, q_basis)?;

    let big_p = p_basis
        .moduli()
        .iter()
        .fold(BigUint::from_u64(1), |acc, m| acc.mul_u64(m.value()));

    let degree = poly.degree();
    let mut out_coeffs = vec![vec![0u64; degree]; q_len];
    for (j, q_modulus) in q_basis.moduli().iter().enumerate() {
        let q = q_modulus.value();
        let p_mod_qj = big_p.divmod_u64(q).1;
        let p_inv = inv_mod(p_mod_qj, q);
        // `i` indexes two independently-shaped collections at once (`poly`'s
        // own `q_i` component and `p_mod_q`'s), so there's no single
        // iterator to zip against.
        #[allow(clippy::needless_range_loop)]
        for i in 0..degree {
            let x_i = poly.coeffs()[j][i];
            let p_mod_q_i = p_mod_q.coeffs()[j][i];
            let diff = sub_mod(x_i, p_mod_q_i, q);
            out_coeffs[j][i] = mul_mod(diff, p_inv, q);
        }
    }

    Poly::from_coeffs(out_coeffs)
}

/// BGV/BFV-style exact modulus switching: drops `q_basis`'s *last* modulus
/// `q_L`, producing a representation congruent to the original true value
/// mod `plaintext_modulus` (`t`) and as close as possible to `value / q_L`.
/// This is the standard technique that shrinks a ciphertext's noise
/// proportionally to `q_L` while leaving the plaintext message it decrypts
/// to unchanged. Unlike [`drop_last_modulus`] (a pure truncation that
/// leaves the *true value* completely unchanged, no rescaling at all) or
/// [`mod_down`] (an exact floor division with no congruence requirement),
/// this both rescales *and* preserves congruence mod `t`. `plaintext_modulus`
/// must be prime and coprime to every modulus in `q_basis` (the same
/// primality assumption [`crate::reduce::inv_mod`] already relies on
/// throughout this crate).
///
/// # Derivation
///
/// For a coefficient's true value `X`, we want `X'` with `X' ≡ X (mod t)`
/// and `X'` the closest such integer to `X / q_L`. Writing `X' = (X +
/// correction) / q_L` for some `correction`, exact divisibility needs
/// `correction ≡ -X (mod q_L)`; multiplying `X' ≡ X (mod t)` by `q_L`
/// (`q_L` is invertible mod `t`) gives `q_L*X' ≡ q_L*X (mod t)`, and since
/// `q_L*X' = X + correction`, this rearranges to `correction ≡ X*(q_L - 1)
/// (mod t)`. By CRT (`gcd(q_L, t) = 1`), a unique `correction mod (q_L *
/// t)` satisfies both congruences - small enough to compute as a concrete
/// integer directly from `X`'s own `q_L` residue (already present in
/// `poly`) and its `t` residue (via [`extend_basis`] into a single-modulus
/// `{t}` target), then reduce mod each remaining `q_i` and combine with
/// that component's own residue. Verified numerically (Python, 200
/// randomized trials, both against a true-value construction and
/// independently via this exact residue-only construction) before
/// implementing.
pub fn modulus_switch_down(poly: &Poly, q_basis: &RnsBasis, t: Modulus) -> Result<Poly> {
    let moduli = q_basis.moduli();
    let len = moduli.len();
    if len <= 1 || poly.moduli_count() != len {
        return Err(RingError::DimensionMismatch);
    }
    let q_last = moduli[len - 1].value();
    let t_value = t.value();

    let t_basis = RnsBasis::new(vec![t])?;
    let c_t_poly = extend_basis(poly, q_basis, &t_basis)?;

    let inv_qlast_mod_t = inv_mod(q_last % t_value, t_value);
    let qlast_minus_one_mod_t = (q_last - 1) % t_value;

    let degree = poly.degree();
    let mut out_coeffs = vec![vec![0u64; degree]; len - 1];

    // `i` indexes two independently-shaped collections at once (`poly`'s
    // own last component and `c_t_poly`'s single component), so there's no
    // single iterator to zip against.
    #[allow(clippy::needless_range_loop)]
    for i in 0..degree {
        let c_qlast = poly.coeffs()[len - 1][i];
        let c_t = c_t_poly.coeffs()[0][i];

        let a1 = neg_mod(c_qlast, q_last);
        let target_t = mul_mod(c_t, qlast_minus_one_mod_t, t_value);
        let k = mul_mod(
            sub_mod(target_t, a1 % t_value, t_value),
            inv_qlast_mod_t,
            t_value,
        );
        let correction: u128 = u128::from(a1) + u128::from(q_last) * u128::from(k);

        // `j` indexes `out_coeffs`, a different-length collection than
        // `moduli`/`poly.coeffs()` (missing the just-dropped last entry),
        // so there's no single iterator to zip against.
        #[allow(clippy::needless_range_loop)]
        for j in 0..len - 1 {
            let qj = moduli[j].value();
            let correction_qj = (correction % u128::from(qj)) as u64;
            let c_qj = poly.coeffs()[j][i];
            let inv_qlast_mod_qj = inv_mod(q_last % qj, qj);
            out_coeffs[j][i] = mul_mod(add_mod(c_qj, correction_qj, qj), inv_qlast_mod_qj, qj);
        }
    }

    Poly::from_coeffs(out_coeffs)
}

/// BFV multiplication's rescale-and-round step: given `poly` represented in
/// an extended `q_basis ∪ p_basis` basis (components ordered `[q_basis...,
/// p_basis...]`), reconstructs each coefficient's true signed value,
/// computes `round(true_value * t / Q)` (`Q` = `q_basis`'s own modulus
/// product), and reduces the (small again, comparable in size to `Q`)
/// result back into `q_basis`'s own moduli.
///
/// # Why an extended basis is required
///
/// A raw BFV ciphertext-ciphertext tensor product's true coefficient
/// magnitude can reach roughly `degree * (Q/2)^2` - far larger than `Q`
/// itself (`Q` alone has no room to represent it without wraparound, the
/// same reason [`extend_basis`]/[`mod_down`] exist for key-switching, just
/// at a much larger scale here since the values involved are *squared*).
/// `p_basis` must be chosen large enough that `q_basis ∪ p_basis`'s full
/// product comfortably exceeds that bound (with margin for centering) -
/// callers are responsible for that; this function only performs the
/// reconstruction/rescale once given a basis already big enough.
///
/// # Algorithm
///
/// Reconstructs each coefficient's true value via CRT (`reconstruct_true_values`,
/// shared with [`extend_basis`]), centers it into `(-QP/2, QP/2]` (via
/// `2*value` vs `QP` - avoids needing a "divide `BigUint` by 2" primitive),
/// then computes `round(|centered| * t / Q)` using `BigUint`'s general
/// `divmod` (general bignum/bignum division - `Q` doesn't fit in a `u64` for a
/// multi-modulus ring, unlike every other divisor this crate's RNS
/// primitives use) with round-half-up (compare `2*remainder` against `Q`),
/// reapplies `centered`'s sign, then reduces the result mod each of
/// `q_basis`'s own moduli. Verified numerically (Python, first against true
/// unbounded-integer arithmetic with no modular reduction at all, then
/// again against an RNS-mechanized simulation using actual CRT
/// reconstruction from residues - both cross-checked against real BFV
/// encrypt/multiply/decrypt round trips, 30 randomized trials each) before
/// implementing.
pub fn rescale_and_round(
    poly: &Poly,
    q_basis: &RnsBasis,
    p_basis: &RnsBasis,
    t: Modulus,
) -> Result<Poly> {
    let q_len = q_basis.moduli().len();
    let p_len = p_basis.moduli().len();
    if poly.moduli_count() != q_len + p_len {
        return Err(RingError::DimensionMismatch);
    }

    let qp_moduli: Vec<Modulus> = q_basis
        .moduli()
        .iter()
        .chain(p_basis.moduli().iter())
        .copied()
        .collect();
    let qp_basis = RnsBasis::new(qp_moduli)?;
    let (big_qp, values) = reconstruct_true_values(poly, &qp_basis)?;

    let big_q = q_basis
        .moduli()
        .iter()
        .fold(BigUint::from_u64(1), |acc, m| acc.mul_u64(m.value()));
    let t_value = t.value();

    let degree = poly.degree();
    let mut out_coeffs = vec![vec![0u64; degree]; q_len];

    for (i, value) in values.iter().enumerate() {
        // Center into (-QP/2, QP/2]: negative iff 2*value > QP.
        let doubled = value.mul_u64(2);
        let negative = doubled.cmp(&big_qp) == Ordering::Greater;
        let magnitude = if negative {
            big_qp.sub(value)
        } else {
            value.clone()
        };

        let scaled = magnitude.mul_u64(t_value);
        let (quotient, remainder) = scaled.divmod(&big_q);
        let rounded = if remainder.mul_u64(2).cmp(&big_q) != Ordering::Less {
            quotient.add(&BigUint::from_u64(1))
        } else {
            quotient
        };

        for (j, modulus) in q_basis.moduli().iter().enumerate() {
            let qj = modulus.value();
            let (_, residue) = rounded.divmod_u64(qj);
            out_coeffs[j][i] = if negative {
                neg_mod(residue, qj)
            } else {
                residue
            };
        }
    }

    Poly::from_coeffs(out_coeffs)
}

/// Undoes `Delta`-style scaling directly to a `mod t` result: reconstructs
/// each coefficient's true signed value across `basis`'s full product `Q`
/// (via CRT, same as [`rescale_and_round`]), computes `round(|value| * t /
/// Q)`, reapplies `value`'s sign, and reduces mod `t`.
///
/// Unlike [`rescale_and_round`], there is no auxiliary basis to extend into
/// first: `poly` here is a freshly decrypted, already-in-`basis` ciphertext
/// coefficient (e.g. BFV's `Delta*m + noise (mod Q)`), not an unreduced
/// tensor product that needs extra headroom to reconstruct safely - so
/// `basis` alone is enough, and the result is already small enough
/// (comparable to `t`) to return directly rather than re-expressing across
/// `basis`'s own moduli the way `rescale_and_round` must.
///
/// This is what real (non-transparent, multi-`Q`-modulus) BFV/CKKS decoding
/// needs and previously didn't have: reading only `basis`'s first modulus
/// (as if it were the whole `Q`) is correct only when `Q` happens to be a
/// single modulus, or when the scaled value is already smaller than any
/// single modulus (true for BGV's `m + t*e`, false for BFV's `Delta*m +
/// noise`, which is comparable in size to the *whole* `Q` by construction).
/// That gap was a real, previously-undiscovered decode bug for
/// multi-modulus `Q`, found while building a production-scale
/// (multi-`Q`-modulus) parameter preset that no existing test had ever
/// exercised.
pub fn decode_scaled_value(poly: &Poly, basis: &RnsBasis, t: Modulus) -> Result<Vec<u64>> {
    if poly.moduli_count() != basis.moduli().len() {
        return Err(RingError::DimensionMismatch);
    }

    let (big_q, values) = reconstruct_true_values(poly, basis)?;
    let t_value = t.value();

    let mut out = Vec::with_capacity(values.len());
    for value in &values {
        // Center into (-Q/2, Q/2]: negative iff 2*value > Q.
        let doubled = value.mul_u64(2);
        let negative = doubled.cmp(&big_q) == Ordering::Greater;
        let magnitude = if negative {
            big_q.sub(value)
        } else {
            value.clone()
        };

        let scaled = magnitude.mul_u64(t_value);
        let (quotient, remainder) = scaled.divmod(&big_q);
        let rounded = if remainder.mul_u64(2).cmp(&big_q) != Ordering::Less {
            quotient.add(&BigUint::from_u64(1))
        } else {
            quotient
        };

        let (_, residue) = rounded.divmod_u64(t_value);
        out.push(if negative {
            neg_mod(residue, t_value)
        } else {
            residue
        });
    }
    Ok(out)
}
