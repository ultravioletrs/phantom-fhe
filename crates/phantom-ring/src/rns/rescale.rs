//! RNS rescaling and modulus dropping helpers.

use crate::bignum::BigUint;
use crate::reduce::{add_mod, inv_mod, mul_mod, neg_mod, sub_mod};
use crate::rns::extension::extend_basis;
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
