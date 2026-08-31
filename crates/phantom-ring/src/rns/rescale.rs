//! RNS rescaling and modulus dropping helpers.

use crate::bignum::BigUint;
use crate::reduce::{inv_mod, mul_mod, sub_mod};
use crate::rns::extension::extend_basis;
use crate::{Poly, Result, RingError, RnsBasis};

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
