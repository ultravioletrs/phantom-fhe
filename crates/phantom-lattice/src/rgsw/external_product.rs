//! RGSW external product.

use crate::rgsw::{GadgetDecomposition, GadgetDecompositionParams, RgswCiphertext};
use crate::rlwe::{Ciphertext, RlweParams};
use crate::Result;

/// Computes the RGSW external product `RGSW(m) ⊡ RLWE(mu) = RLWE(m * mu)`.
///
/// Let `ct = (c0, c1)` with `c0 + c1*s = mu + e_ct`, and `rgsw` encrypt `m`
/// as `rows()[0][i] = RLWE_s(B^i * m)`, `rows()[1][i] = RLWE_s(B^i * m * s)`
/// (see [`RgswCiphertext::encrypt`]). Gadget-decompose `c0 = sum_i B^i *
/// c0_i` and `c1 = sum_i B^i * c1_i` (the same base/levels `rgsw` was
/// encrypted with), then:
///
/// ```text
/// result = sum_i c0_i * rows()[0][i]  +  sum_i c1_i * rows()[1][i]
/// ```
///
/// Decrypting `result` gives `sum_i c0_i*(B^i*m) + sum_i c1_i*(B^i*m*s) +
/// noise = m*(c0 + c1*s) + noise = m*mu + m*e_ct + noise`, where `noise` is
/// the small combination of each gadget digit against its row's own fresh
/// encryption error (bounded by
/// [`crate::noise::external_product_noise_bound`]) - i.e. exactly `RLWE(m *
/// mu)` with real, boundable noise, not a plaintext-multiplication scaffold.
pub fn external_product(
    params: &RlweParams,
    decomposition_params: GadgetDecompositionParams,
    ct: &Ciphertext,
    rgsw: &RgswCiphertext,
) -> Result<Ciphertext> {
    let ring = params.ring();
    ring.check_poly(&ct.value()[0])?;
    ring.check_poly(&ct.value()[1])?;

    let moduli = ring.moduli();
    let c0_digits = GadgetDecomposition::decompose(&ct.value()[0], decomposition_params, moduli)?;
    let c1_digits = GadgetDecomposition::decompose(&ct.value()[1], decomposition_params, moduli)?;

    let mut acc0 = ring.zero();
    let mut acc1 = ring.zero();

    for (digit, row) in c0_digits.digits().iter().zip(rgsw.rows()[0].iter()) {
        acc0 = ring.add(&acc0, &ring.mul(digit, &row.value()[0])?)?;
        acc1 = ring.add(&acc1, &ring.mul(digit, &row.value()[1])?)?;
    }
    for (digit, row) in c1_digits.digits().iter().zip(rgsw.rows()[1].iter()) {
        acc0 = ring.add(&acc0, &ring.mul(digit, &row.value()[0])?)?;
        acc1 = ring.add(&acc1, &ring.mul(digit, &row.value()[1])?)?;
    }

    Ok(Ciphertext::new(vec![acc0, acc1]))
}
