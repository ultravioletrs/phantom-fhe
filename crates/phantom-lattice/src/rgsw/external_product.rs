//! RGSW external product scaffold.

use crate::rgsw::RgswCiphertext;
use crate::rlwe::{Ciphertext, RlweParams};
use crate::Result;

/// Applies an early-implementation external product by multiplying every RLWE component by the
/// plaintext-backed RGSW message polynomial.
pub fn external_product(
    params: &RlweParams,
    ct: &Ciphertext,
    rgsw: &RgswCiphertext,
) -> Result<Ciphertext> {
    params.ring().check_poly(rgsw.message())?;
    let mut out = Vec::with_capacity(ct.value().len());
    for component in ct.value() {
        params.ring().check_poly(component)?;
        out.push(params.ring().schoolbook_mul(component, rgsw.message())?);
    }
    Ok(Ciphertext::new(out))
}
