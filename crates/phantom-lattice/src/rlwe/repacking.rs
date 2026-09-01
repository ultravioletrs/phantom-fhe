//! RLWE coefficient repacking (Workstream 4 item 6): combining several
//! single-slot ciphertexts - each encrypting a scalar message at
//! coefficient 0, all under the same secret key - into one ciphertext with
//! each input's message at its own coefficient position, via the standard
//! monomial-shift-and-sum technique. No key-switching is needed, since
//! every input already shares the output's secret key.
//!
//! # Derivation
//!
//! For `ct_i = (c0, c1)` with `c0 + c1*s = m_i + e_i`, `X^i * ct_i = (X^i *
//! c0, X^i * c1)` decrypts to `X^i * m_i + X^i * e_i` - multiplying a
//! ciphertext by a public monomial is linear and stays valid under the same
//! secret (it's the same trick [`crate::rlwe::Evaluator::add_plain`] uses
//! for addition, applied to multiplication by a known plaintext instead).
//! Summing `X^i * ct_i` over every `i` therefore yields `sum_i X^i * m_i +
//! sum_i X^i * e_i` - exactly the coefficient-packed message plus
//! accumulated noise. Verified numerically (Python, negacyclic schoolbook
//! multiplication) before implementing.

use phantom_ring::{Poly, Ring};

use crate::rlwe::Ciphertext;
use crate::{LatticeError, Result};

/// Packs `cts` into a single ciphertext: `cts[i]`'s message ends up at
/// coefficient `i` of the result. `cts` must be non-empty, every entry must
/// have the same shape (component count) and match `ring`, and `cts.len()`
/// must not exceed `ring.degree()` - packing more inputs than that would
/// alias positions via the ring's negacyclic wraparound (`X^N = -1`) rather
/// than erroring, silently corrupting the result.
pub fn repack(cts: &[Ciphertext], ring: &Ring) -> Result<Ciphertext> {
    let Some(first) = cts.first() else {
        return Err(LatticeError::DimensionMismatch);
    };
    if cts.len() > ring.degree() {
        return Err(LatticeError::InvalidParameters(
            "repack cannot pack more ciphertexts than the ring's degree",
        ));
    }
    let shape = first.value().len();

    let mut acc = Ciphertext::new(vec![ring.zero(); shape]);
    for (i, ct) in cts.iter().enumerate() {
        if ct.value().len() != shape {
            return Err(LatticeError::DimensionMismatch);
        }
        for component in ct.value() {
            ring.check_poly(component)?;
        }

        let monomial = monomial(ring, i);
        for (j, component) in ct.value().iter().enumerate() {
            let shifted = ring.mul(component, &monomial)?;
            ring.add_assign(&mut acc.value_mut()[j], &shifted)?;
        }
    }
    Ok(acc)
}

/// The polynomial `X^exponent`, represented identically (the literal
/// coefficient `1`) across every RNS component - `exponent` must be `<
/// ring.degree()`, enforced by [`repack`]'s own length check before this is
/// ever called with an out-of-range value.
fn monomial(ring: &Ring, exponent: usize) -> Poly {
    let mut poly = ring.zero();
    for component in poly.coeffs_mut() {
        component[exponent] = 1;
    }
    poly
}
