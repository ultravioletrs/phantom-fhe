//! Correct baseline CPU NTT backend.

use crate::ntt::backend::NttBackend;
use crate::ntt::table::NttTable;
use crate::reduce::{add_mod, mul_mod, pow_mod};
use crate::{Poly, Result, Ring};

/// Baseline CPU backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuNttBackend;

impl NttBackend for CpuNttBackend {
    fn forward(&self, ring: &Ring, poly: &mut Poly) -> Result<()> {
        ring.check_poly(poly)?;
        for (j, modulus) in ring.moduli().iter().enumerate() {
            let table = NttTable::new(ring.degree(), *modulus)?;
            let input = poly.coeffs()[j].clone();
            let output = forward_component(&input, &table);
            poly.coeffs_mut()[j] = output;
        }
        Ok(())
    }

    fn inverse(&self, ring: &Ring, poly: &mut Poly) -> Result<()> {
        ring.check_poly(poly)?;
        for (j, modulus) in ring.moduli().iter().enumerate() {
            let table = NttTable::new(ring.degree(), *modulus)?;
            let input = poly.coeffs()[j].clone();
            let output = inverse_component(&input, &table);
            poly.coeffs_mut()[j] = output;
        }
        Ok(())
    }
}

fn forward_component(input: &[u64], table: &NttTable) -> Vec<u64> {
    let n = table.degree();
    let q = table.modulus().value();
    let mut twisted = vec![0u64; n];
    for j in 0..n {
        twisted[j] = mul_mod(input[j], pow_mod(table.psi(), j as u64, q), q);
    }

    let mut out = vec![0u64; n];
    for (k, slot) in out.iter_mut().enumerate() {
        let mut acc = 0u64;
        for (j, value) in twisted.iter().enumerate() {
            let root = pow_mod(table.omega(), (j * k) as u64, q);
            acc = add_mod(acc, mul_mod(*value, root, q), q);
        }
        *slot = acc;
    }
    out
}

fn inverse_component(input: &[u64], table: &NttTable) -> Vec<u64> {
    let n = table.degree();
    let q = table.modulus().value();
    let mut untwisted = vec![0u64; n];
    for (j, slot) in untwisted.iter_mut().enumerate() {
        let mut acc = 0u64;
        for (k, value) in input.iter().enumerate() {
            let root = pow_mod(table.inv_omega(), (j * k) as u64, q);
            acc = add_mod(acc, mul_mod(*value, root, q), q);
        }
        acc = mul_mod(acc, table.inv_degree(), q);
        *slot = mul_mod(acc, pow_mod(table.inv_psi(), j as u64, q), q);
    }
    untwisted
}
