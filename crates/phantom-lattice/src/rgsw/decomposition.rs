//! Gadget decomposition over RNS polynomials.

use phantom_ring::Poly;

use crate::{LatticeError, Result};

/// Gadget decomposition parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GadgetDecompositionParams {
    base_log: u32,
    levels: usize,
}

impl GadgetDecompositionParams {
    /// Creates decomposition parameters.
    pub fn new(base_log: u32, levels: usize) -> Result<Self> {
        if base_log == 0 || base_log >= 63 {
            return Err(LatticeError::InvalidParameters("base_log must be in 1..63"));
        }
        if levels == 0 {
            return Err(LatticeError::InvalidParameters("levels must be non-zero"));
        }
        Ok(Self { base_log, levels })
    }

    /// Returns the base bit length.
    pub const fn base_log(self) -> u32 {
        self.base_log
    }

    /// Returns the number of levels.
    pub const fn levels(self) -> usize {
        self.levels
    }

    /// Returns the base.
    pub const fn base(self) -> u64 {
        1u64 << self.base_log
    }
}

/// Gadget decomposition of a polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GadgetDecomposition {
    params: GadgetDecompositionParams,
    digits: Vec<Poly>,
}

impl GadgetDecomposition {
    /// Decomposes a polynomial coefficient-wise in base `2^base_log`.
    pub fn decompose(poly: &Poly, params: GadgetDecompositionParams) -> Result<Self> {
        let mask = params.base() - 1;
        let mut digits = Vec::with_capacity(params.levels());

        for level in 0..params.levels() {
            let shift = level as u32 * params.base_log();
            let mut coeffs = vec![vec![0u64; poly.degree()]; poly.moduli_count()];
            for (j, component) in poly.coeffs().iter().enumerate() {
                for (i, &coeff) in component.iter().enumerate() {
                    coeffs[j][i] = (coeff >> shift) & mask;
                }
            }
            digits.push(Poly::from_coeffs(coeffs)?);
        }

        Ok(Self { params, digits })
    }

    /// Returns decomposition digits.
    pub fn digits(&self) -> &[Poly] {
        &self.digits
    }

    /// Reconstructs the polynomial modulo the provided RNS moduli.
    pub fn recompose(&self, moduli: &[phantom_ring::Modulus]) -> Result<Poly> {
        let first = self.digits.first().ok_or(LatticeError::InvalidParameters(
            "missing decomposition digits",
        ))?;
        if first.moduli_count() != moduli.len() {
            return Err(LatticeError::DimensionMismatch);
        }

        let mut coeffs = vec![vec![0u64; first.degree()]; first.moduli_count()];
        for (level, digit) in self.digits.iter().enumerate() {
            let shift = level as u32 * self.params.base_log();
            for (j, modulus) in moduli.iter().enumerate() {
                let q = modulus.value() as u128;
                let weight = ((1u128 << shift) % q) as u64;
                for (out_coeff, &digit_coeff) in coeffs[j].iter_mut().zip(&digit.coeffs()[j]) {
                    let term = phantom_ring::reduce::mul_mod(digit_coeff, weight, modulus.value());
                    *out_coeff = phantom_ring::reduce::add_mod(*out_coeff, term, modulus.value());
                }
            }
        }

        Ok(Poly::from_coeffs(coeffs)?)
    }
}
