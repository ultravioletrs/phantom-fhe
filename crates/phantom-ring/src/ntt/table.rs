//! NTT table generation.

use crate::reduce::{inv_mod, pow_mod};
use crate::{Modulus, Result, RingError};

/// Roots needed for the initial CPU negacyclic NTT.
#[derive(Clone, Debug)]
pub struct NttTable {
    modulus: Modulus,
    degree: usize,
    psi: u64,
    omega: u64,
    inv_psi: u64,
    inv_omega: u64,
    inv_degree: u64,
}

impl NttTable {
    /// Builds a table for one modulus and degree.
    pub fn new(degree: usize, modulus: Modulus) -> Result<Self> {
        if !modulus.supports_ntt(degree) {
            return Err(RingError::InvalidNttModulus {
                modulus: modulus.value(),
                two_n: 2 * degree,
            });
        }

        let psi = primitive_root_of_order(2 * degree, modulus.value())?;
        let omega = crate::reduce::mul_mod(psi, psi, modulus.value());
        let inv_psi = inv_mod(psi, modulus.value());
        let inv_omega = inv_mod(omega, modulus.value());
        let inv_degree = inv_mod(degree as u64, modulus.value());

        Ok(Self {
            modulus,
            degree,
            psi,
            omega,
            inv_psi,
            inv_omega,
            inv_degree,
        })
    }

    /// Returns the degree.
    pub const fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the modulus.
    pub const fn modulus(&self) -> Modulus {
        self.modulus
    }

    /// Returns the 2N-th root.
    pub const fn psi(&self) -> u64 {
        self.psi
    }

    /// Returns the N-th root.
    pub const fn omega(&self) -> u64 {
        self.omega
    }

    /// Returns inverse psi.
    pub const fn inv_psi(&self) -> u64 {
        self.inv_psi
    }

    /// Returns inverse omega.
    pub const fn inv_omega(&self) -> u64 {
        self.inv_omega
    }

    /// Returns inverse degree.
    pub const fn inv_degree(&self) -> u64 {
        self.inv_degree
    }
}

fn primitive_root_of_order(order: usize, modulus: u64) -> Result<u64> {
    for candidate in 2..modulus {
        if pow_mod(candidate, order as u64, modulus) != 1 {
            continue;
        }
        if pow_mod(candidate, (order / 2) as u64, modulus) == 1 {
            continue;
        }
        return Ok(candidate);
    }
    Err(RingError::MissingRoot(modulus))
}
