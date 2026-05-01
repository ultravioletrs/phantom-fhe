//! Ring context and polynomial operations.

use crate::modulus::Modulus;
use crate::poly::Poly;
use crate::reduce::{add_mod, mul_mod, neg_mod, sub_mod};
use crate::{Degree, Result, RingError};

/// RNS polynomial ring context.
#[derive(Clone, Debug)]
pub struct Ring {
    degree: Degree,
    moduli: Vec<Modulus>,
}

impl Ring {
    /// Creates a validated ring context.
    pub fn new(degree: Degree, moduli: Vec<Modulus>) -> Result<Self> {
        if moduli.is_empty() {
            return Err(RingError::DimensionMismatch);
        }
        Ok(Self { degree, moduli })
    }

    /// Creates a ring and validates all moduli for negacyclic NTT.
    pub fn new_ntt(degree: Degree, moduli: Vec<Modulus>) -> Result<Self> {
        for modulus in &moduli {
            if !modulus.supports_ntt(degree.get()) {
                return Err(RingError::InvalidNttModulus {
                    modulus: modulus.value(),
                    two_n: 2 * degree.get(),
                });
            }
        }
        Self::new(degree, moduli)
    }

    /// Returns the ring degree.
    pub fn degree(&self) -> usize {
        self.degree.get()
    }

    /// Returns the RNS moduli.
    pub fn moduli(&self) -> &[Modulus] {
        &self.moduli
    }

    /// Allocates a zero polynomial.
    pub fn zero(&self) -> Poly {
        Poly::zero_for(self)
    }

    /// Checks that a polynomial matches this ring.
    pub fn check_poly(&self, poly: &Poly) -> Result<()> {
        if poly.degree() != self.degree() || poly.moduli_count() != self.moduli.len() {
            return Err(RingError::DimensionMismatch);
        }
        Ok(())
    }

    /// Adds `rhs` into `lhs`.
    pub fn add_assign(&self, lhs: &mut Poly, rhs: &Poly) -> Result<()> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for i in 0..self.degree() {
                lhs.coeffs_mut()[j][i] = add_mod(lhs.coeffs()[j][i], rhs.coeffs()[j][i], q);
            }
        }
        Ok(())
    }

    /// Returns `lhs + rhs`.
    pub fn add(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        let mut out = lhs.clone();
        self.add_assign(&mut out, rhs)?;
        Ok(out)
    }

    /// Subtracts `rhs` from `lhs`.
    pub fn sub_assign(&self, lhs: &mut Poly, rhs: &Poly) -> Result<()> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for i in 0..self.degree() {
                lhs.coeffs_mut()[j][i] = sub_mod(lhs.coeffs()[j][i], rhs.coeffs()[j][i], q);
            }
        }
        Ok(())
    }

    /// Returns `lhs - rhs`.
    pub fn sub(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        let mut out = lhs.clone();
        self.sub_assign(&mut out, rhs)?;
        Ok(out)
    }

    /// Negates a polynomial in place.
    pub fn neg_assign(&self, poly: &mut Poly) -> Result<()> {
        self.check_poly(poly)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for coeff in &mut poly.coeffs_mut()[j] {
                *coeff = neg_mod(*coeff, q);
            }
        }
        Ok(())
    }

    /// Returns `-poly`.
    pub fn neg(&self, poly: &Poly) -> Result<Poly> {
        let mut out = poly.clone();
        self.neg_assign(&mut out)?;
        Ok(out)
    }

    /// Multiplies each coefficient by `scalar`.
    pub fn scalar_mul_assign(&self, poly: &mut Poly, scalar: u64) -> Result<()> {
        self.check_poly(poly)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for coeff in &mut poly.coeffs_mut()[j] {
                *coeff = mul_mod(*coeff, scalar % q, q);
            }
        }
        Ok(())
    }

    /// Returns `poly * scalar`.
    pub fn scalar_mul(&self, poly: &Poly, scalar: u64) -> Result<Poly> {
        let mut out = poly.clone();
        self.scalar_mul_assign(&mut out, scalar)?;
        Ok(out)
    }

    /// Coefficient-wise multiplication.
    pub fn coeffwise_mul(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        let mut out = self.zero();
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for i in 0..self.degree() {
                out.coeffs_mut()[j][i] = mul_mod(lhs.coeffs()[j][i], rhs.coeffs()[j][i], q);
            }
        }
        Ok(out)
    }

    /// Schoolbook negacyclic multiplication for correctness tests and small rings.
    pub fn schoolbook_mul(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        let n = self.degree();
        let mut out = self.zero();
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for a in 0..n {
                for b in 0..n {
                    let prod = mul_mod(lhs.coeffs()[j][a], rhs.coeffs()[j][b], q);
                    let idx = a + b;
                    if idx < n {
                        out.coeffs_mut()[j][idx] = add_mod(out.coeffs()[j][idx], prod, q);
                    } else {
                        let idx = idx - n;
                        out.coeffs_mut()[j][idx] = sub_mod(out.coeffs()[j][idx], prod, q);
                    }
                }
            }
        }
        Ok(out)
    }
}
