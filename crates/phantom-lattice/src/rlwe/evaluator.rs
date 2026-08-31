//! RLWE evaluator operations.

use crate::rlwe::{Ciphertext, Plaintext, RelinearizationKey, RlweParams};
use crate::{LatticeError, Result};

/// Scheme-agnostic evaluator.
#[derive(Clone, Debug)]
pub struct Evaluator {
    params: RlweParams,
}

impl Evaluator {
    /// Creates an evaluator.
    pub const fn new(params: RlweParams) -> Self {
        Self { params }
    }

    /// Adds two ciphertexts.
    pub fn add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.binary_zip(lhs, rhs, |ring, a, b| ring.add(a, b))
    }

    /// Subtracts two ciphertexts.
    pub fn sub(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.binary_zip(lhs, rhs, |ring, a, b| ring.sub(a, b))
    }

    /// Negates a ciphertext.
    pub fn neg(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        let mut out = Vec::with_capacity(ct.value().len());
        for component in ct.value() {
            self.params.ring().check_poly(component)?;
            out.push(self.params.ring().neg(component)?);
        }
        Ok(Ciphertext::new(out))
    }

    /// Adds a plaintext to the first ciphertext component.
    pub fn add_plain(&self, ct: &Ciphertext, pt: &Plaintext) -> Result<Ciphertext> {
        self.params.ring().check_poly(pt.value())?;
        let mut out = ct.clone();
        if out.value().is_empty() {
            return Err(LatticeError::DimensionMismatch);
        }
        self.params
            .ring()
            .add_assign(&mut out.value_mut()[0], pt.value())?;
        Ok(out)
    }

    /// Multiplies two ciphertexts and returns the unrelinearized product.
    pub fn mul(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_ciphertext(lhs)?;
        self.check_ciphertext(rhs)?;
        let degree = lhs.degree() + rhs.degree();
        let mut out = Ciphertext::zero(self.params.ring(), degree);

        for (i, a) in lhs.value().iter().enumerate() {
            for (j, b) in rhs.value().iter().enumerate() {
                let term = self.params.ring().mul(a, b)?;
                self.params
                    .ring()
                    .add_assign(&mut out.value_mut()[i + j], &term)?;
            }
        }

        Ok(out)
    }

    /// Placeholder relinearization that preserves decryptability.
    pub fn relinearize(&self, ct: &Ciphertext, _key: &RelinearizationKey) -> Result<Ciphertext> {
        self.check_ciphertext(ct)?;
        Ok(ct.clone())
    }

    /// Applies a simple cyclic coefficient rotation to every component.
    pub fn rotate_coefficients(&self, ct: &Ciphertext, shift: usize) -> Result<Ciphertext> {
        self.check_ciphertext(ct)?;
        let n = self.params.ring().degree();
        let shift = shift % n;
        let mut out = ct.clone();
        for component in out.value_mut() {
            for rns in component.coeffs_mut() {
                rns.rotate_left(shift);
            }
        }
        Ok(out)
    }

    fn check_ciphertext(&self, ct: &Ciphertext) -> Result<()> {
        if ct.value().is_empty() {
            return Err(LatticeError::DimensionMismatch);
        }
        for component in ct.value() {
            self.params.ring().check_poly(component)?;
        }
        Ok(())
    }

    fn binary_zip<F>(&self, lhs: &Ciphertext, rhs: &Ciphertext, f: F) -> Result<Ciphertext>
    where
        F: Fn(
            &phantom_ring::Ring,
            &phantom_ring::Poly,
            &phantom_ring::Poly,
        ) -> phantom_ring::Result<phantom_ring::Poly>,
    {
        self.check_ciphertext(lhs)?;
        self.check_ciphertext(rhs)?;
        if lhs.value().len() != rhs.value().len() {
            return Err(LatticeError::DimensionMismatch);
        }

        let mut out = Vec::with_capacity(lhs.value().len());
        for (a, b) in lhs.value().iter().zip(rhs.value()) {
            out.push(f(self.params.ring(), a, b)?);
        }
        Ok(Ciphertext::new(out))
    }
}
