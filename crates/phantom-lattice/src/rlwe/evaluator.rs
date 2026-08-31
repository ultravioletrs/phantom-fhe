//! RLWE evaluator operations.

use crate::rlwe::keyswitch::key_switch;
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

    /// Relinearizes a degree-2 ciphertext back to degree 1 using `key`.
    ///
    /// If `key` is the identity-preserving placeholder
    /// ([`RelinearizationKey::placeholder`]), returns `ct` unchanged -
    /// today's behavior for every caller not yet supplying a real key. With
    /// a real key ([`RelinearizationKey::from_key_switch_key`]), treats
    /// `ct`'s third component `c2` (the one multiplying `s²`) as the `c1`
    /// half of a throwaway ciphertext `(0, c2)`, key-switches that from `s²`
    /// to `s`, and adds the result into `ct`'s first two components -
    /// `c0 + c1*s + c2*s² = (c0 + switched_c0) + (c1 + switched_c1)*s`.
    pub fn relinearize(&self, ct: &Ciphertext, key: &RelinearizationKey) -> Result<Ciphertext> {
        self.check_ciphertext(ct)?;
        let Some(ksk) = key.key_switch_key() else {
            return Ok(ct.clone());
        };
        if ct.value().len() != 3 {
            return Err(LatticeError::InvalidParameters(
                "relinearize with a real key expects a degree-2 ciphertext (3 components)",
            ));
        }

        let c2 = &ct.value()[2];
        let c2_ct = Ciphertext::new(vec![self.params.ring().zero(), c2.clone()]);
        let switched = key_switch(&c2_ct, ksk, &self.params)?;

        let new_c0 = self
            .params
            .ring()
            .add(&ct.value()[0], &switched.value()[0])?;
        let new_c1 = self
            .params
            .ring()
            .add(&ct.value()[1], &switched.value()[1])?;
        Ok(Ciphertext::new(vec![new_c0, new_c1]))
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
