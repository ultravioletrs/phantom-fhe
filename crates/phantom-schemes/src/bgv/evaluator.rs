//! BGV evaluator.

use super::{BgvParams, Ciphertext, EvaluationKeys, ModulusSwitcher, Plaintext};
use crate::Result;

/// BGV homomorphic evaluator.
#[derive(Clone, Debug)]
pub struct Evaluator {
    inner: phantom_lattice::rlwe::Evaluator,
    modulus_switcher: ModulusSwitcher,
}

impl Evaluator {
    /// Creates an evaluator.
    pub fn new(params: BgvParams) -> Result<Self> {
        Ok(Self {
            inner: phantom_lattice::rlwe::Evaluator::new(params.rlwe_params()?),
            modulus_switcher: ModulusSwitcher::new(params),
        })
    }

    /// Adds two ciphertexts.
    pub fn add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(self.inner.add(lhs.inner(), rhs.inner())?))
    }

    /// Subtracts two ciphertexts.
    pub fn sub(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(self.inner.sub(lhs.inner(), rhs.inner())?))
    }

    /// Negates a ciphertext.
    pub fn neg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(self.inner.neg(ciphertext.inner())?))
    }

    /// Adds a plaintext to a ciphertext.
    pub fn add_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner
                .add_plain(ciphertext.inner(), plaintext.inner())?,
        ))
    }

    /// Multiplies two ciphertexts and optionally relinearizes with evaluation keys.
    pub fn mul(
        &self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        evaluation_keys: Option<&EvaluationKeys>,
    ) -> Result<Ciphertext> {
        let product = self.inner.mul(lhs.inner(), rhs.inner())?;
        let product = if let Some(keys) = evaluation_keys {
            self.inner.relinearize(&product, &keys.relinearization)?
        } else {
            product
        };
        Ok(Ciphertext::new(product))
    }

    /// Multiplies a ciphertext by a plaintext.
    pub fn mul_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        let pt_as_ct =
            phantom_lattice::rlwe::Ciphertext::new(vec![plaintext.inner().value().clone()]);
        Ok(Ciphertext::new(
            self.inner.mul(ciphertext.inner(), &pt_as_ct)?,
        ))
    }

    /// Applies the current modulus-switching scaffold.
    pub fn modulus_switch_next(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        self.modulus_switcher.switch_next(ciphertext)
    }

    /// Rotates packed coefficient slots.
    pub fn rotate_slots(&self, ciphertext: &Ciphertext, shift: usize) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner.rotate_coefficients(ciphertext.inner(), shift)?,
        ))
    }

    /// Sums `count` rotations into the first slot interval.
    pub fn sum_slots(&self, ciphertext: &Ciphertext, count: usize) -> Result<Ciphertext> {
        let mut acc = ciphertext.clone();
        for shift in 1..count {
            let rotated = self.rotate_slots(ciphertext, shift)?;
            acc = self.add(&acc, &rotated)?;
        }
        Ok(acc)
    }
}
