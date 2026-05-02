//! BFV evaluator.

use super::{BfvParams, Ciphertext, EvaluationKeys, Plaintext};
use crate::{bgv, Result};

/// BFV homomorphic evaluator.
#[derive(Clone, Debug)]
pub struct Evaluator {
    inner: bgv::Evaluator,
}

impl Evaluator {
    /// Creates an evaluator.
    pub fn new(params: BfvParams) -> Result<Self> {
        Ok(Self {
            inner: bgv::Evaluator::new(params.inner().clone())?,
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
        let keys = evaluation_keys.map(|keys| &keys.inner);
        Ok(Ciphertext::new(self.inner.mul(
            lhs.inner(),
            rhs.inner(),
            keys,
        )?))
    }

    /// Multiplies a ciphertext by a plaintext.
    pub fn mul_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner
                .mul_plain(ciphertext.inner(), plaintext.inner())?,
        ))
    }

    /// Rotates packed coefficient slots.
    pub fn rotate_slots(&self, ciphertext: &Ciphertext, shift: usize) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner.rotate_slots(ciphertext.inner(), shift)?,
        ))
    }

    /// Sums `count` rotations into the first slot interval.
    pub fn sum_slots(&self, ciphertext: &Ciphertext, count: usize) -> Result<Ciphertext> {
        Ok(Ciphertext::new(
            self.inner.sum_slots(ciphertext.inner(), count)?,
        ))
    }
}
