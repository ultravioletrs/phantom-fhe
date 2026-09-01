//! BGV evaluator.

use super::relinearization::{key_switch, BgvRelinearizationKey};
use super::{BgvParams, Ciphertext, EvaluationKeys, ModulusSwitcher, Plaintext};
use crate::Result;

/// BGV homomorphic evaluator.
#[derive(Clone, Debug)]
pub struct Evaluator {
    params: BgvParams,
    inner: phantom_lattice::rlwe::Evaluator,
    modulus_switcher: ModulusSwitcher,
}

impl Evaluator {
    /// Creates an evaluator.
    pub fn new(params: BgvParams) -> Result<Self> {
        let inner = phantom_lattice::rlwe::Evaluator::new(params.rlwe_params()?);
        let modulus_switcher = ModulusSwitcher::new(params.clone());
        Ok(Self {
            params,
            inner,
            modulus_switcher,
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

    /// Relinearizes a **real** degree-2 BGV ciphertext back to degree 1,
    /// using a key from
    /// [`super::BgvKeyGenerator::generate_relinearization_key_real`]. See
    /// [`BgvRelinearizationKey`]'s own module doc comment for why this -
    /// not [`Self::mul`]'s `RelinearizationKey`/[`phantom_lattice::rlwe::key_switch`]
    /// path - is what real BGV relinearization needs.
    pub fn relinearize_real(
        &self,
        ciphertext: &Ciphertext,
        key: &BgvRelinearizationKey,
    ) -> Result<Ciphertext> {
        let ring = self.params.ring();
        let components = ciphertext.inner().value();
        if components.len() != 3 {
            return Err(crate::SchemesError::InvalidParameters(
                "relinearize_real expects a degree-2 ciphertext (3 components)",
            ));
        }
        let (acc_b, acc_a) = key_switch(&components[2], key, ring)?;
        let new_c0 = ring.add(&components[0], &acc_b)?;
        let new_c1 = ring.add(&components[1], &acc_a)?;
        Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(
            vec![new_c0, new_c1],
        )))
    }

    /// Multiplies a ciphertext by a plaintext.
    pub fn mul_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        let pt_as_ct =
            phantom_lattice::rlwe::Ciphertext::new(vec![plaintext.inner().value().clone()]);
        Ok(Ciphertext::new(
            self.inner.mul(ciphertext.inner(), &pt_as_ct)?,
        ))
    }

    /// Applies the current modulus-switching scaffold (unchanged
    /// identity behavior - see [`Self::modulus_switch_next_real`] and
    /// [`ModulusSwitcher`]'s own module doc comment).
    pub fn modulus_switch_next(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        self.modulus_switcher.switch_next(ciphertext)
    }

    /// Performs real RNS modulus switching, dropping the ring's last
    /// modulus. The result must be decrypted against
    /// [`Self::next_modulus_switch_params`] and
    /// [`Self::switch_secret_key`]'s output.
    pub fn modulus_switch_next_real(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        self.modulus_switcher.switch_next_real(ciphertext)
    }

    /// Parameters for the ciphertext [`Self::modulus_switch_next_real`]
    /// returns.
    pub fn next_modulus_switch_params(&self) -> Result<BgvParams> {
        self.modulus_switcher.next_params()
    }

    /// Drops a secret key's own last RNS component to match
    /// [`Self::next_modulus_switch_params`]'s ring.
    pub fn switch_secret_key(
        &self,
        sk: &phantom_lattice::rlwe::SecretKey,
    ) -> Result<phantom_lattice::rlwe::SecretKey> {
        self.modulus_switcher.switch_secret_key(sk)
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
