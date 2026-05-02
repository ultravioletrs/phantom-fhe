//! CKKS evaluator.

use super::{Ciphertext, CkksParams, Complex64, EvaluationKeys, Plaintext};
use crate::{Result, SchemesError};

/// CKKS homomorphic evaluator.
#[derive(Clone, Debug)]
pub struct Evaluator {
    params: CkksParams,
}

impl Evaluator {
    /// Creates an evaluator.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Adds two ciphertexts.
    pub fn add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        Ok(Ciphertext::new(
            zip_slots(lhs, rhs, |a, b| a + b),
            lhs.scale(),
            lhs.level(),
            lhs.precision().min(rhs.precision()).degrade(0.25),
            lhs.degree().max(rhs.degree()),
        ))
    }

    /// Subtracts two ciphertexts.
    pub fn sub(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        Ok(Ciphertext::new(
            zip_slots(lhs, rhs, |a, b| a - b),
            lhs.scale(),
            lhs.level(),
            lhs.precision().min(rhs.precision()).degrade(0.25),
            lhs.degree().max(rhs.degree()),
        ))
    }

    /// Negates a ciphertext.
    pub fn neg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        self.check_ciphertext(ciphertext)?;
        Ok(Ciphertext::new(
            ciphertext.slots().iter().copied().map(|v| -v).collect(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }

    /// Adds a plaintext to a ciphertext.
    pub fn add_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        self.check_plain_binary(ciphertext, plaintext)?;
        Ok(Ciphertext::new(
            ciphertext
                .slots()
                .iter()
                .copied()
                .zip(plaintext.slots().iter().copied())
                .map(|(a, b)| a + b)
                .collect(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext
                .precision()
                .min(plaintext.precision())
                .degrade(0.25),
            ciphertext.degree(),
        ))
    }

    /// Multiplies two ciphertexts and optionally relinearizes with evaluation keys.
    pub fn mul(
        &self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        evaluation_keys: Option<&EvaluationKeys>,
    ) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        let degree = if evaluation_keys.is_some() {
            1
        } else {
            lhs.degree() + rhs.degree()
        };
        Ok(Ciphertext::new(
            zip_slots(lhs, rhs, |a, b| a * b),
            super::Scale::new(lhs.scale().value() * rhs.scale().value())?,
            lhs.level().min(rhs.level()),
            lhs.precision().min(rhs.precision()).degrade(1.0),
            degree,
        ))
    }

    /// Multiplies a ciphertext by a plaintext.
    pub fn mul_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        self.check_plain_binary(ciphertext, plaintext)?;
        Ok(Ciphertext::new(
            ciphertext
                .slots()
                .iter()
                .copied()
                .zip(plaintext.slots().iter().copied())
                .map(|(a, b)| a * b)
                .collect(),
            super::Scale::new(ciphertext.scale().value() * plaintext.scale().value())?,
            ciphertext.level().min(plaintext.level()),
            ciphertext
                .precision()
                .min(plaintext.precision())
                .degrade(1.0),
            ciphertext.degree(),
        ))
    }

    /// Rescales a ciphertext to the next level and the default scale.
    pub fn rescale_next(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        self.check_ciphertext(ciphertext)?;
        if ciphertext.level() == 0 {
            return Err(SchemesError::InvalidParameters(
                "cannot rescale at level zero",
            ));
        }
        Ok(Ciphertext::new(
            ciphertext.slots().to_vec(),
            self.params.default_scale(),
            ciphertext.level() - 1,
            ciphertext.precision().degrade(1.0),
            ciphertext.degree(),
        ))
    }

    /// Aligns two ciphertexts to a common level when their scales are compatible.
    pub fn align_levels(
        &self,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
    ) -> Result<(Ciphertext, Ciphertext)> {
        self.check_ciphertext(lhs)?;
        self.check_ciphertext(rhs)?;
        if !lhs.scale().compatible(rhs.scale()) {
            return Err(SchemesError::InvalidParameters("scale mismatch"));
        }
        let level = lhs.level().min(rhs.level());
        Ok((
            with_level(
                lhs,
                level,
                lhs.precision().degrade((lhs.level() - level) as f64),
            ),
            with_level(
                rhs,
                level,
                rhs.precision().degrade((rhs.level() - level) as f64),
            ),
        ))
    }

    /// Rotates packed slots.
    pub fn rotate_slots(&self, ciphertext: &Ciphertext, shift: usize) -> Result<Ciphertext> {
        self.check_ciphertext(ciphertext)?;
        let len = ciphertext.slots().len();
        if len == 0 {
            return Ok(ciphertext.clone());
        }
        let mut slots = ciphertext.slots().to_vec();
        slots.rotate_left(shift % len);
        Ok(Ciphertext::new(
            slots,
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision().degrade(0.25),
            ciphertext.degree(),
        ))
    }

    /// Conjugates packed complex slots.
    pub fn conjugate(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        self.check_ciphertext(ciphertext)?;
        Ok(Ciphertext::new(
            ciphertext
                .slots()
                .iter()
                .copied()
                .map(Complex64::conj)
                .collect(),
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision().degrade(0.25),
            ciphertext.degree(),
        ))
    }

    fn check_binary(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<()> {
        self.check_ciphertext(lhs)?;
        self.check_ciphertext(rhs)?;
        if lhs.slots().len() != rhs.slots().len() || lhs.level() != rhs.level() {
            return Err(SchemesError::DimensionMismatch);
        }
        if !lhs.scale().compatible(rhs.scale()) {
            return Err(SchemesError::InvalidParameters("scale mismatch"));
        }
        Ok(())
    }

    fn check_plain_binary(&self, lhs: &Ciphertext, rhs: &Plaintext) -> Result<()> {
        self.check_ciphertext(lhs)?;
        if lhs.slots().len() != rhs.slots().len() || lhs.level() != rhs.level() {
            return Err(SchemesError::DimensionMismatch);
        }
        if !lhs.scale().compatible(rhs.scale()) {
            return Err(SchemesError::InvalidParameters("scale mismatch"));
        }
        Ok(())
    }

    fn check_ciphertext(&self, ciphertext: &Ciphertext) -> Result<()> {
        if ciphertext.slots().len() > self.params.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        if self.params.conjugate_invariant() && ciphertext.slots().iter().any(|v| v.im != 0.0) {
            return Err(SchemesError::InvalidParameters(
                "conjugate-invariant CKKS accepts real slots only",
            ));
        }
        Ok(())
    }
}

fn zip_slots(
    lhs: &Ciphertext,
    rhs: &Ciphertext,
    f: impl Fn(Complex64, Complex64) -> Complex64,
) -> Vec<Complex64> {
    lhs.slots()
        .iter()
        .copied()
        .zip(rhs.slots().iter().copied())
        .map(|(a, b)| f(a, b))
        .collect()
}

fn with_level(ciphertext: &Ciphertext, level: usize, precision: super::Precision) -> Ciphertext {
    Ciphertext::new(
        ciphertext.slots().to_vec(),
        ciphertext.scale(),
        level,
        precision,
        ciphertext.degree(),
    )
}
