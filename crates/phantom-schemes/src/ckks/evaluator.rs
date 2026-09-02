//! CKKS evaluator.
//!
//! [`Evaluator::add_real`]/[`sub_real`](Evaluator::sub_real)/[`neg_real`](Evaluator::neg_real)/[`add_plain_real`](Evaluator::add_plain_real)/[`mul_real`](Evaluator::mul_real)/[`mul_plain_real`](Evaluator::mul_plain_real)/[`relinearize_real`](Evaluator::relinearize_real)/[`rotate_real`](Evaluator::rotate_real)/[`conjugate_real`](Evaluator::conjugate_real)/[`rescale_next_real`](Evaluator::rescale_next_real)/[`drop_level_real`](Evaluator::drop_level_real)
//! are CKKS's real-path arithmetic, alongside the long-standing transparent
//! [`Evaluator::add`]/[`sub`](Evaluator::sub)/etc. (kept unchanged so every
//! existing caller keeps compiling and behaving identically - see this
//! module's other methods).
//!
//! A real CKKS ciphertext is structurally a plain RLWE ciphertext (its
//! message is Delta-scaled once, by the encoder, not per-operation the way
//! BFV's is) - `add`/`sub`/`neg`/`add_plain`/`mul` (raw tensor, no
//! relinearization) are therefore direct, unmodified pass-throughs to
//! [`phantom_lattice::rlwe::Evaluator`], the same reasoning
//! [`crate::bfv::Evaluator::relinearize_real`] documents for its own
//! pass-through. `mul_real` needs no BFV-style extended-basis
//! tensor-and-rescale procedure: unlike BFV (where the raw tensor product's
//! true magnitude must be recovered *before* reducing mod `Q`, since the
//! rescale step needs it), CKKS's mod-`Q` tensor product mod is already
//! exactly the value the next [`Evaluator::rescale_next_real`] call needs -
//! CKKS's rescaling happens as a separate, later step, not fused into
//! multiplication itself.
//!
//! [`Evaluator::rescale_next_real`] drops the ciphertext's last RNS
//! component via [`phantom_ring::rns::rescale::mod_down`] (`P` = that one
//! modulus), the standard "grow noise in a bigger modulus, then divide it
//! back down" RNS-CKKS rescale technique, and divides the tracked
//! [`super::Scale`] by that modulus's own value to match. Unlike
//! [`phantom_ring::rns::rescale::modulus_switch_down`] (BGV's rescale,
//! which needs an exact congruence-preserving correction term to keep a
//! plaintext-modulus invariant intact), CKKS has no such invariant to
//! preserve - it's already approximate arithmetic - so a plain floor
//! division suffices; the resulting off-by-at-most-one-per-coefficient
//! rounding (rather than round-to-nearest) is a slightly larger constant
//! factor in the noise, not a correctness gap, and was verified numerically
//! (Python, 200 randomized trials, both directly against the floor-division
//! identity and via a full encrypt/rescale/decrypt/decode round trip)
//! before implementing.

use phantom_lattice::rlwe::{Ciphertext as RlweCiphertext, Evaluator as RlweEvaluator};
use phantom_ring::rns::rescale::mod_down;
use phantom_ring::RnsBasis;

use super::noise::{
    add_degrade_bits, align_degrade_bits, mul_degrade_bits, rescale_degrade_bits,
    ASSUMED_REAL_MESSAGE_BOUND,
};
use super::{Ciphertext, CkksParams, Complex64, EvaluationKeys, Plaintext, Scale};
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

    /// Builds the [`phantom_lattice::rlwe::Evaluator`] real-path methods
    /// delegate to, for `ciphertext`'s own level - not built once at
    /// [`Self::new`], since [`Self::rescale_next_real`] can drop RNS
    /// components, changing which ring subsequent operations on the result
    /// need (mirrors [`super::Decryptor::decrypt_real`]'s own per-call
    /// derivation for the same reason).
    fn inner_at(&self, level: usize) -> Result<RlweEvaluator> {
        Ok(RlweEvaluator::new(
            self.params.at_level(level)?.rlwe_params()?,
        ))
    }

    /// The ring degree every [`super::noise`] precision formula needs -
    /// shared here so each call site doesn't repeat `self.params.ring().degree()`.
    fn degree(&self) -> usize {
        self.params.ring().degree()
    }

    /// Adds two ciphertexts.
    pub fn add(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        Self::check_scale(lhs.scale(), rhs.scale())?;
        let degrade = add_degrade_bits(
            self.degree(),
            lhs.scale().value(),
            lhs.precision().bits(),
            rhs.scale().value(),
            rhs.precision().bits(),
        );
        Ok(Ciphertext::new(
            zip_slots(lhs, rhs, |a, b| a + b),
            lhs.scale(),
            lhs.level(),
            lhs.precision().min(rhs.precision()).degrade(degrade),
            lhs.degree().max(rhs.degree()),
        ))
    }

    /// Subtracts two ciphertexts.
    pub fn sub(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        Self::check_scale(lhs.scale(), rhs.scale())?;
        let degrade = add_degrade_bits(
            self.degree(),
            lhs.scale().value(),
            lhs.precision().bits(),
            rhs.scale().value(),
            rhs.precision().bits(),
        );
        Ok(Ciphertext::new(
            zip_slots(lhs, rhs, |a, b| a - b),
            lhs.scale(),
            lhs.level(),
            lhs.precision().min(rhs.precision()).degrade(degrade),
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
        Self::check_scale(ciphertext.scale(), plaintext.scale())?;
        let degrade = add_degrade_bits(
            self.degree(),
            ciphertext.scale().value(),
            ciphertext.precision().bits(),
            plaintext.scale().value(),
            plaintext.precision().bits(),
        );
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
                .degrade(degrade),
            ciphertext.degree(),
        ))
    }

    /// Multiplies two ciphertexts and optionally relinearizes with evaluation keys.
    ///
    /// The precision degrade applies [`super::noise::mul_degrade_bits`]
    /// regardless of whether `evaluation_keys` is given - relinearization's
    /// own key-switching noise contribution isn't modeled separately (see
    /// `super::noise`'s module doc comment for why), so this is a slight
    /// underestimate of the true cost when keys are provided.
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
        let degrade = mul_degrade_bits(
            self.degree(),
            lhs.scale().value(),
            lhs.precision().bits(),
            message_bound(lhs.slots()),
            rhs.scale().value(),
            rhs.precision().bits(),
            message_bound(rhs.slots()),
        );
        Ok(Ciphertext::new(
            zip_slots(lhs, rhs, |a, b| a * b),
            super::Scale::new(lhs.scale().value() * rhs.scale().value())?,
            lhs.level().min(rhs.level()),
            lhs.precision().min(rhs.precision()).degrade(degrade),
            degree,
        ))
    }

    /// Multiplies a ciphertext by a plaintext.
    pub fn mul_plain(&self, ciphertext: &Ciphertext, plaintext: &Plaintext) -> Result<Ciphertext> {
        self.check_plain_binary(ciphertext, plaintext)?;
        let degrade = mul_degrade_bits(
            self.degree(),
            ciphertext.scale().value(),
            ciphertext.precision().bits(),
            message_bound(ciphertext.slots()),
            plaintext.scale().value(),
            plaintext.precision().bits(),
            message_bound(plaintext.slots()),
        );
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
                .degrade(degrade),
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
        let degrade = rescale_degrade_bits(
            self.degree(),
            ciphertext.scale().value(),
            ciphertext.precision().bits(),
            self.params.default_scale().value(),
        );
        Ok(Ciphertext::new(
            ciphertext.slots().to_vec(),
            self.params.default_scale(),
            ciphertext.level() - 1,
            ciphertext.precision().degrade(degrade),
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
        let lhs_degrade = align_degrade_bits(
            self.degree(),
            lhs.scale().value(),
            lhs.precision().bits(),
            lhs.level() - level,
        );
        let rhs_degrade = align_degrade_bits(
            self.degree(),
            rhs.scale().value(),
            rhs.precision().bits(),
            rhs.level() - level,
        );
        Ok((
            with_level(lhs, level, lhs.precision().degrade(lhs_degrade)),
            with_level(rhs, level, rhs.precision().degrade(rhs_degrade)),
        ))
    }

    /// Rotates packed slots.
    ///
    /// No precision degrade is applied: a Galois automorphism is a pure
    /// coefficient permutation with sign flips, which doesn't change any
    /// coefficient's magnitude - see `super::noise`'s module doc comment
    /// for why the key-switch this would need in a real implementation
    /// (to bring the permuted secret key back to the original one) isn't
    /// modeled here either, the same not-yet-derived gap as
    /// relinearization's own key-switching noise.
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
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }

    /// Conjugates packed complex slots. See [`Self::rotate_slots`]'s own
    /// doc comment for why no precision degrade is applied.
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
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }

    /// Adds two **real** ciphertexts - see the module doc comment.
    pub fn add_real(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        Self::check_scale(lhs.scale(), rhs.scale())?;
        let (lhs_poly, rhs_poly) = (self.real_poly(lhs)?, self.real_poly(rhs)?);
        let sum = self.inner_at(lhs.level())?.add(lhs_poly, rhs_poly)?;
        let degrade = add_degrade_bits(
            self.degree(),
            lhs.scale().value(),
            lhs.precision().bits(),
            rhs.scale().value(),
            rhs.precision().bits(),
        );
        Ok(Ciphertext::new_real(
            sum,
            lhs.scale(),
            lhs.level(),
            lhs.precision().min(rhs.precision()).degrade(degrade),
            lhs.degree().max(rhs.degree()),
        ))
    }

    /// Subtracts two **real** ciphertexts - see the module doc comment.
    pub fn sub_real(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        Self::check_scale(lhs.scale(), rhs.scale())?;
        let (lhs_poly, rhs_poly) = (self.real_poly(lhs)?, self.real_poly(rhs)?);
        let diff = self.inner_at(lhs.level())?.sub(lhs_poly, rhs_poly)?;
        let degrade = add_degrade_bits(
            self.degree(),
            lhs.scale().value(),
            lhs.precision().bits(),
            rhs.scale().value(),
            rhs.precision().bits(),
        );
        Ok(Ciphertext::new_real(
            diff,
            lhs.scale(),
            lhs.level(),
            lhs.precision().min(rhs.precision()).degrade(degrade),
            lhs.degree().max(rhs.degree()),
        ))
    }

    /// Negates a **real** ciphertext - see the module doc comment.
    pub fn neg_real(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        let negated = self.inner_at(ciphertext.level())?.neg(poly)?;
        Ok(Ciphertext::new_real(
            negated,
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }

    /// Adds a **real** plaintext ([`Plaintext::poly`] from
    /// [`super::Encoder::encode_complex_real`]) to a **real** ciphertext -
    /// see the module doc comment.
    pub fn add_plain_real(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        let m = plaintext.poly().ok_or(SchemesError::InvalidParameters(
            "plaintext has no real ring representation - encode with encode_complex_real",
        ))?;
        if ciphertext.level() != plaintext.level() {
            return Err(SchemesError::DimensionMismatch);
        }
        if !ciphertext.scale().compatible(plaintext.scale()) {
            return Err(SchemesError::InvalidParameters("scale mismatch"));
        }
        let sum = self
            .inner_at(ciphertext.level())?
            .add_plain(poly, &phantom_lattice::rlwe::Plaintext::new(m.clone()))?;
        let degrade = add_degrade_bits(
            self.degree(),
            ciphertext.scale().value(),
            ciphertext.precision().bits(),
            plaintext.scale().value(),
            plaintext.precision().bits(),
        );
        Ok(Ciphertext::new_real(
            sum,
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext
                .precision()
                .min(plaintext.precision())
                .degrade(degrade),
            ciphertext.degree(),
        ))
    }

    /// Multiplies a **real** ciphertext by a **real** plaintext - no
    /// relinearization needed (the plaintext contributes no `s`-power), and
    /// no scale-compatibility requirement either, for the same reason
    /// [`Self::mul_real`] doesn't need one (see the module doc comment):
    /// the result's scale is simply the product of the two either way.
    /// Implemented the same way BGV/BFV's own real `mul_plain` are - wrap
    /// the plaintext's raw poly as a degree-`0` (single-component)
    /// ciphertext and reuse [`phantom_lattice::rlwe::Evaluator::mul`]'s
    /// generic degree handling, rather than a bespoke "scale every
    /// component" loop.
    pub fn mul_plain_real(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        let m = plaintext.poly().ok_or(SchemesError::InvalidParameters(
            "plaintext has no real ring representation - encode with encode_complex_real",
        ))?;
        if ciphertext.level() != plaintext.level() {
            return Err(SchemesError::DimensionMismatch);
        }
        let pt_as_ct = RlweCiphertext::new(vec![m.clone()]);
        let product = self.inner_at(ciphertext.level())?.mul(poly, &pt_as_ct)?;
        let degrade = mul_degrade_bits(
            self.degree(),
            ciphertext.scale().value(),
            ciphertext.precision().bits(),
            ASSUMED_REAL_MESSAGE_BOUND,
            plaintext.scale().value(),
            plaintext.precision().bits(),
            ASSUMED_REAL_MESSAGE_BOUND,
        );
        Ok(Ciphertext::new_real(
            product,
            Scale::new(ciphertext.scale().value() * plaintext.scale().value())?,
            ciphertext.level(),
            ciphertext
                .precision()
                .min(plaintext.precision())
                .degrade(degrade),
            ciphertext.degree(),
        ))
    }

    /// Multiplies two **real** ciphertexts (raw tensor product, no
    /// relinearization - see [`Self::relinearize_real`]) - see the module
    /// doc comment for why this needs no BFV-style rescale-and-round step.
    pub fn mul_real(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        self.check_binary(lhs, rhs)?;
        let (lhs_poly, rhs_poly) = (self.real_poly(lhs)?, self.real_poly(rhs)?);
        let product = self.inner_at(lhs.level())?.mul(lhs_poly, rhs_poly)?;
        let degrade = mul_degrade_bits(
            self.degree(),
            lhs.scale().value(),
            lhs.precision().bits(),
            ASSUMED_REAL_MESSAGE_BOUND,
            rhs.scale().value(),
            rhs.precision().bits(),
            ASSUMED_REAL_MESSAGE_BOUND,
        );
        Ok(Ciphertext::new_real(
            product,
            Scale::new(lhs.scale().value() * rhs.scale().value())?,
            lhs.level(),
            lhs.precision().min(rhs.precision()).degrade(degrade),
            lhs.degree() + rhs.degree(),
        ))
    }

    /// Relinearizes a degree-2 **real** ciphertext (e.g. [`Self::mul_real`]'s
    /// output) back to degree 1, using a key from
    /// [`super::CkksKeyGenerator::generate_hybrid_relinearization_key`].
    pub fn relinearize_real(
        &self,
        ciphertext: &Ciphertext,
        key: &phantom_lattice::rlwe::RelinearizationKey,
    ) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        let relinearized = self.inner_at(ciphertext.level())?.relinearize(poly, key)?;
        Ok(Ciphertext::new_real(
            relinearized,
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
            1,
        ))
    }

    /// Rotates a degree-1 **real** ciphertext's slots left by `shift`
    /// positions, using a key generated for
    /// [`super::CkksParams::rotation_element`]`(shift)` (e.g. from
    /// [`super::CkksKeyGenerator::generate_hybrid_galois_key`] directly, or
    /// via a downstream crate's own key generator built on top of it).
    /// See [`super::Encoder`]'s own module doc comment for why
    /// this is a clean per-slot rotation (not a permutation mixing in
    /// conjugates) precisely because `rotation_element` uses `5`-power
    /// indexing, and
    /// [`phantom_lattice::rlwe::Evaluator::apply_galois_automorphism`]'s
    /// own doc comment for the underlying key-switching mechanics. Errors
    /// if `ciphertext` isn't degree-1 (checked by `apply_galois_automorphism`
    /// itself) - matching [`Self::relinearize_real`]'s own precondition
    /// that its *input* be the right shape, this needs its *output* shape
    /// already reduced.
    pub fn rotate_real(
        &self,
        ciphertext: &Ciphertext,
        key: &phantom_lattice::rlwe::GaloisKey,
    ) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        let rotated = self
            .inner_at(ciphertext.level())?
            .apply_galois_automorphism(poly, key)?;
        Ok(Ciphertext::new_real(
            rotated,
            ciphertext.scale(),
            ciphertext.level(),
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }

    /// Conjugates a degree-1 **real** ciphertext's slots, using a key
    /// generated for [`super::CkksParams::conjugation_element`] - see
    /// [`Self::rotate_real`]'s own doc comment for the shared mechanics and
    /// preconditions.
    pub fn conjugate_real(
        &self,
        ciphertext: &Ciphertext,
        key: &phantom_lattice::rlwe::GaloisKey,
    ) -> Result<Ciphertext> {
        self.rotate_real(ciphertext, key)
    }

    /// Rescales a **real** ciphertext to the next level, dividing its
    /// tracked scale by the dropped modulus's own value - see the module
    /// doc comment for the algorithm.
    pub fn rescale_next_real(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        if ciphertext.level() == 0 {
            return Err(SchemesError::InvalidParameters(
                "cannot rescale at level zero",
            ));
        }
        let level_params = self.params.at_level(ciphertext.level())?;
        let moduli = level_params.ring().moduli();
        let q_basis = RnsBasis::new(moduli[..moduli.len() - 1].to_vec())?;
        let p_basis = RnsBasis::new(moduli[moduli.len() - 1..].to_vec())?;
        let q_last = moduli[moduli.len() - 1].value();

        let mut out = Vec::with_capacity(poly.value().len());
        for component in poly.value() {
            out.push(mod_down(component, &q_basis, &p_basis)?);
        }

        let new_scale = ciphertext.scale().value() / q_last as f64;
        let degrade = rescale_degrade_bits(
            self.degree(),
            ciphertext.scale().value(),
            ciphertext.precision().bits(),
            new_scale,
        );
        Ok(Ciphertext::new_real(
            RlweCiphertext::new(out),
            Scale::new(new_scale)?,
            ciphertext.level() - 1,
            ciphertext.precision().degrade(degrade),
            ciphertext.degree(),
        ))
    }

    /// Drops a **real** ciphertext's last RNS component from every
    /// component, *without* dividing scale or noise the way
    /// [`Self::rescale_next_real`] does - a plain
    /// [`phantom_ring::rns::rescale::drop_last_modulus`] applied to `c0`
    /// and `c1` each (the same operation `bgv::ModulusSwitcher::switch_secret_key`
    /// already uses for a secret key, here applied to a ciphertext
    /// instead). Needed for multi-level circuits (e.g. Horner-method
    /// polynomial evaluation) that must bring one ciphertext's *level*
    /// down to match another's without disturbing its *scale* - unlike
    /// `rescale_next_real`, which always changes both together.
    ///
    /// **Precondition, not checked here**: the ciphertext's true decrypted
    /// value must already fit within the *remaining* (smaller) modulus
    /// product - i.e. this is only valid for a ciphertext whose noise
    /// hasn't grown enough to need the dropped modulus's own headroom.
    /// Dropping a component from a ciphertext that doesn't satisfy this
    /// silently produces garbage (the same way any RNS modulus product
    /// too small for its own contents would) rather than erroring - the
    /// same caveat [`Self::rescale_next_real`]'s own sibling in
    /// `phantom_ring::rns::rescale` documents for `drop_last_modulus`
    /// generally. Precision is left unchanged (not degraded): assuming the
    /// precondition holds, decryption recovers exactly the same value as
    /// before dropping, since nothing about the represented value or its
    /// noise actually changed - only its own RNS representation shrank.
    pub fn drop_level_real(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        if ciphertext.level() == 0 {
            return Err(SchemesError::InvalidParameters(
                "cannot drop level at level zero",
            ));
        }
        let mut out = Vec::with_capacity(poly.value().len());
        for component in poly.value() {
            out.push(phantom_ring::rns::rescale::drop_last_modulus(component)?);
        }
        Ok(Ciphertext::new_real(
            RlweCiphertext::new(out),
            ciphertext.scale(),
            ciphertext.level() - 1,
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }

    /// Raises a **real**, level-zero ciphertext's modulus up to
    /// `target_level`, the first stage of real CKKS bootstrapping, before
    /// `phantom_bootstrapping::ckks::Bootstrapper::bootstrap_real`'s own
    /// pipeline (`CoeffsToSlots`/`EvalMod`/`SlotsToCoeffs`) can run on it.
    ///
    /// A ciphertext `(c0, c1)` at level `0` decrypts as `c0 + c1*s ≡ Δm + e
    /// (mod q0)`, `q0` its own single remaining modulus. This method leaves
    /// every coefficient of `c0`/`c1` numerically unchanged (their
    /// *centered*, signed, `|value| <= q0/2` representation) and simply
    /// re-embeds them into `target_level`'s much bigger modulus product `Q`, via
    /// [`phantom_ring::rns::extension::extend_basis_centered`] (*not*
    /// [`phantom_ring::rns::extension::extend_basis`], whose own
    /// non-negative `[0, Q_source)` reconstruction would offset every
    /// coefficient by up to the entirety of `q0` for a negative centered
    /// value - see that primitive's own doc comment for why the distinction
    /// matters here specifically).
    ///
    /// Since `Q >> q0 * N * ||s||_1` for any parameter set this crate
    /// generates, the *raw* (unreduced) integer value of `c0 + c1*s` is
    /// unchanged by moving to the bigger basis, and it no longer gets
    /// silently reduced mod `q0` the way it did before raising - so
    /// decrypting the raised ciphertext recovers `Δm + e + q0*I` for a
    /// **bounded** integer `I` (the same "unknown multiple of `q0`"
    /// `phantom_bootstrapping::ckks::EvalMod` is built to remove), rather
    /// than the correct `Δm + e` a non-exhausted ciphertext would
    /// give directly. `I`'s own bound follows from negacyclic convolution:
    /// `|c1*s|`'s raw coefficients are bounded by `||c1||_inf * ||s||_1 <=
    /// (q0/2) * h` (`h` = the secret's Hamming weight, `||s||_1` for a
    /// ternary secret), so `|raw(c0 + c1*s)| <= (q0/2)*(1+h)`, giving `|I|
    /// <= (h+2)/2` - verified numerically (Python, 400 randomized trials
    /// across several Hamming weights) before implementing, never exceeded
    /// (worst observed ratio to the bound: `~0.67`). This is why
    /// `BootstrapParams::raise_modulus` should be the ciphertext's own real
    /// `q0` (this evaluator's `at_level(0)` modulus), not a freely-chosen
    /// constant, and why `EvalMod::reduce_mod_q_real`'s own tight domain
    /// (`|I| <= 1`) only actually holds for a secret sparse enough that
    /// `(h+2)/2 <= 1` - i.e. `h <= 0` in the worst case, which no usable
    /// secret satisfies. Widening `EvalMod`'s domain to match a realistic
    /// secret's own Hamming weight (more Chebyshev terms, or an
    /// iterated-doubling reconstruction from a narrow base case) is a
    /// further, separate derivation, not attempted here - this method only
    /// builds the raise itself and documents the bound it produces.
    pub fn raise_level_real(
        &self,
        ciphertext: &Ciphertext,
        target_level: usize,
    ) -> Result<Ciphertext> {
        let poly = self.real_poly(ciphertext)?;
        if ciphertext.level() != 0 {
            return Err(SchemesError::InvalidParameters(
                "raise_level_real only accepts a level-zero ciphertext",
            ));
        }
        let source_basis = RnsBasis::new(self.params.at_level(0)?.ring().moduli().to_vec())
            .map_err(|_| SchemesError::InvalidParameters("invalid source basis"))?;
        let target_basis =
            RnsBasis::new(self.params.at_level(target_level)?.ring().moduli().to_vec())
                .map_err(|_| SchemesError::InvalidParameters("invalid target basis"))?;

        let mut out = Vec::with_capacity(poly.value().len());
        for component in poly.value() {
            out.push(phantom_ring::rns::extension::extend_basis_centered(
                component,
                &source_basis,
                &target_basis,
            )?);
        }
        Ok(Ciphertext::new_real(
            RlweCiphertext::new(out),
            ciphertext.scale(),
            target_level,
            ciphertext.precision(),
            ciphertext.degree(),
        ))
    }

    fn real_poly<'a>(&self, ciphertext: &'a Ciphertext) -> Result<&'a RlweCiphertext> {
        ciphertext.poly().ok_or(SchemesError::InvalidParameters(
            "ciphertext has no real ring representation - encrypt with Encryptor::encrypt_real",
        ))
    }

    /// Level/slot-count compatibility only - **not** scale, since CKKS
    /// multiplication (unlike addition) doesn't require matching operand
    /// scales: the result's scale is simply their product either way (see
    /// [`Self::mul`]/[`Self::mul_real`]). Callers that need addition's
    /// stricter "same scale" requirement call [`Self::check_scale`]
    /// themselves alongside this.
    fn check_binary(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<()> {
        self.check_ciphertext(lhs)?;
        self.check_ciphertext(rhs)?;
        if lhs.slots().len() != rhs.slots().len() || lhs.level() != rhs.level() {
            return Err(SchemesError::DimensionMismatch);
        }
        Ok(())
    }

    /// See [`Self::check_binary`]'s own doc comment for why this is a
    /// separate check rather than folded into it.
    fn check_scale(lhs: Scale, rhs: Scale) -> Result<()> {
        if !lhs.compatible(rhs) {
            return Err(SchemesError::InvalidParameters("scale mismatch"));
        }
        Ok(())
    }

    fn check_plain_binary(&self, lhs: &Ciphertext, rhs: &Plaintext) -> Result<()> {
        self.check_ciphertext(lhs)?;
        if lhs.slots().len() != rhs.slots().len() || lhs.level() != rhs.level() {
            return Err(SchemesError::DimensionMismatch);
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

/// The largest slot magnitude among `slots` - `0.0` for an empty slice,
/// which [`mul_degrade_bits`] handles without a special case (the
/// `noise*noise` cross term alone still bounds the result). Used by the
/// transparent scaffold's `mul`/`mul_plain`, which - unlike the real
/// path's `mul_real` - know their operands' actual values directly.
fn message_bound(slots: &[Complex64]) -> f64 {
    slots.iter().map(|c| c.re.hypot(c.im)).fold(0.0, f64::max)
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
