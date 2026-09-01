//! BGV modulus-switching surface.
//!
//! Like [`super::Encryptor`], [`ModulusSwitcher`] has two coexisting modes.
//! [`ModulusSwitcher::switch_next`] is unchanged: a correctness scaffold
//! that preserves the ciphertext unchanged, kept so every existing caller
//! keeps compiling and behaving identically. [`ModulusSwitcher::switch_next_real`]
//! is new: genuine RNS modulus switching, dropping the ring's last modulus
//! `q_L` via [`phantom_ring::rns::rescale::modulus_switch_down`] - the
//! standard BGV technique that rescales each ciphertext component to stay
//! congruent to its original value mod the plaintext modulus `t` (so the
//! message is unchanged) while shrinking noise proportionally to `q_L`
//! (so it doesn't eventually overwhelm the ciphertext modulus after many
//! homomorphic operations). Since the result has one fewer RNS component,
//! decrypting it needs matching smaller-ring parameters and a matching
//! smaller-ring secret key - [`ModulusSwitcher::next_params`] and
//! [`ModulusSwitcher::switch_secret_key`] produce both.

use phantom_lattice::rlwe::SecretKey;
use phantom_ring::rns::rescale::{drop_last_modulus, modulus_switch_down};
use phantom_ring::{Degree, Modulus, Ring, RnsBasis};

use super::{BgvParams, Ciphertext};
use crate::Result;

/// Modulus-switching facade.
#[derive(Clone, Debug)]
pub struct ModulusSwitcher {
    params: BgvParams,
}

impl ModulusSwitcher {
    /// Creates a switcher.
    pub const fn new(params: BgvParams) -> Self {
        Self { params }
    }

    /// Switches to the next modulus level.
    ///
    /// This correctness scaffold preserves the ciphertext unchanged - kept
    /// for existing callers not yet migrated to
    /// [`Self::switch_next_real`]. See the module doc comment.
    pub fn switch_next(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        for component in ciphertext.inner().value() {
            self.params.ring().check_poly(component)?;
        }
        Ok(ciphertext.clone())
    }

    /// Performs real RNS modulus switching: drops the ring's last modulus,
    /// rescaling every ciphertext component to stay congruent to its
    /// original value mod the plaintext modulus. The result must be
    /// decrypted against [`Self::next_params`] and [`Self::switch_secret_key`]'s
    /// output, not the original params/secret key (their ring has one more
    /// modulus than the switched ciphertext now does).
    pub fn switch_next_real(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        let ring = self.params.ring();
        let q_basis = RnsBasis::new(ring.moduli().to_vec())?;
        let t = Modulus::new(self.params.plaintext_modulus())?;

        let mut out = Vec::with_capacity(ciphertext.inner().value().len());
        for component in ciphertext.inner().value() {
            ring.check_poly(component)?;
            out.push(modulus_switch_down(component, &q_basis, t)?);
        }
        Ok(Ciphertext::new(phantom_lattice::rlwe::Ciphertext::new(out)))
    }

    /// Parameters for the ciphertext [`Self::switch_next_real`] returns:
    /// the same ring with its last modulus dropped, same plaintext modulus.
    pub fn next_params(&self) -> Result<BgvParams> {
        let ring = self.params.ring();
        let moduli = ring.moduli();
        let degree = Degree::new(ring.degree())?;
        let next_ring = Ring::new(degree, moduli[..moduli.len() - 1].to_vec())?;
        BgvParams::new(next_ring, self.params.plaintext_modulus())
    }

    /// Drops a secret key's own last RNS component to match
    /// [`Self::next_params`]'s ring - a secret key isn't rescaled the way a
    /// ciphertext is (it has no "value mod t" to preserve), so this is a
    /// plain [`drop_last_modulus`], not [`modulus_switch_down`].
    pub fn switch_secret_key(&self, sk: &SecretKey) -> Result<SecretKey> {
        Ok(SecretKey::new(drop_last_modulus(sk.value())?))
    }
}
