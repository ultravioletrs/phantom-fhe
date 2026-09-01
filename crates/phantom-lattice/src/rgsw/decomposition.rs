//! Gadget decomposition over RNS polynomials.
//!
//! # RNS soundness
//!
//! For a ring with more than one RNS modulus, a coefficient's true value
//! `x` is only known through its *residues* `x mod q_0`, `x mod q_1`, ...,
//! `x mod q_{L-1}` - there is no single small representation of `x` to
//! bit-slice directly. [`GadgetDecomposition::decompose`] therefore treats
//! *each RNS modulus as its own gadget level*: for modulus `q_j`, the
//! coefficient's own `q_j`-residue (already the size of `q_j`, no CRT
//! ambiguity - it's a single, ordinary small-ish integer at that point) is
//! further split into `levels` base-`B` digits (`B = 2^base_log`), exactly
//! as before but confined to that one modulus. Each digit is then embedded
//! *consistently* across every output RNS component (`digit mod q_i` for
//! every `i`) - unlike bit-slicing each component's own residue
//! independently (the previous, unsound approach: two different numbers,
//! not a shared small value), this makes every digit a genuine
//! CRT-coherent representation of one plain, bounded integer.
//!
//! [`GadgetDecomposition::recompose`] (and, symmetrically, any caller
//! baking gadget-level scaling into key material - see
//! `phantom-schemes::bgv::relinearization` and
//! [`crate::rgsw::RgswCiphertext::encrypt`]) needs the standard CRT
//! reconstruction identity `sum_j G_j * (x mod q_j) ≡ x (mod Q)`, where
//! `G_j` is [`phantom_ring::rns::extension::crt_lift_constant`]'s own
//! output for modulus index `j` - the "gadget vector" entry for level `j`
//! is therefore `B^level * G_j`, not just `B^level` the way a single-modulus
//! ring's gadget vector is. For a genuinely single-modulus ring, `G_0 == 1`
//! always (there is nothing else to CRT-lift against), so this reduces
//! *exactly* to the previous, always-correct single-modulus behavior - a
//! backward-compatible generalization, not a behavior change for existing
//! single-modulus callers. Verified (Python, before implementing): 100
//! randomized trials of the full decompose/key-material/recombine identity
//! across 2-4 moduli and varying bases, plus 200 trials of the plain
//! decompose/recompose round trip including the single-modulus case.

use phantom_ring::reduce::{add_mod, mul_mod};
use phantom_ring::rns::extension::crt_lift_constant;
use phantom_ring::{Modulus, Poly, RnsBasis};

use crate::{LatticeError, Result};

/// Gadget decomposition parameters - `base_log`/`levels` apply *per RNS
/// modulus* (see the module doc comment), so a polynomial with `n` moduli
/// decomposes into `n * levels` digits, not `levels`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GadgetDecompositionParams {
    base_log: u32,
    levels: usize,
}

impl GadgetDecompositionParams {
    /// Creates decomposition parameters.
    pub fn new(base_log: u32, levels: usize) -> Result<Self> {
        if base_log == 0 || base_log >= 63 {
            return Err(LatticeError::InvalidParameters("base_log must be in 1..63"));
        }
        if levels == 0 {
            return Err(LatticeError::InvalidParameters("levels must be non-zero"));
        }
        Ok(Self { base_log, levels })
    }

    /// Returns the base bit length.
    pub const fn base_log(self) -> u32 {
        self.base_log
    }

    /// Returns the number of levels per RNS modulus.
    pub const fn levels(self) -> usize {
        self.levels
    }

    /// Returns the base.
    pub const fn base(self) -> u64 {
        1u64 << self.base_log
    }
}

/// Gadget decomposition of a polynomial - see the module doc comment for
/// why this is RNS-modulus-aware rather than a flat, ring-size-agnostic
/// digit list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GadgetDecomposition {
    params: GadgetDecompositionParams,
    modulus_count: usize,
    /// `digits[modulus_index * params.levels() + level]`.
    digits: Vec<Poly>,
}

impl GadgetDecomposition {
    /// Decomposes `poly` (whose own RNS components must match `moduli`)
    /// into `moduli.len() * params.levels()` digits - see the module doc
    /// comment for the algorithm and why this needs `moduli` explicitly
    /// (unlike bit-slicing a single value, embedding a digit consistently
    /// across every output component needs to know each one's own modulus).
    pub fn decompose(
        poly: &Poly,
        params: GadgetDecompositionParams,
        moduli: &[Modulus],
    ) -> Result<Self> {
        if poly.moduli_count() != moduli.len() {
            return Err(LatticeError::DimensionMismatch);
        }
        let mask = params.base() - 1;
        let degree = poly.degree();
        let n_moduli = moduli.len();
        let mut digits = Vec::with_capacity(n_moduli * params.levels());

        for source_component in poly.coeffs() {
            for level in 0..params.levels() {
                let shift = level as u32 * params.base_log();
                let mut coeffs = vec![vec![0u64; degree]; n_moduli];
                for (coeff_index, &coeff) in source_component.iter().enumerate() {
                    let digit_value = (coeff >> shift) & mask;
                    for (out_component, out_modulus) in coeffs.iter_mut().zip(moduli) {
                        out_component[coeff_index] = digit_value % out_modulus.value();
                    }
                }
                digits.push(Poly::from_coeffs(coeffs)?);
            }
        }

        Ok(Self {
            params,
            modulus_count: n_moduli,
            digits,
        })
    }

    /// Returns decomposition digits, ordered `modulus_index * levels() +
    /// level` - the same order [`Self::recompose`] and any caller pairing
    /// digits against per-`(modulus, level)` key material (e.g.
    /// `bgv::relinearization::key_switch`, [`crate::rgsw::external_product()`])
    /// must iterate in.
    pub fn digits(&self) -> &[Poly] {
        &self.digits
    }

    /// Returns the number of RNS moduli `self` was decomposed against.
    pub const fn modulus_count(&self) -> usize {
        self.modulus_count
    }

    /// Reconstructs the original polynomial modulo the provided RNS moduli
    /// (must match what [`Self::decompose`] was called with) - see the
    /// module doc comment for the CRT-lift identity this relies on.
    pub fn recompose(&self, moduli: &[Modulus]) -> Result<Poly> {
        if moduli.len() != self.modulus_count {
            return Err(LatticeError::DimensionMismatch);
        }
        let levels = self.params.levels();
        if self.digits.len() != self.modulus_count * levels {
            return Err(LatticeError::InvalidParameters(
                "digit count doesn't match modulus_count * levels",
            ));
        }
        let Some(first) = self.digits.first() else {
            return Err(LatticeError::InvalidParameters(
                "missing decomposition digits",
            ));
        };
        let degree = first.degree();
        let source_basis = RnsBasis::new(moduli.to_vec())?;

        let mut coeffs = vec![vec![0u64; degree]; moduli.len()];
        for modulus_index in 0..self.modulus_count {
            let lift = crt_lift_constant(&source_basis, modulus_index, moduli)?;
            for level in 0..levels {
                let digit = &self.digits[modulus_index * levels + level];
                let shift = level as u32 * self.params.base_log();
                for (j, modulus) in moduli.iter().enumerate() {
                    let q = modulus.value() as u128;
                    let weight = ((1u128 << shift) % q) as u64;
                    let scale = mul_mod(weight, lift[j], modulus.value());
                    for (out_coeff, &digit_coeff) in coeffs[j].iter_mut().zip(&digit.coeffs()[j]) {
                        let term = mul_mod(digit_coeff, scale, modulus.value());
                        *out_coeff = add_mod(*out_coeff, term, modulus.value());
                    }
                }
            }
        }

        Ok(Poly::from_coeffs(coeffs)?)
    }
}
