//! RGSW ciphertext representation.

use rand_core::{CryptoRng, RngCore};

use phantom_ring::reduce::mul_mod;
use phantom_ring::rns::extension::crt_lift_constant;
use phantom_ring::{Poly, Ring, RnsBasis};

use crate::rgsw::{GadgetDecompositionParams, RgswKey};
use crate::rlwe::{Ciphertext, Encryptor, Plaintext, RlweParams};
use crate::Result;

/// Ring-GSW ciphertext: a real encrypted gadget matrix, the standard
/// GSW/RGSW construction (e.g. Gama-Izabachène-Nguyen-Xiao; the ring
/// variant used in FHEW/TFHE-style bootstrapping). For gadget base `B =
/// 2^base_log`, `levels` digits *per RNS modulus* `q_j`, and CRT lift
/// constants `G_j` (see `decomposition.rs`'s own module doc comment for why
/// a multi-modulus ring needs these at all):
///
/// - `rows()[0][j*levels+i] = RLWE_s(B^i * G_j * message)`
/// - `rows()[1][j*levels+i] = RLWE_s(B^i * G_j * message * s)`
///
/// For a single-modulus ring `G_0 == 1` always, so this is exactly the
/// previous `RLWE_s(B^i * message)` construction - no behavior change for
/// existing single-modulus callers.
///
/// `external_product` gadget-decomposes an RLWE operand's `c0` and `c1`
/// against this same base/levels/moduli and dot-products the digits against
/// these two blocks respectively - see `external_product.rs`'s doc comment
/// for the full derivation of why that recovers `RLWE_s(message *
/// plaintext)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RgswCiphertext {
    rows: [Vec<Ciphertext>; 2],
}

impl RgswCiphertext {
    /// Encrypts `message` under `key` as a real gadget matrix.
    pub fn encrypt<R>(
        params: &RlweParams,
        message: &Poly,
        key: &RgswKey,
        decomposition_params: GadgetDecompositionParams,
        rng: &mut R,
    ) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        params.ring().check_poly(message)?;
        let ring = params.ring();
        let moduli = ring.moduli();
        let source_basis = RnsBasis::new(moduli.to_vec())?;
        let levels = decomposition_params.levels();
        let base_log = decomposition_params.base_log();
        let encryptor = Encryptor::with_secret_key(params.clone(), key.secret().clone());
        let s_times_m = ring.mul(key.secret().value(), message)?;

        let total_rows = moduli.len() * levels;
        let mut m_block = Vec::with_capacity(total_rows);
        let mut sm_block = Vec::with_capacity(total_rows);
        for modulus_index in 0..moduli.len() {
            let lift = crt_lift_constant(&source_basis, modulus_index, moduli)?;
            for level in 0..levels {
                let scaled_m = scale_by_base_power_and_lift(ring, message, base_log, level, &lift)?;
                let scaled_sm =
                    scale_by_base_power_and_lift(ring, &s_times_m, base_log, level, &lift)?;

                let zero = Plaintext::new(ring.zero());
                let z = encryptor.encrypt(&zero, rng)?;
                let c0_m = ring.add(&z.value()[0], &scaled_m)?;
                m_block.push(Ciphertext::new(vec![c0_m, z.value()[1].clone()]));

                let zero_prime = Plaintext::new(ring.zero());
                let z_prime = encryptor.encrypt(&zero_prime, rng)?;
                let c0_sm = ring.add(&z_prime.value()[0], &scaled_sm)?;
                sm_block.push(Ciphertext::new(vec![c0_sm, z_prime.value()[1].clone()]));
            }
        }

        Ok(Self {
            rows: [m_block, sm_block],
        })
    }

    /// Returns the two gadget-matrix blocks, ordered `modulus_index *
    /// levels + level` (see [`Self`]'s own doc comment) - the same order
    /// [`crate::rgsw::external_product()`] pairs against
    /// [`crate::rgsw::GadgetDecomposition::digits`].
    pub fn rows(&self) -> &[Vec<Ciphertext>; 2] {
        &self.rows
    }
}

/// Scales `poly` by `B^level * lift[j]` per RNS component `j` (`B =
/// 2^base_log`) - `lift` is the CRT lift constant for one RNS modulus
/// (`phantom_ring::rns::extension::crt_lift_constant`'s own output,
/// reduced into every component `j`), matching exactly how
/// [`crate::rgsw::GadgetDecomposition::recompose`] weights each
/// `(modulus, level)` digit block. For a single-modulus ring `lift == [1]`
/// always, so this reduces to the previous plain `B^level` scaling.
fn scale_by_base_power_and_lift(
    ring: &Ring,
    poly: &Poly,
    base_log: u32,
    level: usize,
    lift: &[u64],
) -> Result<Poly> {
    let shift = level as u32 * base_log;
    let mut coeffs = vec![vec![0u64; poly.degree()]; poly.moduli_count()];
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value() as u128;
        let weight = ((1u128 << shift) % q) as u64;
        let scale = mul_mod(weight, lift[j], modulus.value());
        for (out, &c) in coeffs[j].iter_mut().zip(&poly.coeffs()[j]) {
            *out = mul_mod(c, scale, modulus.value());
        }
    }
    Ok(Poly::from_coeffs(coeffs)?)
}
