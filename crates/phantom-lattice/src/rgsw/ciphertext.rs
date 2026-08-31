//! RGSW ciphertext representation.

use rand_core::{CryptoRng, RngCore};

use phantom_ring::{reduce::mul_mod, Poly, Ring};

use crate::rgsw::{GadgetDecompositionParams, RgswKey};
use crate::rlwe::{Ciphertext, Encryptor, Plaintext, RlweParams};
use crate::Result;

/// Ring-GSW ciphertext: a real encrypted gadget matrix, the standard
/// GSW/RGSW construction (e.g. Gama-Izabachène-Nguyen-Xiao; the ring
/// variant used in FHEW/TFHE-style bootstrapping). For gadget base `B =
/// 2^base_log` and `levels` digits:
///
/// - `rows()[0][i] = RLWE_s(B^i * message)` for `i = 0..levels`
/// - `rows()[1][i] = RLWE_s(B^i * message * s)` for `i = 0..levels`
///
/// `external_product` gadget-decomposes an RLWE operand's `c0` and `c1`
/// against this same base and dot-products the digits against these two
/// blocks respectively - see `external_product.rs`'s doc comment for the
/// full derivation of why that recovers `RLWE_s(message * plaintext)`.
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
        let levels = decomposition_params.levels();
        let base_log = decomposition_params.base_log();
        let encryptor = Encryptor::with_secret_key(params.clone(), key.secret().clone());
        let s_times_m = ring.mul(key.secret().value(), message)?;

        let mut m_block = Vec::with_capacity(levels);
        let mut sm_block = Vec::with_capacity(levels);
        for level in 0..levels {
            let scaled_m = scale_by_base_power(ring, message, base_log, level)?;
            let scaled_sm = scale_by_base_power(ring, &s_times_m, base_log, level)?;

            let zero = Plaintext::new(ring.zero());
            let z = encryptor.encrypt(&zero, rng)?;
            let c0_m = ring.add(&z.value()[0], &scaled_m)?;
            m_block.push(Ciphertext::new(vec![c0_m, z.value()[1].clone()]));

            let zero_prime = Plaintext::new(ring.zero());
            let z_prime = encryptor.encrypt(&zero_prime, rng)?;
            let c0_sm = ring.add(&z_prime.value()[0], &scaled_sm)?;
            sm_block.push(Ciphertext::new(vec![c0_sm, z_prime.value()[1].clone()]));
        }

        Ok(Self {
            rows: [m_block, sm_block],
        })
    }

    /// Returns the two gadget-matrix blocks: `rows()[0]` encrypts `B^i *
    /// message`, `rows()[1]` encrypts `B^i * message * s`, both for `i =
    /// 0..levels`.
    pub fn rows(&self) -> &[Vec<Ciphertext>; 2] {
        &self.rows
    }
}

/// Scales `poly` by `B^level` per RNS component (`B = 2^base_log`),
/// matching exactly how [`crate::rgsw::GadgetDecomposition::recompose`]
/// computes the same weight (`(1 << shift) mod q`, via `u128` to avoid
/// overflow for large shifts) - consistency with that existing, tested
/// recomposition is what makes `B^i * message` mean the same thing on both
/// sides of the gadget decomposition.
fn scale_by_base_power(ring: &Ring, poly: &Poly, base_log: u32, level: usize) -> Result<Poly> {
    let shift = level as u32 * base_log;
    let mut coeffs = vec![vec![0u64; poly.degree()]; poly.moduli_count()];
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = modulus.value() as u128;
        let weight = ((1u128 << shift) % q) as u64;
        for (out, &c) in coeffs[j].iter_mut().zip(&poly.coeffs()[j]) {
            *out = mul_mod(c, weight, modulus.value());
        }
    }
    Ok(Poly::from_coeffs(coeffs)?)
}
