//! BGV real relinearization: classical (power-of-base) gadget-decomposition
//! key-switching with `t`-scaled noise.
//!
//! [`phantom_lattice::rlwe`]'s real key-switching (RNS hybrid, the
//! technique Workstream 4 built and BFV's own real relinearization reuses
//! unmodified) can't be reused here even with `t`-scaled key-switching
//! noise: its `mod_down` step computes `floor(X/P)` for an accumulator `X`
//! split across two components (`acc_b`, `acc_a`) that only combine into
//! something congruent to the wanted value mod `t` *after* multiplying by
//! the secret `s_new` - information the evaluator performing key-switching
//! doesn't have. `floor` doesn't distribute over that sum, so the rounding
//! error `mod_down` introduces is small in magnitude but not generally a
//! multiple of `t`, corrupting BGV's exact mod-`t` decode. Confirmed
//! numerically (Python) before concluding the naive "just scale the
//! key-switching key's noise by `t`" fix doesn't work: the residual
//! relinearization introduces was small (e.g. `[21, 12, -21, -23]`) but not
//! `≡ 0 (mod t)` in 3 of 4 coefficients.
//!
//! Classical gadget decomposition sidesteps this entirely: it needs no
//! auxiliary modulus or division/rounding step at all (`c1 = sum_i B^i *
//! c1_i` is an *exact* integer identity, not an approximation), so `t`-scaled
//! fresh noise in the key-switching key's rows stays an exact multiple of
//! `t` all the way through key-switching, with no rounding step to corrupt
//! it. The tradeoff is a real one: more gadget levels than the RNS hybrid
//! technique needs (proportional to `log_B(Q)`, not the number of RNS
//! moduli), and picking too large a base `B` reintroduces the same kind of
//! problem in a different guise - a large digit multiplied against even a
//! *tiny* noise difference between two close values can amplify past `Q`
//! under the ring convolution (confirmed while deriving this: a `B = 2^20`
//! attempt failed outright, not just imprecisely, until switched to a small
//! base). Verified numerically (Python, 50 randomized trials, base `B = 16`
//! and `B = 4` both exact) before implementing - see `tests/phase5_bgv.rs`
//! for the Rust-level end-to-end regression coverage.
//!
//! Reuses [`GadgetDecomposition`]/[`GadgetDecompositionParams`] from
//! [`phantom_lattice::rgsw`] (built for RGSW's external product) rather
//! than a new decomposition implementation - this key only needs one
//! gadget block (`B^i * s_old`, not RGSW's two), so it's its own type
//! rather than a repurposed [`phantom_lattice::rgsw::RgswCiphertext`].

use phantom_lattice::rgsw::{GadgetDecomposition, GadgetDecompositionParams};
use phantom_lattice::rlwe::{Ciphertext, RlweParams, SecretKey};
use phantom_lattice::security::STANDARD_ERROR_STD_DEV;
use phantom_ring::reduce::mul_mod;
use phantom_ring::sampling::{sample_discrete_gaussian, sample_uniform};
use phantom_ring::{Poly, Ring};
use rand_core::{CryptoRng, RngCore};

use crate::Result;

/// BGV's own real relinearization key: `levels` rows, row `i` a real RLWE
/// ciphertext encrypting `B^i * s_old` (`B = 2^base_log`) under `s_new`,
/// with fresh noise scaled by the plaintext modulus `t`. See the module
/// doc comment for why this needs its own construction rather than reusing
/// [`phantom_lattice::rlwe`]'s generic RNS hybrid key-switching.
#[derive(Clone, Debug)]
pub struct BgvRelinearizationKey {
    decomposition_params: GadgetDecompositionParams,
    rows: Vec<Ciphertext>,
}

impl BgvRelinearizationKey {
    /// Generates a key from `s_old` (typically `s^2`, already in `params`'s
    /// own ring - no CRT lift needed, unlike the RNS hybrid technique's
    /// extended `QP` basis) to `s_new`, with fresh noise scaled by `t`.
    pub fn generate<R>(
        params: &RlweParams,
        s_old: &Poly,
        s_new: &SecretKey,
        decomposition_params: GadgetDecompositionParams,
        t: u64,
        rng: &mut R,
    ) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        let ring = params.ring();
        ring.check_poly(s_old)?;
        let levels = decomposition_params.levels();
        let base_log = decomposition_params.base_log();

        let mut rows = Vec::with_capacity(levels);
        for level in 0..levels {
            let scaled_s_old = scale_by_base_power(ring, s_old, base_log, level)?;
            let a = sample_uniform(ring, rng);
            let e = sample_discrete_gaussian(ring, rng, STANDARD_ERROR_STD_DEV);
            let t_e = ring.scalar_mul(&e, t)?;
            let a_s = ring.mul(&a, s_new.value())?;
            let b = ring.sub(&ring.add(&scaled_s_old, &t_e)?, &a_s)?;
            rows.push(Ciphertext::new(vec![b, a]));
        }

        Ok(Self {
            decomposition_params,
            rows,
        })
    }
}

/// Key-switches `poly` (typically a degree-2 ciphertext's `c2` component)
/// from `s_old` to `s_new` using `key`, returning the `(c0, c1)`
/// contributions to fold into the ciphertext being relinearized.
pub fn key_switch(poly: &Poly, key: &BgvRelinearizationKey, ring: &Ring) -> Result<(Poly, Poly)> {
    let decomposition = GadgetDecomposition::decompose(poly, key.decomposition_params)?;
    let digits = decomposition.digits();

    let mut acc_b = ring.zero();
    let mut acc_a = ring.zero();
    for (digit, row) in digits.iter().zip(&key.rows) {
        acc_b = ring.add(&acc_b, &ring.mul(digit, &row.value()[0])?)?;
        acc_a = ring.add(&acc_a, &ring.mul(digit, &row.value()[1])?)?;
    }
    Ok((acc_b, acc_a))
}

/// Scales `poly` by `B^level` (`B = 2^base_log`) per RNS component,
/// matching exactly how [`GadgetDecomposition::recompose`] and
/// [`phantom_lattice::rgsw::RgswCiphertext`]'s own (private) equivalent
/// compute the same weight (`(1 << shift) mod q`, via `u128` to avoid
/// overflow for large shifts).
fn scale_by_base_power(ring: &Ring, poly: &Poly, base_log: u32, level: usize) -> Result<Poly> {
    let shift = level as u32 * base_log;
    let mut coeffs = vec![vec![0u64; poly.degree()]; poly.moduli_count()];
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = u128::from(modulus.value());
        let weight = ((1u128 << shift) % q) as u64;
        for (out, &c) in coeffs[j].iter_mut().zip(&poly.coeffs()[j]) {
            *out = mul_mod(c, weight, modulus.value());
        }
    }
    Ok(Poly::from_coeffs(coeffs)?)
}
