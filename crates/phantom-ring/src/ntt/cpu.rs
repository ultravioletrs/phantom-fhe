//! CPU NTT backend.
//!
//! The forward/inverse negacyclic transform is: twist by powers of `ψ`,
//! run a standard radix-2 cyclic NTT with `ω = ψ²` (the textbook iterative
//! Cooley-Tukey butterfly network, O(N log N)), then - for the inverse -
//! scale by `N⁻¹` and untwist by powers of `ψ⁻¹`. The twist/untwist steps
//! now use [`NttTable`]'s precomputed `psi_powers`/`inv_psi_powers` (an `O(n)`
//! running-product table, built once per table) instead of an independent
//! `pow_mod(psi, j, q)` call per coefficient (`O(n log n)` total) - same
//! values, computed once instead of `n` times. Every multiplication in the
//! twist step and the butterfly network itself routes through the table's
//! precomputed [`crate::reduce::BarrettReducer`] instead of division-based
//! [`mul_mod`], with the same defensive `< modulus` guard `Ring`'s own
//! `mul_residue` helper uses (`Poly`'s type doesn't guarantee coefficients
//! are already reduced, so the guard - not just the reducer's own
//! precondition - is what keeps this correct for any input).
//! Correctness rests on two independent checks:
//! `tests/phase2.rs::ntt_multiplication_matches_schoolbook` compares against
//! `Ring::schoolbook_mul`, a structurally unrelated direct negacyclic
//! multiplication, and `ntt_round_trip_*` checks forward/inverse consistency
//! across many degrees and moduli - both passed unchanged through this
//! rewrite, since it changes performance, not results.

use crate::ntt::backend::NttBackend;
use crate::ntt::table::NttTable;
use crate::reduce::{add_mod, mul_mod, pow_mod, sub_mod, BarrettReducer};
use crate::{Poly, Result, Ring};

/// Multiplies two residues modulo `modulus`, using `reducer`'s fast path when
/// both operands are already `< modulus` and falling back to division-based
/// [`mul_mod`] otherwise - the same defensive pattern `Ring`'s own
/// `mul_residue` helper uses, needed for the same reason: nothing in
/// [`Poly`]'s type guarantees a coefficient is already reduced.
fn mul_residue(reducer: BarrettReducer, a: u64, b: u64, modulus: u64) -> u64 {
    if a < modulus && b < modulus {
        reducer.reduce(a as u128 * b as u128)
    } else {
        mul_mod(a, b, modulus)
    }
}

/// Baseline CPU backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuNttBackend;

impl NttBackend for CpuNttBackend {
    fn forward(&self, ring: &Ring, poly: &mut Poly) -> Result<()> {
        ring.check_poly(poly)?;
        for (j, modulus) in ring.moduli().iter().enumerate() {
            let table = NttTable::new(ring.degree(), *modulus)?;
            forward_transform_in_place(&mut poly.coeffs_mut()[j], &table);
        }
        Ok(())
    }

    fn inverse(&self, ring: &Ring, poly: &mut Poly) -> Result<()> {
        ring.check_poly(poly)?;
        for (j, modulus) in ring.moduli().iter().enumerate() {
            let table = NttTable::new(ring.degree(), *modulus)?;
            inverse_transform_in_place(&mut poly.coeffs_mut()[j], &table);
        }
        Ok(())
    }
}

/// Forward transform for one RNS component, entirely in place: no
/// allocation. `pub(crate)` so `Ring` can reuse a precomputed [`NttTable`]
/// across many multiplications instead of rebuilding one (a primitive-root
/// search) per call, the way [`NttBackend::forward`] does for the
/// single-shot API. Safe to run the twist step in place because each
/// coefficient's twisted value depends only on that same coefficient's own
/// input value - nothing here reads a value after another iteration has
/// already overwritten it.
pub(crate) fn forward_transform_in_place(buf: &mut [u64], table: &NttTable) {
    let n = table.degree();
    let q = table.modulus().value();
    let reducer = table.reducer();
    let psi_powers = table.psi_powers();
    for j in 0..n {
        buf[j] = mul_residue(reducer, buf[j], psi_powers[j], q);
    }
    radix2_ntt_inplace(buf, table.omega(), reducer, q);
}

/// Forward transform for one RNS component, reading `input` and writing the
/// result into `out` (which must have length `table.degree()`) - used where
/// the input must be preserved (e.g. [`Ring::mul`](crate::ring::Ring::mul),
/// which still needs `lhs`'s original coefficients after transforming a
/// separate scratch buffer for `rhs`).
pub(crate) fn forward_component_into(input: &[u64], table: &NttTable, out: &mut [u64]) {
    out.copy_from_slice(input);
    forward_transform_in_place(out, table);
}

/// Inverse transform for one RNS component, entirely in place: no
/// allocation. See [`forward_transform_in_place`] for why this is sound
/// in place, and [`NttBackend::inverse`] / [`Ring::mul`](crate::ring::Ring::mul)
/// for its two call sites.
pub(crate) fn inverse_transform_in_place(buf: &mut [u64], table: &NttTable) {
    let q = table.modulus().value();
    let reducer = table.reducer();
    let inv_psi_powers = table.inv_psi_powers();
    radix2_ntt_inplace(buf, table.inv_omega(), reducer, q);
    for (j, slot) in buf.iter_mut().enumerate() {
        let scaled = mul_residue(reducer, *slot, table.inv_degree(), q);
        *slot = mul_residue(reducer, scaled, inv_psi_powers[j], q);
    }
}

/// In-place radix-2 cyclic NTT: the standard iterative decimation-in-time
/// Cooley-Tukey butterfly network (bit-reverse permute, then `log2(n)`
/// butterfly stages), evaluating `a` at powers of `root` (an `n`-th root of
/// unity mod `q`). `a.len()` must be a power of two. `reducer` must be for
/// modulus `q` - every multiplication in the butterfly stages routes through
/// it (via [`mul_residue`]) instead of division-based [`mul_mod`].
///
/// Running this same function with `root = ω⁻¹` computes `n` times the
/// inverse transform (by the standard NTT/DFT duality: applying the forward
/// structure with the inverse root, then scaling by `n⁻¹`, recovers the
/// original sequence) - [`inverse_transform_in_place`] above does exactly
/// that scaling itself, so this function has no separate "inverse" variant.
fn radix2_ntt_inplace(a: &mut [u64], root: u64, reducer: BarrettReducer, q: u64) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros();
    bit_reverse_permute(a, log_n);

    let mut m = 2usize;
    while m <= n {
        let w_m = pow_mod(root, (n / m) as u64, q);
        let mut k = 0;
        while k < n {
            let mut w = 1u64;
            for j in 0..m / 2 {
                let t = mul_residue(reducer, w, a[k + j + m / 2], q);
                let u = a[k + j];
                a[k + j] = add_mod(u, t, q);
                a[k + j + m / 2] = sub_mod(u, t, q);
                w = mul_residue(reducer, w, w_m, q);
            }
            k += m;
        }
        m *= 2;
    }
}

fn bit_reverse_permute(a: &mut [u64], log_n: u32) {
    for i in 0..a.len() {
        let j = reverse_bits(i, log_n);
        if j > i {
            a.swap(i, j);
        }
    }
}

fn reverse_bits(mut x: usize, bits: u32) -> usize {
    let mut result = 0usize;
    for _ in 0..bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::radix2_ntt_inplace;
    use crate::reduce::{mul_mod, BarrettReducer};

    /// Hand-derived reference: q=5, n=4, ω=2 (order 4 in (Z/5)*), input
    /// [1,2,3,4] transforms to [0,4,3,2] by direct evaluation
    /// `A[k] = sum_j a[j]*omega^(j*k) mod q`; verified by hand before this
    /// implementation was written, independent of `radix2_ntt_inplace`.
    #[test]
    fn radix2_ntt_matches_hand_computed_reference() {
        let mut a = [1u64, 2, 3, 4];
        let reducer = BarrettReducer::new(5).unwrap();
        radix2_ntt_inplace(&mut a, 2, reducer, 5);
        assert_eq!(a, [0, 4, 3, 2]);
    }

    #[test]
    fn radix2_ntt_matches_direct_dft_for_random_cases() {
        // Independent O(n^2) direct evaluation, not sharing any code with
        // radix2_ntt_inplace, as the correctness oracle.
        fn direct_dft(a: &[u64], root: u64, q: u64) -> Vec<u64> {
            let n = a.len();
            (0..n)
                .map(|k| {
                    let mut acc = 0u64;
                    for (j, &value) in a.iter().enumerate() {
                        let mut root_pow = 1u64;
                        for _ in 0..(j * k) % n {
                            root_pow = mul_mod(root_pow, root, q);
                        }
                        acc = crate::reduce::add_mod(acc, mul_mod(value, root_pow, q), q);
                    }
                    acc
                })
                .collect()
        }

        // (degree, prime modulus with modulus = 1 mod 2*degree). Roots are
        // sourced from NttTable::omega() - the crate's own verified
        // primitive-root search - rather than hand-picked, so this test
        // never depends on an unverified claim about a specific root's order.
        let cases: [(usize, u64); 4] = [
            (4, 17),   // 17 - 1 = 16, divisible by 2*4
            (8, 97),   // 96, divisible by 2*8
            (16, 193), // 192, divisible by 2*16
            (32, 257), // 256, divisible by 2*32
        ];

        for (n, q) in cases {
            let table =
                crate::ntt::table::NttTable::new(n, crate::Modulus::new(q).expect("valid modulus"))
                    .expect("modulus supports NTT at this degree");
            let root = table.omega();

            let mut rng_state = q.wrapping_mul(0x9E3779B97F4A7C15) ^ n as u64;
            let a: Vec<u64> = (0..n)
                .map(|_| {
                    rng_state ^= rng_state >> 12;
                    rng_state ^= rng_state << 25;
                    rng_state ^= rng_state >> 27;
                    rng_state % q
                })
                .collect();

            let expected = direct_dft(&a, root, q);
            let mut actual = a.clone();
            radix2_ntt_inplace(&mut actual, root, table.reducer(), q);
            assert_eq!(actual, expected, "mismatch for n={n}, q={q}, root={root}");
        }
    }
}
