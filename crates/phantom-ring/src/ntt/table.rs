//! NTT table generation.

use crate::reduce::{inv_mod, mul_mod, pow_mod, BarrettReducer};
use crate::{Modulus, Result, RingError};

/// Roots needed for the initial CPU negacyclic NTT.
#[derive(Clone, Debug)]
pub struct NttTable {
    modulus: Modulus,
    degree: usize,
    psi: u64,
    omega: u64,
    inv_psi: u64,
    inv_omega: u64,
    inv_degree: u64,
    /// `psi_powers[j] = psi^j mod modulus`, precomputed once here instead of
    /// recomputing each `pow_mod(psi, j, q)` (an `O(log j)` computation) on
    /// every forward/inverse transform call - this turns the twist step's
    /// total cost from `O(n log n)` back down to the `O(n)` it should be,
    /// via one running-product pass at table-construction time.
    psi_powers: Vec<u64>,
    /// `inv_psi_powers[j] = psi^-j mod modulus`, same rationale as
    /// `psi_powers` but for the inverse transform's untwist step.
    inv_psi_powers: Vec<u64>,
    /// Precomputed [`BarrettReducer`] for `modulus`, reused for every
    /// multiplication the twist/butterfly steps perform against this table
    /// instead of re-deriving it (or falling back to division-based
    /// [`mul_mod`]) per call.
    reducer: BarrettReducer,
}

impl NttTable {
    /// Builds a table for one modulus and degree.
    pub fn new(degree: usize, modulus: Modulus) -> Result<Self> {
        if !modulus.supports_ntt(degree) {
            return Err(RingError::InvalidNttModulus {
                modulus: modulus.value(),
                two_n: 2 * degree,
            });
        }

        let q = modulus.value();
        let psi = primitive_root_of_order(2 * degree, q)?;
        let omega = mul_mod(psi, psi, q);
        let inv_psi = inv_mod(psi, q);
        let inv_omega = inv_mod(omega, q);
        let inv_degree = inv_mod(degree as u64, q);
        let psi_powers = power_table(psi, degree, q);
        let inv_psi_powers = power_table(inv_psi, degree, q);
        // Every valid Modulus (odd, > 1) is >= 3 >= 2, so BarrettReducer::new
        // cannot fail here - a valid Modulus can never hit its ModulusTooSmall
        // rejection.
        let reducer = BarrettReducer::new(q)?;

        Ok(Self {
            modulus,
            degree,
            psi,
            omega,
            inv_psi,
            inv_omega,
            inv_degree,
            psi_powers,
            inv_psi_powers,
            reducer,
        })
    }

    /// Returns the degree.
    pub const fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the modulus.
    pub const fn modulus(&self) -> Modulus {
        self.modulus
    }

    /// Returns the 2N-th root.
    pub const fn psi(&self) -> u64 {
        self.psi
    }

    /// Returns the N-th root.
    pub const fn omega(&self) -> u64 {
        self.omega
    }

    /// Returns inverse psi.
    pub const fn inv_psi(&self) -> u64 {
        self.inv_psi
    }

    /// Returns inverse omega.
    pub const fn inv_omega(&self) -> u64 {
        self.inv_omega
    }

    /// Returns inverse degree.
    pub const fn inv_degree(&self) -> u64 {
        self.inv_degree
    }

    /// Returns `psi^j mod modulus` for every `j` in `0..degree`.
    pub(crate) fn psi_powers(&self) -> &[u64] {
        &self.psi_powers
    }

    /// Returns `psi^-j mod modulus` for every `j` in `0..degree`.
    pub(crate) fn inv_psi_powers(&self) -> &[u64] {
        &self.inv_psi_powers
    }

    /// Returns the precomputed [`BarrettReducer`] for this table's modulus.
    pub(crate) fn reducer(&self) -> BarrettReducer {
        self.reducer
    }
}

/// Computes `[root^0, root^1, ..., root^(count-1)] mod modulus` via one
/// running-product pass (`O(count)` multiplications) rather than `count`
/// independent `pow_mod` calls (`O(count log count)` total).
fn power_table(root: u64, count: usize, modulus: u64) -> Vec<u64> {
    let mut powers = Vec::with_capacity(count);
    let mut current = 1u64;
    for _ in 0..count {
        powers.push(current);
        current = mul_mod(current, root, modulus);
    }
    powers
}

/// Finds an element of exact multiplicative order `order` (a power of two;
/// `NttTable::new`'s only caller always passes `2 * degree`) modulo
/// `modulus`, given `modulus.supports_ntt` has already confirmed `order`
/// divides `modulus - 1`.
///
/// Works by first raising a small candidate base `g` to the cofactor power
/// `k = (modulus - 1) / order`: since `g^(modulus-1) == 1 (mod modulus)`
/// (Fermat) for any `g` coprime to `modulus`, `h = g^k` automatically
/// satisfies `h^order == 1`, landing `h` inside the unique order-`order`
/// subgroup directly - no search over that subgroup's own (effectively
/// randomly scattered) elements is needed. The only thing left to check is
/// whether `h`'s order is the full `order` or a smaller power-of-two
/// divisor of it (`h^(order/2) == 1` catches every such case, since `order`
/// is a power of two), exactly as the direct search below already checks -
/// just applied to `h`, not to `g` itself. `g` only needs to range over a
/// handful of small integers for this to succeed (roughly half of all `g`
/// give an `h` of the exact right order), regardless of how large `modulus`
/// is - unlike a direct search for `h` over `2..modulus`, which is only
/// fast when `modulus` is close in size to `order` (every existing modulus
/// in this codebase happens to satisfy that, which is exactly why the
/// previous direct-search implementation here never surfaced its own
/// `O(modulus / order)` blowup until a real production-scale modulus - far
/// larger than `2 * degree` - was tried and it never returned; a
/// denial-of-service-shaped bug, not merely a slow one, found and fixed
/// directly rather than routed around).
fn primitive_root_of_order(order: usize, modulus: u64) -> Result<u64> {
    let order = order as u64;
    let cofactor = (modulus - 1) / order;
    // `SEARCH_LIMIT` bounds the (already near-certain-to-succeed-within-a-
    // handful-of-tries) search rather than leaving it fully unbounded, so a
    // modulus/order combination that somehow never yields a match fails
    // loudly instead of looping - and stays `<= modulus` for every modulus
    // this crate's own tests use below the limit, preserving their exact
    // prior search range.
    const SEARCH_LIMIT: u64 = 10_000;
    for candidate in 2..modulus.min(SEARCH_LIMIT) {
        let h = pow_mod(candidate, cofactor, modulus);
        if pow_mod(h, order, modulus) != 1 {
            continue;
        }
        if pow_mod(h, order / 2, modulus) == 1 {
            continue;
        }
        return Ok(h);
    }
    Err(RingError::MissingRoot(modulus))
}

#[cfg(test)]
mod tests {
    use super::{power_table, NttTable};
    use crate::reduce::pow_mod;
    use crate::Modulus;

    #[test]
    fn power_table_matches_independent_pow_mod_for_every_exponent() {
        let cases: [(u64, usize, u64); 4] = [(2, 8, 17), (3, 16, 97), (5, 32, 193), (7, 64, 769)];
        for (root, count, modulus) in cases {
            let table = power_table(root, count, modulus);
            assert_eq!(table.len(), count);
            for (j, &value) in table.iter().enumerate() {
                assert_eq!(
                    value,
                    pow_mod(root, j as u64, modulus),
                    "mismatch at j={j} for root={root}, modulus={modulus}"
                );
            }
        }
    }

    #[test]
    fn ntt_table_psi_powers_match_independent_pow_mod() {
        let cases: [(usize, u64); 3] = [(4, 17), (8, 97), (16, 193)];
        for (degree, modulus) in cases {
            let table = NttTable::new(degree, Modulus::new(modulus).unwrap()).unwrap();
            for j in 0..degree {
                assert_eq!(
                    table.psi_powers()[j],
                    pow_mod(table.psi(), j as u64, modulus),
                    "psi_powers mismatch at j={j}, degree={degree}, modulus={modulus}"
                );
                assert_eq!(
                    table.inv_psi_powers()[j],
                    pow_mod(table.inv_psi(), j as u64, modulus),
                    "inv_psi_powers mismatch at j={j}, degree={degree}, modulus={modulus}"
                );
            }
        }
    }
}
