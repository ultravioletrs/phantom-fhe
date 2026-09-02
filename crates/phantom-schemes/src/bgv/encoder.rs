//! BGV batching encoder.
//!
//! [`BatchEncoder::encode_u64`]/[`decode_u64`](BatchEncoder::decode_u64)
//! pack raw integers directly into a plaintext polynomial's own
//! coefficients - correct arithmetic (BGV's plaintext ring operations are
//! genuinely coefficient-wise mod `t`), but *not* genuine SIMD batching:
//! each "slot" is really just one coefficient, and real BGV ciphertext
//! multiplication is negacyclic *ring* convolution across every
//! coefficient jointly, not elementwise - so a circuit evaluator that
//! treats these as independent per-slot values has no real-ciphertext
//! equivalent (see `phantom-circuits`' own `PolynomialEvaluator`/
//! `LinearTransformEvaluator` for BGV/BFV, which are still transparent-only
//! for exactly this reason).
//!
//! [`BatchEncoder::encode_batched`]/[`decode_batched`](BatchEncoder::decode_batched)
//! are the real technique: CRT-based plaintext batching, exact algebraic
//! evaluation (no rounding, unlike CKKS's own floating-point canonical
//! embedding), giving genuine independent SIMD slots that real ciphertext
//! multiplication correctly treats elementwise. `R_t = Z_t[X]/(X^N+1)`
//! splits as `Z_t^N` (via CRT / the Chinese Remainder Theorem) exactly
//! when `t` is prime and `t ≡ 1 (mod 2N)` - the same "NTT-friendly
//! modulus" condition [`phantom_ring::ntt::NttTable`] already requires for
//! *ciphertext* moduli, applied here to the *plaintext* modulus instead
//! (checked by [`phantom_ring::ntt::NttTable::new`] itself, which this
//! rejects through if it fails). Concretely: `X^N+1`'s `N` roots in `Z_t`
//! are exactly the odd powers of a primitive `2N`-th root of unity `psi`
//! (`negacyclic_forward`/`negacyclic_inverse`'s own contract - see their
//! doc comments), so evaluating a degree-`<N` polynomial at those `N`
//! points is a bijection between coefficients and `N` independent values
//! mod `t`.
//!
//! Slots are laid out as `2` "rows" of `N/2`, the standard structure (also
//! used by e.g. SEAL's own `BatchEncoder`): row `0`, slot `j`, is assigned
//! embedding exponent `5^j mod 2N`; row `1`, slot `j`, gets `-5^j mod 2N`
//! (`row1_exponents`'s own construction) - `5`-power indexing, the same
//! choice [`crate::ckks::Encoder`]'s own module doc comment derives
//! and justifies for CKKS (`(Z/2N)* = <5> x {+-1}` for `N` a power of two
//! `>= 8`), reused here because it gives the same payoff: the ring
//! automorphism `X -> X^(5^shift mod 2N)` cyclically rotates *both* rows by
//! `shift` simultaneously (multiplying every exponent by `5^shift` maps row
//! `r`, slot `j`'s exponent to row `r`, slot `(j+shift) mod (N/2)`'s, for
//! both rows at once, since `-1` commutes with multiplication), and `X ->
//! X^(2N-1 mod 2N)` (`k = -1`) swaps the two rows entirely (row `0`'s `5^j`
//! becomes row `1`'s own `-5^j`, and vice versa) - unlike CKKS, row `1`
//! isn't forced to be any function of row `0` (no conjugate-symmetry
//! constraint applies to a finite-field encoding), so this genuinely packs
//! `N` *independent* slots, not `N/2`. Verified numerically (Python, `(N,
//! t)` in `{(8,97), (8,193), (16,257)}`, all three properties: round trip,
//! every row-rotation shift, and the row swap) before implementing.

use phantom_lattice::rlwe;
use phantom_ring::ntt::{negacyclic_forward, negacyclic_inverse, NttTable};
use phantom_ring::Modulus;

use super::{BgvParams, Plaintext};
use crate::{Result, SchemesError};

/// Coefficient-batching encoder for exact integers modulo `t` - see the
/// module doc comment for the two encoding modes this offers.
#[derive(Clone, Debug)]
pub struct BatchEncoder {
    params: BgvParams,
}

impl BatchEncoder {
    /// Creates an encoder.
    pub const fn new(params: BgvParams) -> Self {
        Self { params }
    }

    /// Returns the number of supported slots.
    pub fn slot_count(&self) -> usize {
        self.params.slot_count()
    }

    /// Encodes unsigned integers modulo the plaintext modulus.
    pub fn encode_u64(&self, values: &[u64]) -> Result<Plaintext> {
        if values.len() > self.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }

        let ring = self.params.ring();
        let t = self.params.plaintext_modulus();
        let mut poly = ring.zero();
        for component_index in 0..poly.moduli_count() {
            let q = ring.moduli()[component_index].value();
            for (slot, value) in values.iter().copied().enumerate() {
                poly.coeffs_mut()[component_index][slot] = (value % t) % q;
            }
        }
        Ok(Plaintext::new(rlwe::Plaintext::new(poly)))
    }

    /// Decodes all slots as unsigned integers modulo the plaintext modulus.
    pub fn decode_u64(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        self.params.ring().check_poly(plaintext.inner().value())?;
        let first_component = plaintext
            .inner()
            .value()
            .component(0)
            .ok_or(SchemesError::DimensionMismatch)?;
        let q = self.params.ring().moduli()[0].value();
        let t = self.params.plaintext_modulus();
        Ok(first_component
            .iter()
            .map(|coeff| decode_signed_residue(*coeff, q, t))
            .collect())
    }

    /// Encodes `values` (up to [`Self::slot_count`] of them, zero-padded)
    /// via genuine CRT-based SIMD batching - see the module doc comment for
    /// the algorithm and slot layout. Errors if the plaintext modulus
    /// doesn't support an NTT at this degree (`t` must be prime and `t ≡ 1
    /// mod 2*degree` - see [`phantom_ring::ntt::NttTable::new`]).
    pub fn encode_batched(&self, values: &[u64]) -> Result<Plaintext> {
        if values.len() > self.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        let ring = self.params.ring();
        let n = ring.degree();
        let t = self.params.plaintext_modulus();
        let table = NttTable::new(n, Modulus::new(t)?)?;
        let exponents = slot_exponents(n);

        let mut sequential = vec![0u64; n];
        for (slot, &value) in values.iter().enumerate() {
            sequential[sequential_position(exponents[slot])] = value % t;
        }
        negacyclic_inverse(&mut sequential, &table)?;

        let mut poly = ring.zero();
        for component_index in 0..poly.moduli_count() {
            let q = ring.moduli()[component_index].value();
            for (i, &coeff) in sequential.iter().enumerate() {
                poly.coeffs_mut()[component_index][i] = coeff % q;
            }
        }
        Ok(Plaintext::new(rlwe::Plaintext::new(poly)))
    }

    /// Decodes all slots from a CRT-batched plaintext - the exact inverse
    /// of [`Self::encode_batched`].
    pub fn decode_batched(&self, plaintext: &Plaintext) -> Result<Vec<u64>> {
        self.params.ring().check_poly(plaintext.inner().value())?;
        let ring = self.params.ring();
        let n = ring.degree();
        let t = self.params.plaintext_modulus();
        let table = NttTable::new(n, Modulus::new(t)?)?;

        let first_component = plaintext
            .inner()
            .value()
            .component(0)
            .ok_or(SchemesError::DimensionMismatch)?;
        let q = ring.moduli()[0].value();
        let mut sequential: Vec<u64> = first_component
            .iter()
            .map(|coeff| decode_signed_residue(*coeff, q, t))
            .collect();
        negacyclic_forward(&mut sequential, &table)?;

        let exponents = slot_exponents(n);
        Ok(exponents
            .iter()
            .map(|&e| sequential[sequential_position(e)])
            .collect())
    }
}

/// Slot `j`'s own canonical-embedding-style exponent - see the module doc
/// comment for the two-row layout and why `5`-power indexing (row `0`)
/// paired with its negation (row `1`) is what this crate uses.
fn slot_exponents(n: usize) -> Vec<usize> {
    let half = n / 2;
    let two_n = 2 * n;
    let mut row0 = Vec::with_capacity(half);
    let mut e = 1usize;
    for _ in 0..half {
        row0.push(e);
        e = (e * 5) % two_n;
    }
    let mut exponents = row0.clone();
    exponents.extend(row0.iter().map(|&x| (two_n - x) % two_n));
    exponents
}

/// The sequential position `i` (`0..n`) [`negacyclic_forward`]/
/// [`negacyclic_inverse`] assign embedding exponent `2i+1` to - the inverse
/// of that assignment, needed to place/read a slot's own (generally
/// non-sequential) exponent at the right index in the buffer those
/// functions operate on.
const fn sequential_position(exponent: usize) -> usize {
    (exponent - 1) / 2
}

fn decode_signed_residue(coeff: u64, modulus: u64, plaintext_modulus: u64) -> u64 {
    if coeff <= modulus / 2 {
        coeff % plaintext_modulus
    } else {
        let magnitude = (modulus - coeff) % plaintext_modulus;
        if magnitude == 0 {
            0
        } else {
            plaintext_modulus - magnitude
        }
    }
}
