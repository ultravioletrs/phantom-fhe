//! CKKS approximate encoders.
//!
//! [`Encoder::encode_complex_real`]/[`Encoder::decode_complex_real`] are the
//! **real** canonical-embedding encode/decode pair - unlike
//! [`Encoder::encode_complex`]/[`Encoder::decode_complex`] (transparent, no
//! real ring representation, kept unchanged so every existing caller keeps
//! compiling and behaving identically), these actually round-trip through
//! a `phantom_ring::Poly` the way real CKKS does.
//!
//! # Canonical embedding
//!
//! For `R = Z[X]/(X^N+1)`, the canonical embedding evaluates a polynomial
//! at `N` of the `2N`-th roots of unity `zeta^e` (`zeta = e^{i*pi/N}`),
//! one per odd residue `e` in a chosen set of `N` distinct odd residues
//! mod `2N`. Slot `j` (`j = 0..N/2`) is assigned exponent `g^j mod 2N` for
//! `g = 5` - not the simpler sequential `2j+1` an earlier version of this
//! encoder used. The reason: for `N` a power of two, `N >= 8`, `(Z/2N)*`
//! factors as `<g> x {+-1}` (`g = 5` generates the order-`N/2` factor,
//! disjoint from `{+-1}`; verified numerically, Python, for `N` in
//! `{8,16,32,64,128}` before relying on it - both the group-structure
//! claim itself and, concretely, that no odd `k` other than `1` and `g`
//! itself keeps every slot's exponent inside `<g>` under the *old*
//! sequential indexing, confirming that scheme couldn't support this).
//! Under `g`-power indexing, multiplying every exponent by `g^s` maps
//! slot `j`'s exponent to slot `(j+s) mod (N/2)`'s, so the ring
//! automorphism `X -> X^(g^s mod 2N)`
//! (`phantom_ring::Ring::apply_automorphism`) rotates slot `j` to slot
//! `(j+s) mod (N/2)` for *every* slot simultaneously, without pulling in
//! any conjugate - exactly the property real Galois-key-based ciphertext
//! rotation needs (`Evaluator::rotate_real`) and the old sequential
//! indexing provably lacked. `X -> X^(2N-1 mod 2N)` (`k = -1`) still
//! conjugates every slot either way, unaffected by this choice.
//!
//! Exponent `-g^j mod 2N` (the conjugate of slot `j`'s own `g^j`) is not
//! itself in `<g>` (since `-1 notin <g>`), so `<g>` and `-<g>` are
//! disjoint and together cover all `N` odd residues mod `2N` (same
//! numerical check above) - giving the `N` embedding coordinates encoding
//! needs, `N/2` "primary" (one per slot) and `N/2` their conjugates.
//!
//! **Encode**: given `N/2` slots `z`, form the length-`N` vector `y =
//! [z_0, ..., z_{N/2-1}, conj(z_0), ..., conj(z_{N/2-1})]` (position
//! `N/2+j` pairs with exponent `-g^j mod 2N`, the conjugate of position
//! `j`'s own `g^j` - a simpler, non-reversed pairing than sequential
//! indexing's; nothing outside encode/decode observes `y`'s own order, so
//! there's no compatibility reason to keep the old reversed one), scale
//! it by `Delta` (the plaintext's scale), and recover the (real, up to
//! floating-point error) coefficients via the closed-form inverse `m_k =
//! (1/N) * sum_a conj(zeta^(E[a]*k)) * y_a`, where `E[a]` is position
//! `a`'s own exponent (`g^a` for `a < N/2`, `-g^{a-N/2} mod 2N` above
//! that). The canonical embedding matrix `U` (`U[a][k] = zeta^(E[a]*k)`)
//! still satisfies `U * conj(U)^T = N * I` for this `E` - the
//! orthogonality argument only needs every pair `E[a]-E[b]` (`a != b`)
//! even and nonzero, true for *any* all-odd, pairwise-distinct exponent
//! set, not specifically the old sequential one - so `U^{-1} = (1/N) *
//! conj(U)^T` exactly, the same identity this encoder has always relied
//! on (verified numerically again for this `E` specifically, alongside
//! the encode/decode round trip and the rotation property itself, before
//! implementing). Each `m_k` is rounded to the nearest integer and
//! embedded into the ring's own RNS residues (negative values via `q -
//! |value|`, the same convention `bgv`/`bfv`'s own encoders use).
//!
//! **Decode**: reconstruct each coefficient's true signed value from its
//! RNS residues (`phantom_ring::rns::extension::reconstruct_centered_values`,
//! CRT-based, so it works across however many moduli the polynomial's own
//! ring level has), evaluate at the same embedding points (`y_j = sum_k
//! zeta^(g^j*k) * m_k` for `j = 0..N/2`), and divide by `Delta`.
//!
//! Conjugate-invariant CKKS (`N` real slots via a different ring
//! structure) isn't supported by the real path yet - `encode_complex_real`
//! rejects it explicitly rather than silently producing wrong results.
//! This is a straightforward `O(N^2)` evaluation (no NTT/FFT fast path),
//! matching this crate's existing "correctness first" primitives -
//! tracked as a future optimization, not attempted here.

use phantom_ring::rns::extension::reconstruct_centered_values;
use phantom_ring::{Poly, Ring, RnsBasis};

use super::{CkksParams, Complex64, Plaintext, Precision, Scale};
use crate::{Result, SchemesError};

/// CKKS encoder for complex and real vectors.
#[derive(Clone, Debug)]
pub struct Encoder {
    params: CkksParams,
}

impl Encoder {
    /// Creates an encoder.
    pub const fn new(params: CkksParams) -> Self {
        Self { params }
    }

    /// Returns the number of supported slots.
    pub fn slot_count(&self) -> usize {
        self.params.slot_count()
    }

    /// Encodes complex slots with the default scale.
    pub fn encode_complex(&self, values: &[Complex64]) -> Result<Plaintext> {
        if self.params.conjugate_invariant() && values.iter().any(|v| v.im != 0.0) {
            return Err(SchemesError::InvalidParameters(
                "conjugate-invariant CKKS accepts real slots only",
            ));
        }
        self.encode_complex_with_scale(values, self.params.default_scale())
    }

    /// Encodes real slots with the default scale.
    pub fn encode_real(&self, values: &[f64]) -> Result<Plaintext> {
        let values = values
            .iter()
            .copied()
            .map(Complex64::real)
            .collect::<Vec<_>>();
        self.encode_complex(&values)
    }

    /// Encodes complex slots with an explicit scale.
    pub fn encode_complex_with_scale(
        &self,
        values: &[Complex64],
        scale: Scale,
    ) -> Result<Plaintext> {
        if values.len() > self.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        if values
            .iter()
            .any(|v| !v.re.is_finite() || !v.im.is_finite())
        {
            return Err(SchemesError::InvalidParameters("CKKS slots must be finite"));
        }
        let precision = Precision::new(scale.value().log2().max(0.0));
        Ok(Plaintext::new(
            values.to_vec(),
            scale,
            self.params.initial_level(),
            precision,
        ))
    }

    /// Decodes complex slots.
    pub fn decode_complex(&self, plaintext: &Plaintext) -> Result<Vec<Complex64>> {
        if plaintext.slots().len() > self.slot_count() {
            return Err(SchemesError::InvalidSlotCount);
        }
        Ok(plaintext.slots().to_vec())
    }

    /// Decodes real slots.
    pub fn decode_real(&self, plaintext: &Plaintext) -> Result<Vec<f64>> {
        Ok(self
            .decode_complex(plaintext)?
            .into_iter()
            .map(|value| value.re)
            .collect())
    }

    /// Encodes complex slots as a **real** plaintext (canonical embedding,
    /// with the default scale) - see the module doc comment for the
    /// algorithm.
    pub fn encode_complex_real(&self, values: &[Complex64]) -> Result<Plaintext> {
        if self.params.conjugate_invariant() {
            return Err(SchemesError::InvalidParameters(
                "real CKKS encoding doesn't support conjugate-invariant packing yet",
            ));
        }
        let ring = self.params.ring();
        let n = ring.degree();
        let slot_count = n / 2;
        if values.len() > slot_count {
            return Err(SchemesError::InvalidSlotCount);
        }
        if values
            .iter()
            .any(|v| !v.re.is_finite() || !v.im.is_finite())
        {
            return Err(SchemesError::InvalidParameters("CKKS slots must be finite"));
        }

        let scale = self.params.default_scale();
        let mut padded = values.to_vec();
        padded.resize(slot_count, Complex64::default());
        let mut y = padded.clone();
        y.extend(padded.iter().map(|v| v.conj()));

        let powers = root_powers(n);
        let two_n = 2 * n;
        let delta = scale.value();
        let primary = embedding_exponents(n);

        let mut coeffs = Vec::with_capacity(n);
        for k in 0..n {
            let mut acc = Complex64::default();
            for (j, &y_j) in y.iter().enumerate() {
                let e = if j < slot_count {
                    primary[j]
                } else {
                    (two_n - primary[j - slot_count]) % two_n
                };
                let exp = (e * k) % two_n;
                let conj_root = powers[(two_n - exp) % two_n];
                acc = acc + conj_root * y_j;
            }
            let scaled = acc * Complex64::real(delta / n as f64);
            coeffs.push(scaled.re.round() as i128);
        }

        let poly = embed_signed_coeffs(&coeffs, ring)?;
        let precision = Precision::new(delta.log2().max(0.0));
        Ok(Plaintext::new_real(
            values.to_vec(),
            scale,
            self.params.initial_level(),
            precision,
            poly,
        ))
    }

    /// Decodes a **real** plaintext's complex slots - see the module doc
    /// comment for the algorithm.
    pub fn decode_complex_real(&self, plaintext: &Plaintext) -> Result<Vec<Complex64>> {
        let poly = plaintext.poly().ok_or(SchemesError::InvalidParameters(
            "plaintext has no real ring representation - encode with encode_complex_real",
        ))?;
        let ring = self.params.ring();
        let n = ring.degree();
        let moduli = &ring.moduli()[..poly.moduli_count()];
        let basis = RnsBasis::new(moduli.to_vec())?;
        let values = reconstruct_centered_values(poly, &basis)?;

        let powers = root_powers(n);
        let two_n = 2 * n;
        let delta = plaintext.scale().value();
        let slot_count = n / 2;
        let primary = embedding_exponents(n);

        let mut slots = Vec::with_capacity(slot_count);
        for &e_j in &primary {
            let mut acc = Complex64::default();
            for (k, &m_k) in values.iter().enumerate() {
                let exp = (e_j * k) % two_n;
                acc = acc + powers[exp] * Complex64::real(m_k as f64);
            }
            slots.push(acc * Complex64::real(1.0 / delta));
        }
        Ok(slots)
    }
}

/// Slot `j`'s own canonical-embedding exponent, `g^j mod 2N` for `g = 5` -
/// see the module doc comment for why `g`-power indexing, not sequential
/// `2j+1`, is what makes Galois-automorphism-based rotation
/// (`Evaluator::rotate_real`) work.
fn embedding_exponents(n: usize) -> Vec<usize> {
    let slot_count = n / 2;
    let two_n = 2 * n;
    let mut exponents = Vec::with_capacity(slot_count);
    let mut e = 1usize;
    for _ in 0..slot_count {
        exponents.push(e);
        e = (e * 5) % two_n;
    }
    exponents
}

/// Precomputed powers of the `2N`-th primitive root of unity `zeta =
/// e^{i*pi/N}`: `powers[k] = zeta^k` for `k = 0..2N`, built via one `O(N)`
/// running-product pass (rather than an `O(N)` `cos`/`sin` call per lookup)
/// - reused for every `(j, k)` pair the embedding matrix needs.
fn root_powers(n: usize) -> Vec<Complex64> {
    let two_n = 2 * n;
    let theta = core::f64::consts::PI / n as f64;
    let zeta = Complex64::new(theta.cos(), theta.sin());
    let mut powers = Vec::with_capacity(two_n);
    let mut current = Complex64::real(1.0);
    for _ in 0..two_n {
        powers.push(current);
        current = current * zeta;
    }
    powers
}

/// Embeds signed coefficients into `ring`'s own RNS residues, one modulus
/// at a time - `rem_euclid` gives a residue in `[0, q)` regardless of
/// sign, the same signed-embedding convention `bgv`/`bfv`'s own encoders
/// use (there via an explicit `q - magnitude` branch).
fn embed_signed_coeffs(coeffs: &[i128], ring: &Ring) -> Result<Poly> {
    let mut out = vec![vec![0u64; coeffs.len()]; ring.moduli().len()];
    for (j, modulus) in ring.moduli().iter().enumerate() {
        let q = i128::from(modulus.value());
        for (i, &c) in coeffs.iter().enumerate() {
            out[j][i] = c.rem_euclid(q) as u64;
        }
    }
    Ok(Poly::from_coeffs(out)?)
}
