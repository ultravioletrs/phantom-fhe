//! CKKS coefficients-to-slots transform scaffold, plus a real (encrypted)
//! evaluator ([`CoeffsToSlots::apply_real`]).

use std::f64::consts::PI;

use phantom_circuits::ckks::{DftDirection, DftEvaluator, LinearTransformEvaluator};
use phantom_circuits::common::LinearTransform;
use phantom_lattice::rlwe::GaloisKey;
use phantom_schemes::ckks::{Ciphertext, Complex64, Evaluator};

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Coefficients-to-slots transform.
#[derive(Clone, Debug)]
pub struct CoeffsToSlots {
    params: BootstrapParams,
    dft: DftEvaluator,
}

impl CoeffsToSlots {
    /// Creates a coefficients-to-slots transform.
    pub fn new(params: BootstrapParams) -> Self {
        let dft = DftEvaluator::new(params.ckks_params().clone());
        Self { params, dft }
    }

    /// Applies the transparent transform.
    pub fn apply(&self, input: &Ciphertext) -> Result<Ciphertext> {
        check_slots(&self.params, input)?;
        self.dft
            .transform(input, DftDirection::Forward)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))
    }

    /// Applies the **real** (encrypted) forward transform - unlike the
    /// transparent scaffold above (a generic size-`n` DFT over whatever the
    /// ciphertext's own canonical-embedding slots currently are), this is
    /// the operation real CKKS bootstrapping's own CoeffToSlot step
    /// performs (Cheon-Han-Kim-Kim-Song, EUROCRYPT 2018, Section 5.1):
    /// "putting polynomial coefficients in plaintext slots" - taking a
    /// ciphertext whose raw ring coefficients are `t_0, ..., t_{N-1}` (what
    /// `phantom_schemes::ckks::Evaluator::raise_level_real` actually
    /// perturbs) and producing **two** new ciphertexts whose own slots hold
    /// those `N` raw coefficients directly, `N/2` per ciphertext - not the
    /// canonical embedding of the wraparound (which is a generic complex
    /// number for a generic integer wraparound polynomial, confirmed
    /// directly by testing the earlier generic-DFT-based version against a
    /// genuine `raise_level_real` output: some slot values came back as
    /// non-integer multiples of the raise modulus, which no domain-widening
    /// could fix, because the operation itself was wrong, not merely
    /// underscoped).
    ///
    /// Let `z' = tau(ciphertext)` be the ciphertext's own current
    /// canonical-embedding slot vector (`tau` the same map
    /// `phantom_schemes::ckks::Encoder::decode_complex_real` computes) and
    /// `U` the `(N/2) x N` canonical-embedding Vandermonde matrix (`U[j][k]
    /// = zeta_j^k`, `zeta_j` the same `5^j`-power roots
    /// `phantom_schemes::ckks::encoder`'s own module doc comment derives).
    /// Split `U` into its left and right `(N/2) x (N/2)` halves `U_0`, `U_1`
    /// (this module's own `u0_u1_matrices`). The paper's own identity
    /// (verified numerically, Python, before implementing: given `t`'s own
    /// raw coefficients, `z'_0 = (1/N)(conj(U_0)^T . z' + U_0^T . conj(z'))`
    /// exactly equals `(t_0, ..., t_{N/2-1})`, real-valued to float
    /// precision, and likewise `z'_1` for the second half, with the inverse
    /// identity `z' = U_0 . z'_0 + U_1 . z'_1` also verified exact) is a
    /// `z -> A.z + B.conj(z)` general linear transform - computed here via
    /// two [`LinearTransformEvaluator::apply_real`] calls (one against
    /// `ciphertext`, one against its conjugate) plus an `add_real`, for
    /// each of the two output ciphertexts.
    ///
    /// `galois_keys` must contain one real [`GaloisKey`] per rotation
    /// offset `1..n` (`n = slot_count`), the same requirement
    /// [`LinearTransformEvaluator::apply_real`] itself documents -
    /// `conjugation_key` must be a real [`GaloisKey`] for
    /// [`phantom_schemes::ckks::CkksParams::conjugation_element`], both
    /// generated at `ciphertext`'s own level. Costs one rescale (all four
    /// underlying `apply_real` calls run as parallel branches from
    /// `ciphertext`'s/its conjugate's own starting level, the same "doesn't
    /// stack" reasoning `EvalMod::reduce_mod_q_real_wide`'s own doc comment
    /// gives for its `sin`/`cos` branches), so both outputs land at
    /// `ciphertext.level() - 1`.
    pub fn apply_real(
        &self,
        ciphertext: &Ciphertext,
        galois_keys: &[GaloisKey],
        conjugation_key: &GaloisKey,
    ) -> Result<(Ciphertext, Ciphertext)> {
        let n = self.params.ckks_params().slot_count();
        let (a0, b0, a1, b1) = coeffs_to_slots_matrices(n);
        let lintrans = LinearTransformEvaluator::new(self.params.ckks_params().clone());
        let evaluator = Evaluator::new(self.params.ckks_params().clone());

        let conj_ct = evaluator
            .conjugate_real(ciphertext, conjugation_key)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;

        let diag_a0 = lintrans
            .diagonalize(&a0)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        let diag_b0 = lintrans
            .diagonalize(&b0)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        let diag_a1 = lintrans
            .diagonalize(&a1)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        let diag_b1 = lintrans
            .diagonalize(&b1)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;

        let term_a0 = lintrans
            .apply_real(ciphertext, &diag_a0, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        let term_b0 = lintrans
            .apply_real(&conj_ct, &diag_b0, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        let z0 = evaluator
            .add_real(&term_a0, &term_b0)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;

        let term_a1 = lintrans
            .apply_real(ciphertext, &diag_a1, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        let term_b1 = lintrans
            .apply_real(&conj_ct, &diag_b1, galois_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;
        let z1 = evaluator
            .add_real(&term_a1, &term_b1)
            .map_err(|_| BootstrappingError::CircuitOperation("coefficients-to-slots"))?;

        Ok((z0, z1))
    }
}

pub(crate) fn check_slots(params: &BootstrapParams, input: &Ciphertext) -> Result<()> {
    if input.slots().len() > params.ckks_params().slot_count() {
        return Err(BootstrappingError::DimensionMismatch);
    }
    if params.ckks_params().conjugate_invariant() && input.slots().iter().any(|slot| slot.im != 0.0)
    {
        return Err(BootstrappingError::InvalidParameters(
            "conjugate-invariant CKKS accepts real slots only",
        ));
    }
    Ok(())
}

/// Builds the dense `n x n` DFT matrix [`DftEvaluator::transform`] computes
/// directly (`M[k][j] = scale * exp(i*sign*2*pi*j*k/n)`, `sign = -1`/scale
/// `= 1` for [`DftDirection::Forward`], `sign = 1`/scale `= 1/n` for
/// [`DftDirection::Inverse`]) - the transparent scaffold's own transform,
/// unrelated to [`CoeffsToSlots::apply_real`]'s own (correct, but
/// different) construction above - kept only for
/// [`DftEvaluator::transform`]'s own transparent callers.
#[allow(dead_code)]
pub(crate) fn dft_matrix(n: usize, direction: DftDirection) -> LinearTransform<Complex64> {
    let sign = match direction {
        DftDirection::Forward => -1.0,
        DftDirection::Inverse => 1.0,
    };
    let scale = match direction {
        DftDirection::Forward => 1.0,
        DftDirection::Inverse => 1.0 / n as f64,
    };
    let mut rows = vec![vec![Complex64::default(); n]; n];
    for (k, row) in rows.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            let angle = sign * 2.0 * PI * (j * k) as f64 / n as f64;
            *entry = Complex64::new(angle.cos(), angle.sin()) * Complex64::real(scale);
        }
    }
    LinearTransform::dense(rows).expect("n x n rows is always square")
}

/// Slot `j`'s own canonical-embedding exponent, `5^j mod 2N` (`N = 2*n`) -
/// the *same* sequence `phantom_schemes::ckks::encoder`'s own (private)
/// `embedding_exponents` computes, reimplemented locally since this crate
/// is a different crate than `phantom-schemes` and that helper isn't part
/// of its public API (a small, self-contained enough sequence that
/// duplicating it here is simpler than widening `phantom-schemes`'s own
/// surface for it).
fn embedding_exponents(n: usize) -> Vec<usize> {
    // `n` here is the *slot count*; the exponent group has order `2N =
    // 4*n` (`N = 2*n` the ring degree) - `phantom_schemes::ckks::encoder`'s
    // own `embedding_exponents` takes `n` as the ring degree directly and
    // computes this same modulus as `2*n` there, which is `4*slot_count`
    // once translated to this function's own `n` = slot-count convention.
    let two_ring_degree = 4 * n;
    let mut exponents = Vec::with_capacity(n);
    let mut e = 1usize;
    for _ in 0..n {
        exponents.push(e);
        e = (e * 5) % two_ring_degree;
    }
    exponents
}

/// `zeta_j = zeta^{embedding_exponents(n)[j]}` for `zeta = exp(i*pi/N)`
/// (`N = 2*n` the ring degree, `n` = slot count) - the `n`
/// canonical-embedding roots [`coeffs_to_slots_matrices`] builds its
/// Vandermonde matrix from. `zeta` has order `2N = 4*n` (a `2N`-th root of
/// unity), so the precomputed power table needs `4*n` entries, not `2*n` -
/// found directly (a transparent, unencrypted round-trip test of the
/// matrices alone failing with a period-`2` pattern in its output, tracing
/// to `embedding_exponents`'s own modulus and this table both being half
/// the size they needed, before this method was ever wired into a real
/// ciphertext at all).
fn embedding_roots(n: usize) -> Vec<Complex64> {
    let ring_degree = 2 * n;
    let two_ring_degree = 4 * n;
    let theta = PI / ring_degree as f64;
    let zeta = Complex64::new(theta.cos(), theta.sin());
    let mut powers = Vec::with_capacity(two_ring_degree);
    let mut current = Complex64::real(1.0);
    for _ in 0..two_ring_degree {
        powers.push(current);
        current = current * zeta;
    }
    embedding_exponents(n)
        .into_iter()
        .map(|e| powers[e])
        .collect()
}

/// Builds `(A_0, B_0, A_1, B_1)` for [`CoeffsToSlots::apply_real`]'s own
/// `z'_k = (1/N)(conj(U_k)^T . z' + U_k^T . conj(z'))` identity (`N = 2*n`,
/// [`CoeffsToSlots::apply_real`]'s own doc comment). `U` is the `n x (2n)`
/// canonical-embedding Vandermonde matrix (`U[j][k] = zeta_j^k`,
/// [`embedding_roots`]); `U_0`/`U_1` are its left/right `n x n` halves.
/// `A_k = conj(U_k)^T / N`, `B_k = U_k^T / N`.
pub(crate) fn coeffs_to_slots_matrices(
    n: usize,
) -> (
    LinearTransform<Complex64>,
    LinearTransform<Complex64>,
    LinearTransform<Complex64>,
    LinearTransform<Complex64>,
) {
    let roots = embedding_roots(n);
    let big_n = 2.0 * n as f64;
    let inv_n = Complex64::real(1.0 / big_n);

    let mut a0 = vec![vec![Complex64::default(); n]; n];
    let mut b0 = vec![vec![Complex64::default(); n]; n];
    let mut a1 = vec![vec![Complex64::default(); n]; n];
    let mut b1 = vec![vec![Complex64::default(); n]; n];
    for row in 0..n {
        // row `r` of `A_k = conj(U_k)^T / N` is column `r` of `conj(U_k)`,
        // i.e. entry `(row=r, col=j)` is `conj(U_k[j][r]) / N`.
        for col in 0..n {
            let u0_j_r = pow_root(&roots, col, row);
            let u1_j_r = pow_root(&roots, col, n + row);
            a0[row][col] = u0_j_r.conj() * inv_n;
            b0[row][col] = u0_j_r * inv_n;
            a1[row][col] = u1_j_r.conj() * inv_n;
            b1[row][col] = u1_j_r * inv_n;
        }
    }
    (
        LinearTransform::dense(a0).expect("n x n rows is always square"),
        LinearTransform::dense(b0).expect("n x n rows is always square"),
        LinearTransform::dense(a1).expect("n x n rows is always square"),
        LinearTransform::dense(b1).expect("n x n rows is always square"),
    )
}

/// Builds `(U_0, U_1)` for [`super::SlotsToCoeffs::apply_real`]'s own
/// inverse identity `z' = U_0 . z0 + U_1 . z1` - the same `U`'s left/right
/// `n x n` halves [`coeffs_to_slots_matrices`] builds `A_k`/`B_k` from, but
/// unconjugated/untransposed (used directly, not `conj(...)^T`).
pub(crate) fn u0_u1_matrices(n: usize) -> (LinearTransform<Complex64>, LinearTransform<Complex64>) {
    let roots = embedding_roots(n);
    let mut u0 = vec![vec![Complex64::default(); n]; n];
    let mut u1 = vec![vec![Complex64::default(); n]; n];
    for row in 0..n {
        for col in 0..n {
            u0[row][col] = pow_root(&roots, row, col);
            u1[row][col] = pow_root(&roots, row, n + col);
        }
    }
    (
        LinearTransform::dense(u0).expect("n x n rows is always square"),
        LinearTransform::dense(u1).expect("n x n rows is always square"),
    )
}

/// `zeta_j^k` for `zeta_j = roots[j]`, `k` in `0..2n` (a full turn of the
/// `2N`-th root) - `k` can exceed `roots.len()` (`U_1`'s own columns range
/// over `n..2n`), so this multiplies out directly rather than indexing a
/// precomputed power table sized only for `U_0`.
fn pow_root(roots: &[Complex64], j: usize, k: usize) -> Complex64 {
    let mut acc = Complex64::real(1.0);
    let mut base = roots[j];
    let mut exp = k;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base;
        }
        base = base * base;
        exp >>= 1;
    }
    acc
}
