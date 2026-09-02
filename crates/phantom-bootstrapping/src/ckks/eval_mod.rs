//! CKKS eval-mod scaffold.
//!
//! Real CKKS bootstrapping's "eval-mod" stage removes an unknown multiple
//! of the ciphertext's own lowest modulus `q_0` that "raising" the
//! ciphertext into a bigger working modulus introduces: after
//! [`super::CoeffsToSlots::apply`], each slot holds (approximately) `m_j +
//! q_0*I_j` for the true message `m_j` (assumed bounded, `|m_j| <<
//! q_0/2`) and some unknown but *bounded* integer `I_j`. Reducing each
//! slot mod `q_0`, centered, recovers `m_j` - the standard technique
//! (Cheon-Han-Kim-Kim-Song and follow-ups) approximates this centered
//! mod-`q_0` reduction with a low-degree polynomial (often built from
//! `sin`/`cos`), but the *exact* operation it approximates is precisely
//! `phantom_circuits::ckks::Mod1Evaluator::centered_fractional_part`'s
//! own `x - round(x)` ("mod 1", centered) - scaled by `q_0`:
//! `q_0 * centered_fractional_part(x / q_0)`.
//!
//! [`Mod1Evaluator::centered_fractional_part`] itself only ever computes
//! the *unscaled* `x - round(x)` (correct for its own direct callers,
//! which operate on already-bounded-by-one inputs) - calling it directly
//! on [`super::CoeffsToSlots::apply`]'s own output, whose magnitude has no
//! relationship to `1`, would silently corrupt any message not already in
//! `(-0.5, 0.5)` (confirmed directly: this crate's own pre-existing test,
//! `eval_mod_exposes_centered_fractional_part_without_forcing_bootstrap_to_change_messages`,
//! is named specifically to document that exposing it wasn't the same as
//! wiring it in unscaled). [`EvalMod::reduce_mod_q`] is the scaled
//! version [`super::Bootstrapper::bootstrap`] actually needs, verified
//! numerically (Python, 20000 randomized trials, `|m| < 0.4*q`, real and
//! complex) before implementing - real and imaginary parts reduced
//! independently, since a genuine complex slot's own real/imaginary
//! "wraparound" integers are themselves independent.

use phantom_circuits::ckks::{Mod1Evaluator, PolynomialEvaluator};
use phantom_lattice::rlwe::RelinearizationKey;
use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64, Encoder, Evaluator, Plaintext};

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Base (`q`-independent) coefficients `c_0..c_17` of the degree-`17` odd
/// polynomial approximating `sin(2*pi*y)` over `y in [-domain, domain]`
/// (`domain = 1.03`) - see this module's own doc comment for the
/// derivation and [`EvalMod::reduce_mod_q_real_wide`] for how `q` and a
/// wider effective domain (via `COS_APPROX_BASE_COEFFICIENTS` and
/// repeated angle-doubling) fold in. Fit via Chebyshev interpolation at
/// Chebyshev-Gauss-Lobatto nodes (numerically stable, unlike a direct
/// monomial-basis least-squares fit - tried first, at a lower degree, and
/// gave wildly wrong results even before considering accuracy, confirmed by
/// the fitted even coefficients coming out non-zero where they should
/// vanish by symmetry). The even coefficients here are hardcoded to exactly
/// `0.0` rather than the fit's own `~1e-10` residuals (`sin` is odd and the
/// domain is symmetric, so they're zero by construction, not merely small).
/// Degree `17`, not the smaller degree an accurate-enough single fit could
/// use alone, specifically so this doubles as angle-doubling's own narrow
/// base case: `reduce_mod_q_real_wide`'s error, after `r` doublings,
/// depends on this base fit's *own* absolute error (each doubling step can
/// amplify it, see that method's own doc comment) - degree `9` gave `~3%`
/// relative error at `r=0` but degraded past `50%` by `r=2`; this degree
/// keeps the base fit within `~1e-7` of true `sin`, verified numerically
/// (Python) to keep the *doubled* result within `~0.6%` relative error
/// uniformly for `r` up to at least `5` (`I` bounds up to `32`), not just
/// `r=0`.
const SIN_APPROX_BASE_COEFFICIENTS: [f64; 18] = [
    0.0,
    6.28318511331201,
    0.0,
    -41.34167572349246,
    0.0,
    81.60464300886207,
    0.0,
    -76.70045166748498,
    0.0,
    42.03422437982965,
    0.0,
    -15.031626795888672,
    0.0,
    3.72306020800866,
    0.0,
    -0.6290793751166195,
    0.0,
    0.05772088671127302,
];

/// Companion `cos(2*pi*y)` approximation to `SIN_APPROX_BASE_COEFFICIENTS`,
/// using the same domain and Chebyshev-Gauss-Lobatto fitting method, and
/// deliberately fit at the exact same degree (`17`, one more than a plain
/// `cos` fit would need - its own leading, degree-`17` coefficient is `0`
/// by symmetry, kept explicit rather than trimmed) so that evaluating both
/// via [`PolynomialEvaluator::evaluate_encrypted`] costs the same number of
/// Horner multiplications and lands both results at the *same* ciphertext
/// level - required by [`EvalMod::reduce_mod_q_real_wide`]'s own
/// angle-doubling step, which multiplies the two together.
const COS_APPROX_BASE_COEFFICIENTS: [f64; 18] = [
    0.9999994434710392,
    0.0,
    -19.73913267412058,
    0.0,
    64.93765269487787,
    0.0,
    -85.44127093762133,
    0.0,
    60.17420520219993,
    0.0,
    -26.244483976410248,
    0.0,
    7.623112583348767,
    0.0,
    -1.4552184283313552,
    0.0,
    0.1451361911635973,
    0.0,
];

/// Eval-mod circuit scaffold.
#[derive(Clone, Debug)]
pub struct EvalMod {
    params: BootstrapParams,
    mod1: Mod1Evaluator,
}

impl EvalMod {
    /// Creates an eval-mod circuit.
    pub fn new(params: BootstrapParams) -> Self {
        let mod1 = Mod1Evaluator::new(params.ckks_params().clone());
        Self { params, mod1 }
    }

    /// Applies centered mod-one directly (`x - round(x)`, **not** scaled
    /// by [`BootstrapParams::raise_modulus`]) - exposed standalone for
    /// direct callers that already have a bounded-by-one input, but *not*
    /// what [`super::Bootstrapper::bootstrap`] itself uses (see
    /// [`Self::reduce_mod_q`] and this module's own doc comment for why).
    pub fn centered_fractional_part(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let _ = &self.params;
        self.mod1
            .centered_fractional_part(input)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))
    }

    /// Transparent eval-mod used by the correctness scaffold to preserve messages.
    pub fn preserve_message(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let _ = &self.params;
        Ok(input.clone())
    }

    /// Removes an unknown multiple of [`BootstrapParams::raise_modulus`]
    /// (`q`) from every slot, real and imaginary parts independently:
    /// `q * centered_fractional_part(x / q)` - see this module's own doc
    /// comment for the derivation and why this, not
    /// [`Self::centered_fractional_part`] directly, is the real-CKKS-style
    /// eval-mod operation [`super::Bootstrapper::bootstrap`] uses.
    pub fn reduce_mod_q(&self, input: &Ciphertext) -> Result<Ciphertext> {
        let q = self.params.raise_modulus();
        let slots = input
            .slots()
            .iter()
            .map(|slot| Complex64::new(reduce_mod(slot.re, q), reduce_mod(slot.im, q)))
            .collect();
        Ok(Ciphertext::new(
            slots,
            input.scale(),
            input.level(),
            input.precision(),
            input.degree(),
        ))
    }

    /// Homomorphically-evaluable, polynomial-approximated version of
    /// [`Self::reduce_mod_q`], using `SIN_APPROX_BASE_COEFFICIENTS`'s own
    /// pre-fit approximation of `sin(2*pi*x/q)` - see this module's own
    /// doc comment for the derivation and accuracy this needs, and
    /// [`PolynomialEvaluator::evaluate_encrypted`] for the Horner-method
    /// evaluation itself. Unlike `reduce_mod_q` (transparent
    /// `f64::round()`, correct for any bounded wraparound and message
    /// magnitude under `q/2`), this needs a much tighter message bound
    /// (`|m| < 0.03*q`, not `0.4*q`) and wraparound range (`|I| <= 1`, not
    /// `reduce_mod_q`'s unrestricted bound) - an inherent property of the
    /// sin-linearization/polynomial-approximation technique real CKKS
    /// bootstrapping uses (the linear approximation `sin(2*pi*z) ~ 2*pi*z`
    /// this is ultimately built on only holds for `z` well inside
    /// `(-0.5, 0.5)`), not an implementation shortcut.
    ///
    /// Also unlike `reduce_mod_q`, this only correctly handles
    /// **real-valued** messages (every slot's imaginary part already `0`):
    /// evaluating a real-coefficient polynomial at a genuinely complex
    /// input mixes real and imaginary parts through the odd-power cross
    /// terms (e.g. `(a+bi)^3`'s real part depends on `b` too), so this does
    /// *not* reduce real/imaginary parts independently the way
    /// `reduce_mod_q` does. Extracting real/imaginary parts homomorphically
    /// first (via `conjugate_real`: `Re = (z + conj(z))/2`, `Im = (z -
    /// conj(z))/(2i)`) and reducing each separately would remove this
    /// restriction - not attempted here.
    ///
    /// `input` is explicitly pre-scaled by `1/q` (one `mul_plain_real` +
    /// `rescale_next_real`) *before* `evaluate_encrypted` runs
    /// `SIN_APPROX_BASE_COEFFICIENTS` directly (unscaled - these already
    /// are `P`'s own coefficients over `y = x/q`), and the result is scaled
    /// back up by `q/(2*pi)` (another `mul_plain_real` + `rescale_next_real`)
    /// afterward - rather than folding `q`'s scaling into the polynomial
    /// coefficients themselves and evaluating directly on `x`, which was
    /// tried first and found to corrupt the result for any `|x|`
    /// meaningfully larger than `1`. The reason: each `evaluate_encrypted`
    /// Horner step multiplies the accumulator by the *same* operand
    /// (`x`, kept at its original, never-rescaled scale throughout the
    /// whole chain, unlike the accumulator, which gets rescaled every
    /// step), so that step's noise growth scales with `Delta*|operand|`
    /// while a rescale only removes a factor of about `Delta` - for
    /// `|operand| ~ 1` these roughly cancel (stable noise-to-modulus
    /// ratio), but for `|operand| >> 1` (like a raw `x` up to `~q`) the
    /// ratio grows by a factor of `|operand|` on *every* step, compounding
    /// exponentially over several steps and overwhelming the modulus long
    /// before the polynomial's own approximation error would matter -
    /// confirmed directly (a real, encrypted test with `|x| ~ 10` came back
    /// as noise-corrupted garbage, `|x| ~ 0.1` came back correct, at the
    /// same degree and modulus chain). Pre-scaling by `1/q` keeps the
    /// repeated operand at `y = x/q`, bounded by `domain ~ 1.03` (see this
    /// module's own doc comment) - the same reason real CKKS bootstrapping
    /// implementations size `q` to the ciphertext's own lowest modulus and
    /// keep the eval-mod input's own scale relative to it, rather than
    /// running the approximation polynomial directly against a
    /// large-magnitude raw value.
    pub fn reduce_mod_q_real(
        &self,
        input: &Ciphertext,
        relin_keys: &[RelinearizationKey],
    ) -> Result<Ciphertext> {
        self.reduce_mod_q_real_wide(input, relin_keys, 0)
    }

    /// Generalizes [`Self::reduce_mod_q_real`] to a wraparound domain wider
    /// than `|I| <= 1` - the concrete gap
    /// `phantom_schemes::ckks::Evaluator::raise_level_real`'s own doc
    /// comment flags: a real modulus-raise introduces `|I| <= (h+2)/2` for
    /// a secret of Hamming weight `h`, which exceeds `1` for any
    /// non-trivial (non-insecure) secret, so [`Self::reduce_mod_q_real`]'s
    /// `r=0` domain alone was never enough to follow a genuine raise.
    ///
    /// `doublings` (`r`) widens the domain via the standard angle-doubling
    /// reconstruction: rather than fitting a single polynomial over the
    /// full wide domain (impractical - a low-degree polynomial can't track
    /// `sin`'s own oscillation across many periods), this evaluates
    /// `SIN_APPROX_BASE_COEFFICIENTS`/`COS_APPROX_BASE_COEFFICIENTS` on
    /// `y' = x/(q*2^r)` (bounded within the base fit's own narrow domain
    /// whenever `2^r >= (K+0.03)/1.03` for the caller's own wraparound
    /// bound `K`), then reconstructs `sin(2*pi*y)` from `sin(2*pi*y')` via
    /// `r` applications of the *exact* trigonometric double-angle identity
    /// `sin(2*theta) = 2*sin(theta)*cos(theta)`, `cos(2*theta) =
    /// 2*cos(theta)^2 - 1` - each step one ciphertext-ciphertext multiply
    /// (relinearized, rescaled) per `sin`/`cos` update, plus a
    /// same-ciphertext `add_real` (`x + x`, not a plaintext multiply by
    /// `2`, since that would cost its own extra rescale for no benefit) and
    /// a plaintext `-1` for `cos`'s update.
    ///
    /// This is exact in principle (angle-doubling introduces no
    /// approximation error of its own) but *amplifies* the base fit's own
    /// error at each step (a small perturbation in `sin(theta)`/`cos(theta)`
    /// propagates roughly linearly through the doubling formula's own
    /// products) - which is exactly why `SIN_APPROX_BASE_COEFFICIENTS`
    /// is fit to a much tighter absolute error (`~1e-7`) than
    /// [`Self::reduce_mod_q_real`]'s original `r=0`-only degree needed:
    /// verified numerically (Python, 20000 randomized trials per `r`,
    /// `r` from `0` to `5`) before implementing, the *doubled* result's own
    /// relative error to the message bound stays close to `0.6%` uniformly
    /// across that whole range, not compounding into anything close to
    /// `reduce_mod_q_real`'s original (lower-degree, `r=0`-only) `~3%`.
    ///
    /// Costs `1 + 17 + r + 1 = 19 + r` rescales total (pre-scale, the
    /// degree-`17` Horner evaluation, one per doubling step, plus the
    /// post-scale) - `sin` and `cos` run as *parallel* branches throughout
    /// (the base evaluation, via two separate `evaluate_encrypted` calls
    /// both starting from the same `scaled` ciphertext rather than
    /// chaining one after the other; each doubling step, updating both
    /// from the same prior level to the same next level), so every stage
    /// consumes its own rescale **once**, not once per branch. This
    /// exactly matches [`Self::reduce_mod_q_real`]'s own cost (`19`) when
    /// `doublings == 0`, which skips evaluating `cos`/doubling entirely
    /// rather than doing a zero-iteration loop for no reason.
    ///
    /// The doubling loop's own `-1` step (`cos(2*theta) = 2*cos(theta)^2 -
    /// 1`) needs its `-1` plaintext encoded at the *ciphertext's own actual
    /// tracked scale*, not the nominal `default_scale` every other constant
    /// in this method uses - found directly (a real, encrypted test with
    /// enough doublings failing `add_plain_real`'s scale check partway
    /// through the loop, not on the first iteration). Root cause: each
    /// doubling step's `mul_real` result scale is the *product* of two
    /// already-slightly-drifted operand scales (a real rescale only ever
    /// divides by a modulus *close to*, never exactly, `2^scale_bits` - see
    /// [`phantom_schemes::ckks::Scale`]'s own doc comment), so the drift
    /// roughly *doubles* every doubling step rather than merely
    /// accumulating additively the way a single Horner chain's own drift
    /// does - eventually exceeding `Scale::compatible`'s tolerance for
    /// large enough `r`, even with primes chosen close to `2^scale_bits`.
    /// Since `sin`/`cos` always share *identical* drift (both branches
    /// rescale by the exact same modulus sequence at every step, so
    /// ciphertext-vs-ciphertext operations like `mul_real`/`add_real`
    /// never see it), only this one ciphertext-vs-*plaintext* comparison is
    /// exposed - encoding the plaintext to match the ciphertext's own
    /// drifted scale exactly sidesteps the exponential-drift concern
    /// entirely, rather than needing an ever-wider tolerance as `r` grows.
    ///
    /// **Known remaining gap, confirmed directly while building the
    /// integration this method exists for**: this is real-only, the same
    /// restriction [`Self::reduce_mod_q_real`]'s own doc comment already
    /// documents ("only correctly handles real-valued messages") - but a
    /// genuine `phantom_schemes::ckks::Evaluator::raise_level_real` call's
    /// own wraparound is a *real* integer per **ring coefficient**, and the
    /// forward DFT [`super::CoeffsToSlots::apply_real`] performs to reach
    /// slot domain (what this method actually operates on) is not
    /// magnitude-preserving *or* real-preserving for a generic real input -
    /// confirmed directly (decoding a real ciphertext's own output right
    /// after a genuine raise and `apply_real`, the imaginary part of every
    /// slot was nonzero and comparable in magnitude to the real part, not
    /// the negligible noise a correctly-real input would leave). Both this
    /// method and [`Self::reduce_mod_q_real`] therefore need a raised
    /// ciphertext's own slot-domain wraparound reduced as a genuinely
    /// complex value (real and imaginary parts independently, e.g. via
    /// `conjugate_real` extraction first, the same direction
    /// [`Self::reduce_mod_q_real`]'s own doc comment already points at)
    /// before a real, genuinely-exhausted ciphertext can be bootstrapped
    /// through `Bootstrapper::bootstrap_real_wide` end to end - not
    /// attempted here.
    pub fn reduce_mod_q_real_wide(
        &self,
        input: &Ciphertext,
        relin_keys: &[RelinearizationKey],
        doublings: u32,
    ) -> Result<Ciphertext> {
        let q = self.params.raise_modulus();
        let two_pi = 2.0 * std::f64::consts::PI;
        let evaluator = Evaluator::new(self.params.ckks_params().clone());
        let slot_count = self.params.ckks_params().slot_count();

        let encode_constant_at = |level: usize, value: f64| -> Result<Plaintext> {
            let level_params = self
                .params
                .ckks_params()
                .at_level(level)
                .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
            let values = vec![Complex64::real(value); slot_count];
            Encoder::new(level_params)
                .encode_complex_real(&values)
                .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))
        };

        // Encodes `value` at *exactly* `ciphertext`'s own tracked scale
        // (not the nominal `default_scale` `encode_constant_at` always
        // uses) - needed for the doubling loop's own `-1` step below,
        // where the ciphertext's scale has drifted measurably from
        // `default_scale` by then (see this method's own doc comment: each
        // doubling step roughly *doubles* the accumulated drift, since
        // `mul_real`'s result scale is the product of two already-drifted
        // operands). `add_plain_real`'s own scale check compares the
        // ciphertext's actual scale against the plaintext's - encoding
        // against the *nominal* scale would compare an undrifted reference
        // against an increasingly drifted one, eventually exceeding
        // `Scale::compatible`'s tolerance; encoding against the
        // ciphertext's own actual scale keeps them exactly equal instead.
        let encode_constant_matching_scale =
            |ciphertext: &Ciphertext, value: f64| -> Result<Plaintext> {
                let level_params = self
                    .params
                    .ckks_params()
                    .at_level(ciphertext.level())
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let matching_params = CkksParams::new(
                    level_params.ring().clone(),
                    ciphertext.scale(),
                    level_params.conjugate_invariant(),
                )
                .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let values = vec![Complex64::real(value); slot_count];
                Encoder::new(matching_params)
                    .encode_complex_real(&values)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))
            };

        let effective_q = q * 2f64.powi(doublings as i32);
        let inv_q = encode_constant_at(input.level(), 1.0 / effective_q)?;
        let scaled = evaluator
            .mul_plain_real(input, &inv_q)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
        let scaled = evaluator
            .rescale_next_real(&scaled)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;

        let poly_evaluator = PolynomialEvaluator::new(self.params.ckks_params().clone());
        let mut sin_value = poly_evaluator
            .evaluate_encrypted(&scaled, &SIN_APPROX_BASE_COEFFICIENTS, relin_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;

        if doublings > 0 {
            let mut cos_value = poly_evaluator
                .evaluate_encrypted(&scaled, &COS_APPROX_BASE_COEFFICIENTS, relin_keys)
                .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;

            for _ in 0..doublings {
                let sin_relin_key = relin_keys
                    .get(sin_value.level())
                    .ok_or(BootstrappingError::CircuitOperation("eval-mod"))?;
                let sin_cos = evaluator
                    .mul_real(&sin_value, &cos_value)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let sin_cos = evaluator
                    .relinearize_real(&sin_cos, sin_relin_key)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let sin_cos = evaluator
                    .rescale_next_real(&sin_cos)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let next_sin = evaluator
                    .add_real(&sin_cos, &sin_cos)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;

                let cos_relin_key = relin_keys
                    .get(cos_value.level())
                    .ok_or(BootstrappingError::CircuitOperation("eval-mod"))?;
                let cos_sq = evaluator
                    .mul_real(&cos_value, &cos_value)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let cos_sq = evaluator
                    .relinearize_real(&cos_sq, cos_relin_key)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let cos_sq = evaluator
                    .rescale_next_real(&cos_sq)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let doubled_cos_sq = evaluator
                    .add_real(&cos_sq, &cos_sq)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
                let neg_one = encode_constant_matching_scale(&doubled_cos_sq, -1.0)?;
                let next_cos = evaluator
                    .add_plain_real(&doubled_cos_sq, &neg_one)
                    .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;

                sin_value = next_sin;
                cos_value = next_cos;
            }
        }

        let scale_back = encode_constant_at(sin_value.level(), q / two_pi)?;
        let rescaled_up = evaluator
            .mul_plain_real(&sin_value, &scale_back)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
        evaluator
            .rescale_next_real(&rescaled_up)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))
    }
}

fn reduce_mod(x: f64, q: f64) -> f64 {
    let scaled = x / q;
    q * (scaled - scaled.round())
}
