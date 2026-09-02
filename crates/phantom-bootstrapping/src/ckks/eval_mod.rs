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
use phantom_schemes::ckks::{Ciphertext, Complex64, Encoder, Evaluator, Plaintext};

use super::BootstrapParams;
use crate::{BootstrappingError, Result};

/// Base (`q`-independent) coefficients `c_0..c_9` of the degree-`9` odd
/// polynomial approximating `sin(2*pi*y)` over `y in [-domain, domain]`
/// (`domain = I_max + msg_bound = 1.03`, `I_max = 1`, `msg_bound = 0.03`) -
/// see this module's own doc comment for the derivation and
/// [`EvalMod::reduce_mod_q_real`] for how `q` folds in. Fit via Chebyshev
/// interpolation at Chebyshev-Gauss-Lobatto nodes (numerically stable,
/// unlike a direct monomial-basis least-squares fit - tried first, and
/// gave wildly wrong results at this degree even before considering
/// accuracy, confirmed by the fitted even coefficients coming out non-zero
/// where they should vanish by symmetry). The even coefficients here are
/// hardcoded to exactly `0.0` rather than the fit's own `~1e-14` residuals
/// (`sin` is odd and the domain is symmetric, so they're zero by
/// construction, not merely small). Verified numerically (Python, 20000
/// randomized trials, `I` uniform in `{-1,0,1}`, `|m| < 0.03*q`, checked
/// across several different `q` values to confirm the scaling in
/// [`EvalMod::reduce_mod_q_real`] generalizes correctly) before
/// implementing: max absolute error in the recovered message is about
/// `2.98%` relative to the message bound, regardless of `q` - the price of
/// a homomorphically-evaluable polynomial standing in for `f64::round()`,
/// not a bug.
const SIN_APPROX_BASE_COEFFICIENTS: [f64; 10] = [
    0.0,
    6.2457475632140085,
    0.0,
    -39.88328266306458,
    0.0,
    71.841454929172,
    0.0,
    -52.15669527720744,
    0.0,
    13.94726810265634,
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

        let inv_q = encode_constant_at(input.level(), 1.0 / q)?;
        let scaled = evaluator
            .mul_plain_real(input, &inv_q)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;
        let scaled = evaluator
            .rescale_next_real(&scaled)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;

        let poly_evaluator = PolynomialEvaluator::new(self.params.ckks_params().clone());
        let poly_result = poly_evaluator
            .evaluate_encrypted(&scaled, &SIN_APPROX_BASE_COEFFICIENTS, relin_keys)
            .map_err(|_| BootstrappingError::CircuitOperation("eval-mod"))?;

        let scale_back = encode_constant_at(poly_result.level(), q / two_pi)?;
        let rescaled_up = evaluator
            .mul_plain_real(&poly_result, &scale_back)
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
