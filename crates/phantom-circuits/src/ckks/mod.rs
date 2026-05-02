//! CKKS approximate circuit helpers.

pub mod comparison;
pub mod dft;
pub mod inverse;
pub mod lintrans;
pub mod minimax;
pub mod mod1;
pub mod polynomial;

pub use comparison::ComparisonEvaluator;
pub use dft::{DftDirection, DftEvaluator};
pub use inverse::InverseEvaluator;
pub use lintrans::LinearTransformEvaluator;
pub use minimax::{CompositePolynomial, MinimaxEvaluator};
pub use mod1::Mod1Evaluator;
pub use polynomial::PolynomialEvaluator;

use phantom_schemes::ckks::{Ciphertext, CkksParams, Complex64};

use crate::error::{CircuitsError, Result};

fn check_ciphertext(params: &CkksParams, ciphertext: &Ciphertext) -> Result<()> {
    if ciphertext.slots().len() > params.slot_count() {
        return Err(CircuitsError::InvalidParameters(
            "CKKS ciphertext has too many slots",
        ));
    }
    if params.conjugate_invariant() && ciphertext.slots().iter().any(|slot| slot.im != 0.0) {
        return Err(CircuitsError::InvalidParameters(
            "conjugate-invariant CKKS accepts real slots only",
        ));
    }
    Ok(())
}

fn ckks_ciphertext_like(
    input: &Ciphertext,
    slots: Vec<Complex64>,
    precision_loss: f64,
) -> Ciphertext {
    Ciphertext::new(
        slots,
        input.scale(),
        input.level(),
        input.precision().degrade(precision_loss),
        input.degree(),
    )
}

fn ensure_finite(slots: &[Complex64]) -> Result<()> {
    if slots
        .iter()
        .any(|slot| !slot.re.is_finite() || !slot.im.is_finite())
    {
        return Err(CircuitsError::InvalidParameters(
            "CKKS circuit produced a non-finite slot",
        ));
    }
    Ok(())
}

fn c_add(a: Complex64, b: Complex64) -> Complex64 {
    a + b
}

fn c_mul(a: Complex64, b: Complex64) -> Complex64 {
    a * b
}

fn c_scale(a: Complex64, scalar: f64) -> Complex64 {
    Complex64::new(a.re * scalar, a.im * scalar)
}
