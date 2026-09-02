//! CKKS scale domain type.

use crate::{Result, SchemesError};

/// Positive CKKS scale.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Scale(f64);

impl Scale {
    /// Creates a validated scale.
    pub fn new(value: f64) -> Result<Self> {
        if !value.is_finite() || value <= 0.0 {
            return Err(SchemesError::InvalidParameters(
                "scale must be finite and positive",
            ));
        }
        Ok(Self(value))
    }

    /// Creates a power-of-two scale.
    pub fn from_bits(bits: u32) -> Result<Self> {
        Self::new(2.0_f64.powi(bits as i32))
    }

    /// Returns the raw scale.
    pub const fn value(self) -> f64 {
        self.0
    }

    /// Absolute tolerance, in bits of `log2(scale)`, for two scales to be
    /// treated as "the same" by `Self::compatible`.
    ///
    /// [`crate::ckks::Evaluator::rescale_next_real`] divides the tracked
    /// scale by the *actual* dropped RNS modulus, which (being odd, per
    /// [`phantom_ring::Modulus::new`]) can only ever approximate - never
    /// exactly equal - a power of two; the standard RNS-CKKS convention of
    /// picking that modulus close to `2^scale_bits` means one rescale's
    /// drift is `log2(modulus / 2^scale_bits)` bits, and additive (not
    /// multiplicative) across a rescale chain - but "close to" isn't
    /// "arbitrarily close": prime gaps near `2^scale_bits` average
    /// `ln(2^scale_bits)` (about `21` for `scale_bits=30`), so a set of
    /// several *distinct* primes all "close to" `2^scale_bits` naturally
    /// spans a few hundred, not single digits - this constant was
    /// originally sized from one specific, unusually close pair (`3` away
    /// from `2^30`) and turned out too tight once a real multi-level
    /// circuit chained enough rescales (a degree-`9` Horner-method
    /// polynomial, `phantom-bootstrapping`'s own real `EvalMod`) with more
    /// realistically-spaced primes - found directly via a failing
    /// `add_plain_real` call, traced to the compounded drift crossing the
    /// old `1e-6` bound around the `4`th-`5`th rescale. Retightened with
    /// real headroom instead: for primes within a few hundred of
    /// `2^scale_bits`, per-rescale drift is on the order of `1e-7` bits, so
    /// even hundreds of chained rescales stay under `1e-4` - this constant
    /// keeps a further `10x` margin beyond that. A genuine scale mismatch
    /// (wrong number of rescales, mismatched `scale_bits` between two
    /// contexts, adding without rescaling after a multiply) differs by at
    /// least one full bit - a factor of two - still four orders of
    /// magnitude clear of this bound. Verified against both the original
    /// rescale-then-add scenario (`ckks_real_arithmetic.rs`) and the
    /// longer chain that motivated widening it
    /// (`phantom-bootstrapping/tests/phase12_ckks_bootstrapping.rs`).
    const COMPATIBLE_TOLERANCE_BITS: f64 = 1e-3;

    /// Returns true if scales are close enough for scaffold arithmetic -
    /// compares `log2(scale)` against `Self::COMPATIBLE_TOLERANCE_BITS`
    /// rather than the raw values, so legitimate real-path rescale drift
    /// (see that constant's own doc comment) doesn't compound into a false
    /// mismatch the way a fixed relative tolerance on the raw value would.
    pub fn compatible(self, rhs: Self) -> bool {
        (self.0.log2() - rhs.0.log2()).abs() <= Self::COMPATIBLE_TOLERANCE_BITS
    }
}
