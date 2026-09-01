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
    /// picking that modulus close to `2^scale_bits` (see
    /// `ckks_real_arithmetic.rs`'s own `RESCALE_MODULUS`, `3` away from
    /// `2^30`) means one rescale's drift is `log2(modulus / 2^scale_bits)`
    /// bits - about `4e-9` bits for that pair, and additive (not
    /// multiplicative) across a rescale chain, so even hundreds of chained
    /// rescales stay far under this tolerance. A genuine scale mismatch
    /// (wrong number of rescales, mismatched `scale_bits` between two
    /// contexts, adding without rescaling after a multiply) differs by at
    /// least one full bit - a factor of two - typically many more, six
    /// orders of magnitude clear of this bound. Verified against exactly
    /// this rescale-then-add scenario in `ckks_real_arithmetic.rs`.
    const COMPATIBLE_TOLERANCE_BITS: f64 = 1e-6;

    /// Returns true if scales are close enough for scaffold arithmetic -
    /// compares `log2(scale)` against `Self::COMPATIBLE_TOLERANCE_BITS`
    /// rather than the raw values, so legitimate real-path rescale drift
    /// (see that constant's own doc comment) doesn't compound into a false
    /// mismatch the way a fixed relative tolerance on the raw value would.
    pub fn compatible(self, rhs: Self) -> bool {
        (self.0.log2() - rhs.0.log2()).abs() <= Self::COMPATIBLE_TOLERANCE_BITS
    }
}
