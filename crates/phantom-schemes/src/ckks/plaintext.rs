//! CKKS plaintext.

use phantom_ring::Poly;

use super::{Complex64, Precision, Scale};

/// CKKS plaintext carrying approximate slots.
///
/// `poly` is `None` for the long-standing transparent representation
/// ([`Plaintext::new`], unchanged so every existing caller keeps compiling
/// and behaving identically) and `Some` for the real canonical-embedding
/// representation (`Plaintext::new_real`, produced by
/// [`super::Encoder::encode_complex_real`] - see that method's own doc
/// comment for the encoding itself - or by
/// [`super::Decryptor::decrypt_real`], which recovers a `poly` without
/// knowing the slots it decodes to). `slots()` always returns the values
/// the plaintext was constructed from either way; for the real
/// representation from `encode_complex_real` those are the *pre-rounding*
/// inputs, not necessarily exactly what
/// [`super::Encoder::decode_complex_real`] recovers from `poly` (canonical
/// embedding is an approximate round trip by construction - see
/// [`Scale`]'s own role in bounding that error); for the real
/// representation from `decrypt_real`, `slots()` is empty (decryption alone
/// doesn't decode - call `decode_complex_real` for that).
#[derive(Clone, Debug, PartialEq)]
pub struct Plaintext {
    slots: Vec<Complex64>,
    scale: Scale,
    level: usize,
    precision: Precision,
    poly: Option<Poly>,
}

impl Plaintext {
    /// Creates a transparent plaintext (no real ring representation - see
    /// the type's own doc comment).
    pub fn new(slots: Vec<Complex64>, scale: Scale, level: usize, precision: Precision) -> Self {
        Self {
            slots,
            scale,
            level,
            precision,
            poly: None,
        }
    }

    /// Creates a real plaintext backed by `poly` - see the type's own doc
    /// comment. Ordinarily built by [`super::Encoder::encode_complex_real`]
    /// or [`super::Decryptor::decrypt_real`]; `phantom-multiparty`'s own
    /// collective decryption (`PartialDecryptor`) also constructs one
    /// directly, from a `poly` legitimately combined from participant
    /// shares the same way `decrypt_real` combines a single secret's own
    /// contribution - `poly` must actually correspond to what it claims for
    /// [`super::Encoder::decode_complex_real`] to recover anything
    /// meaningful from it, the caller's own responsibility either way.
    pub fn new_real(
        slots: Vec<Complex64>,
        scale: Scale,
        level: usize,
        precision: Precision,
        poly: Poly,
    ) -> Self {
        Self {
            slots,
            scale,
            level,
            precision,
            poly: Some(poly),
        }
    }

    /// Returns encoded slots.
    pub fn slots(&self) -> &[Complex64] {
        &self.slots
    }

    /// Returns the scale.
    pub const fn scale(&self) -> Scale {
        self.scale
    }

    /// Returns the level.
    pub const fn level(&self) -> usize {
        self.level
    }

    /// Returns the precision estimate.
    pub const fn precision(&self) -> Precision {
        self.precision
    }

    /// Returns the real ring representation, if this is a real (not
    /// transparent) plaintext.
    pub const fn poly(&self) -> Option<&Poly> {
        self.poly.as_ref()
    }
}
