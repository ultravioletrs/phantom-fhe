//! CKKS ciphertext.

use phantom_lattice::rlwe::Ciphertext as RlweCiphertext;

use super::{Complex64, Precision, Scale};

/// CKKS ciphertext.
///
/// `poly` is `None` for the long-standing transparent representation
/// ([`Ciphertext::new`], unchanged so every existing caller keeps compiling
/// and behaving identically - `slots()` carries the plaintext values in the
/// clear) and `Some` for the real RLWE representation (`Ciphertext::new_real`,
/// produced only by [`super::Encryptor::encrypt_real`] and
/// [`super::Evaluator`]'s own real-path operations). Unlike
/// [`super::Plaintext`] (whose `slots()` is always meaningful, since a
/// plaintext isn't secret), a real `Ciphertext`'s `slots()` is empty -
/// carrying the cleartext message in a "real" (encrypted) ciphertext object
/// would defeat the point of encrypting it. Recover the slots by decrypting
/// ([`super::Decryptor::decrypt_real`]) and decoding
/// ([`super::Encoder::decode_complex_real`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext {
    slots: Vec<Complex64>,
    scale: Scale,
    level: usize,
    precision: Precision,
    degree: usize,
    poly: Option<RlweCiphertext>,
}

impl Ciphertext {
    /// Creates a transparent ciphertext (no real ring representation - see
    /// the type's own doc comment).
    pub fn new(
        slots: Vec<Complex64>,
        scale: Scale,
        level: usize,
        precision: Precision,
        degree: usize,
    ) -> Self {
        Self {
            slots,
            scale,
            level,
            precision,
            degree,
            poly: None,
        }
    }

    /// Creates a real ciphertext backed by `poly` - see the type's own doc
    /// comment. `pub(crate)`: only [`super::Encryptor::encrypt_real`] and
    /// [`super::Evaluator`]'s own real-path operations should construct
    /// one.
    pub(crate) fn new_real(
        poly: RlweCiphertext,
        scale: Scale,
        level: usize,
        precision: Precision,
        degree: usize,
    ) -> Self {
        Self {
            slots: Vec::new(),
            scale,
            level,
            precision,
            degree,
            poly: Some(poly),
        }
    }

    /// Returns transparent slots (empty for a real ciphertext - see the
    /// type's own doc comment).
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

    /// Returns ciphertext degree.
    pub const fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the real RLWE representation, if this is a real (not
    /// transparent) ciphertext.
    pub const fn poly(&self) -> Option<&RlweCiphertext> {
        self.poly.as_ref()
    }
}
