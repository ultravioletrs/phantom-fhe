//! RGSW key.

use crate::rlwe::SecretKey;

/// RGSW secret key wrapper.
#[derive(Clone, Debug)]
pub struct RgswKey {
    secret: SecretKey,
}

impl RgswKey {
    /// Creates an RGSW key from an RLWE secret key.
    pub const fn new(secret: SecretKey) -> Self {
        Self { secret }
    }

    /// Returns the underlying secret key.
    pub const fn secret(&self) -> &SecretKey {
        &self.secret
    }
}
