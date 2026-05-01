//! Key-switching scaffolding.

use crate::rlwe::Ciphertext;
use crate::Result;

/// Placeholder key-switch operation that preserves decryptability.
pub fn key_switch_identity(ct: &Ciphertext) -> Result<Ciphertext> {
    Ok(ct.clone())
}
