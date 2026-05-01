//! RLWE repacking scaffolding.

use crate::rlwe::Ciphertext;
use crate::Result;

/// Placeholder repacking operation.
pub fn repack_identity(ct: &Ciphertext) -> Result<Ciphertext> {
    Ok(ct.clone())
}
