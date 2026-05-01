//! Lazy reduction helpers.

/// Reduces `value` only if it is at least `modulus`.
pub fn reduce_once(value: u64, modulus: u64) -> u64 {
    if value >= modulus {
        value - modulus
    } else {
        value
    }
}
