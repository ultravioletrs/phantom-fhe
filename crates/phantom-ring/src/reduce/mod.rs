//! Modular reduction helpers.

pub mod barrett;
pub mod lazy;
pub mod montgomery;

pub use barrett::BarrettReducer;
pub use montgomery::MontgomeryReducer;

/// The largest modulus [`MontgomeryReducer`] currently supports (exclusive).
/// [`BarrettReducer`] has no such limit - it supports the full 64-bit
/// modulus range. See [`montgomery`]'s module doc for why `2^63` is this
/// bound, not an arbitrary round number.
pub const MONTGOMERY_MAX_MODULUS: u64 = 1 << 63;

/// Adds two residues modulo `modulus`.
pub fn add_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    let sum = lhs as u128 + rhs as u128;
    (sum % modulus as u128) as u64
}

/// Subtracts two residues modulo `modulus`.
pub fn sub_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    if lhs >= rhs {
        lhs - rhs
    } else {
        modulus - (rhs - lhs)
    }
}

/// Negates a residue modulo `modulus`.
pub fn neg_mod(value: u64, modulus: u64) -> u64 {
    if value == 0 {
        0
    } else {
        modulus - value
    }
}

/// Multiplies two residues modulo `modulus`.
pub fn mul_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    ((lhs as u128 * rhs as u128) % modulus as u128) as u64
}

/// Computes `base^exp mod modulus`.
pub fn pow_mod(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut acc = 1u64;
    base %= modulus;
    while exp != 0 {
        if exp & 1 == 1 {
            acc = mul_mod(acc, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exp >>= 1;
    }
    acc
}

/// Computes modular inverse using Fermat's little theorem for prime moduli.
pub fn inv_mod(value: u64, modulus: u64) -> u64 {
    pow_mod(value, modulus - 2, modulus)
}
