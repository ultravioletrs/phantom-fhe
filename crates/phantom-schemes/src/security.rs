//! Shared parameter-builder validation (Workstream 5 item 6).
//!
//! Two different kinds of check, with two different default strictness:
//!
//! - **Inconsistent settings** ([`check_distinct_moduli`],
//!   [`check_plaintext_modulus_coprime_to_ciphertext_moduli`]): things that
//!   break correctness regardless of parameter size, so `bgv::BgvParamsBuilder`,
//!   `bfv::BfvParamsBuilder` (delegates to BGV's own builder), and
//!   `ckks::CkksParamsBuilder` all call these unconditionally from `build()`.
//!   Duplicate ciphertext moduli break the CRT reconstruction every RNS
//!   primitive in `phantom_ring::rns` relies on (`extend_basis` and
//!   everything built on it assume the moduli are pairwise coprime, which a
//!   repeated modulus trivially isn't); a plaintext modulus not coprime to
//!   every ciphertext modulus breaks `inv_mod` wherever BGV/BFV need it
//!   (modulus switching's own CRT correction, BFV's `Delta = floor(Q/t)`
//!   scaling). Verified safe to enable unconditionally by auditing every
//!   parameter combination actually constructed anywhere in this workspace
//!   (`BgvParams`/`BfvParams`/`CkksParams`, direct and builder-based alike)
//!   before adding these checks - none violate either condition.
//! - **Insecure settings** ([`check_128_bit_security`]): opt-in only, via
//!   each builder's own `.require_128_bit_security()`. Every
//!   development/test preset this crate's own test suite uses (ring degree
//!   `8`-`64`) is far below the smallest degree
//!   [`phantom_lattice::security::max_secure_total_modulus_bits_128`]'s
//!   table covers (`1024`), so an unconditional check would reject
//!   essentially every existing caller across `phantom-schemes`,
//!   `phantom-circuits`, `phantom-bootstrapping`, `phantom-multiparty`, and
//!   `phantom-examples` - consistent with `SECURITY.md`'s own description
//!   of those presets as "small development sizes chosen for fast
//!   iteration, not production security margins," not a defect to silently
//!   paper over by weakening the check.

use phantom_ring::Modulus;

use crate::{Result, SchemesError};

/// Rejects `moduli` if the ring degree `degree` has a published
/// 128-bit-security table entry
/// ([`phantom_lattice::security::max_secure_total_modulus_bits_128`]) and
/// the total ciphertext-modulus bit-length exceeds it, *or* if `degree`
/// has no table entry at all (below the table's smallest covered degree,
/// `1024`, or above its largest, `32768`) - a caller that explicitly opted
/// into requiring 128-bit security gets a hard error either way, since "no
/// published guidance available" is not the same as "known secure."
pub(crate) fn check_128_bit_security(degree: usize, moduli: &[Modulus]) -> Result<()> {
    let total_bits: f64 = moduli.iter().map(|m| (m.value() as f64).log2()).sum();
    match phantom_lattice::security::max_secure_total_modulus_bits_128(degree) {
        Some(limit) if total_bits <= f64::from(limit) => Ok(()),
        _ => Err(SchemesError::InvalidParameters(
            "parameters do not meet the requested 128-bit security level - see \
             phantom_lattice::security::max_secure_total_modulus_bits_128",
        )),
    }
}

/// Rejects `moduli` if any value appears more than once - see the module
/// doc comment for why a repeated modulus breaks CRT-based RNS arithmetic.
pub(crate) fn check_distinct_moduli(moduli: &[Modulus]) -> Result<()> {
    for (i, a) in moduli.iter().enumerate() {
        for b in &moduli[i + 1..] {
            if a.value() == b.value() {
                return Err(SchemesError::InvalidParameters(
                    "ciphertext moduli must be pairwise distinct",
                ));
            }
        }
    }
    Ok(())
}

/// Rejects `plaintext_modulus` if it shares a common factor with any
/// ciphertext modulus in `moduli` - see the module doc comment for why
/// BGV/BFV need this coprimality wherever they invert the plaintext
/// modulus modulo a ciphertext modulus.
pub(crate) fn check_plaintext_modulus_coprime_to_ciphertext_moduli(
    plaintext_modulus: u64,
    moduli: &[Modulus],
) -> Result<()> {
    for modulus in moduli {
        if gcd(plaintext_modulus, modulus.value()) != 1 {
            return Err(SchemesError::InvalidParameters(
                "plaintext modulus must be coprime to every ciphertext modulus",
            ));
        }
    }
    Ok(())
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_moduli_within_the_published_table_limit() {
        // degree=1024 allows 27 bits total; one ~26-bit-ish prime fits.
        let moduli = [Modulus::new(60_000_011).unwrap()]; // ~26 bits
        assert!(check_128_bit_security(1024, &moduli).is_ok());
    }

    #[test]
    fn rejects_moduli_exceeding_the_published_table_limit() {
        // degree=1024 allows 27 bits total; this modulus alone is ~40 bits.
        let moduli = [Modulus::new(1_000_000_000_001).unwrap()];
        assert!(check_128_bit_security(1024, &moduli).is_err());
    }

    #[test]
    fn rejects_degrees_with_no_published_table_entry() {
        let moduli = [Modulus::new(257).unwrap()];
        assert!(check_128_bit_security(8, &moduli).is_err());
    }

    #[test]
    fn gcd_matches_hand_worked_cases() {
        assert_eq!(gcd(12, 18), 6);
        assert_eq!(gcd(17, 257), 1);
        assert_eq!(gcd(0, 5), 5);
        assert_eq!(gcd(5, 0), 5);
    }

    #[test]
    fn check_distinct_moduli_accepts_distinct_and_rejects_repeats() {
        let distinct = [
            Modulus::new(257).unwrap(),
            Modulus::new(769).unwrap(),
            Modulus::new(3329).unwrap(),
        ];
        assert!(check_distinct_moduli(&distinct).is_ok());

        let repeated = [
            Modulus::new(257).unwrap(),
            Modulus::new(769).unwrap(),
            Modulus::new(257).unwrap(),
        ];
        assert!(check_distinct_moduli(&repeated).is_err());
    }

    #[test]
    fn check_plaintext_modulus_coprime_accepts_coprime_and_rejects_shared_factor() {
        let moduli = [Modulus::new(257).unwrap(), Modulus::new(769).unwrap()];
        assert!(check_plaintext_modulus_coprime_to_ciphertext_moduli(17, &moduli).is_ok());

        let moduli_sharing_a_factor = [Modulus::new(51).unwrap()]; // 51 = 3*17
        assert!(
            check_plaintext_modulus_coprime_to_ciphertext_moduli(17, &moduli_sharing_a_factor)
                .is_err()
        );
    }
}
