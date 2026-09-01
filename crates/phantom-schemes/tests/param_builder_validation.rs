//! Tests for the parameter-builder validation added in Workstream 5 item 6
//! (`crate::security`, not itself public - exercised only through
//! `BgvParamsBuilder`/`BfvParamsBuilder`/`CkksParamsBuilder::build`).

use phantom_schemes::bfv::BfvParams;
use phantom_schemes::bgv::BgvParams;
use phantom_schemes::ckks::CkksParams;

#[test]
fn bgv_builder_rejects_duplicate_moduli() {
    let result = BgvParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 257])
        .plaintext_modulus(17)
        .build();
    assert!(result.is_err());
}

#[test]
fn bgv_builder_rejects_a_plaintext_modulus_sharing_a_factor_with_a_ciphertext_modulus() {
    // 51 = 3*17, shares a factor with plaintext modulus 17.
    let result = BgvParams::builder()
        .degree(8)
        .moduli(vec![51])
        .plaintext_modulus(17)
        .build();
    assert!(result.is_err());
}

#[test]
fn bgv_builder_accepts_the_existing_toy_preset_unchanged() {
    let result = BgvParams::builder()
        .degree(8)
        .moduli(vec![257, 769])
        .plaintext_modulus(17)
        .build();
    assert!(result.is_ok());
}

#[test]
fn bfv_builder_inherits_bgv_s_consistency_checks() {
    let duplicate = BfvParams::builder()
        .degree(8)
        .moduli(vec![257, 257])
        .plaintext_modulus(17)
        .build();
    assert!(duplicate.is_err());

    let shared_factor = BfvParams::builder()
        .degree(8)
        .moduli(vec![51])
        .plaintext_modulus(17)
        .build();
    assert!(shared_factor.is_err());
}

#[test]
fn ckks_builder_rejects_duplicate_moduli() {
    let result = CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 257])
        .default_scale_bits(10)
        .build();
    assert!(result.is_err());
}

#[test]
fn ckks_builder_accepts_the_existing_toy_preset_unchanged() {
    let result = CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build();
    assert!(result.is_ok());
}

#[test]
fn require_128_bit_security_rejects_toy_sized_parameters() {
    // degree=8 has no published homomorphicencryption.org table entry at
    // all (the table starts at 1024), so this must fail regardless of how
    // small the modulus is.
    let bgv = BgvParams::builder()
        .degree(8)
        .moduli(vec![257])
        .plaintext_modulus(17)
        .require_128_bit_security()
        .build();
    assert!(bgv.is_err());

    let ckks = CkksParams::builder()
        .degree(8)
        .moduli(vec![257])
        .default_scale_bits(4)
        .require_128_bit_security()
        .build();
    assert!(ckks.is_err());
}

#[test]
fn require_128_bit_security_accepts_a_table_covered_degree_within_its_bit_budget() {
    // degree=1024 allows 27 bits total (homomorphicencryption.org); one
    // ~26-bit prime comfortably fits.
    let result = BgvParams::builder()
        .degree(1024)
        .moduli(vec![67_108_879]) // ~26 bits, prime
        .plaintext_modulus(17)
        .require_128_bit_security()
        .build();
    assert!(result.is_ok());
}

#[test]
fn require_128_bit_security_rejects_a_table_covered_degree_over_its_bit_budget() {
    // degree=1024 allows only 27 bits total; this modulus alone is ~40 bits.
    let result = BgvParams::builder()
        .degree(1024)
        .moduli(vec![1_000_000_000_001])
        .plaintext_modulus(17)
        .require_128_bit_security()
        .build();
    assert!(result.is_err());
}

#[test]
fn without_require_128_bit_security_toy_parameters_still_build_successfully() {
    // Backward compatibility: the default (no opt-in) path must keep
    // accepting every existing toy/test preset unchanged.
    let result = BgvParams::builder()
        .degree(8)
        .moduli(vec![257, 769])
        .plaintext_modulus(17)
        .build();
    assert!(result.is_ok());
}
