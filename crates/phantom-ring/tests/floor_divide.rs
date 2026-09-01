//! Tests for `floor_divide_residues` (the RNS primitive BFV's real "Delta"
//! plaintext-scaling factor is built on - Workstream 5 item 1, BFV).
//! Expected values computed independently in Python (arbitrary-precision
//! integers, not this crate's own logic).

use phantom_ring::rns::extension::floor_divide_residues;
use phantom_ring::{Modulus, RnsBasis};

fn basis(values: &[u64]) -> RnsBasis {
    RnsBasis::new(values.iter().map(|&v| Modulus::new(v).unwrap()).collect()).unwrap()
}

#[test]
fn floor_divide_residues_matches_independently_computed_values() {
    // Q = 1000000007 * 1000000009 * 1000000021 = 1000000037000000399000001323
    // divisor = 17, floor(Q/17) = 58823531588235317588235371
    let basis = basis(&[1000000007, 1000000009, 1000000021]);
    let residues = floor_divide_residues(&basis, 17);
    assert_eq!(residues, vec![352941178, 58823529, 176470591]);
}

#[test]
fn floor_divide_residues_matches_a_single_modulus_case() {
    // Single-modulus basis: floor(q/t) is the ordinary integer division.
    let basis = basis(&[1_000_000_000_000_037]);
    let residues = floor_divide_residues(&basis, 17);
    assert_eq!(residues, vec![1_000_000_000_000_037 / 17]);
}
