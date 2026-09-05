use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use phantom_ring::rns::crt::{decompose_value, reconstruct_residue};
use phantom_ring::{Modulus, RnsBasis};

mod support;

fn ring_rns(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_rns");

    // toy = the original 2-modulus basis this bench has always used.
    group.bench_function(BenchmarkId::from_parameter("toy"), |b| {
        let basis =
            RnsBasis::new(vec![Modulus::new(17).unwrap(), Modulus::new(97).unwrap()]).unwrap();
        b.iter(|| {
            let residues = decompose_value(1234, &basis);
            black_box(reconstruct_residue(&residues, &basis).unwrap());
        });
    });

    // small = the same ~22-bit modulus family `rlwe_keyswitch`'s own small
    // tier uses - a real, already-exercised-elsewhere RNS limb size,
    // rather than inventing a new one. `reconstruct_residue`'s own doc
    // comment calls it "a debug helper intended for tests and small
    // parameter sets": beyond checking the basis *product* fits in `u128`
    // (`checked_mul`), its per-term reconstruction (`residue * partial *
    // inv`, all `u128`, only reduced mod the product at the very end) can
    // itself overflow `u128` well before the product does for large
    // moduli - verified this modulus family doesn't (residue, partial, and
    // inv are all comfortably under 2^22 here, so the product of three is
    // nowhere near 2^128), unlike the ~61-bit primes `ring_extend_basis`
    // uses for `extend_basis`'s own, separately bignum-based, arithmetic.
    group.bench_function(BenchmarkId::from_parameter("small"), |b| {
        let basis = RnsBasis::new(vec![
            Modulus::new(4_000_081u64).unwrap(),
            Modulus::new(4_000_063u64).unwrap(),
        ])
        .unwrap();
        b.iter(|| {
            let residues = decompose_value(1234, &basis);
            black_box(reconstruct_residue(&residues, &basis).unwrap());
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = ring_rns
}
criterion_main!(benches);
