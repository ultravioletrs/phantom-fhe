use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use phantom_ring::rns::extension::extend_basis;
use phantom_ring::{Modulus, Poly, RnsBasis};

mod support;

fn ring_extend_basis(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_extend_basis");

    // toy = the same small case
    // crates/phantom-ring/tests/phase2.rs::crt_reconstructs_and_extends_basis
    // uses (2 source moduli, degree 2, extending into a basis that includes
    // one new modulus).
    group.bench_function(BenchmarkId::from_parameter("toy"), |b| {
        let source =
            RnsBasis::new(vec![Modulus::new(17).unwrap(), Modulus::new(97).unwrap()]).unwrap();
        let target = RnsBasis::new(vec![
            Modulus::new(17).unwrap(),
            Modulus::new(97).unwrap(),
            Modulus::new(193).unwrap(),
        ])
        .unwrap();
        let poly = Poly::from_coeffs(vec![vec![1, 5], vec![1, 42]]).unwrap();
        b.iter(|| black_box(extend_basis(&poly, &source, &target).unwrap()));
    });

    // small = 8 ~61-bit NTT-unrelated primes (the same source basis size
    // used in crates/phantom-ring/tests/phase2.rs's extend_basis regression
    // test) - a realistic RNS-CKKS/BGV source tower, and specifically the
    // scale the bignum-based rewrite (replacing the old u128 CRT round
    // trip, which silently overflowed here) needs to actually reach
    // production performance for.
    group.bench_function(BenchmarkId::from_parameter("small"), |b| {
        let source = RnsBasis::new(
            [
                2305843009213693951u64,
                2305843009213693907,
                2305843009213693881,
                2305843009213693829,
                2305843009213693807,
                2305843009213693719,
                2305843009213693697,
                2305843009213693677,
            ]
            .iter()
            .map(|&q| Modulus::new(q).unwrap())
            .collect(),
        )
        .unwrap();
        let target = RnsBasis::new(vec![
            Modulus::new(12289).unwrap(),
            Modulus::new(40961).unwrap(),
        ])
        .unwrap();

        let degree = 1024;
        let coeffs: Vec<Vec<u64>> = source
            .moduli()
            .iter()
            .map(|m| (0..degree as u64).map(|i| i % m.value()).collect())
            .collect();
        let poly = Poly::from_coeffs(coeffs).unwrap();

        b.iter(|| black_box(extend_basis(&poly, &source, &target).unwrap()));
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = ring_extend_basis
}
criterion_main!(benches);
