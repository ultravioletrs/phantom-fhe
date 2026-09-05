use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use phantom_ring::ntt::{CpuNttBackend, NttBackend};
use phantom_ring::{Degree, Modulus, Poly, Ring};

mod support;

fn ring_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_ntt");
    // toy = the documented development preset (degree 8, modulus 257 - see
    // docs/user-guide.md#choosing-parameters); small = degree 1024 with the
    // NTT-friendly prime 12289 (= 3*2^12 + 1), large enough for the O(N log
    // N) vs. the old O(N^2) transform to actually show apart, still a
    // millisecond-scale run.
    for &(label, degree, modulus) in &[("toy", 8usize, 257u64), ("small", 1024, 12289)] {
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(degree, modulus),
            |b, &(degree, modulus)| {
                let ring = Ring::new_ntt(
                    Degree::new(degree).unwrap(),
                    vec![Modulus::new(modulus).unwrap()],
                )
                .unwrap();
                let backend = CpuNttBackend;
                let coeffs: Vec<u64> = (0..degree as u64).collect();
                b.iter(|| {
                    let mut poly = Poly::from_coeffs(vec![coeffs.clone()]).unwrap();
                    backend.forward(&ring, &mut poly).unwrap();
                    backend.inverse(&ring, &mut poly).unwrap();
                    black_box(&poly);
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = ring_ntt
}
criterion_main!(benches);
