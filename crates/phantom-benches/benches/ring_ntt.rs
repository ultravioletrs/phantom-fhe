use phantom_benches::{print_result, time_iterations};
use phantom_ring::ntt::{CpuNttBackend, NttBackend};
use phantom_ring::{Degree, Modulus, Poly, Ring};

fn main() {
    // Degree 4 was too small to show O(N log N) vs. the old O(N^2) transform
    // apart - dominated by fixed overhead either way. 1024 with the
    // NTT-friendly prime 12289 (= 3*2^12 + 1, so q-1 is divisible by 2*1024)
    // is still a "smoke" size (runs in milliseconds) but large enough for
    // the asymptotic difference to actually show up in the measurement.
    let ring = Ring::new_ntt(
        Degree::new(1024).unwrap(),
        vec![Modulus::new(12289).unwrap()],
    )
    .unwrap();
    let backend = CpuNttBackend;
    let iterations = 100;
    let coeffs: Vec<u64> = (0..1024).collect();
    let elapsed = time_iterations(
        || {
            let mut poly = Poly::from_coeffs(vec![coeffs.clone()]).unwrap();
            backend.forward(&ring, &mut poly).unwrap();
            backend.inverse(&ring, &mut poly).unwrap();
        },
        iterations,
    );
    print_result("ring_ntt", iterations, elapsed);
}
