use phantom_benches::{print_result, time_iterations};
use phantom_ring::ntt::{CpuNttBackend, NttBackend};
use phantom_ring::{Degree, Modulus, Poly, Ring};

fn main() {
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    let backend = CpuNttBackend;
    let iterations = 100;
    let elapsed = time_iterations(
        || {
            let mut poly = Poly::from_coeffs(vec![vec![1, 2, 3, 4]]).unwrap();
            backend.forward(&ring, &mut poly).unwrap();
            backend.inverse(&ring, &mut poly).unwrap();
        },
        iterations,
    );
    print_result("ring_ntt", iterations, elapsed);
}
