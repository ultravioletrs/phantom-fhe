use phantom_benches::{print_result, time_iterations};
use phantom_ring::rns::crt::{decompose_value, reconstruct_residue};
use phantom_ring::{Modulus, RnsBasis};

fn main() {
    let basis = RnsBasis::new(vec![Modulus::new(17).unwrap(), Modulus::new(97).unwrap()]).unwrap();
    let iterations = 100;
    let elapsed = time_iterations(
        || {
            let residues = decompose_value(1234, &basis);
            let _ = reconstruct_residue(&residues, &basis).unwrap();
        },
        iterations,
    );
    print_result("ring_rns", iterations, elapsed);
}
