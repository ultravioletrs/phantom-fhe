use phantom_benches::{print_result, time_iterations};
use phantom_ring::rns::extension::extend_basis;
use phantom_ring::{Modulus, Poly, RnsBasis};

fn main() {
    // 8 ~61-bit NTT-unrelated primes (the same source basis size used in
    // crates/phantom-ring/tests/phase2.rs's extend_basis regression test) -
    // a realistic RNS-CKKS/BGV source tower, and specifically the scale the
    // bignum-based rewrite (replacing the old u128 CRT round trip, which
    // silently overflowed here) needs to actually reach production
    // performance for.
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

    let iterations = 100;
    let elapsed = time_iterations(
        || {
            let _ = extend_basis(&poly, &source, &target).unwrap();
        },
        iterations,
    );
    print_result("ring_extend_basis", iterations, elapsed);
}
