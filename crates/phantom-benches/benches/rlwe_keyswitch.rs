use phantom_benches::{print_result, time_iterations};
use phantom_lattice::rlwe::{
    Encryptor, Evaluator, KeyGenerator, Plaintext, RlweParams, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() {
    // Real RNS hybrid key-switching needs headroom for its own noise
    // contribution beyond fresh-encryption noise (see
    // phantom_lattice::rlwe::keyswitch's module doc comment), so this uses
    // the same realistically-sized ring and auxiliary P moduli
    // crates/phantom-lattice/tests/phase3_rlwe.rs does, not the old
    // degree=4/modulus=17 toy ring the placeholder-only version of this
    // bench used (real relinearization is now what this measures, not
    // key_switch_identity's no-op).
    let degree = 8;
    let modulus = 4_000_081u64;
    let ring = Ring::new_ntt(
        Degree::new(degree).unwrap(),
        vec![Modulus::new(modulus).unwrap()],
    )
    .unwrap();
    let params = RlweParams::builder().ring(ring).build().unwrap();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([2; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);

    let p_moduli = vec![
        Modulus::new(4_000_063).unwrap(),
        Modulus::new(4_000_067).unwrap(),
    ];
    let relin = keygen
        .generate_hybrid_relinearization_key(&sk, &p_moduli, &mut rng)
        .unwrap();

    let encryptor = Encryptor::with_secret_key(params.clone(), sk);
    let evaluator = Evaluator::new(params.clone());
    let a = Plaintext::new(Poly::from_coeffs(vec![(0..degree as u64).collect()]).unwrap());
    let b = Plaintext::new(
        Poly::from_coeffs(vec![(0..degree as u64).map(|i| i + 1).collect()]).unwrap(),
    );
    let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
    let ct_b = encryptor.encrypt(&b, &mut rng).unwrap();
    let product = evaluator.mul(&ct_a, &ct_b).unwrap();

    let iterations = 100;
    let elapsed = time_iterations(
        || {
            let _ = evaluator.relinearize(&product, &relin).unwrap();
        },
        iterations,
    );
    print_result("rlwe_keyswitch", iterations, elapsed);
}
