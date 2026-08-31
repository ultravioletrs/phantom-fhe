use phantom_benches::{print_result, time_iterations};
use phantom_lattice::rlwe::{Encryptor, KeyGenerator, Plaintext, RlweParams, SecretDistribution};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() {
    // Degree 4 was too small to exercise Ring::mul's NTT path meaningfully
    // (see ring_ntt.rs for the same reasoning). 1024 with the NTT-friendly
    // prime 12289 keeps this a fast smoke bench while actually using the
    // multiplication encrypt() now goes through.
    let ring = Ring::new_ntt(
        Degree::new(1024).unwrap(),
        vec![Modulus::new(12289).unwrap()],
    )
    .unwrap();
    let params = RlweParams::builder().ring(ring).build().unwrap();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
    let encryptor = Encryptor::with_public_key(params, pk);
    let coeffs: Vec<u64> = (0..1024).collect();
    let plaintext = Plaintext::new(Poly::from_coeffs(vec![coeffs]).unwrap());
    let iterations = 100;
    let elapsed = time_iterations(
        || {
            let _ = encryptor.encrypt(&plaintext, &mut rng).unwrap();
        },
        iterations,
    );
    print_result("rlwe_encrypt", iterations, elapsed);
}
