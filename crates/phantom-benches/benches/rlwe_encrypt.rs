use phantom_benches::{print_result, time_iterations};
use phantom_lattice::rlwe::{Encryptor, KeyGenerator, Plaintext, RlweParams, SecretDistribution};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() {
    let ring = Ring::new_ntt(Degree::new(4).unwrap(), vec![Modulus::new(17).unwrap()]).unwrap();
    let params = RlweParams::builder().ring(ring).build().unwrap();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
    let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
    let encryptor = Encryptor::with_public_key(params, pk);
    let plaintext = Plaintext::new(Poly::from_coeffs(vec![vec![1, 2, 3, 4]]).unwrap());
    let iterations = 100;
    let elapsed = time_iterations(
        || {
            let _ = encryptor.encrypt(&plaintext, &mut rng).unwrap();
        },
        iterations,
    );
    print_result("rlwe_encrypt", iterations, elapsed);
}
