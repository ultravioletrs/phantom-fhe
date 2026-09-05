use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use phantom_lattice::rlwe::{Encryptor, KeyGenerator, Plaintext, RlweParams, SecretDistribution};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

mod support;

fn rlwe_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("rlwe_encrypt");
    // toy = the documented development preset (degree 8, modulus 257 - see
    // docs/user-guide.md#choosing-parameters); small = degree 1024 with the
    // NTT-friendly prime 12289, actually exercising `Ring::mul`'s NTT path
    // (see ring_ntt.rs for the same reasoning) while staying a fast smoke
    // size.
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
                let params = RlweParams::builder().ring(ring).build().unwrap();
                let keygen = KeyGenerator::new(params.clone());
                let mut rng = ChaCha20Rng::from_seed([1; 32]);
                let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);
                let pk = keygen.generate_public_key(&sk, &mut rng).unwrap();
                let encryptor = Encryptor::with_public_key(params, pk);
                let coeffs: Vec<u64> = (0..degree as u64).collect();
                let plaintext = Plaintext::new(Poly::from_coeffs(vec![coeffs]).unwrap());
                b.iter(|| black_box(encryptor.encrypt(&plaintext, &mut rng).unwrap()));
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = rlwe_encrypt
}
criterion_main!(benches);
