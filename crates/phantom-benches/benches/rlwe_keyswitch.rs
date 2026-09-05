use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use phantom_lattice::rlwe::{
    Encryptor, Evaluator, KeyGenerator, Plaintext, RlweParams, SecretDistribution,
};
use phantom_ring::{Degree, Modulus, Poly, Ring};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

mod support;

struct Params {
    degree: usize,
    modulus: u64,
    p_moduli: [u64; 2],
    seed: u8,
}

fn bench_relinearize(b: &mut criterion::Bencher<'_>, params: &Params) {
    let Params {
        degree,
        modulus,
        p_moduli,
        seed,
    } = *params;
    let ring = Ring::new_ntt(
        Degree::new(degree).unwrap(),
        vec![Modulus::new(modulus).unwrap()],
    )
    .unwrap();
    let params = RlweParams::builder().ring(ring).build().unwrap();
    let keygen = KeyGenerator::new(params.clone());
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let sk = keygen.generate_secret_key(&mut rng, SecretDistribution::Ternary);

    let p_moduli: Vec<Modulus> = p_moduli.iter().map(|&q| Modulus::new(q).unwrap()).collect();
    let relin = keygen
        .generate_hybrid_relinearization_key(&sk, &p_moduli, &mut rng)
        .unwrap();

    let encryptor = Encryptor::with_secret_key(params.clone(), sk);
    let evaluator = Evaluator::new(params);
    let a = Plaintext::new(Poly::from_coeffs(vec![(0..degree as u64).collect()]).unwrap());
    let b_pt = Plaintext::new(
        Poly::from_coeffs(vec![(0..degree as u64).map(|i| i + 1).collect()]).unwrap(),
    );
    let ct_a = encryptor.encrypt(&a, &mut rng).unwrap();
    let ct_b = encryptor.encrypt(&b_pt, &mut rng).unwrap();
    let product = evaluator.mul(&ct_a, &ct_b).unwrap();

    b.iter(|| black_box(evaluator.relinearize(&product, &relin).unwrap()));
}

fn rlwe_keyswitch(c: &mut Criterion) {
    let mut group = c.benchmark_group("rlwe_keyswitch");

    // toy = the original degree=8 toy ring this bench has always used. Real
    // RNS hybrid key-switching needs headroom for its own noise
    // contribution beyond fresh-encryption noise (see
    // phantom_lattice::rlwe::keyswitch's module doc comment), so this
    // reuses the same realistically-sized-for-its-scale ring and auxiliary
    // P moduli crates/phantom-lattice/tests/phase3_rlwe.rs does.
    group.bench_function(BenchmarkId::from_parameter("toy"), |b| {
        bench_relinearize(
            b,
            &Params {
                degree: 8,
                modulus: 4_000_081,
                p_moduli: [4_000_063, 4_000_067],
                seed: 2,
            },
        );
    });

    // small = the same construction at degree 1024 with the NTT-friendly
    // prime 12289 (matching ring_ntt.rs/rlwe_encrypt.rs's own "small"
    // tier); the auxiliary P moduli don't need any NTT relationship to the
    // ring (they're only ever used for RNS basis extension, not for
    // Ring::mul's own NTT path - see
    // KeyGenerator::generate_hybrid_relinearization_key's doc comment), so
    // any two distinct primes work.
    group.bench_function(BenchmarkId::from_parameter("small"), |b| {
        bench_relinearize(
            b,
            &Params {
                degree: 1024,
                modulus: 12289,
                p_moduli: [40961, 65537],
                seed: 3,
            },
        );
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = rlwe_keyswitch
}
criterion_main!(benches);
