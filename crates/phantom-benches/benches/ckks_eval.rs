use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use phantom_benches::alloc::CountingAllocator;

mod support;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn ckks_eval(c: &mut Criterion) {
    phantom_benches::alloc::print_one_shot("ckks_eval", || {
        black_box(phantom_examples::ckks_rescale().unwrap());
    });
    c.bench_function("ckks_eval", |b| {
        b.iter(|| black_box(phantom_examples::ckks_rescale().unwrap()));
    });
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = ckks_eval
}
criterion_main!(benches);
