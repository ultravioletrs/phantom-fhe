use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use phantom_benches::alloc::CountingAllocator;

mod support;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn multiparty(c: &mut Criterion) {
    phantom_benches::alloc::print_one_shot("multiparty", || {
        black_box(phantom_examples::mpckks_interactive_bootstrap().unwrap());
    });
    c.bench_function("multiparty", |b| {
        b.iter(|| black_box(phantom_examples::mpckks_interactive_bootstrap().unwrap()));
    });
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = multiparty
}
criterion_main!(benches);
