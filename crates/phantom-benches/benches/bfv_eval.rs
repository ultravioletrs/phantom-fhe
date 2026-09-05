use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use phantom_benches::alloc::CountingAllocator;

mod support;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn bfv_eval(c: &mut Criterion) {
    phantom_benches::alloc::print_one_shot("bfv_eval", || {
        black_box(phantom_examples::bfv_rotation().unwrap());
    });
    c.bench_function("bfv_eval", |b| {
        b.iter(|| black_box(phantom_examples::bfv_rotation().unwrap()));
    });
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = bfv_eval
}
criterion_main!(benches);
