use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use phantom_benches::alloc::CountingAllocator;

mod support;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn bgv_eval(c: &mut Criterion) {
    phantom_benches::alloc::print_one_shot("bgv_eval", || {
        black_box(phantom_examples::bgv_polynomial().unwrap());
    });
    c.bench_function("bgv_eval", |b| {
        b.iter(|| black_box(phantom_examples::bgv_polynomial().unwrap()));
    });
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = bgv_eval
}
criterion_main!(benches);
