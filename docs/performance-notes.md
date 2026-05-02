# Performance Notes

The current implementation prioritizes small, readable correctness scaffolds.

## CPU Backend

- `phantom-ring::ntt::CpuNttBackend` is correctness-first and suitable for toy sizes.
- Current benchmark targets are smoke benchmarks, not statistically rigorous performance reports.
- The `phantom-benches` crate uses dependency-free `Instant` timing so benchmarks run without network access or extra setup.

## Future Work

- Replace smoke timing with Criterion once dependency policy and CI caching are settled.
- Add optimized NTT kernels and measure against schoolbook multiplication for crossover points.
- Add allocation tracking for evaluator hot paths.
- Add larger parameter sets only after security and noise-management work catches up.
