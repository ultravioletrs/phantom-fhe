use std::time::Duration;

use criterion::Criterion;

/// Returns a CI-tuned [`Criterion`] configuration.
///
/// `cargo bench -p phantom-benches` runs as part of `make ci`, so total
/// wall-clock time across all benchmark binaries has to stay reasonable.
/// Criterion's own defaults (~3s warm-up + ~5s measurement per benchmark,
/// regardless of how cheap the operation is) would push a full run into
/// several minutes across this crate's ~18 benchmark cases. This trims
/// warm-up and measurement time and drops to Criterion's own minimum sample
/// count (10) - still real repeated-sample statistics, not a single
/// reading, just a faster one. For a deeper local sweep, override at the
/// command line, e.g. `cargo bench -p phantom-benches -- --sample-size 100
/// --measurement-time 5`.
pub fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_millis(1500))
        .sample_size(10)
}
