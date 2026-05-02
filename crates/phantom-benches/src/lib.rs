//! Lightweight benchmark support crate.

use std::time::{Duration, Instant};

/// Runs `iterations` of `operation` and returns the elapsed time.
pub fn time_iterations(mut operation: impl FnMut(), iterations: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

/// Prints a compact benchmark result line.
pub fn print_result(name: &str, iterations: usize, elapsed: Duration) {
    println!("{name}: {iterations} iterations in {elapsed:?}");
}
