//! Shared benchmark support: an allocation-count diagnostic for evaluator
//! hot paths.
//!
//! The Criterion configuration shared across bench binaries lives in
//! `benches/support.rs` instead of here - `criterion` is a dev-dependency,
//! so code in `src/lib.rs` (compiled once, as an ordinary rlib) can't use
//! it; only code compiled directly into a bench/test/example binary can.

/// A one-shot allocation-count diagnostic for evaluator hot paths.
///
/// Not a dependency of any core crate - `phantom-benches` is
/// `publish = false` and outside the trusted core surface (see
/// `docs/internal/dependency-policy.md`). Wraps [`std::alloc::System`] with
/// atomic counters; a bench binary installs it as its `#[global_allocator]`
/// and calls [`alloc::reset`]/[`alloc::snapshot`] around one representative call, printed
/// once per binary run alongside (not folded into) Criterion's own timing
/// statistics - Criterion's public API has no per-iteration allocation
/// hook without a custom `Measurement` implementation, which would be far
/// more machinery than a "where possible" diagnostic needs.
pub mod alloc {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering};

    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);

    /// A counting wrapper around [`System`].
    pub struct CountingAllocator;

    // SAFETY: every method forwards directly to `System`, which is a valid
    // `GlobalAlloc`; the counters are only ever updated with atomic ops
    // around that forwarded call, so this preserves `System`'s own safety
    // contract exactly.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    /// Allocation counts since the last [`reset`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AllocationStats {
        /// Number of `alloc` calls.
        pub allocations: u64,
        /// Total bytes requested across those calls.
        pub bytes: u64,
    }

    /// Zeroes the counters.
    pub fn reset() {
        ALLOCATIONS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
    }

    /// Reads the counters without resetting them.
    pub fn snapshot() -> AllocationStats {
        AllocationStats {
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
            bytes: BYTES.load(Ordering::Relaxed),
        }
    }

    /// Prints a labeled one-shot allocation count for `name`, computed by
    /// resetting the counters, running `operation` once, and snapshotting -
    /// explicitly not a Criterion-averaged metric.
    pub fn print_one_shot(name: &str, operation: impl FnOnce()) {
        reset();
        operation();
        let stats = snapshot();
        println!(
            "{name} allocations: {} calls, {} bytes (one representative call, not a Criterion-averaged metric)",
            stats.allocations, stats.bytes
        );
    }
}
