# Release Checklist

## Alpha

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo doc --workspace --no-deps`
- Run the `phantom-examples` binaries on toy presets.
- Run the `phantom-benches` smoke benchmarks.
- Confirm README and implementation plan statuses match the code.

## Beta

- Add CI for the full command matrix.
- Decide whether Criterion is part of the benchmark dependency policy.
- Add security notes for every published parameter preset.
- Audit serialization compatibility and versioning decisions.
- Confirm secret-bearing types remain non-serializable by default.

## Stable

- Freeze public APIs and serialization domains for the first compatibility window.
- Publish production parameter guidance.
- Complete performance baselines for supported CPU targets.
- Complete security review and release notes.
