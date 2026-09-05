# Release Checklist

## Alpha

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-targets`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo doc --workspace --no-deps`
- Run the `phantom-examples` binaries on toy presets.
- Run the `phantom-benches` smoke benchmarks.
- Confirm README, `docs/`, and implementation plan statuses match the code.
- CI (`.github/workflows/ci.yml`) runs the same command matrix on push/PR - done.
- `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, and `docs/internal/dependency-policy.md` exist and are current - done.
- `docs/` (getting-started, user-guide, concepts, architecture, developer-guide, technical-manual) exists and reflects current source - done.

## Beta

- Criterion adopted as a `phantom-benches`-only dev-dependency, with toy/small benchmark tiers and per-evaluator allocation-count diagnostics - done (Alpha Hardening Workstream 9).
- Add security notes for every published parameter preset.
- Serialization compatibility and versioning audited: domain tags vs. versions, golden-byte/version-mismatch/proptest coverage for every serialized type - done, see `docs/internal/serialization-compatibility-policy.md` (Alpha Hardening Workstream 8).
- Secret-bearing types confirmed to remain non-serializable by default, with the one deliberate, documented exception (`vss::VssShare`) - done (Alpha Hardening Workstream 8).

## Stable

- Freeze public APIs and serialization domains for the first compatibility window.
- Publish production parameter guidance.
- Complete performance baselines for supported CPU targets.
- Complete security review and release notes.
