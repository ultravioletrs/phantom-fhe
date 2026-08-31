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

- Decide whether Criterion is part of the benchmark dependency policy (pre-approved as a `phantom-benches`-only dev-dependency in `docs/internal/dependency-policy.md`; not yet adopted).
- Add security notes for every published parameter preset.
- Audit serialization compatibility and versioning decisions.
- Confirm secret-bearing types remain non-serializable by default.

## Stable

- Freeze public APIs and serialization domains for the first compatibility window.
- Publish production parameter guidance.
- Complete performance baselines for supported CPU targets.
- Complete security review and release notes.
