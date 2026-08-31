# Contributing

Phantom-FHE is an original Rust implementation. Public papers and mature
open-source FHE libraries may be used for understanding algorithms,
terminology, parameters, and validation behavior, but source code, tests,
examples, documentation, and serialization formats in this repository must
be authored for this repository - see "Contributing" in `README.md`.

For deeper conventions than this file covers (coding patterns, testing
conventions, adding a new scheme or serialized type), see
`docs/developer-guide.md`.

## Before you start

- Read the relevant section of `docs/internal/implementation-plan.md` for the crate you
  are touching. It tracks phase status, owned areas, and exit criteria.
- If your change affects security-relevant status (toy vs. hardened
  behavior), update `SECURITY.md`, `docs/technical-manual.md`, and the
  crate's Rustdoc in the same change.
- Check `docs/internal/dependency-policy.md` before adding a dependency.

## Local checks

Run the same commands CI runs before opening a PR:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
```

If you touched `phantom-benches`, also run:

```bash
cargo bench -p phantom-benches
```

## Formatting and style

- Use `cargo fmt` defaults; do not hand-format around it.
- Keep public error types informative but do not leak secret material into
  `Debug`/`Display` output or error variants.
- Prefer explicit, testable behavior over cleverness, matching the existing
  scaffold style (see any `phantom-*` crate's `error.rs` and `serialization.rs`
  for the expected shape of new public types).

## Testing

- New public behavior needs tests in the owning crate's `tests/` directory
  or inline `#[cfg(test)]` modules, following existing conventions.
- Serialization changes need round-trip tests plus malformed/truncated/
  wrong-domain rejection tests (see `phantom-lattice`, `phantom-schemes`,
  and `phantom-bootstrapping` `serialization.rs` modules for examples).
- Randomized/property-style tests should be deterministic (seeded RNGs),
  matching the existing `rand_chacha`-based test helpers.

## Authorship and licensing

- Do not copy or mechanically translate third-party implementation code,
  comments, tests, examples, serialization formats, or internal layouts
  into this repository.
- By contributing, you agree your contribution is licensed under this
  repository's `Apache-2.0` license.
- Sign off your commits (`git commit -s`) so authorship is traceable.

## Scope of changes

- Keep PRs scoped to one workstream/phase where possible; see
  `docs/internal/implementation-plan.md` for the current workstream breakdown.
- Toy/scaffold behavior should stay clearly labeled (docs, Rustdoc, and
  naming) rather than silently promoted to look production-ready - see
  Workstream 2 in `docs/internal/implementation-plan.md`.
